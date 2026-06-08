#!/usr/bin/env node
// ndc.mjs · the .ndc container format (LAB build) + seal/inspect CLI
//
// This is a real, working envelope-encryption container — zero dependencies,
// Node built-in crypto only. It mirrors the production NDC v0.3 shape with a
// simpler suite so it runs anywhere:
//
//   LAB suite : X25519 (key wrap) + AES-256-GCM (content)
//   PROD suite: hybrid X25519+ML-KEM-768 (wrap) + AES-256-GCM (content)
//               + Ed25519+ML-DSA-65 (signature)
//
// The point the lab proves: the plaintext is NEVER in the file. The per-file
// content_key is WRAPPED so that only the holder of the recipient PRIVATE key
// (the governed executor — NOT the developer, NOT GitHub) can unwrap it.
//
// Wire layout:
//   magic        4 bytes   "NDLB"
//   version      1 byte    0x01
//   header_len   4 bytes   uint32 big-endian
//   header       N bytes   UTF-8 JSON
//   ciphertext   M bytes   AES-256-GCM(plaintext)

import {
  generateKeyPairSync, createPublicKey, createPrivateKey,
  diffieHellman, hkdfSync, randomBytes, createCipheriv, createDecipheriv,
  createHash,
} from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';

export const MAGIC = Buffer.from('NDLB');
export const VERSION = 1;
const WRAP_INFO = Buffer.from('ndc-v1-wrap');

const sha256hex = (buf) => createHash('sha256').update(buf).digest('hex');
const der = (key, kind) => key.export({ type: kind === 'pub' ? 'spki' : 'pkcs8', format: 'der' });

// ── seal: plaintext + recipient PUBLIC key → .ndc container bytes ──────────
export function sealContainer({ plaintext, recipientPublicDer, filename = 'file', contentType = 'application/octet-stream' }) {
  // ephemeral X25519 → ECDH with the recipient public key → HKDF → wrapKey.
  // Only the recipient PRIVATE key can re-derive wrapKey, so only the executor
  // that holds it can unwrap the content_key.
  const ephem = generateKeyPairSync('x25519');
  const recipientPub = createPublicKey({ key: recipientPublicDer, type: 'spki', format: 'der' });
  const shared = diffieHellman({ privateKey: ephem.privateKey, publicKey: recipientPub });
  const wrapKey = Buffer.from(hkdfSync('sha256', shared, Buffer.alloc(0), WRAP_INFO, 32));

  // per-file content key, AES-256-GCM over the plaintext
  const contentKey = randomBytes(32);
  const iv = randomBytes(12);
  const c = createCipheriv('aes-256-gcm', contentKey, iv);
  const ciphertext = Buffer.concat([c.update(plaintext), c.final()]);
  const tag = c.getAuthTag();

  // wrap the content key under wrapKey (also AES-256-GCM)
  const wrapIv = randomBytes(12);
  const wc = createCipheriv('aes-256-gcm', wrapKey, wrapIv);
  const wrapped = Buffer.concat([wc.update(contentKey), wc.final()]);
  const wrapTag = wc.getAuthTag();

  const header = {
    format: 'NDC-LAB',
    version: VERSION,
    profile: 'x25519-aesgcm',
    note: 'LAB suite. Production adds ML-KEM-768 (PQ wrap) + ML-DSA-65 (PQ signature).',
    kem: {
      alg: 'X25519',
      ephemeral_pub: ephem.publicKey.export({ type: 'spki', format: 'der' }).toString('base64'),
      recipient_kid: sha256hex(recipientPublicDer).slice(0, 16),
    },
    wrapped_content_key: { ct: wrapped.toString('base64'), iv: wrapIv.toString('base64'), tag: wrapTag.toString('base64') },
    content: { aead: 'AES-256-GCM', iv: iv.toString('base64'), tag: tag.toString('base64'), sha256: sha256hex(plaintext) },
    filename,
    content_type: contentType,
    issued_at: new Date().toISOString(),
  };

  const headerBuf = Buffer.from(JSON.stringify(header), 'utf8');
  const lenBuf = Buffer.alloc(4);
  lenBuf.writeUInt32BE(headerBuf.length, 0);
  return Buffer.concat([MAGIC, Buffer.from([VERSION]), lenBuf, headerBuf, ciphertext]);
}

// ── parse: container bytes → { header, ciphertext } (no key needed) ────────
export function parseContainer(buf) {
  if (buf.length < 9 || !buf.subarray(0, 4).equals(MAGIC)) {
    throw new Error('not a .ndc container (bad magic)');
  }
  const version = buf[4];
  const headerLen = buf.readUInt32BE(5);
  const header = JSON.parse(buf.subarray(9, 9 + headerLen).toString('utf8'));
  const ciphertext = buf.subarray(9 + headerLen);
  return { version, header, ciphertext };
}

// ── open: container + recipient PRIVATE key → plaintext (governed call) ─────
// This is pure crypto. The EXECUTOR decides WHETHER to call it (policy), then
// holds the only copy of the private key. Possession of the file alone can
// never reach here.
export function openContainer({ container, recipientPrivateDer }) {
  const { header, ciphertext } = parseContainer(container);
  const recipientPriv = createPrivateKey({ key: recipientPrivateDer, type: 'pkcs8', format: 'der' });
  const ephemeralPub = createPublicKey({ key: Buffer.from(header.kem.ephemeral_pub, 'base64'), type: 'spki', format: 'der' });
  const shared = diffieHellman({ privateKey: recipientPriv, publicKey: ephemeralPub });
  const wrapKey = Buffer.from(hkdfSync('sha256', shared, Buffer.alloc(0), WRAP_INFO, 32));

  const wk = header.wrapped_content_key;
  const wd = createDecipheriv('aes-256-gcm', wrapKey, Buffer.from(wk.iv, 'base64'));
  wd.setAuthTag(Buffer.from(wk.tag, 'base64'));
  const contentKey = Buffer.concat([wd.update(Buffer.from(wk.ct, 'base64')), wd.final()]);

  const cd = createDecipheriv('aes-256-gcm', contentKey, Buffer.from(header.content.iv, 'base64'));
  cd.setAuthTag(Buffer.from(header.content.tag, 'base64'));
  const plaintext = Buffer.concat([cd.update(ciphertext), cd.final()]);

  if (sha256hex(plaintext) !== header.content.sha256) throw new Error('integrity check failed');
  return { plaintext, header };
}

// ─────────────────────────── CLI ───────────────────────────
function cli() {
  const [cmd, ...rest] = process.argv.slice(2);
  const flag = (name) => { const i = rest.indexOf(name); return i >= 0 ? rest[i + 1] : undefined; };

  if (cmd === 'seal') {
    const file = rest[0];
    const pubFile = flag('--pub-file');
    if (!file || !pubFile) { console.error('usage: ndc seal <file> --pub-file <recipient.pub> [--out <file.ndc>]'); process.exit(2); }
    const out = flag('--out') ?? `${file}.ndc`;
    const recipientPublicDer = Buffer.from(readFileSync(pubFile, 'utf8').trim(), 'base64');
    const container = sealContainer({
      plaintext: readFileSync(file),
      recipientPublicDer,
      filename: file.split(/[\\/]/).pop(),
      contentType: file.endsWith('.csv') ? 'text/csv' : 'application/octet-stream',
    });
    writeFileSync(out, container);
    console.log(`sealed → ${out} (${container.length} bytes, plaintext nowhere inside)`);
    return;
  }

  if (cmd === 'inspect') {
    const file = rest[0];
    if (!file) { console.error('usage: ndc inspect <file.ndc>'); process.exit(2); }
    const { version, header, ciphertext } = parseContainer(readFileSync(file));
    console.log(JSON.stringify({
      magic: 'NDLB', wireVersion: version, profile: header.profile,
      filename: header.filename, content_type: header.content_type,
      recipient_kid: header.kem.recipient_kid, plaintext_sha256: header.content.sha256,
      issued_at: header.issued_at, ciphertext_bytes: ciphertext.length,
    }, null, 2));
    return;
  }

  console.error('commands: seal | inspect');
  process.exit(2);
}

if (import.meta.url === `file://${process.argv[1]}` || process.argv[1]?.endsWith('ndc.mjs')) cli();
