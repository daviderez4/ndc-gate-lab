#!/usr/bin/env node
// executor.mjs · the GOVERNED open path (the NoData side)
//
// This represents NoData / the customer's KMS — the side that HOLDS the
// recipient private key (the KEK) and DECIDES whether a given principal may
// open a given .ndc. A developer's machine never has this key. GitHub never
// has this key. Possession of the .ndc file therefore ≠ access.
//
// It enforces:
//   • policy        — only authorized principals may open
//   • revocation    — a revoked principal is denied, even for a file they
//                     already cloned/downloaded (this is the killer property)
//   • receipts      — every decision (allow/deny) is appended to a hash-chained
//                     log = the proof / odometer
//
//   node tools/executor.mjs init
//   node tools/executor.mjs pubkey
//   node tools/executor.mjs open <file.ndc> --principal <name> [--out <file>]
//   node tools/executor.mjs grant <name> | revoke <name>
//   node tools/executor.mjs receipts

import { generateKeyPairSync, createHash } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync, existsSync, appendFileSync } from 'node:fs';
import { openContainer } from './ndc.mjs';

const VAULT = new URL('./vault/', import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1');
const f = (name) => `${VAULT}${name}`;
const sha256hex = (s) => createHash('sha256').update(s).digest('hex');

function loadPolicy() { return JSON.parse(readFileSync(f('policy.json'), 'utf8')); }
function savePolicy(p) { writeFileSync(f('policy.json'), JSON.stringify(p, null, 2)); }

function emitReceipt(rec) {
  let prev = 'genesis';
  let index = 0;
  if (existsSync(f('receipts.log'))) {
    const lines = readFileSync(f('receipts.log'), 'utf8').trim().split('\n').filter(Boolean);
    if (lines.length) { const last = JSON.parse(lines[lines.length - 1]); prev = last.hash; index = last.index + 1; }
  }
  const body = { index, ts: new Date().toISOString(), ...rec };
  const hash = sha256hex(prev + JSON.stringify(body));
  appendFileSync(f('receipts.log'), JSON.stringify({ ...body, prev, hash }) + '\n');
  return hash;
}

function init() {
  mkdirSync(VAULT, { recursive: true });
  const { publicKey, privateKey } = generateKeyPairSync('x25519');
  writeFileSync(f('recipient.pub'), publicKey.export({ type: 'spki', format: 'der' }).toString('base64'));
  writeFileSync(f('recipient.key'), privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64'));
  if (!existsSync(f('policy.json'))) savePolicy({ authorized: ['alice', 'ci-runner'], revoked: [] });
  if (!existsSync(f('receipts.log'))) writeFileSync(f('receipts.log'), '');
  console.log('✓ vault ready (executor holds recipient.key — the KEK). authorized: alice, ci-runner');
  console.log('  recipient public key → tools/vault/recipient.pub (give this to sealers; it cannot open anything)');
}

function decide(principal) {
  const p = loadPolicy();
  if (p.revoked.includes(principal)) return { allow: false, reason: 'revoked' };
  if (!p.authorized.includes(principal)) return { allow: false, reason: 'not_authorized' };
  return { allow: true, reason: 'ok' };
}

function open(file, principal, out) {
  if (!principal) { console.error('--principal <name> required'); process.exit(2); }
  const verdict = decide(principal);
  if (!verdict.allow) {
    const h = emitReceipt({ principal, file, decision: 'deny', reason: verdict.reason });
    console.error(`⛔ DENY — principal "${principal}" (${verdict.reason}). receipt 🔗${h.slice(0, 10)}`);
    console.error('   the file stays ciphertext. possession ≠ access.');
    process.exit(13);
  }
  const recipientPrivateDer = Buffer.from(readFileSync(f('recipient.key'), 'utf8').trim(), 'base64');
  const { plaintext, header } = openContainer({ container: readFileSync(file), recipientPrivateDer });
  const h = emitReceipt({ principal, file, decision: 'allow', sha256: header.content.sha256 });
  if (out) { writeFileSync(out, plaintext); console.error(`✓ ALLOW — opened for "${principal}" → ${out}. receipt 🔗${h.slice(0, 10)}`); }
  else { process.stderr.write(`✓ ALLOW — opened for "${principal}". receipt 🔗${h.slice(0, 10)}\n`); process.stdout.write(plaintext); }
}

function main() {
  const [cmd, ...rest] = process.argv.slice(2);
  const flag = (name) => { const i = rest.indexOf(name); return i >= 0 ? rest[i + 1] : undefined; };
  switch (cmd) {
    case 'init': return init();
    case 'pubkey': return void process.stdout.write(readFileSync(f('recipient.pub'), 'utf8'));
    case 'open': return open(rest[0], flag('--principal'), flag('--out'));
    case 'grant': { const p = loadPolicy(); if (!p.authorized.includes(rest[0])) p.authorized.push(rest[0]); p.revoked = p.revoked.filter((x) => x !== rest[0]); savePolicy(p); return console.log(`✓ granted ${rest[0]}`); }
    case 'revoke': { const p = loadPolicy(); if (!p.revoked.includes(rest[0])) p.revoked.push(rest[0]); savePolicy(p); return console.log(`✓ revoked ${rest[0]} — every future open denied, including already-cloned copies`); }
    case 'receipts': return void process.stdout.write(existsSync(f('receipts.log')) ? readFileSync(f('receipts.log'), 'utf8') : '(none)\n');
    default: console.error('commands: init | pubkey | open | grant | revoke | receipts'); process.exit(2);
  }
}
main();
