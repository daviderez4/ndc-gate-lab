#!/usr/bin/env node
// ndc-filter.mjs · OPTIONAL "transparent" mode (git clean/smudge)
//
// This is what makes the experience SMOOTH: files keep their normal names,
// but git stores the sealed .ndc bytes and shows authorized developers the
// plaintext on checkout. Unauthorized developers see ciphertext.
//
// Enable (local, per-clone — by design it cannot be forced from a clone):
//   git config filter.ndc.clean  "node tools/ndc-filter.mjs clean %f"
//   git config filter.ndc.smudge "node tools/ndc-filter.mjs smudge %f"
//   git config filter.ndc.required true
//   # .gitattributes already routes protected paths through filter=ndc
//
//   clean  (working tree → repo): seal plaintext to .ndc using the PUBLIC key
//   smudge (repo → working tree): ask the executor to open, as $NDC_PRINCIPAL.
//                                 authorized → plaintext; otherwise → ciphertext.
//
// Reads stdin, writes stdout (the git filter contract).

import { readFileSync } from 'node:fs';
import { sealContainer, parseContainer, openContainer } from './ndc.mjs';

const VAULT = new URL('./vault/', import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1');
const readStdin = () => readFileSync(0);

const mode = process.argv[2];
const filename = process.argv[3] ?? 'file';
const input = readStdin();

if (mode === 'clean') {
  // already sealed? pass through unchanged (idempotent)
  try { parseContainer(input); process.stdout.write(input); process.exit(0); } catch { /* plaintext → seal */ }
  const pub = Buffer.from(readFileSync(`${VAULT}recipient.pub`, 'utf8').trim(), 'base64');
  process.stdout.write(sealContainer({ plaintext: input, recipientPublicDer: pub, filename }));
} else if (mode === 'smudge') {
  const principal = process.env.NDC_PRINCIPAL;
  try {
    if (!principal) throw new Error('no principal');
    // governed open: in production this calls the executor service; here we
    // read the locally-held key only if the principal is authorized.
    const policy = JSON.parse(readFileSync(`${VAULT}policy.json`, 'utf8'));
    if (policy.revoked.includes(principal) || !policy.authorized.includes(principal)) throw new Error('denied');
    const priv = Buffer.from(readFileSync(`${VAULT}recipient.key`, 'utf8').trim(), 'base64');
    const { plaintext } = openContainer({ container: input, recipientPrivateDer: priv });
    process.stdout.write(plaintext); // authorized → transparent plaintext
  } catch {
    process.stdout.write(input); // unauthorized / no executor → ciphertext stays
  }
} else {
  process.stderr.write('usage: ndc-filter.mjs <clean|smudge> <filename>\n');
  process.exit(2);
}
