#!/usr/bin/env node
// ndc-gate · iteration 0.2 (anti-cheat)
//
// The unbypassable boundary check: inside any protected path, every tracked
// file must be a REAL sealed container — verified by its magic bytes "NDLB",
// not just a ".ndc" name. A plaintext file renamed to .ndc is now rejected.
//
// Zero dependencies. Runs in CI (required status check) and locally.
//   node scripts/ndc-gate.mjs
// Exit 0 = clean. Exit 1 = violations (blocks the merge).

import { readFileSync, openSync, readSync, closeSync } from 'node:fs';
import { execFileSync } from 'node:child_process';

const POLICY_PATH = '.nodata/policy.json';
const MAGIC = Buffer.from('NDLB'); // every .ndc container starts with these 4 bytes

function loadPolicy() {
  try { return JSON.parse(readFileSync(POLICY_PATH, 'utf8')); }
  catch (e) { console.error(`✗ cannot read ${POLICY_PATH}: ${e.message}`); process.exit(2); }
}

// minimal glob → RegExp: supports ** (any depth, incl. /) and * (within a segment)
function globToRegExp(glob) {
  let re = '';
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i];
    if (c === '*') {
      if (glob[i + 1] === '*') { re += '.*'; i++; if (glob[i + 1] === '/') i++; }
      else re += '[^/]*';
    } else if ('.+^${}()|[]\\'.includes(c)) re += '\\' + c;
    else re += c;
  }
  return new RegExp('^' + re + '$');
}
const matchesAny = (path, globs) => globs.some((g) => globToRegExp(g).test(path));

function trackedFiles() {
  return execFileSync('git', ['ls-files'], { encoding: 'utf8' }).split('\n').map((s) => s.trim()).filter(Boolean);
}

// Read the first 4 bytes. CI is the enforcement point and runs WITHOUT the
// smudge filter, so the working-tree file == the stored (sealed) blob there.
function first4(path) {
  try {
    const fd = openSync(path, 'r');
    const buf = Buffer.alloc(4);
    readSync(fd, buf, 0, 4, 0);
    closeSync(fd);
    return buf;
  } catch { return Buffer.alloc(0); }
}
const isSealed = (path) => first4(path).equals(MAGIC);

function main() {
  const policy = loadPolicy();
  const protectedPaths = policy.protectedPaths ?? [];
  const allowPlaintext = policy.allowPlaintext ?? [];
  const files = trackedFiles();

  const violations = [];
  let protectedCount = 0;

  for (const f of files) {
    if (!matchesAny(f, protectedPaths)) continue;
    protectedCount++;
    if (matchesAny(f, allowPlaintext)) continue;
    if (isSealed(f)) continue; // real "NDLB" container — OK
    violations.push(f);
  }

  console.log(`ndc-gate · scanned ${files.length} tracked files · ${protectedCount} inside protected paths`);
  console.log(`protected: ${protectedPaths.join(', ') || '(none)'} · check: magic bytes "NDLB"`);

  if (violations.length === 0) {
    console.log('✓ PASS — every protected file is a real sealed .ndc container.');
    process.exit(0);
  }

  console.error(`\n✗ BLOCKED — ${violations.length} file(s) inside protected paths are not sealed containers:`);
  for (const v of violations) console.error(`   • ${v}   → plaintext or a fake .ndc (no "NDLB" magic). Seal it for real.`);
  console.error('\nA renamed plaintext file does not pass. The gate cannot be bypassed with --no-verify.');
  process.exit(1);
}

main();
