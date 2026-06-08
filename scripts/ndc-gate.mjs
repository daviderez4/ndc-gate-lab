#!/usr/bin/env node
// ndc-gate · iteration 0
//
// The unbypassable boundary check: inside any protected path, every tracked
// file MUST be a `.ndc` container. Plaintext data files are rejected.
//
// Zero dependencies. Runs in CI (required status check) and locally.
//   node scripts/ndc-gate.mjs
// Exit 0 = clean. Exit 1 = violations (blocks the merge).

import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';

const POLICY_PATH = '.nodata/policy.json';

function loadPolicy() {
  try {
    return JSON.parse(readFileSync(POLICY_PATH, 'utf8'));
  } catch (e) {
    console.error(`✗ cannot read ${POLICY_PATH}: ${e.message}`);
    process.exit(2);
  }
}

// minimal glob → RegExp: supports ** (any depth, incl. /) and * (within a segment)
function globToRegExp(glob) {
  let re = '';
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i];
    if (c === '*') {
      if (glob[i + 1] === '*') {
        // ** → match anything including slashes
        re += '.*';
        i++;
        if (glob[i + 1] === '/') i++; // swallow trailing slash of **/
      } else {
        re += '[^/]*';
      }
    } else if ('.+^${}()|[]\\'.includes(c)) {
      re += '\\' + c;
    } else {
      re += c;
    }
  }
  return new RegExp('^' + re + '$');
}

function matchesAny(path, globs) {
  return globs.some((g) => globToRegExp(g).test(path));
}

function trackedFiles() {
  // static command, no user input — execFile (no shell) per security best practice
  const out = execFileSync('git', ['ls-files'], { encoding: 'utf8' });
  return out.split('\n').map((s) => s.trim()).filter(Boolean);
}

function main() {
  const policy = loadPolicy();
  const protectedPaths = policy.protectedPaths ?? [];
  const allowPlaintext = policy.allowPlaintext ?? [];
  const files = trackedFiles();

  const violations = [];
  let protectedCount = 0;

  for (const f of files) {
    if (!matchesAny(f, protectedPaths)) continue; // not in a protected zone
    protectedCount++;
    if (matchesAny(f, allowPlaintext)) continue; // explicitly allowed plaintext
    if (f.endsWith('.ndc')) continue; // sealed — OK
    violations.push(f);
  }

  console.log(`ndc-gate · scanned ${files.length} tracked files · ${protectedCount} inside protected paths`);
  console.log(`protected: ${protectedPaths.join(', ') || '(none)'}`);

  if (violations.length === 0) {
    console.log('✓ PASS — every protected file is a sealed .ndc container.');
    process.exit(0);
  }

  console.error(`\n✗ BLOCKED — ${violations.length} plaintext file(s) inside protected paths:`);
  for (const v of violations) console.error(`   • ${v}   → must be sealed to ${v}.ndc`);
  console.error('\nSeal them (ndc seal <file>) or move them out of a protected path. The gate cannot be bypassed with --no-verify.');
  process.exit(1);
}

main();
