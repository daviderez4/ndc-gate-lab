#!/usr/bin/env bash
# End-to-end demo: prove the three properties.
#   1. plaintext is never in the .ndc (possession ≠ access)
#   2. authorized principal opens; unauthorized gets denied
#   3. revoke kills access to an ALREADY-downloaded file; every open is receipted
#
#   bash demo/run.sh
set -e
cd "$(dirname "$0")/.."
WS=demo/workspace
rm -rf "$WS" tools/vault && mkdir -p "$WS"

line() { printf '\n\033[1;33m── %s\033[0m\n' "$1"; }

line "1. executor mints its keypair (the KEK lives ONLY here = the NoData side)"
node tools/executor.mjs init

line "2. a developer creates a sensitive file"
printf 'full_name,national_id,phone\nDani Levi,123456789,0521234567\nMaya Cohen,987654321,0539876543\n' > "$WS/customers.csv"
cat "$WS/customers.csv"

line "3. the gate forces it through seal → .ndc (using only the PUBLIC key)"
node tools/ndc.mjs seal "$WS/customers.csv" --pub-file tools/vault/recipient.pub --out "$WS/customers.csv.ndc"
rm "$WS/customers.csv"   # plaintext gone; only the sealed container remains (this is what lands in git)

line "4. what GitHub / any cloner sees — raw bytes of the .ndc (gibberish, no plaintext)"
node -e 'const b=require("fs").readFileSync(process.argv[1]);process.stdout.write(b.subarray(0,48).toString("hex").replace(/(..)/g,"$1 ")+"\n")' "$WS/customers.csv.ndc"
echo "inspect (metadata only, still no plaintext):"
node tools/ndc.mjs inspect "$WS/customers.csv.ndc"

line "5. authorized developer 'alice' opens it through the executor"
node tools/executor.mjs open "$WS/customers.csv.ndc" --principal alice

line "6. unauthorized developer 'bob' tries — DENIED (has the file, has no key)"
node tools/executor.mjs open "$WS/customers.csv.ndc" --principal bob || true

line "7. now REVOKE alice — she already has the file cloned on her laptop"
node tools/executor.mjs revoke alice

line "8. alice tries the SAME file again — DENIED. control persisted after download."
node tools/executor.mjs open "$WS/customers.csv.ndc" --principal alice || true

line "9. the proof: every decision is a hash-chained receipt (the odometer)"
node tools/executor.mjs receipts

printf '\n\033[1;32m✓ done — GitHub stayed dumb (just bytes); access lived entirely in the executor.\033[0m\n'
