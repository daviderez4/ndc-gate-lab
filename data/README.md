# data/ — protected zone

Every file here is a **protected path** (see `.nodata/policy.json`). The gate
requires every file in this folder to be a sealed **`.ndc`** container — never
plaintext. `README.md` and `.gitkeep` are the only allow-listed exceptions.

To add a real data file, seal it through the executor's public key first:
```bash
node tools/ndc.mjs seal customers.csv --pub-file tools/vault/recipient.pub
# commit customers.csv.ndc — never the plaintext
```

See the full walkthrough in [`../FORMAT.md`](../FORMAT.md) and run `bash demo/run.sh`.
