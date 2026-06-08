# data/ — protected zone

Every file here is a **protected path** (see `.nodata/policy.json`). The gate
requires every file in this folder to be a sealed **`.ndc`** container — never
plaintext. `README.md` and `.gitkeep` are the only allow-listed exceptions.

- ✅ `customers.ndc` — sealed, passes the gate
- ❌ `customers.csv` — plaintext, **blocked** by the gate

To add a real data file: seal it first (`ndc seal customers.csv` → `customers.csv.ndc`),
commit the `.ndc`, never the plaintext.
