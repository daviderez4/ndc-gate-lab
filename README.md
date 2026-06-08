# ndc-gate-lab

**An unbypassable GitHub gate that turns a shared repo into a governed boundary.**
Developers work on GitHub exactly as today — but every data file enters only as a
sealed **`.ndc`** container, code keeps working, and the org keeps control over
each file *even after it's been cloned*.

### 🌐 Read the full explanation → **https://daviderez4.github.io/ndc-gate-lab/**

GitHub stops being just a warehouse for your files. It becomes a controlled
gateway: nothing crosses it in the clear, and what's stored there is inert on its
own — a cloned file is useless without a live, authorized open you can revoke.

## What's public here — the gate
| Piece | File |
|---|---|
| **Policy** — which paths must be sealed | `.nodata/policy.json` |
| **The gate** — blocks any plaintext data file | `scripts/ndc-gate.mjs` |
| **Required check** — runs on every PR + push to `main` | `.github/workflows/ndc-gate.yml` |
| **Ruleset** — makes the check unbypassable (empty bypass) | `.nodata/ruleset.json` |

**See it block:** [PR #2](https://github.com/daviderez4/ndc-gate-lab/pull/2) — a developer tries to add a
plaintext PII file; the `ndc-gate` check fails ❌ and the merge is blocked, even for an admin.

## What's not here
The `.ndc` container format, the governed open path (key custody, revocation,
receipts), and the transparent filter are part of **NoData** and are not in this
public lab. Learn more at **[nodatacapsule.com](https://nodatacapsule.com)**.

> We compute access, not permissions. The absence is the technology.
