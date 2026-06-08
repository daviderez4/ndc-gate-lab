# ndc-gate-lab

**Experiment:** an *unbypassable* GitHub gate that forces every **data file** in a repo to be a `.ndc` (NoData sealed container) — never plaintext — while letting **source code keep working**, and keeping **control over the files even after someone clones them**.

This is the PoC for the two conditions that make it real:

1. **Possession ≠ access.** Anyone with repo access can `git clone` the `.ndc` files like any employee — but a `.ndc` is just ciphertext. Opening it requires a *live, authorized* open through NoData (governed mode), so we can **revoke / burn / audit** even after download.
2. **Code still works.** Source code stays plaintext (it must compile). Data files become `.ndc` and are opened *transparently at runtime* by authorized principals (CI, the app) via the executor — so the build doesn't break.

## What's in this lab

**Iteration 0 — the blocking gate**

| Piece | File | Status |
|---|---|---|
| **Policy** — which paths must be `.ndc` | `.nodata/policy.json` | ✅ |
| **The gate** — fails if a protected file is plaintext | `scripts/ndc-gate.mjs` (zero-dep Node) | ✅ |
| **Required check** — runs the gate on PR + push to `main` | `.github/workflows/ndc-gate.yml` | ✅ |
| **Ruleset** — makes the check unbypassable (empty bypass) | `.nodata/ruleset.json` | ✅ |

**Iteration 1 — the real format + governed open** → see **[`FORMAT.md`](FORMAT.md)**

| Piece | File | Status |
|---|---|---|
| **`.ndc` container format** — real envelope crypto (X25519 + AES-256-GCM) | `tools/ndc.mjs` | ✅ |
| **Governed executor** — holds the key, enforces policy/revoke, emits receipts | `tools/executor.mjs` | ✅ |
| **Transparent mode** — git clean/smudge filter | `tools/ndc-filter.mjs` | ✅ (optional) |
| **End-to-end demo** — seal → deny → revoke → receipts | `demo/run.sh` | ✅ |

```bash
bash demo/run.sh   # watch possession ≠ access, and revoke kill an already-cloned file
```

### How the gate works (iteration 0)
- `.nodata/policy.json` declares **protected globs** (e.g. `data/**`). Inside them, every file **must end in `.ndc`** (except an allow-list like `README.md` / `.gitkeep`).
- The gate runs `git ls-files`, matches against the policy, and **exits non-zero** if any protected file is plaintext.
- Wired as a **required status check** via a branch/org **ruleset** with an *empty bypass list* → it is enforced server-side by GitHub. `git commit --no-verify` cannot get past it; even admins don't bypass. That is the "can't do it without the gate" property.

### See it block (the demo)
```bash
# green today. now try to sneak a plaintext data file in:
echo "name,ssn" > data/leak.csv
git add data/leak.csv && git commit -m "oops"
git push origin HEAD:test-branch   # open a PR → the ndc-gate check FAILS → merge blocked
```

## Roadmap (next iterations)
- **i1 — auto-seal (clean/smudge):** git filter routes through the NoData executor. `commit` → seals to `.ndc`; `checkout` (authorized) → transparent plaintext; unauthorized → ciphertext.
- **i2 — governed open:** pin `.ndc` to executor-mediated open so revoke/burn works on already-cloned copies; every open emits a signed receipt (odometer).
- **i3 — org ruleset:** one organization-wide ruleset so the gate is required on **every** repo, not just this one.
- **i4 — container validation:** gate also runs `ndc inspect` to confirm each `.ndc` is a real sealed container, not a renamed plaintext.

> Honest limits: a cache TTL trades instant-revoke for offline speed; an authorized human can still copy the plaintext at the moment they open it; native tools need the filter/FUSE shim to read `.ndc`.
