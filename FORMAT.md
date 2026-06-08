# The `.ndc` format — full spec + how it works with GitHub

This explains, end to end, how an org can store **only `.ndc` files**, let
developers work on a shared GitHub normally, and still hold control over every
file *after* it's been cloned — because of **where the keys live**.

---

## 1. Why GitHub "just works"

GitHub never sees a key and never decrypts anything. To GitHub a `.ndc` is
**opaque bytes** — like a `.zip`. `clone`, `push`, `pull`, `diff` all behave
exactly as today. You only swapped plaintext bytes for ciphertext bytes.

```
developer ──clone──► gets every .ndc (ciphertext)        GitHub: stores bytes, no keys
developer ──open───► must ask the EXECUTOR (holds key)   ← access decision lives here
```

There are **two separate layers**, and only one of them involves keys:

| layer | who | keys? |
|-------|-----|-------|
| **storage** | GitHub | none — stores ciphertext |
| **use** | the dev's machine / CI | yes — via the governed executor |

---

## 2. The container

```
magic        4 bytes   "NDLB"          (0x4E 0x44 0x4C 0x42)
version      1 byte    0x01
header_len   4 bytes   uint32 big-endian
header       N bytes   UTF-8 JSON  (see below)
ciphertext   M bytes   AES-256-GCM(plaintext, content_key)
```

Header (lab suite):
```jsonc
{
  "format": "NDC-LAB", "version": 1, "profile": "x25519-aesgcm",
  "kem": {                          // how the content_key is wrapped
    "alg": "X25519",
    "ephemeral_pub": "<base64>",    // one-time public key for this file
    "recipient_kid": "<id of the executor key that can unwrap>"
  },
  "wrapped_content_key": { "ct": "...", "iv": "...", "tag": "..." },
  "content": { "aead": "AES-256-GCM", "iv": "...", "tag": "...", "sha256": "<plaintext hash>" },
  "filename": "customers.csv", "content_type": "text/csv", "issued_at": "..."
}
```

**The plaintext is never in the file.** Implementation: [`tools/ndc.mjs`](tools/ndc.mjs).

### The crypto (envelope encryption)
1. `content_key` = random 256-bit key. The file body is `AES-256-GCM(plaintext, content_key)`.
2. `content_key` is itself **wrapped**: a one-time X25519 key does ECDH against
   the **executor's public key** → HKDF → a wrap key → `AES-256-GCM(content_key)`.
3. To unwrap you need the executor's **private** key. Nobody else has it.

> **Lab vs production.** The lab uses `X25519 + AES-256-GCM`. Production NDC v0.3
> is post-quantum hybrid: `X25519 + ML-KEM-768` for the wrap and
> `Ed25519 + ML-DSA-65` for a signature. Same shape, stronger suite.

---

## 3. "A dev has access to all files but no key" — exactly

A developer with repo access clones every `.ndc`. But:
- the `content_key` is wrapped under a key **only the executor holds**;
- `cat customers.csv.ndc` → random bytes;
- to actually read it, their tool must ask the **executor** to open it.

So **downloading the files does not help them.** Possession ≠ access.

---

## 4. The executor = where access lives (and where revoke/burn happen)

The executor represents **NoData / the customer's KMS**. It holds the recipient
private key and, on every open request, enforces:

- **policy** — is this principal authorized?
- **revocation** — a revoked principal is denied **even for a file they already
  cloned** — because opening needs a *live* decision, not just the bytes.
- **receipts** — every allow/deny is a hash-chained log entry = the proof/odometer.

Implementation: [`tools/executor.mjs`](tools/executor.mjs). **Burn** = destroy the
wrapped-key material → every copy of that `.ndc` in the world is dead forever.

⚠️ **Critical setting.** The same format can run in two modes:
1. **offline-key** — the holder has the private key and opens alone → *no revoke*. ❌
2. **governed** — opening is mediated by the executor → revocable, audited. ✅ **Use this for repo files.**

---

## 5. How the CODE keeps working

- **Source code stays plaintext** (it must compile). The gate's policy does not
  convert `.ts`/`.py` — only data/secrets/datasets paths.
- **Data files (`.ndc`) are opened at runtime by an authorized principal** — the
  CI runner or the app itself, through the executor. The build works because CI
  is authorized. Revoke CI → the build stops. That's the control reaching into
  the pipeline, on purpose.

### Smooth mode (transparent filenames)
[`tools/ndc-filter.mjs`](tools/ndc-filter.mjs) is a git **clean/smudge** filter:
files keep normal names, git stores sealed bytes, and on checkout an authorized
dev (`NDC_PRINCIPAL`) gets plaintext transparently while everyone else gets
ciphertext. This is the git-crypt pattern — but routed through the **governed**
executor, so it is revocable and audited (git-crypt's shared key is neither).

---

## 6. Honest limits
1. **At the moment of an authorized open**, the plaintext exists in memory / on
   screen — an authorized human can copy it then. No system prevents that;
   NoData shrinks the blast radius (revoke future opens, audit every open, burn).
2. **Online vs cache.** Per-open online checks = instant revoke but need
   connectivity; a cached capability = fast/offline but revoke lags by the TTL.
3. **Tooling.** Native tools can't read `.ndc` without the filter/FUSE shim — that
   shim is what makes it feel "smooth".

---

## 7. Run it
```bash
bash demo/run.sh
```
Shows: seal → ciphertext on disk → authorized open ✓ → unauthorized deny ⛔ →
revoke → same file now denied → the receipt chain.
