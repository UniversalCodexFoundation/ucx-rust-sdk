English | [中文](README.md)

# unicodex (Rust SDK)

Read-only **reader SDK** for the Unicodex `.ucx` novel container format.

This crate is a thin **facade** over the reference Rust implementation: it reuses
the workspace crates `ucx-parse`, `ucx-verify`, `ucx-crypto`, and `ucx-types`
via path dependencies and re-exports a clean public API conforming to
[`sdk/SDK-API.md`](../SDK-API.md) and the byte-level
[`sdk/UCX-FORMAT.md`](../UCX-FORMAT.md).

Scope: **parse + integrity + dual-layer signature verification + UCXE
decryption**. It does **not** write, sign, or encrypt.

- License: `MIT`
- Edition: Rust 2024
- Capability level: **L3 (decryption)** -- the highest tier.

---

## Install

This SDK is part of the Unicodex monorepo and depends on sibling crates by path.
Add it to a crate that can resolve those paths (e.g. within or beside the
workspace):

```toml
[dependencies]
unicodex = { path = "sdk/rust" }
```

It declares its own `[workspace]` table so it is **not** absorbed into the parent
workspace's member list; the `ucx-*` path dependencies still resolve their
`*.workspace = true` inheritance from their own parent workspace.

---

## Usage

### Open, read metadata, list chapters

```rust
use unicodex::UcxArchive;

let mut archive = UcxArchive::open("testdata/sample.ucx")?;

// Metadata (parsed at open time).
let codex = archive.codex();
println!("title = {}", codex.title.main);
println!("ucx_id = {}", codex.identifier.ucx_id);
println!("language = {}", codex.language);

// Flattened table of contents (depth-first leaf order).
for ch in archive.chapters() {
    println!("{} -> {} ({})", ch.title, ch.file, ch.path);
}

// Read a plaintext chapter as text.
let text = archive.read_chapter_text("chapter-001.md")?;
print!("{text}");
# Ok::<(), unicodex::UcxError>(())
```

You can also open from memory with `UcxArchive::open_bytes(&data)`.

### Integrity (BLAKE3 vs MANIFEST)

```rust
use unicodex::UcxArchive;
let mut archive = UcxArchive::open("testdata/sample.ucx")?;

let result = archive.verify_integrity()?;
assert!(result.valid);
for e in &result.entries {
    // `expected` / `actual` are Base64-standard (padded), NOT hex.
    println!("{}: {}", e.name, if e.valid { "ok" } else { "MISMATCH" });
}
# Ok::<(), unicodex::UcxError>(())
```

### Signature verification (Ed25519 dual-layer)

```rust
use unicodex::{UcxArchive, SignatureStatus};
let archive = UcxArchive::open("testdata/sample-signed.ucx")?;

let sig = archive.verify_signatures()?;
match sig.status {
    SignatureStatus::Verified          => println!("both layers valid"),
    SignatureStatus::ValidWithWarnings => println!("only one layer present"),
    SignatureStatus::Invalid           => println!("verification FAILED"),
    SignatureStatus::Unsigned          => println!("no signatures"),
}
for s in &sig.signers {
    println!("{} cn={:?} fp={:?}", s.signer_id, s.subject_cn, s.fingerprint);
}
# Ok::<(), unicodex::UcxError>(())
```

### Decryption (UCXE)

Module-level functions operate on UCXE byte slices:

```rust
use unicodex::{decrypt_with_key, decrypt_with_passphrase, is_ucxe};

let ucxe = std::fs::read("testdata/plain-aesgcm.ucxe")?;
assert!(is_ucxe(&ucxe));

// Direct-key mode (KDF=None). KEY = base64 "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=".
let key: [u8; 32] = *b"0123456789abcdef0123456789abcdef";
let plaintext = decrypt_with_key(&ucxe, &key)?;
assert_eq!(plaintext, b"The quick brown fox jumps over the lazy dog.\n");

// Passphrase mode (NFC-normalized -> KDF -> AEAD/CBC).
let ucxe_pass = std::fs::read("testdata/plain-pass.ucxe")?;
let plaintext = decrypt_with_passphrase(&ucxe_pass, "sdktest-passphrase")?;
assert_eq!(plaintext.len(), 45);
# Ok::<(), unicodex::UcxError>(())
```

Any decryption failure (wrong key, tampered ciphertext, malformed header)
collapses into a single opaque `UcxError::DecryptionError` to prevent oracle
attacks; only I/O errors pass through.

### Capabilities

```rust
let caps = unicodex::capabilities();
assert!(caps.parse && caps.integrity && caps.verify_signatures);
assert!(caps.decrypt_direct_key && caps.decrypt_passphrase);
println!("algorithms = {:?}", caps.algorithms);
println!("kdfs = {:?}", caps.kdfs);
```

---

## Capability matrix

| Capability                     | Supported | Notes                                                  |
|--------------------------------|-----------|--------------------------------------------------------|
| `parse`                        | yes       | ZIP@0 + mimetype + codex/struct/manifest               |
| `integrity`                    | yes       | BLAKE3 -> Base64-standard(padded) vs MANIFEST          |
| `verify_signatures`            | yes       | Layer 1 (SF/EC) + Layer 2 (signing block), Ed25519     |
| `decrypt_direct_key`           | yes       | KDF=None; AES-CBC rejected in direct-key mode          |
| `decrypt_passphrase`           | yes       | NFC -> Argon2id / PBKDF2-HMAC-SHA256 -> AEAD/CBC        |
| Algorithms                     | yes       | AES-256-GCM, AES-256-CBC, ChaCha20-Poly1305            |
| KDFs                           | yes       | argon2id, pbkdf2                                        |
| Chunked decryption (>64 MiB)   | yes       | inherited from `ucx-crypto`                            |

This SDK reaches **L3** (the maximum reader tier).

---

## Conformance tests

`tests/conformance.rs` implements T1--T10 from `SDK-API.md S8`, asserting against
the bundled `testdata/expected.json` and fixtures (copied from `sdk/testdata/`,
so this SDK is self-contained):

| #   | Operation                                              | Expectation                                  |
|-----|--------------------------------------------------------|----------------------------------------------|
| T1  | `open(sample.ucx).codex`                               | ucxId / title / creators / language          |
| T2  | `chapters()`                                           | one leaf `chapter-001.md`                     |
| T3  | `read_chapter_text("chapter-001.md")`                  | exact text                                    |
| T4  | `verify_integrity()` (sample.ucx)                      | valid, 3 entries, Base64 digests             |
| T5  | `verify_signatures()` (sample-signed.ucx)             | VERIFIED, both layers, signer AUTHOR         |
| T6  | `verify_signatures()` (sample.ucx)                    | UNSIGNED                                      |
| T7  | `decrypt_with_key(plain-aesgcm.ucxe, KEY)`            | == plaintext                                  |
| T8  | `decrypt_with_key(plain-chacha.ucxe, KEY)`           | == plaintext                                  |
| T9  | `decrypt_with_passphrase(plain-pass.ucxe, pass)`     | == plaintext                                  |
| T10 | `decrypt_with_key(tampered ucxe, KEY)`               | `DecryptionError`                             |

Run them with:

```sh
cargo test
```

---

## Limitations

- **Facade / monorepo coupling.** This SDK builds against sibling `ucx-*` crates
  via relative path dependencies; it is not yet published as a standalone crate
  on crates.io. To open-source it independently, vendor or publish those crates.
- **`open_bytes` spills to a temp file.** The upstream parser and verifier accept
  only a `&Path`, so `open_bytes` (and the byte-oriented `decrypt_*` functions)
  write the input to a per-process `tempfile::NamedTempFile` and delegate. The
  temp file contains only ciphertext/archive bytes and is auto-deleted; it never
  holds plaintext or keys.
- **Read-only.** Writing, signing, and encryption are out of scope by design.

---

## Versioning

This SDK uses `X.Y.Z` version numbers (see project ADR-012):
- **`X.Y`** (the first two parts) = the supported **UCX standard version** (major.minor). **Identical first two parts imply the same UCX standard and the same public API**.
- **`Z`** (the last part) = the SDK's own patch number (bug fixes only; no public API changes).

The current version **0.4.0** corresponds to UCX standard **0.4.x**. When the UCX standard advances to the next minor version (e.g. 0.5), a new SDK line (0.5.x) will be created, while the old standard line (0.4.x) **continues to receive patches and is not deprecated** (similar to how Python maintains multiple version series in parallel).

---

## License

Licensed under `MIT`, matching the parent project. See [`LICENSE`](LICENSE).
