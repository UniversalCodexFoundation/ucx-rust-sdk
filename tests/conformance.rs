//! 一致性测试 T1–T10 / Conformance tests T1–T10 (SDK-API.md §8).
//!
//! 断言全部来自本目录自带的 `testdata/expected.json` 与夹具文件（复制自
//! `sdk/testdata/`，使本 SDK 自包含、可独立开源）。每个测试对应契约 §8 的一行。
//!
//! All assertions come from the bundled `testdata/expected.json` and fixture
//! files (copied from `sdk/testdata/`, making this SDK self-contained). Each test
//! corresponds to one row of the §8 table.

use std::path::PathBuf;
use std::sync::OnceLock;

use base64::Engine as _;
use serde_json::Value;

use unicodex::{
    SignatureStatus, UcxArchive, decrypt_with_key, decrypt_with_passphrase, is_ucxe,
};

// =============================================================================
// 测试夹具路径与期望值 / Fixture paths & expectations
// =============================================================================

/// 返回 `testdata/` 目录下某夹具的绝对路径。
/// Absolute path of a fixture under `testdata/`.
fn fixture(name: &str) -> PathBuf {
    // CARGO_MANIFEST_DIR 指向 sdk/rust/，testdata 是其子目录。
    // CARGO_MANIFEST_DIR points at sdk/rust/; testdata is a subdirectory.
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("testdata");
    p.push(name);
    p
}

/// 懒加载并缓存 `testdata/expected.json` 为 JSON 值。
/// Lazily load and cache `testdata/expected.json` as a JSON value.
fn expected() -> &'static Value {
    static EXPECTED: OnceLock<Value> = OnceLock::new();
    EXPECTED.get_or_init(|| {
        let raw = std::fs::read_to_string(fixture("expected.json"))
            .expect("read testdata/expected.json");
        serde_json::from_str(&raw).expect("parse expected.json")
    })
}

/// 解码 `expected.json` 中的 32 字节直接密钥（Base64）。
/// Decode the 32-byte direct key from `expected.json` (Base64).
fn direct_key() -> [u8; 32] {
    let b64 = expected()["decryption"]["direct_key_base64"]
        .as_str()
        .expect("direct_key_base64");
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .expect("decode key");
    bytes.try_into().expect("key is 32 bytes")
}

/// `expected.json` 中各 .ucxe 对应的参考明文。
/// The reference plaintext for the .ucxe fixtures, from `expected.json`.
fn plaintext() -> Vec<u8> {
    expected()["decryption"]["plaintext"]
        .as_str()
        .expect("plaintext")
        .as_bytes()
        .to_vec()
}

// =============================================================================
// T1 — codex 元数据 / codex metadata
// =============================================================================

#[test]
fn t1_codex_metadata() {
    let archive = UcxArchive::open(fixture("sample.ucx")).expect("open sample.ucx");
    let codex = archive.codex();

    let exp = &expected()["archive"];
    assert_eq!(
        codex.identifier.ucx_id.to_string(),
        exp["ucx_id"].as_str().unwrap(),
        "ucx_id"
    );
    assert_eq!(codex.title.main, exp["title"].as_str().unwrap(), "title.main");
    assert_eq!(
        codex.creators[0].name,
        exp["author"].as_str().unwrap(),
        "creators[0].name"
    );
    assert_eq!(codex.creators[0].role, "author", "creators[0].role");
    assert_eq!(codex.language, exp["language"].as_str().unwrap(), "language");
}

// =============================================================================
// T2 — chapters() 扁平化 / flattened chapters
// =============================================================================

#[test]
fn t2_chapters() {
    let archive = UcxArchive::open(fixture("sample.ucx")).expect("open sample.ucx");
    let chapters = archive.chapters();

    let exp = expected()["archive"]["chapters"].as_array().unwrap();
    assert_eq!(chapters.len(), exp.len(), "chapter count");

    let first = &chapters[0];
    assert_eq!(first.title, exp[0]["title"].as_str().unwrap(), "chapter title");
    assert_eq!(first.file, exp[0]["file"].as_str().unwrap(), "chapter file");
    // path 必须是归档内绝对路径 content/{file}。
    // path must be the archive-absolute content/{file}.
    assert_eq!(first.path, "content/chapter-001.md", "chapter path");
}

// =============================================================================
// T3 — readChapterText / 章节文本
// =============================================================================

#[test]
fn t3_read_chapter_text() {
    let mut archive = UcxArchive::open(fixture("sample.ucx")).expect("open sample.ucx");
    let text = archive
        .read_chapter_text("chapter-001.md")
        .expect("read chapter text");

    let exp = expected()["archive"]["chapter_content"]["content/chapter-001.md"]
        .as_str()
        .unwrap();
    assert_eq!(text, exp, "chapter text");
}

// =============================================================================
// T4 — verifyIntegrity / 完整性
// =============================================================================

#[test]
fn t4_verify_integrity() {
    let mut archive = UcxArchive::open(fixture("sample.ucx")).expect("open sample.ucx");
    let result = archive.verify_integrity().expect("verify integrity");

    assert!(result.valid, "overall integrity valid");

    let exp_entries = expected()["archive"]["manifest_entries"]
        .as_array()
        .unwrap();
    assert_eq!(result.entries.len(), exp_entries.len(), "3 manifest entries");

    // 每条都通过，且 expected digest 与 expected.json 的 Base64 摘要一致。
    // Every entry passes, and each expected digest equals the Base64 from expected.json.
    for exp in exp_entries {
        let name = exp["name"].as_str().unwrap();
        let b64 = exp["blake3_base64"].as_str().unwrap();
        let got = result
            .entries
            .iter()
            .find(|e| e.name == name)
            .unwrap_or_else(|| panic!("entry {name} present"));
        assert!(got.valid, "entry {name} valid");
        assert_eq!(got.expected, b64, "entry {name} expected digest (Base64)");
        assert_eq!(got.actual, b64, "entry {name} actual digest (Base64)");
    }
}

// =============================================================================
// T5 — verifySignatures (signed) / 已签名归档验签
// =============================================================================

#[test]
fn t5_verify_signatures_signed() {
    let archive =
        UcxArchive::open(fixture("sample-signed.ucx")).expect("open sample-signed.ucx");
    let sig = archive.verify_signatures().expect("verify signatures");

    assert_eq!(sig.status, SignatureStatus::Verified, "status VERIFIED");
    assert!(sig.layer1_valid, "layer1 valid");
    assert!(sig.layer2_valid, "layer2 valid");
    assert!(sig.layer1_present && sig.layer2_present, "both layers present");

    let exp = &expected()["signature"];
    let signer = &sig.signers[0];
    assert_eq!(
        signer.signer_id,
        exp["signer_id"].as_str().unwrap(),
        "signer_id"
    );
    assert_eq!(
        signer.subject_cn.as_deref(),
        Some(exp["subject_cn"].as_str().unwrap()),
        "subject_cn"
    );
    assert_eq!(
        signer.fingerprint.as_deref(),
        Some(exp["fingerprint_sha256"].as_str().unwrap()),
        "fingerprint (lowercase-hex BLAKE3 of cert DER)"
    );
    // cert_type 规范化为小写 "self-signed"。
    // cert_type normalized to lowercase "self-signed".
    assert_eq!(
        signer.cert_type.as_deref(),
        Some(exp["cert_type"].as_str().unwrap()),
        "cert_type"
    );
}

// =============================================================================
// T6 — verifySignatures (unsigned) / 未签名归档
// =============================================================================

#[test]
fn t6_verify_signatures_unsigned() {
    let archive = UcxArchive::open(fixture("sample.ucx")).expect("open sample.ucx");
    let sig = archive.verify_signatures().expect("verify signatures");

    assert_eq!(sig.status, SignatureStatus::Unsigned, "status UNSIGNED");
    assert!(!sig.layer1_present && !sig.layer2_present, "no layers present");
}

// =============================================================================
// T7 — decryptWithKey (AES-256-GCM)
// =============================================================================

#[test]
fn t7_decrypt_aes_gcm_direct_key() {
    let ucxe = std::fs::read(fixture("plain-aesgcm.ucxe")).expect("read plain-aesgcm.ucxe");
    assert!(is_ucxe(&ucxe), "fixture is UCXE");

    let out = decrypt_with_key(&ucxe, &direct_key()).expect("decrypt aesgcm");
    assert_eq!(out, plaintext(), "AES-256-GCM direct-key plaintext");
}

// =============================================================================
// T8 — decryptWithKey (ChaCha20-Poly1305)
// =============================================================================

#[test]
fn t8_decrypt_chacha_direct_key() {
    let ucxe = std::fs::read(fixture("plain-chacha.ucxe")).expect("read plain-chacha.ucxe");
    assert!(is_ucxe(&ucxe), "fixture is UCXE");

    let out = decrypt_with_key(&ucxe, &direct_key()).expect("decrypt chacha");
    assert_eq!(out, plaintext(), "ChaCha20-Poly1305 direct-key plaintext");
}

// =============================================================================
// T9 — decryptWithPassphrase (Argon2id)
// =============================================================================

#[test]
fn t9_decrypt_passphrase_argon2id() {
    let ucxe = std::fs::read(fixture("plain-pass.ucxe")).expect("read plain-pass.ucxe");
    assert!(is_ucxe(&ucxe), "fixture is UCXE");

    let pass = expected()["decryption"]["cases"][2]["passphrase"]
        .as_str()
        .expect("passphrase");
    let out = decrypt_with_passphrase(&ucxe, pass).expect("decrypt passphrase");
    assert_eq!(out, plaintext(), "Argon2id passphrase plaintext");
}

// =============================================================================
// T10 — tampered ucxe -> DecryptionError / 篡改密文
// =============================================================================

#[test]
fn t10_tampered_ucxe_fails_opaquely() {
    let mut ucxe = std::fs::read(fixture("plain-aesgcm.ucxe")).expect("read plain-aesgcm.ucxe");

    // 翻转最后一个字节（落在认证标签内），破坏 AEAD 标签。
    // Flip the last byte (inside the auth tag) to break the AEAD tag.
    let last = ucxe.len() - 1;
    ucxe[last] ^= 0xFF;

    let err = decrypt_with_key(&ucxe, &direct_key()).expect_err("tampered must fail");
    // 必须是不透明的 DecryptionError（防 oracle）。
    // Must be the opaque DecryptionError (anti-oracle).
    assert!(
        matches!(err, unicodex::UcxError::DecryptionError),
        "tampered ciphertext yields opaque DecryptionError, got: {err:?}"
    );
}

// =============================================================================
// 额外：能力查询自检 / Extra: capabilities sanity (not a numbered conformance test)
// =============================================================================

#[test]
fn capabilities_report_l3() {
    let caps = unicodex::capabilities();
    assert!(caps.parse && caps.integrity && caps.verify_signatures);
    assert!(caps.decrypt_direct_key && caps.decrypt_passphrase);
    assert!(caps.algorithms.contains(&"AES-256-GCM".to_string()));
    assert!(caps.algorithms.contains(&"ChaCha20-Poly1305".to_string()));
    assert!(caps.kdfs.contains(&"argon2id".to_string()));
}
