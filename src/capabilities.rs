//! 能力分级与查询 / Capability levels & query (SDK-API.md §7).
//!
//! Rust 是参考实现，本 facade 直接复用上游全部能力，达到 **L3（解密）**：
//! 解析 + 完整性 + 双层验签 + 直接密钥/口令解密，支持三种对称算法与两种 KDF。
//! `capabilities()` 如实返回这些布尔与子集，便于调用方在运行时探测。
//!
//! Rust is the reference implementation; this facade reuses all upstream
//! capabilities and reaches **L3 (decryption)**: parse + integrity + dual-layer
//! verify + direct-key/passphrase decryption, with three symmetric algorithms
//! and two KDFs. `capabilities()` reports these honestly for runtime probing.

/// SDK 能力声明（契约 §7）。
///
/// Capability declaration of the SDK (contract §7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capabilities {
    /// 解析能力（恒为 true）。
    /// Parse capability (always true).
    pub parse: bool,

    /// 完整性校验（BLAKE3 可用）。
    /// Integrity checking (BLAKE3 available).
    pub integrity: bool,

    /// 双层 Ed25519 验签。
    /// Dual-layer Ed25519 signature verification.
    pub verify_signatures: bool,

    /// 直接密钥解密（KDF=None）。
    /// Direct-key decryption (KDF=None).
    pub decrypt_direct_key: bool,

    /// 口令解密（含 KDF）。
    /// Passphrase decryption (with a KDF).
    pub decrypt_passphrase: bool,

    /// 实际支持的对称算法子集。
    /// The subset of symmetric algorithms actually supported.
    pub algorithms: Vec<String>,

    /// 实际支持的 KDF 子集。
    /// The subset of KDFs actually supported.
    pub kdfs: Vec<String>,
}

/// 返回本 SDK 的能力集合。
///
/// Return this SDK's capability set.
///
/// Rust 参考实现支持全部三种算法与两种 KDF，故所有布尔为 true。
/// The Rust reference impl supports all three algorithms and both KDFs, so every
/// boolean is true.
pub fn capabilities() -> Capabilities {
    Capabilities {
        parse: true,
        integrity: true,
        verify_signatures: true,
        decrypt_direct_key: true,
        decrypt_passphrase: true,
        // 算法名与 struct.json `encryption.algorithm` / 文档中的写法一致。
        // Algorithm names match struct.json `encryption.algorithm` / the docs.
        algorithms: vec![
            "AES-256-GCM".to_string(),
            "AES-256-CBC".to_string(),
            "ChaCha20-Poly1305".to_string(),
        ],
        // KDF 名用小写标识，与契约 §7 示例（["argon2id","pbkdf2"]）一致。
        // KDF names are lowercase, matching the §7 example (["argon2id","pbkdf2"]).
        kdfs: vec!["argon2id".to_string(), "pbkdf2".to_string()],
    }
}
