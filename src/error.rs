//! 统一错误模型 / Unified error model (SDK-API.md §5).
//!
//! 本 SDK 把上游三个 crate（ucx-parse / ucx-verify / ucx-crypto）各自的错误类型
//! 折叠为契约规定的单一 `UcxError` 枚举，类别与 §5 表格一一对应：
//!
//! | 类别 / Category   | 触发 / Trigger                                              |
//! |-------------------|------------------------------------------------------------|
//! | `InvalidFormat`   | 非 ZIP、mimetype 不符、MAJOR>1、UCXE magic/version 非法     |
//! | `NotFound`        | 请求的条目/章节不存在                                       |
//! | `ParseError`      | JSON / MANIFEST 解析失败                                    |
//! | `Unsupported`     | 该 SDK 未实现的算法/KDF/能力                                |
//! | `DecryptionError` | 任何解密失败（**不透明**，统一文案，防 oracle）            |
//! | `IoError`         | 文件读写失败                                               |
//!
//! This SDK folds the error types of the three upstream crates into the single
//! `UcxError` enum mandated by the contract; the variants map 1:1 to the §5
//! table. The `DecryptionError` variant is deliberately opaque (a single fixed
//! message) so it cannot be used as a decryption oracle.

use thiserror::Error;

/// 统一对外错误类型 / The unified public error type.
///
/// 各语言把这些类别映射到惯用机制（Rust 用 `Result` + enum）。
/// Each language maps these categories to its idiomatic mechanism (Rust uses
/// `Result` + enum).
#[derive(Debug, Error)]
pub enum UcxError {
    /// 非 ZIP、mimetype 不符、UCX MAJOR>1、UCXE magic/version 非法。
    /// Not a ZIP, mimetype mismatch, UCX MAJOR>1, or illegal UCXE magic/version.
    #[error("invalid format: {0}")]
    InvalidFormat(String),

    /// 请求的条目/章节不存在。
    /// The requested entry/chapter does not exist.
    #[error("not found: {0}")]
    NotFound(String),

    /// JSON / MANIFEST 解析失败。
    /// JSON / MANIFEST parsing failed.
    #[error("parse error: {0}")]
    ParseError(String),

    /// 该 SDK 未实现的算法 / KDF / 能力。
    /// An algorithm / KDF / capability not implemented by this SDK.
    #[error("unsupported: {0}")]
    Unsupported(String),

    /// 任何解密失败。**不透明**：统一文案，不泄露具体原因（防 oracle，对齐参考实现）。
    /// Any decryption failure. Opaque: a single fixed message, leaking no
    /// distinguishing detail (anti-oracle, matching the reference impl).
    #[error("decryption failed")]
    DecryptionError,

    /// 文件读写失败（I/O 错误可透传）。
    /// File I/O failure (I/O errors pass through).
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),
}

/// 便捷别名：本 SDK 的标准 Result 类型。
/// Convenience alias: this SDK's standard `Result` type.
pub type Result<T> = std::result::Result<T, UcxError>;

// =============================================================================
// 上游错误 → UcxError 映射 / Upstream-error mapping
// =============================================================================

impl From<ucx_parse::ParseError> for UcxError {
    /// 把 `ucx-parse` 的解析错误映射到 §5 的类别。
    /// Map `ucx-parse` errors to the §5 categories.
    fn from(e: ucx_parse::ParseError) -> Self {
        use ucx_parse::ParseError as P;
        match e {
            // 非法格式 / 版本不支持 / 路径穿越 → InvalidFormat。
            // 注意：`UnsupportedVersion` 来自 MAJOR>1，属于"格式不被接受"，按契约
            // §5 归入 InvalidFormat（与 §4.1 "MAJOR>1 抛 InvalidFormat" 一致），
            // 而非 `Unsupported`（后者专指 SDK 未实现的能力）。
            // Note: `UnsupportedVersion` (MAJOR>1) is a rejected on-disk format,
            // so per §5 / §4.1 it maps to InvalidFormat, not `Unsupported`
            // (which is reserved for capabilities this SDK does not implement).
            P::InvalidFormat(m) => UcxError::InvalidFormat(m),
            P::UnsupportedVersion(m) => UcxError::InvalidFormat(m),
            P::PathTraversal(m) => UcxError::InvalidFormat(m),
            // 文件已加密但被当作明文读取时，归类为"未找到明文/格式不符"。
            // 这里选择 InvalidFormat：调用方应改用解密 API。
            // Reading an encrypted entry as plaintext is a format mismatch;
            // callers should use the decrypt API instead.
            P::Encrypted(m) => UcxError::InvalidFormat(m),
            // 缺失文件 → NotFound。
            // Missing entry → NotFound.
            P::MissingFile(m) => UcxError::NotFound(m),
            // 各类解析失败 → ParseError。
            // Parsing failures → ParseError.
            P::MetadataParse(m) => UcxError::ParseError(m),
            P::ManifestParse(m) => UcxError::ParseError(m),
            P::Encoding(m) => UcxError::ParseError(m),
            // ZIP 读取错误：FileNotFound 单独映射为 NotFound，其余作格式错误。
            // ZIP read errors: FileNotFound → NotFound, otherwise InvalidFormat.
            P::Zip(zip::result::ZipError::FileNotFound) => {
                UcxError::NotFound("zip entry not found".to_string())
            }
            P::Zip(z) => UcxError::InvalidFormat(format!("zip error: {z}")),
            // I/O 透传。
            // I/O passes through.
            P::Io(io) => UcxError::IoError(io),
        }
    }
}

impl From<ucx_verify::VerifyError> for UcxError {
    /// 把 `ucx-verify` 的错误映射到 §5 的类别。
    /// Map `ucx-verify` errors to the §5 categories.
    ///
    /// 注意：`verifySignatures()` 的"未通过"是一个**状态**（`SignatureStatus`），
    /// 不是错误；只有当 `verify()` 本身无法运行（I/O、非 ZIP）时才返回错误。
    /// Note: a failed signature check is a *status* (`SignatureStatus`), not an
    /// error; this conversion only handles the cases where `verify()` itself
    /// cannot run (I/O, non-ZIP input).
    fn from(e: ucx_verify::VerifyError) -> Self {
        use ucx_verify::VerifyError as V;
        match e {
            V::Io(io) => UcxError::IoError(io),
            V::InvalidFile(m) => UcxError::InvalidFormat(m),
            // 以下变体在 `verify()` 顶层入口实际上不会返回（它把无签名/无效签名
            // 编码进 VerifyStatus 而非 Err），但为穷尽匹配保留，归入 InvalidFormat。
            // The remaining variants are not actually returned by the top-level
            // `verify()` (which encodes them into VerifyStatus), but are kept
            // here for exhaustiveness and mapped to InvalidFormat.
            V::SigningBlockNotFound => {
                UcxError::InvalidFormat("signing block not found".to_string())
            }
            V::SignatureInvalid(m) => UcxError::InvalidFormat(m),
            V::CertificateInvalid(m) => UcxError::InvalidFormat(m),
            V::HashMismatch { path, .. } => {
                UcxError::InvalidFormat(format!("hash mismatch: {path}"))
            }
        }
    }
}

impl From<ucx_crypto::CryptoError> for UcxError {
    /// 把 `ucx-crypto` 的错误映射到 §5。
    /// Map `ucx-crypto` errors to §5.
    ///
    /// 解密路径的**任何**密码学/解析/认证失败都折叠为不透明的 `DecryptionError`，
    /// 仅 I/O 错误透传——与上游 `decrypt*` 公开 API 的防 oracle 语义完全一致。
    /// Every cryptographic/parse/auth failure on the decrypt path collapses into
    /// the opaque `DecryptionError`; only I/O errors pass through — exactly the
    /// anti-oracle behaviour of the upstream public `decrypt*` API.
    fn from(e: ucx_crypto::CryptoError) -> Self {
        use ucx_crypto::CryptoError as C;
        match e {
            C::Io(io) => UcxError::IoError(io),
            _ => UcxError::DecryptionError,
        }
    }
}
