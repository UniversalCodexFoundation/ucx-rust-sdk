//! 数据模型 / Data model (SDK-API.md §3).
//!
//! 作为 facade SDK，本模块**直接 re-export** 上游 `ucx-types` 已经建模好的
//! `Codex` / `Structure` / `StructureNode` / `Manifest` / `ManifestEntry` 等类型
//! （它们的字段名已是 `snake_case`，且对 JSON key 做了正确的 serde rename），
//! 避免重复建模导致的漂移。在此之上再定义 SDK 契约特有的结果类型：
//! `Chapter`、`IntegrityResult`/`IntegrityEntry`、`SignatureResult`/`Signer`/
//! `SignatureStatus`。
//!
//! As a facade SDK, this module re-exports the upstream `ucx-types` models
//! (`Codex` / `Structure` / `StructureNode` / `Manifest` / `ManifestEntry` …),
//! whose fields are already `snake_case` with correct serde renames, avoiding
//! duplicated modelling drift. On top of them it defines the SDK-contract
//! result types: `Chapter`, `IntegrityResult`/`IntegrityEntry`,
//! `SignatureResult`/`Signer`/`SignatureStatus`.

// --- 直接 re-export 上游模型 / Direct re-exports of upstream models ---
// 这些类型的字段命名（snake_case）、可选字段语义（serde skip）、JSON key 映射
// （如 struct.json 的 "type" → node_type、codex.json 的 "$schema" → schema）均
// 已由 ucx-types 正确实现，无需在 facade 层复制。
// The upstream types already carry the correct snake_case fields, optional-field
// semantics, and JSON key mappings; no need to duplicate them in the facade.
pub use ucx_types::{
    Codex, FileVersion, HashAlgorithm, Manifest, ManifestEntry, Structure, StructureNode, UcxId,
};

// `Codex` 的嵌套类型也一并导出，方便使用者无需再 `use ucx_types::codex::*`。
// Re-export the nested Codex types so consumers need not reach into `ucx_types::codex`.
pub use ucx_types::codex::{
    Creator, Dates, Description, Identifier, Publisher, Rating, Rights, Series, Title,
};

// `Structure` 的嵌套加密配置类型导出（StructureNode.encryption 用到）。
// Re-export the structure encryption-config types (used by StructureNode.encryption).
pub use ucx_types::structure::{Encryption, KeyAccess};

// =============================================================================
// Chapter — chapters() 扁平化后的叶子 / flattened leaf
// =============================================================================

/// 章节叶子节点的扁平化视图（`chapters()` 的元素）。
///
/// A flattened view of a leaf chapter node (an element of `chapters()`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chapter {
    /// 章节标题（来自 struct.json 叶子节点的 `title`）。
    /// Chapter title (from the leaf node's `title` in struct.json).
    pub title: String,

    /// 相对 `content/` 的文件路径，如 `"chapter-001.md"`。
    /// File path relative to `content/`, e.g. `"chapter-001.md"`.
    pub file: String,

    /// 归档内绝对路径 `"content/{file}"`。
    /// Archive-absolute path `"content/{file}"`.
    pub path: String,
}

// =============================================================================
// IntegrityResult / 完整性结果
// =============================================================================

/// `verify_integrity()` 的结果：是否全部通过 + 逐条目明细。
///
/// Result of `verify_integrity()`: overall pass flag plus per-entry detail.
#[derive(Debug, Clone)]
pub struct IntegrityResult {
    /// 所有 manifest 条目均通过时为 `true`。
    /// `true` iff every manifest entry passed.
    pub valid: bool,

    /// 逐条目结果。
    /// Per-entry results.
    pub entries: Vec<IntegrityEntry>,
}

/// 单个 manifest 条目的完整性校验结果。
///
/// Integrity-check result for a single manifest entry.
#[derive(Debug, Clone)]
pub struct IntegrityEntry {
    /// 归档相对路径。
    /// Archive-relative path.
    pub name: String,

    /// manifest 中记录的期望摘要（Base64-standard，padded）。
    /// Expected digest from the manifest (Base64-standard, padded).
    pub expected: String,

    /// 实际重算得到的摘要（Base64-standard，padded）。
    /// Actual recomputed digest (Base64-standard, padded).
    pub actual: String,

    /// 期望与实际是否相等。
    /// Whether expected == actual.
    pub valid: bool,
}

// =============================================================================
// SignatureResult / 签名结果
// =============================================================================

/// 双层签名验证状态（严格遵循 UCX-FORMAT §6 状态表）。
///
/// Dual-layer signature verification status (strictly per UCX-FORMAT §6 table).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureStatus {
    /// 无任何签名。
    /// No signatures at all.
    Unsigned,

    /// 两层都在且都有效。
    /// Both layers present and valid.
    Verified,

    /// 仅一层在且有效（覆盖不完整）。
    /// Only one layer present and valid (incomplete coverage).
    ValidWithWarnings,

    /// 存在签名但校验失败（两层都在时任一失败即此态）。
    /// Signatures present but verification failed (any failure when both present).
    Invalid,
}

/// `verify_signatures()` 的结果。
///
/// Result of `verify_signatures()`.
#[derive(Debug, Clone)]
pub struct SignatureResult {
    /// 总体状态。
    /// Overall status.
    pub status: SignatureStatus,

    /// Layer 1 是否存在。
    /// Whether Layer 1 is present.
    pub layer1_present: bool,

    /// Layer 1 是否有效。
    /// Whether Layer 1 is valid.
    pub layer1_valid: bool,

    /// Layer 2 是否存在。
    /// Whether Layer 2 is present.
    pub layer2_present: bool,

    /// Layer 2 是否有效。
    /// Whether Layer 2 is valid.
    pub layer2_valid: bool,

    /// 各签名者信息。
    /// Per-signer information.
    pub signers: Vec<Signer>,
}

/// 单个签名者的信息。
///
/// Information about a single signer.
#[derive(Debug, Clone)]
pub struct Signer {
    /// 签名者 ID（来自 `META-INF/signatures/{SIGNER}.SF` 文件名 stem）。
    /// Signer id (from the `META-INF/signatures/{SIGNER}.SF` filename stem).
    pub signer_id: String,

    /// 证书主体 CN（可选）。
    /// Subject Common Name from the cert (optional).
    pub subject_cn: Option<String>,

    /// 证书 BLAKE3 指纹（小写 hex，64 字符）（可选）。
    /// Cert BLAKE3 fingerprint (lowercase hex, 64 chars) (optional).
    pub fingerprint: Option<String>,

    /// 证书类型："self-signed" | "ca-issued"（可选）。
    /// Cert type: "self-signed" | "ca-issued" (optional).
    pub cert_type: Option<String>,

    /// 此签名者的 Layer 1 是否有效。
    /// Whether this signer's Layer 1 is valid.
    pub layer1_valid: bool,

    /// 此签名者的 Layer 2 是否有效。
    /// Whether this signer's Layer 2 is valid.
    pub layer2_valid: bool,
}
