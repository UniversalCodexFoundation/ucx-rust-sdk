// =============================================================================
// Unicodex Rust SDK — crate 根 / Crate root
// =============================================================================
// SPDX-License-Identifier: MIT
//
// 这是 Unicodex 阅读器 SDK 的 Rust 实现（facade 门面）。它通过 path 依赖复用工作区
// 既有的 `ucx-parse` / `ucx-verify` / `ucx-crypto` / `ucx-types`，并 re-export 一套
// 符合 `sdk/SDK-API.md` 契约的整洁公开 API。范围为**只读阅读器**：
//   解析(parse) + 完整性(integrity) + 双层验签(verify) + UCXE 解密(decrypt)。
// 不包含写入/签名/加密。
//
// This is the Rust implementation of the Unicodex reader SDK (a facade). It
// reuses the existing workspace crates via path dependencies and re-exports a
// clean public API conforming to `sdk/SDK-API.md`. Scope: a read-only reader =
// parse + integrity + dual-layer signature verify + UCXE decryption. It does
// not write/sign/encrypt.
// =============================================================================

#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

// --- 子模块 / Sub-modules ---
pub mod archive; // UcxArchive 句柄 / the UcxArchive handle
pub mod capabilities; // 能力查询 / capability query
pub mod constants; // 量化常量 / quantified constants
pub mod decrypt; // UCXE 解密 / UCXE decryption
pub mod error; // 统一错误模型 / unified error model
pub mod model; // 数据模型 / data model

// =============================================================================
// 顶层 re-export / Top-level re-exports
// =============================================================================
// 把最常用的类型与函数提到 crate 根，使调用方 `use unicodex::*;` 即可获得契约
// 规定的整洁 API（`UcxArchive`、`decrypt_with_key`、`capabilities` 等）。
//
// Hoist the most-used types and functions to the crate root so `use unicodex::*;`
// yields the contract's clean API (`UcxArchive`, `decrypt_with_key`, …).

// 主归档句柄（契约统一命名 `UcxArchive`）。
// The main archive handle (contract-canonical name `UcxArchive`).
pub use archive::UcxArchive;

// 错误模型。
// Error model.
pub use error::{Result, UcxError};

// 能力查询。
// Capability query.
pub use capabilities::{Capabilities, capabilities};

// 模块级解密函数（§4.6）。
// Module-level decryption functions (§4.6).
pub use decrypt::{decrypt_with_key, decrypt_with_passphrase, is_ucxe};

// 数据模型类型（§3）。
// Data-model types (§3).
pub use model::{
    Chapter, Codex, Creator, Dates, Description, Encryption, FileVersion, HashAlgorithm,
    Identifier, IntegrityEntry, IntegrityResult, KeyAccess, Manifest, ManifestEntry, Publisher,
    Rating, Rights, Series, SignatureResult, SignatureStatus, Signer, Structure, StructureNode,
    Title, UcxId,
};

// 量化常量（§6）以 `constants::*` 暴露；同时把最常用的 MIMETYPE/magic 提到根。
// Quantified constants (§6) are exposed under `constants::*`; the most-used
// MIMETYPE/magics are also hoisted to the root for convenience.
pub use constants::{MIMETYPE, UCXE_MAGIC, ZIP_MAGIC};
