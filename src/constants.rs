//! 量化常量 / Quantified constants (SDK-API.md §6).
//!
//! 每个 SDK 都暴露同名常量（命名按各语言惯例本地化，Rust 用 `SCREAMING_SNAKE`）。
//! 数值取自 UCX-FORMAT.md Appendix A，全部已源码核验。本模块仅声明常量，不含逻辑，
//! 便于人类与 LLM 直接核对每一个数值的来源。
//!
//! Every SDK exposes the same named constants (localized per language; Rust uses
//! `SCREAMING_SNAKE`). The values come from UCX-FORMAT.md Appendix A and are all
//! source-verified. This module is pure declarations so the provenance of each
//! number is trivial to audit.

// =============================================================================
// 容器与版本 / Container & version
// =============================================================================

/// UCX 归档的固定 MIME 类型字符串（28 字节，无尾随换行）。
/// Fixed mimetype string for UCX archives (28 bytes, no trailing newline).
/// 来源 / Source: UCX-FORMAT.md §6, `ucx-build/src/archive.rs:28`.
pub const MIMETYPE: &str = "application/vnd.unicodex+zip";

/// ZIP 本地文件头魔数，必须出现在文件 offset 0。
/// ZIP local file header magic; must appear at file offset 0.
/// 来源 / Source: `ucx-parse/src/lib.rs:37`.
pub const ZIP_MAGIC: [u8; 4] = [0x50, 0x4B, 0x03, 0x04];

/// UCXE 加密容器魔数 "UCXE"。
/// UCXE encrypted-container magic, the ASCII bytes "UCXE".
/// 来源 / Source: `ucx-crypto/src/lib.rs:80`.
pub const UCXE_MAGIC: [u8; 4] = [0x55, 0x43, 0x58, 0x45];

/// UCXE 容器格式版本。
/// UCXE container format version.
/// 来源 / Source: `ucx-crypto/src/lib.rs:84`.
pub const UCXE_FORMAT_VERSION: u8 = 0x01;

/// 本 SDK 支持的最高 UCX-Version MAJOR；解析时拒绝 MAJOR>1。
/// Highest supported UCX-Version MAJOR; archives with MAJOR>1 are rejected.
/// 来源 / Source: `ucx-parse/src/lib.rs:50`.
pub const SUPPORTED_UCX_MAJOR: u32 = 1;

// =============================================================================
// 对称算法 ID（UCXE 头部第 6 字节）/ Symmetric algorithm IDs (UCXE header byte 6)
// =============================================================================

/// AES-256-GCM：nonce 12 字节，tag 16 字节。
/// AES-256-GCM: 12-byte nonce, 16-byte tag.
pub const ALGO_AES_256_GCM: u8 = 0x01;

/// AES-256-CBC + HMAC-SHA256（Encrypt-then-MAC）：iv 16 字节，mac 32 字节。
/// AES-256-CBC + HMAC-SHA256 (Encrypt-then-MAC): 16-byte IV, 32-byte MAC.
pub const ALGO_AES_256_CBC: u8 = 0x02;

/// ChaCha20-Poly1305：nonce 12 字节，tag 16 字节。
/// ChaCha20-Poly1305: 12-byte nonce, 16-byte tag.
pub const ALGO_CHACHA20_POLY1305: u8 = 0x03;

// =============================================================================
// KDF ID（UCXE 头部第 7 字节）/ KDF IDs (UCXE header byte 7)
// =============================================================================

/// KDF=None：直接密钥模式，无参数块。
/// KDF=None: direct-key mode, no parameter block.
pub const KDF_NONE: u8 = 0x00;

/// Argon2id：12 字节参数块 `mem_kib:u32 ‖ time:u32 ‖ par:u32`（LE）。
/// Argon2id: 12-byte parameter block `mem_kib:u32 ‖ time:u32 ‖ par:u32` (LE).
pub const KDF_ARGON2ID: u8 = 0x01;

/// PBKDF2-HMAC-SHA256：4 字节参数块 `iterations:u32`（LE）。
/// PBKDF2-HMAC-SHA256: 4-byte parameter block `iterations:u32` (LE).
pub const KDF_PBKDF2_HMAC_SHA256: u8 = 0x02;

// =============================================================================
// 长度 / Lengths
// =============================================================================

/// AEAD（GCM / ChaCha20）nonce 长度（字节）。
/// AEAD (GCM / ChaCha20) nonce length in bytes.
pub const AEAD_NONCE_LEN: usize = 12;

/// AES-CBC IV 长度（字节）。
/// AES-CBC IV length in bytes.
pub const CBC_IV_LEN: usize = 16;

/// GCM 认证标签长度（字节）。
/// GCM authentication tag length in bytes.
pub const GCM_TAG_LEN: usize = 16;

/// ChaCha20-Poly1305 认证标签长度（字节）。
/// ChaCha20-Poly1305 authentication tag length in bytes.
pub const CHACHA_TAG_LEN: usize = 16;

/// AES-CBC 的 HMAC-SHA256 标签长度（字节）。
/// AES-CBC HMAC-SHA256 MAC length in bytes.
pub const CBC_MAC_LEN: usize = 32;

/// 口令模式下盐值的精确长度（解密路径要求恰好 16）。
/// Exact salt length on the passphrase decrypt path (must be exactly 16).
pub const SALT_LEN: usize = 16;

// =============================================================================
// KDF 默认与边界 / KDF defaults & bounds
// =============================================================================

/// Argon2 版本号 0x13（v19）。
/// Argon2 version 0x13 (v19).
pub const ARGON2_VERSION: u8 = 0x13;

/// Argon2id 默认内存代价（KiB），即 64 MiB；边界 19456..=4194304。
/// Argon2id default memory cost (KiB) = 64 MiB; bounds 19456..=4194304.
pub const ARGON2_DEFAULT_MEM_KIB: u32 = 65536;

/// Argon2id 默认时间代价（迭代轮数）；边界 2..=100。
/// Argon2id default time cost (passes); bounds 2..=100.
pub const ARGON2_DEFAULT_TIME: u32 = 3;

/// Argon2id 默认并行度；边界 ≥1。
/// Argon2id default parallelism; bounds ≥1.
pub const ARGON2_DEFAULT_PARALLELISM: u32 = 4;

/// PBKDF2-HMAC-SHA256 默认迭代次数；边界 100000..=10000000。
/// PBKDF2-HMAC-SHA256 default iterations; bounds 100000..=10000000.
pub const PBKDF2_DEFAULT_ITERS: u32 = 600_000;

// =============================================================================
// 分块（大文件）/ Chunking (large files)
// =============================================================================

/// 分块阈值：明文 > 64 MiB 才分块（严格大于）。
/// Chunking threshold: plaintext > 64 MiB triggers chunking (strict `>`).
pub const CHUNK_THRESHOLD: u64 = 67_108_864;

/// 单块大小：1 MiB；最后一块可更小。
/// Chunk size: 1 MiB; the last chunk may be smaller.
pub const CHUNK_SIZE: usize = 1_048_576;

// =============================================================================
// 签名 / Signatures
// =============================================================================

/// 签名算法 ID `0x0001`（Ed25519 + BLAKE3，两层通用）。
/// Signature algorithm ID `0x0001` (Ed25519 + BLAKE3, both layers).
pub const SIG_ALGO_ED25519_BLAKE3: u32 = 0x0001;

/// Ed25519 签名长度（字节）。
/// Ed25519 signature length in bytes.
pub const ED25519_SIG_LEN: usize = 64;

/// Ed25519 公钥长度（字节）。
/// Ed25519 public-key length in bytes.
pub const ED25519_PUBKEY_LEN: usize = 32;

/// Ed25519 在 X.509 SPKI 中的 OID。
/// Ed25519 SPKI OID inside X.509 certificates.
pub const ED25519_SPKI_OID: &str = "1.3.101.112";

/// Layer 2 签名块魔数（16 字节，注意尾随 NUL）。
/// Layer 2 signing-block magic (16 bytes, note the trailing NUL).
pub const L2_BLOCK_MAGIC: &[u8; 16] = b"UCX Sig Block 1\0";

/// Layer 2 pair id 常量。
/// Layer 2 pair-id constant.
pub const L2_PAIR_ID: u32 = 0x5543_5801;

/// Layer 2 分块摘要前缀字节。
/// Layer 2 per-chunk digest prefix byte.
pub const L2_CHUNK_PREFIX: u8 = 0xA5;

/// Layer 2 顶层摘要前缀字节。
/// Layer 2 top-level digest prefix byte.
pub const L2_TOP_PREFIX: u8 = 0x5A;

// =============================================================================
// 编译期一致性自检 / Compile-time consistency checks
// =============================================================================
// 这些静态断言把本 SDK 暴露的常量与上游真值绑定：若任一上游常量被改动而 SDK
// 未同步，编译将失败，从而保证 SDK 的常量始终可追溯、可验证。
//
// These static assertions bind the SDK-exposed constants to the upstream
// ground truth: if any upstream constant changes without updating the SDK,
// compilation fails — keeping the constants traceable and verifiable.

const _: () = {
    // UCXE 魔数与版本来自 ucx-crypto。
    // UCXE magic and version come from ucx-crypto.
    assert!(matches_bytes(UCXE_MAGIC, ucx_crypto::UCXE_MAGIC));
    assert!(UCXE_FORMAT_VERSION == ucx_crypto::UCXE_FORMAT_VERSION);
    // 支持的 MAJOR 来自 ucx-parse。
    // Supported MAJOR comes from ucx-parse.
    assert!(SUPPORTED_UCX_MAJOR == ucx_parse::SUPPORTED_UCX_MAJOR);
};

/// 在 const 上下文中比较两个 4 字节数组是否相等。
/// Compare two 4-byte arrays for equality in a const context.
const fn matches_bytes(a: [u8; 4], b: [u8; 4]) -> bool {
    a[0] == b[0] && a[1] == b[1] && a[2] == b[2] && a[3] == b[3]
}
