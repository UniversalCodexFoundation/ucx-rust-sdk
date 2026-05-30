//! 解密 / Decryption (SDK-API.md §4.6).
//!
//! 模块级函数，作用于 UCXE 字节：
//! - `is_ucxe(data)` —— 前 4 字节是否等于 UCXE magic。
//! - `decrypt_with_key(ucxe, key)` —— KDF=None 直接密钥模式（AES-CBC 在此模式被拒）。
//! - `decrypt_with_passphrase(ucxe, passphrase)` —— 口令模式（NFC 归一化 → KDF → AEAD/CBC）。
//!
//! Module-level functions over UCXE bytes:
//! - `is_ucxe(data)` — first 4 bytes equal the UCXE magic.
//! - `decrypt_with_key(ucxe, key)` — direct-key mode (KDF=None; AES-CBC rejected here).
//! - `decrypt_with_passphrase(ucxe, passphrase)` — passphrase mode (NFC → KDF → AEAD/CBC).
//!
//! # 设计取舍 / Design trade-off
//!
//! 上游 `ucx-crypto` 的公开解密入口 `decrypt(&Path, &key)` 与
//! `decrypt_with_passphrase(&Path, &str)` 接受**文件路径**，并在其中完成了关键的
//! "防 oracle" 错误折叠（把一切密码学/解析/认证失败统一塌缩为不透明的
//! `DecryptionFailed`，仅 I/O 透传）。
//!
//! 本 facade 的契约要求以**字节切片**为输入。为了**复用**上游久经测试的解密与防
//! oracle 逻辑、而非重写密码学，我们把内存中的 UCXE 字节写入一个安全的临时文件
//! （`tempfile::NamedTempFile`，进程私有、自动清理），再调用上游函数。临时文件仅
//! 含**密文**，不含明文或密钥，且写入后立即用于读取、随作用域结束删除。
//!
//! Upstream `ucx-crypto`'s public decrypt entry points take a *path* and perform
//! the crucial anti-oracle error folding. The contract here wants *byte-slice*
//! inputs, so to reuse the proven upstream crypto + anti-oracle logic (rather
//! than re-implement cryptography) we spill the in-memory UCXE bytes to a secure
//! per-process temp file (`tempfile::NamedTempFile`, auto-deleted) and call the
//! upstream functions. The temp file holds only ciphertext (never plaintext or
//! keys) and is removed when it goes out of scope.

use std::io::Write as _;

use crate::constants::UCXE_MAGIC;
use crate::error::{Result, UcxError};

/// 判断字节序列是否为 UCXE 容器（前 4 字节 == UCXE magic）。
///
/// Whether the byte slice is a UCXE container (first 4 bytes == UCXE magic).
///
/// 直接委托上游 `ucx_crypto::is_encrypted`，保证与解析器的判定完全一致。
/// Delegates to upstream `ucx_crypto::is_encrypted` to stay byte-identical with
/// the parser's detection logic.
pub fn is_ucxe(data: &[u8]) -> bool {
    // 等价于 `data.len() >= 4 && data[0..4] == UCXE_MAGIC`，但走上游以避免漂移。
    // Equivalent to checking the 4-byte prefix, but routed upstream to avoid drift.
    debug_assert_eq!(UCXE_MAGIC, ucx_crypto::UCXE_MAGIC);
    ucx_crypto::is_encrypted(data)
}

/// 把 UCXE 字节写入临时文件并返回句柄。
///
/// Spill UCXE bytes to a temp file and return the handle.
///
/// 句柄必须由调用方保活直到上游读取完成；丢弃句柄即删除文件。
/// The caller must keep the handle alive until the upstream read completes;
/// dropping it deletes the file.
fn spill_to_tempfile(ucxe: &[u8]) -> Result<tempfile::NamedTempFile> {
    // `NamedTempFile` 在系统临时目录创建一个唯一文件，Drop 时自动删除。
    // `NamedTempFile` creates a unique file in the system temp dir, auto-deleted on Drop.
    let mut tf = tempfile::NamedTempFile::new()?;
    tf.write_all(ucxe)?;
    // 确保字节已落盘，随后上游用独立的 File::open 读取。
    // Flush so the bytes are on disk before upstream re-opens the path.
    tf.flush()?;
    Ok(tf)
}

/// 直接密钥模式解密（KDF=None）。AES-CBC 在此模式被上游拒绝。
///
/// Direct-key decryption (KDF=None). AES-CBC is rejected by upstream in this mode.
///
/// # 参数 / Arguments
/// * `ucxe` —— 完整的 UCXE 容器字节。/ Full UCXE container bytes.
/// * `key`  —— 32 字节密钥。/ 32-byte key.
///
/// # 错误 / Errors
/// 任何解密失败统一为不透明的 [`UcxError::DecryptionError`]（防 oracle）；
/// I/O 错误透传为 [`UcxError::IoError`]。
/// Any decryption failure collapses into the opaque [`UcxError::DecryptionError`];
/// I/O errors pass through as [`UcxError::IoError`].
pub fn decrypt_with_key(ucxe: &[u8], key: &[u8; 32]) -> Result<Vec<u8>> {
    let tf = spill_to_tempfile(ucxe)?;
    // 委托上游 `decrypt`：它内部解析 UCXE、拒绝 KDF≠None、重算 AAD、验证标签。
    // Delegate to upstream `decrypt`: it parses UCXE, rejects KDF≠None, rebuilds
    // the AAD, and verifies the tag.
    ucx_crypto::decrypt(tf.path(), key).map_err(UcxError::from)
}

/// 口令模式解密。passphrase 先做 Unicode NFC 归一化再进 KDF（由上游保证）。
///
/// Passphrase decryption. The passphrase is NFC-normalized before the KDF
/// (guaranteed by upstream).
///
/// # 参数 / Arguments
/// * `ucxe`       —— 完整的 UCXE 容器字节。/ Full UCXE container bytes.
/// * `passphrase` —— 口令字符串。/ The passphrase string.
///
/// # 错误 / Errors
/// 同 [`decrypt_with_key`]：解密失败折叠为不透明错误，I/O 透传。
/// Same as [`decrypt_with_key`]: failures collapse to an opaque error, I/O passes through.
pub fn decrypt_with_passphrase(ucxe: &[u8], passphrase: &str) -> Result<Vec<u8>> {
    let tf = spill_to_tempfile(ucxe)?;
    // 委托上游 `decrypt_with_passphrase`：内部做 NFC 归一化、KDF 派生、AEAD/CBC 解密。
    // Delegate to upstream `decrypt_with_passphrase`: NFC normalization, KDF
    // derivation, and AEAD/CBC decryption all happen inside.
    ucx_crypto::decrypt_with_passphrase(tf.path(), passphrase).map_err(UcxError::from)
}
