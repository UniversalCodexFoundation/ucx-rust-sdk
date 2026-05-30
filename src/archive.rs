//! `UcxArchive` —— 打开/解析/读取/校验/验签的统一句柄。
//! The `UcxArchive` handle: open / parse / read / integrity / verify.
//!
//! 本类型是 facade 的核心：它包裹上游 `ucx_parse::UcxArchive`，对外暴露契约 §4
//! 规定的整洁 API，并把上游错误映射为统一的 `UcxError`。签名验证委托
//! `ucx_verify::verify`，完整性委托上游的逐条 BLAKE3+Base64 比对。
//!
//! This type is the heart of the facade: it wraps the upstream
//! `ucx_parse::UcxArchive`, exposes the clean §4 API, and maps upstream errors
//! to the unified `UcxError`. Signature verification delegates to
//! `ucx_verify::verify`; integrity delegates to the upstream per-entry
//! BLAKE3+Base64 comparison.

use std::path::{Path, PathBuf};

use crate::error::Result;
use crate::model::{
    Chapter, Codex, IntegrityEntry, IntegrityResult, Manifest, SignatureResult, SignatureStatus,
    Signer, Structure, StructureNode,
};

/// 已打开的 UCX 归档句柄。
///
/// An opened UCX archive handle.
///
/// 通过 [`UcxArchive::open`] 或 [`UcxArchive::open_bytes`] 构造。打开时即解析并缓存
/// `codex` / `structure` / `manifest`；章节字节按需懒读取。
///
/// Construct via [`UcxArchive::open`] or [`UcxArchive::open_bytes`]. Opening
/// parses and caches `codex` / `structure` / `manifest`; chapter bytes are read
/// lazily on demand.
pub struct UcxArchive {
    /// 被包裹的上游解析器（持有 ZIP reader 与缓存的元数据）。
    /// The wrapped upstream parser (owns a ZIP reader and cached metadata).
    inner: ucx_parse::UcxArchive,

    /// 归档在磁盘上的路径（用于 `verify_signatures` 重新读取整文件）。
    /// On-disk path of the archive (used by `verify_signatures`, which re-reads
    /// the whole file).
    path: PathBuf,

    /// 当通过 `open_bytes` 构造时，保活的临时文件句柄；其 Drop 会删除文件。
    /// 必须与 `inner`/`path` 同生命周期：`verify_signatures` 仍会用到该路径。
    ///
    /// A kept-alive temp-file handle when constructed via `open_bytes`; its Drop
    /// deletes the file. It must outlive `inner`/`path` because
    /// `verify_signatures` reads the path again.
    _tempfile: Option<tempfile::NamedTempFile>,
}

impl std::fmt::Debug for UcxArchive {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UcxArchive")
            .field("path", &self.path)
            .field("inner", &self.inner)
            .finish()
    }
}

impl UcxArchive {
    // =========================================================================
    // 4.1 打开与解析 / Open & parse
    // =========================================================================

    /// 打开并解析一个 `.ucx` 文件。
    ///
    /// Open and parse a `.ucx` file.
    ///
    /// 流程：校验 offset-0 的 ZIP magic → 校验 mimetype → 解析
    /// codex/struct/manifest（含 MAJOR≤1 检查）。
    /// Flow: validate ZIP magic @0 → validate mimetype → parse
    /// codex/struct/manifest (including the MAJOR≤1 check).
    ///
    /// # 错误 / Errors
    /// 非 ZIP / mimetype 不符 / MAJOR>1 → [`UcxError::InvalidFormat`]；
    /// 缺文件 → [`UcxError::NotFound`]；JSON/MANIFEST 解析失败 → [`UcxError::ParseError`]；
    /// I/O → [`UcxError::IoError`]。
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let inner = ucx_parse::open(path)?;
        Ok(Self {
            inner,
            path: path.to_path_buf(),
            _tempfile: None,
        })
    }

    /// 从内存字节打开并解析一个 UCX 归档。
    ///
    /// Open and parse a UCX archive from in-memory bytes.
    ///
    /// 上游解析器只接受文件路径，故本方法把字节写入进程私有的临时文件
    /// （`tempfile::NamedTempFile`，自动清理）再委托 `open`，并将临时文件句柄随
    /// 归档保活——因为后续的 `verify_signatures` 仍需读取该路径。
    ///
    /// The upstream parser accepts only a path, so this method spills the bytes
    /// to a per-process temp file (auto-deleted) and delegates to `open`, keeping
    /// the temp-file handle alive alongside the archive because a later
    /// `verify_signatures` re-reads that path.
    pub fn open_bytes(data: &[u8]) -> Result<Self> {
        use std::io::Write as _;

        // 写入临时文件并保活。
        // Spill to a temp file and keep it alive.
        let mut tf = tempfile::NamedTempFile::new()?;
        tf.write_all(data)?;
        tf.flush()?;

        let path = tf.path().to_path_buf();
        // 注意：先解析，若失败临时文件随 tf Drop 自动清理。
        // Note: parse first; on failure the temp file is auto-cleaned via tf's Drop.
        let inner = ucx_parse::open(&path)?;

        Ok(Self {
            inner,
            path,
            _tempfile: Some(tf),
        })
    }

    // =========================================================================
    // 4.2 元数据与结构 / Metadata & structure (已在 open 时解析)
    // =========================================================================

    /// 作品元数据 `codex.json`。
    /// The work metadata from `codex.json`.
    pub fn codex(&self) -> &Codex {
        self.inner.codex()
    }

    /// 内容结构树 `struct.json`。
    /// The content structure tree from `struct.json`.
    pub fn structure(&self) -> &Structure {
        self.inner.structure()
    }

    /// 资源清单 `META-INF/MANIFEST.MF`。
    /// The resource manifest from `META-INF/MANIFEST.MF`.
    pub fn manifest(&self) -> &Manifest {
        self.inner.manifest()
    }

    /// 归档文件在磁盘上的路径（`open_bytes` 时为临时文件路径）。
    /// The on-disk path of the archive (a temp path when opened via `open_bytes`).
    pub fn file_path(&self) -> &Path {
        &self.path
    }

    /// 深度优先扁平化所有叶子章节，按文档顺序返回。
    ///
    /// Depth-first flatten of all leaf chapters, in document order.
    ///
    /// 仅收集"叶子"（有 `file` 字段）节点，容器节点跳过但递归其子节点。
    /// Collects only leaf nodes (those with a `file` field); container nodes are
    /// skipped but their children are recursed.
    pub fn chapters(&self) -> Vec<Chapter> {
        let mut out = Vec::new();
        collect_chapters(&self.structure().structure, &mut out);
        out
    }

    /// 列出归档内的全部条目名。
    /// List every entry name inside the archive.
    pub fn list_files(&self) -> Vec<String> {
        self.inner.list_files()
    }

    // =========================================================================
    // 4.3 章节读取 / Chapter reading
    // =========================================================================

    /// 读取 `content/{file}` 的原始字节（可能是 UCXE 密文）。
    ///
    /// Read the raw bytes of `content/{file}` (possibly UCXE ciphertext).
    ///
    /// 不检查 UCXE magic、不做 UTF-8 解码；适合加密章节的外部解密。
    /// Does not check the UCXE magic nor decode UTF-8; suitable for feeding an
    /// encrypted chapter to the decrypt API.
    pub fn read_chapter(&mut self, file: &str) -> Result<Vec<u8>> {
        Ok(self.inner.read_chapter_raw(file)?)
    }

    /// 读取 `content/{file}` 并以 UTF-8 解码为字符串。
    ///
    /// Read `content/{file}` and decode it as a UTF-8 string.
    ///
    /// 若章节是 UCXE 密文，上游会返回"已加密"错误（映射为 [`UcxError::InvalidFormat`]），
    /// 而非误把密文当作文本。
    /// If the chapter is UCXE ciphertext, upstream returns an "encrypted" error
    /// (mapped to [`UcxError::InvalidFormat`]) rather than mis-decoding it.
    pub fn read_chapter_text(&mut self, file: &str) -> Result<String> {
        Ok(self.inner.read_chapter(file)?)
    }

    /// 判断 `content/{file}` 是否为 UCXE 加密（前 4 字节 == UCXE magic）。
    ///
    /// Whether `content/{file}` is UCXE-encrypted (first 4 bytes == UCXE magic).
    pub fn is_chapter_encrypted(&mut self, file: &str) -> Result<bool> {
        Ok(self.inner.is_chapter_encrypted(file)?)
    }

    // =========================================================================
    // 4.4 完整性校验 / Integrity
    // =========================================================================

    /// 对每个 manifest 条目重算 BLAKE3 → Base64-standard，并与记录的摘要比对。
    ///
    /// For each manifest entry, recompute BLAKE3 → Base64-standard and compare to
    /// the recorded digest.
    ///
    /// 直接复用上游 `verify_hashes`（同样使用 Base64-standard-padded 编码），
    /// 再聚合为契约的 [`IntegrityResult`]。
    /// Reuses the upstream `verify_hashes` (also Base64-standard-padded) and
    /// aggregates into the contract's [`IntegrityResult`].
    pub fn verify_integrity(&mut self) -> Result<IntegrityResult> {
        let upstream = self.inner.verify_hashes()?;
        let entries: Vec<IntegrityEntry> = upstream
            .into_iter()
            .map(|r| IntegrityEntry {
                name: r.name,
                expected: r.expected,
                actual: r.actual,
                valid: r.valid,
            })
            .collect();
        // 全部条目通过才算整体有效（空清单视为 true，与"无失败"语义一致）。
        // Overall valid iff all entries pass (an empty manifest is true: no failures).
        let valid = entries.iter().all(|e| e.valid);
        Ok(IntegrityResult { valid, entries })
    }

    // =========================================================================
    // 4.5 签名验证 / Signature verification
    // =========================================================================

    /// 验证双层 Ed25519 签名（Layer1 SF/EC + Layer2 签名块），按 UCX-FORMAT §6。
    ///
    /// Verify the dual-layer Ed25519 signatures (Layer1 SF/EC + Layer2 signing
    /// block), per UCX-FORMAT §6.
    ///
    /// 委托 `ucx_verify::verify`，再把其 `VerifyReport` 翻译为契约的
    /// [`SignatureResult`]，包括严格的 §6 状态映射与逐签名者信息。
    /// Delegates to `ucx_verify::verify`, then translates its `VerifyReport` into
    /// the contract's [`SignatureResult`], including the strict §6 status mapping
    /// and per-signer details.
    pub fn verify_signatures(&self) -> Result<SignatureResult> {
        let report = ucx_verify::verify(&self.path)?;

        // 把上游的存在性/有效性拆出，便于映射布尔字段。
        // Pull out presence/validity to map the boolean fields.
        let layer1_present = report.layer1.is_some();
        let layer1_valid = report.layer1.as_ref().is_some_and(|l| l.valid);
        let layer2_present = report.layer2.is_some();
        let layer2_valid = report.layer2.as_ref().is_some_and(|l| l.valid);

        // 状态映射：上游 VerifyStatus → 契约 SignatureStatus。
        // 上游已严格实现 §6 状态表（两层都在则任一失败为 Invalid 等），这里仅做
        // 名称对齐：Valid → Verified。
        // Status mapping: upstream VerifyStatus → contract SignatureStatus.
        // Upstream already implements the §6 table strictly; we only align names
        // (Valid → Verified).
        let status = match report.status {
            ucx_verify::VerifyStatus::Unsigned => SignatureStatus::Unsigned,
            ucx_verify::VerifyStatus::Valid => SignatureStatus::Verified,
            ucx_verify::VerifyStatus::ValidWithWarnings => SignatureStatus::ValidWithWarnings,
            ucx_verify::VerifyStatus::Invalid => SignatureStatus::Invalid,
        };

        // 逐签名者翻译。上游的 cert_type 用 "self-signed"/"CA-issued"；契约示例
        // 用小写 "self-signed"/"ca-issued"，这里规范化为小写。
        // Per-signer translation. Upstream cert_type is "self-signed"/"CA-issued";
        // the contract uses lowercase, so normalize.
        let signers = report
            .signers
            .into_iter()
            .map(|s| Signer {
                signer_id: s.signer_id,
                subject_cn: opt_nonempty(s.subject_cn),
                fingerprint: opt_nonempty(s.fingerprint_blake3),
                cert_type: opt_nonempty(s.cert_type).map(|t| t.to_ascii_lowercase()),
                layer1_valid: s.layer1_valid,
                layer2_valid: s.layer2_valid,
            })
            .collect();

        Ok(SignatureResult {
            status,
            layer1_present,
            layer1_valid,
            layer2_present,
            layer2_valid,
            signers,
        })
    }

    // =========================================================================
    // 便捷解密 / Convenience decryption (SDK-API.md §4.6 可选便捷)
    // =========================================================================

    /// 读取 `content/{file}` 密文并用直接密钥解密。
    /// Read the `content/{file}` ciphertext and decrypt it with a direct key.
    pub fn read_chapter_decrypted_with_key(
        &mut self,
        file: &str,
        key: &[u8; 32],
    ) -> Result<Vec<u8>> {
        let ucxe = self.read_chapter(file)?;
        crate::decrypt::decrypt_with_key(&ucxe, key)
    }

    /// 读取 `content/{file}` 密文并用口令解密。
    /// Read the `content/{file}` ciphertext and decrypt it with a passphrase.
    pub fn read_chapter_decrypted_with_passphrase(
        &mut self,
        file: &str,
        passphrase: &str,
    ) -> Result<Vec<u8>> {
        let ucxe = self.read_chapter(file)?;
        crate::decrypt::decrypt_with_passphrase(&ucxe, passphrase)
    }
}

// =============================================================================
// 内部辅助 / Internal helpers
// =============================================================================

/// 深度优先递归收集叶子章节。
/// Depth-first recursive collection of leaf chapters.
fn collect_chapters(nodes: &[StructureNode], out: &mut Vec<Chapter>) {
    for node in nodes {
        // 叶子：有 `file` 字段。容器：有 `children`。两者按规范互斥，但为稳健起见
        // 我们对"既有 file 又有 children"的异常节点：把 file 收为章节，并继续递归
        // children（不丢数据）。
        // Leaf: has `file`. Container: has `children`. They are mutually exclusive
        // per spec, but defensively: if a node has both, we record the file as a
        // chapter AND recurse children (lossless).
        if let Some(ref file) = node.file {
            out.push(Chapter {
                title: node.title.clone(),
                file: file.clone(),
                path: format!("content/{file}"),
            });
        }
        if let Some(ref children) = node.children {
            collect_chapters(children, out);
        }
    }
}

/// 把可能为空的字符串规整为 `Option`：空串视为缺失。
/// Normalize a possibly-empty string into `Option`: empty means absent.
fn opt_nonempty(s: String) -> Option<String> {
    if s.is_empty() { None } else { Some(s) }
}
