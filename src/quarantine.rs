//! Download quarantine pipeline вЂ” Layer 5 of the SafeRouter model.
//!
//! When the matrix routes a write to Temp/Executable/AiClientConfig from a
//! Provider/Web/Mcp source to `Quarantine`, the artifact is held here for
//! inspection before it can be executed. The classic attack this stops:
//!
//! ```text
//! step 1: provider -> tool_use Write /tmp/cache.sh
//! step 2: provider -> tool_use Bash /tmp/cache.sh
//! ```
//!
//! Without quarantine, step 2 runs step 1's payload. With quarantine, step 1
//! is diverted to `~/.saferouter/quarantine/<sha256>.<ext>` and step 2's
//! target path no longer exists вЂ” the original `/tmp/cache.sh` is empty or
//! absent. The artifact can be reviewed, hashed, signature-checked, and
//! either released or purged.

use std::collections::HashSet;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineEntry {
    pub original_path: String,
    pub stored_path: PathBuf,
    pub sha256: String,
    pub size_bytes: usize,
    pub mime_guess: String,
    pub extension: String,
    pub released: bool,
    /// Content-type sniffed from magic bytes (independent of extension).
    pub sniffed_type: SniffedType,
    /// True if the content is an archive; member names listed below.
    pub archive_members: Vec<String>,
    /// True if the content looks like an executable binary.
    pub is_executable: bool,
}

/// Magic-byte content classification. Independent of file extension вЂ”
/// catches payloads disguised as .txt or extensionless.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SniffedType {
    /// Unknown / unclassifiable.
    Unknown,
    /// Windows PE executable (MZ header).
    WindowsExe,
    /// Linux ELF executable.
    ElfExecutable,
    /// macOS Mach-O binary.
    MachO,
    /// gzip compressed.
    Gzip,
    /// ZIP archive.
    ZipArchive,
    /// tar archive.
    TarArchive,
    /// bzip2 compressed.
    Bzip2,
    /// xz compressed.
    Xz,
    /// RAR archive.
    Rar,
    /// 7z archive.
    SevenZip,
    /// PDF document.
    Pdf,
    /// Shell script (#! shebang).
    ShellScript,
    /// PowerShell script (shebang or BOM).
    PowerShell,
    /// Python script (shebang).
    Python,
    /// Plain text.
    Text,
    /// JSON document.
    Json,
    /// XML document.
    Xml,
}

impl SniffedType {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::WindowsExe => "windows-exe",
            Self::ElfExecutable => "elf-executable",
            Self::MachO => "mach-o",
            Self::Gzip => "gzip",
            Self::ZipArchive => "zip-archive",
            Self::TarArchive => "tar-archive",
            Self::Bzip2 => "bzip2",
            Self::Xz => "xz",
            Self::Rar => "rar",
            Self::SevenZip => "7z",
            Self::Pdf => "pdf",
            Self::ShellScript => "shell-script",
            Self::PowerShell => "powershell",
            Self::Python => "python",
            Self::Text => "text",
            Self::Json => "json",
            Self::Xml => "xml",
        }
    }

    pub fn is_executable(&self) -> bool {
        matches!(
            self,
            Self::WindowsExe | Self::ElfExecutable | Self::MachO
        )
    }

    pub fn is_archive(&self) -> bool {
        matches!(
            self,
            Self::Gzip
                | Self::ZipArchive
                | Self::TarArchive
                | Self::Bzip2
                | Self::Xz
                | Self::Rar
                | Self::SevenZip
        )
    }

    pub fn is_script(&self) -> bool {
        matches!(
            self,
            Self::ShellScript | Self::PowerShell | Self::Python
        )
    }
}

pub struct QuarantineStore {
    root: PathBuf,
    entries: Arc<Mutex<Vec<QuarantineEntry>>>,
    /// Hash allowlist вЂ” known-good hashes that auto-release on intake.
    allowlist: Arc<Mutex<HashSet<String>>>,
    /// Monotonic counter for unique filenames when sha collides.
    counter: Arc<std::sync::atomic::AtomicU64>,
}

impl QuarantineStore {
    pub fn open(root: impl AsRef<Path>) -> std::io::Result<Self> {
        let root = root.as_ref().to_path_buf();
        std::fs::create_dir_all(&root)?;
        Ok(Self {
            root,
            entries: Arc::new(Mutex::new(Vec::new())),
            allowlist: Arc::new(Mutex::new(HashSet::new())),
            counter: Arc::new(std::sync::atomic::AtomicU64::new(1)),
        })
    }

    pub fn open_default() -> std::io::Result<Self> {
        let path = default_root();
        Self::open(path)
    }

    /// Intake a downloaded/written artifact. Returns the entry describing
    /// where it was stored.
    pub fn intake(&self, original_path: &str, content: &[u8]) -> std::io::Result<QuarantineEntry> {
        let mut hasher = Sha256::new();
        hasher.update(content);
        let hash = hasher.finalize();
        let sha = hex::encode(hash);

        // Sniff content type from magic bytes.
        let sniffed = sniff_content(content);
        let archive_members = if sniffed.is_archive() {
            list_archive_members(content, sniffed)
        } else {
            Vec::new()
        };
        let is_executable = sniffed.is_executable();

        // Allowlist short-circuit.
        {
            let allow = self.allowlist.lock().unwrap();
            if allow.contains(&sha) {
                let entry = QuarantineEntry {
                    original_path: original_path.to_string(),
                    stored_path: PathBuf::from(original_path),
                    sha256: sha,
                    size_bytes: content.len(),
                    mime_guess: guess_mime(original_path),
                    extension: extension_of(original_path),
                    released: true,
                    sniffed_type: sniffed,
                    archive_members,
                    is_executable,
                };
                let mut entries = self.entries.lock().unwrap();
                entries.push(entry.clone());
                return Ok(entry);
            }
        }

        let ext = extension_of(original_path);
        let n = self
            .counter
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let filename = if ext.is_empty() {
            format!("{sha}-{n}.bin")
        } else {
            format!("{sha}-{n}.{ext}")
        };
        let stored_path = self.root.join(filename);

        let mut file = std::fs::File::create(&stored_path)?;
        file.write_all(content)?;
        // Drop write/exec perms on the stored file вЂ” make execution harder.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&stored_path, std::fs::Permissions::from_mode(0o600));
        }

        let entry = QuarantineEntry {
            original_path: original_path.to_string(),
            stored_path,
            sha256: sha,
            size_bytes: content.len(),
            mime_guess: guess_mime(original_path),
            extension: ext,
            released: false,
            sniffed_type: sniffed,
            archive_members,
            is_executable,
        };
        let mut entries = self.entries.lock().unwrap();
        entries.push(entry.clone());
        Ok(entry)
    }

    /// Release a quarantined artifact: copy it back to its original path.
    /// This is the manual-review "approve" path.
    pub fn release(&self, sha256: &str) -> std::io::Result<()> {
        let mut entries = self.entries.lock().unwrap();
        for entry in entries.iter_mut() {
            if entry.sha256 == sha256 && !entry.released {
                std::fs::copy(&entry.stored_path, &entry.original_path)?;
                entry.released = true;
                return Ok(());
            }
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "quarantine entry not found or already released",
        ))
    }

    /// Purge a quarantined artifact (delete it permanently).
    pub fn purge(&self, sha256: &str) -> std::io::Result<()> {
        let mut entries = self.entries.lock().unwrap();
        let idx = entries.iter().position(|e| e.sha256 == sha256);
        if let Some(i) = idx {
            let entry = entries.remove(i);
            let _ = std::fs::remove_file(&entry.stored_path);
            Ok(())
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "quarantine entry not found",
            ))
        }
    }

    pub fn list(&self) -> Vec<QuarantineEntry> {
        self.entries.lock().unwrap().clone()
    }

    pub fn add_allowlist(&self, sha: &str) {
        let mut allow = self.allowlist.lock().unwrap();
        allow.insert(sha.to_string());
    }

    /// True if the artifact's original path is currently in quarantine
    /// (i.e. step 2 trying to execute it should fail). Used by the proxy to
    /// short-circuit execute attempts against quarantined paths.
    pub fn is_quarantined(&self, original_path: &str) -> bool {
        let entries = self.entries.lock().unwrap();
        entries
            .iter()
            .any(|e| e.original_path == original_path && !e.released)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }
}

fn default_root() -> PathBuf {
    crate::paths::state_dir("quarantine")
}

fn extension_of(path: &str) -> String {
    Path::new(path)
        .extension()
        .and_then(|s| s.to_str())
        .map(|s| s.to_lowercase())
        .unwrap_or_default()
}

fn guess_mime(path: &str) -> String {
    let ext = extension_of(path);
    match ext.as_str() {
        "sh" | "bash" | "zsh" => "text/x-shellscript".to_string(),
        "ps1" => "text/x-powershell".to_string(),
        "py" => "text/x-python".to_string(),
        "exe" | "dll" => "application/x-msdownload".to_string(),
        "so" | "dylib" => "application/octet-stream".to_string(),
        "bat" | "cmd" => "application/x-bat".to_string(),
        "json" => "application/json".to_string(),
        "txt" | "md" => "text/plain".to_string(),
        "" => "application/octet-stream".to_string(),
        _ => format!("application/x-{}", ext),
    }
}

/// Sniff the actual content type from magic bytes вЂ” independent of the
/// file extension. Catches payloads disguised as .txt or extensionless.
pub fn sniff_content(data: &[u8]) -> SniffedType {
    if data.is_empty() {
        return SniffedType::Unknown;
    }
    // Windows PE (MZ header).
    if data.len() >= 2 && &data[0..2] == b"MZ" {
        return SniffedType::WindowsExe;
    }
    // ELF.
    if data.len() >= 4 && &data[0..4] == b"\x7fELF" {
        return SniffedType::ElfExecutable;
    }
    // Mach-O (32/64-bit, BE/LE). Magic: 0xFEEDFACE / 0xFEEDFACF / 0xCEFAEDFE / 0xCFFAEDFE.
    if data.len() >= 4 {
        let m = &data[0..4];
        if m == [0xFE, 0xED, 0xFA, 0xCE]
            || m == [0xFE, 0xED, 0xFA, 0xCF]
            || m == [0xCE, 0xFA, 0xED, 0xFE]
            || m == [0xCF, 0xFA, 0xED, 0xFE]
        {
            return SniffedType::MachO;
        }
    }
    // gzip.
    if data.len() >= 2 && data[0] == 0x1F && data[1] == 0x8B {
        return SniffedType::Gzip;
    }
    // ZIP (and zip-derived: jar, apk, docx, xlsx, odt вЂ” all zip).
    if data.len() >= 4 && &data[0..4] == b"PK\x03\x04" {
        return SniffedType::ZipArchive;
    }
    if data.len() >= 4 && &data[0..4] == b"PK\x05\x06" {
        return SniffedType::ZipArchive; // empty zip
    }
    // bzip2.
    if data.len() >= 3 && &data[0..3] == b"BZh" {
        return SniffedType::Bzip2;
    }
    // xz.
    if data.len() >= 6 && &data[0..6] == b"\xFD7zXZ\x00" {
        return SniffedType::Xz;
    }
    // 7z.
    if data.len() >= 6 && &data[0..6] == b"\x37\x7A\xBC\xAF\x27\x1C" {
        return SniffedType::SevenZip;
    }
    // RAR (RAR v4: "Rar!\x1A\x07", RAR v5: "Rar!\x1A\x07\x01\x00").
    if data.len() >= 7 && &data[0..7] == b"Rar!\x1A\x07\x01" {
        return SniffedType::Rar;
    }
    if data.len() >= 6 && &data[0..6] == b"Rar!\x1A\x07" {
        return SniffedType::Rar;
    }
    // PDF.
    if data.len() >= 4 && &data[0..4] == b"%PDF" {
        return SniffedType::Pdf;
    }
    // tar вЂ” ustar magic at offset 257.
    if data.len() >= 265 && &data[257..262] == b"ustar" {
        return SniffedType::TarArchive;
    }
    // Shebang scripts.
    if data.len() >= 2 && &data[0..2] == b"#!" {
        // Get the first line to detect interpreter.
        let first_line_end = data.iter().position(|&b| b == b'\n').unwrap_or(data.len().min(128));
        let first_line = std::str::from_utf8(&data[2..first_line_end]).unwrap_or("");
        let lower = first_line.to_lowercase();
        if lower.contains("powershell") || lower.contains("pwsh") {
            return SniffedType::PowerShell;
        }
        if lower.contains("python") {
            return SniffedType::Python;
        }
        return SniffedType::ShellScript;
    }
    // PowerShell without shebang вЂ” UTF-8 BOM + script content.
    if data.len() >= 3 && &data[0..3] == b"\xEF\xBB\xBF" {
        // Check if content looks like PowerShell (Param/Function/Set-).
        let tail = &data[3..];
        let tail_str = std::str::from_utf8(tail).unwrap_or("");
        let lower = tail_str.to_lowercase();
        if lower.contains("param(") || lower.contains("set-") || lower.contains("invoke-") {
            return SniffedType::PowerShell;
        }
    }
    // JSON.
    let trimmed = data
        .iter()
        .skip_while(|&&b| b.is_ascii_whitespace())
        .cloned()
        .collect::<Vec<_>>();
    if !trimmed.is_empty() && (trimmed[0] == b'{' || trimmed[0] == b'[') {
        if let Ok(s) = std::str::from_utf8(&trimmed) {
            let trimmed_end = s.trim_end();
            if (trimmed_end.ends_with('}') || trimmed_end.ends_with(']'))
                && serde_json::from_str::<serde_json::Value>(s).is_ok()
            {
                return SniffedType::Json;
            }
        }
    }
    // XML.
    let lower_prefix: String = data
        .iter()
        .take(50)
        .map(|&b| b.to_ascii_lowercase() as char)
        .collect();
    if lower_prefix.starts_with("<?xml") {
        return SniffedType::Xml;
    }
    // Plain text вЂ” only ASCII printable / whitespace.
    if !data.is_empty()
        && data
            .iter()
            .all(|&b| b.is_ascii() && (b.is_ascii_graphic() || b == b' ' || b == b'\n' || b == b'\r' || b == b'\t'))
    {
        return SniffedType::Text;
    }
    SniffedType::Unknown
}

/// Walk the members of an archive without unpacking it. Returns member names
/// so the audit log can show what's inside without exposing the content.
pub fn list_archive_members(data: &[u8], sniffed: SniffedType) -> Vec<String> {
    match sniffed {
        SniffedType::ZipArchive => list_zip_members(data),
        SniffedType::TarArchive => list_tar_members(data),
        SniffedType::Gzip => {
            // gzip is single-stream; can't tell the inner name without
            // decompression. Flag as opaque.
            vec!["<gzip-single-stream>".to_string()]
        }
        SniffedType::Bzip2 | SniffedType::Xz | SniffedType::SevenZip | SniffedType::Rar => {
            vec![format!("<{}-opaque>", sniffed.label())]
        }
        _ => Vec::new(),
    }
}

/// List ZIP archive members by walking the central directory. ZIP format:
/// each central-directory header starts with magic 0x50 0x4B 0x01 0x02,
/// followed by version, flags, method, time, date, crc, sizes, name-len,
/// extra-len, comment-len, disk, internal, external, local-header-offset,
/// then the variable-length name / extra / comment.
fn list_zip_members(data: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    // Scan for the central directory magic вЂ” it appears after the local file
    // headers, so we can't start at offset 0.
    let mut i = 0;
    while i + 4 <= data.len() {
        if &data[i..i + 4] != b"PK\x01\x02" {
            i += 1;
            continue;
        }
        // Found a central directory file header at i.
        if i + 46 > data.len() {
            break;
        }
        let name_len = u16::from_le_bytes([data[i + 28], data[i + 29]]) as usize;
        let extra_len = u16::from_le_bytes([data[i + 30], data[i + 31]]) as usize;
        let comment_len = u16::from_le_bytes([data[i + 32], data[i + 33]]) as usize;
        let name_start = i + 46;
        let name_end = name_start + name_len;
        if name_end > data.len() {
            break;
        }
        if let Ok(name) = std::str::from_utf8(&data[name_start..name_end]) {
            out.push(name.to_string());
        } else {
            out.push("<non-utf8-name>".to_string());
        }
        // Advance past name + extra + comment to the next central-dir entry.
        i = name_end + extra_len + comment_len;
    }
    out
}

/// List tar archive members by walking the 512-byte block headers.
fn list_tar_members(data: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0;
    while i + 512 <= data.len() {
        // ustar header: name at 0..100, magic at 257..262.
        if &data[i + 257..i + 262] != b"ustar" {
            break;
        }
        // Name is a NUL-terminated string in 0..100.
        let name_end = data[i..i + 100].iter().position(|&b| b == 0).unwrap_or(100);
        if let Ok(name) = std::str::from_utf8(&data[i..i + name_end]) {
            if !name.is_empty() {
                out.push(name.to_string());
            }
        }
        // Size field is octal ASCII at 124..136.
        let size_field = &data[i + 124..i + 136];
        let size_str = std::str::from_utf8(size_field).unwrap_or("");
        let octal_trimmed = size_str.trim_end_matches(|c: char| c == '\0' || c.is_whitespace());
        let size = u64::from_str_radix(octal_trimmed.trim(), 8).unwrap_or(0);
        // Next header at i + 512 + ceil(size / 512) * 512.
        let blocks = size.div_ceil(512);
        i += 512 + (blocks * 512) as usize;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn store() -> QuarantineStore {
        let dir = tempdir().unwrap().keep();
        QuarantineStore::open(dir).unwrap()
    }

    #[test]
    fn intake_creates_entry_with_hash() {
        let s = store();
        let entry = s.intake("/tmp/payload.sh", b"#!/bin/sh\necho pwned\n").unwrap();
        assert!(!entry.sha256.is_empty());
        assert_eq!(entry.extension, "sh");
        assert_eq!(entry.mime_guess, "text/x-shellscript");
        assert!(!entry.released);
        assert!(entry.stored_path.exists());
    }

    #[test]
    fn intake_same_content_same_hash() {
        let s = store();
        let e1 = s.intake("/tmp/a.sh", b"payload").unwrap();
        let e2 = s.intake("/tmp/b.sh", b"payload").unwrap();
        assert_eq!(e1.sha256, e2.sha256);
        assert_ne!(e1.stored_path, e2.stored_path);
    }

    #[test]
    fn release_copies_back() {
        let s = store();
        let _ = s
            .intake("/tmp/cache.sh", b"#!/bin/sh\necho safe\n")
            .unwrap();
        // simulate manual approval
        let entries = s.list();
        let sha = entries[0].sha256.clone();
        s.release(&sha).unwrap();
        let entries = s.list();
        assert!(entries[0].released);
    }

    #[test]
    fn purge_removes_entry() {
        let s = store();
        let e = s.intake("/tmp/x.sh", b"data").unwrap();
        let path = e.stored_path.clone();
        assert!(path.exists());
        s.purge(&e.sha256).unwrap();
        assert!(!path.exists());
        assert!(s.list().is_empty());
    }

    #[test]
    fn is_quarantined_after_intake() {
        let s = store();
        assert!(!s.is_quarantined("/tmp/x.sh"));
        let _ = s.intake("/tmp/x.sh", b"data").unwrap();
        assert!(s.is_quarantined("/tmp/x.sh"));
    }

    #[test]
    fn is_quarantined_false_after_release() {
        let s = store();
        let e = s.intake("/tmp/x.sh", b"data").unwrap();
        s.release(&e.sha256).unwrap();
        assert!(!s.is_quarantined("/tmp/x.sh"));
    }

    #[test]
    fn allowlist_short_circuits_release() {
        let s = store();
        // pre-add the hash to allowlist
        let sha = {
            let mut h = Sha256::new();
            h.update(b"trusted-content");
            hex::encode(h.finalize())
        };
        s.add_allowlist(&sha);
        let entry = s.intake("/tmp/trusted.sh", b"trusted-content").unwrap();
        assert!(entry.released);
    }

    #[test]
    fn extension_extraction_handles_no_ext() {
        assert_eq!(extension_of("/tmp/noext"), "");
        assert_eq!(extension_of("/tmp/file.SH"), "sh");
        assert_eq!(extension_of("/tmp/file.tar.gz"), "gz");
    }

    #[test]
    fn guess_mime_known_extensions() {
        assert_eq!(guess_mime("a.sh"), "text/x-shellscript");
        assert_eq!(guess_mime("a.ps1"), "text/x-powershell");
        assert_eq!(guess_mime("a.exe"), "application/x-msdownload");
        assert_eq!(guess_mime("noext"), "application/octet-stream");
    }

    #[test]
    fn sniff_recognizes_windows_exe() {
        let data = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff";
        assert_eq!(sniff_content(data), SniffedType::WindowsExe);
        assert!(sniff_content(data).is_executable());
    }

    #[test]
    fn sniff_recognizes_elf() {
        let data = b"\x7fELF\x02\x01\x01\x00";
        assert_eq!(sniff_content(data), SniffedType::ElfExecutable);
    }

    #[test]
    fn sniff_recognizes_zip() {
        let data = b"PK\x03\x04\x14\x00\x00\x00";
        assert_eq!(sniff_content(data), SniffedType::ZipArchive);
        assert!(sniff_content(data).is_archive());
    }

    #[test]
    fn sniff_recognizes_gzip() {
        let data = b"\x1f\x8b\x08\x00\x00\x00\x00\x00";
        assert_eq!(sniff_content(data), SniffedType::Gzip);
    }

    #[test]
    fn sniff_recognizes_pdf() {
        let data = b"%PDF-1.4\n%";
        assert_eq!(sniff_content(data), SniffedType::Pdf);
    }

    #[test]
    fn sniff_recognizes_shell_shebang() {
        let data = b"#!/bin/bash\necho hello\n";
        assert_eq!(sniff_content(data), SniffedType::ShellScript);
        assert!(sniff_content(data).is_script());
    }

    #[test]
    fn sniff_recognizes_python_shebang() {
        let data = b"#!/usr/bin/env python3\nprint('hi')\n";
        assert_eq!(sniff_content(data), SniffedType::Python);
    }

    #[test]
    fn sniff_recognizes_powershell_bom() {
        let data = b"\xEF\xBB\xBFParam(\n  [string]$x\n)\nSet-Content foo.txt $x";
        assert_eq!(sniff_content(data), SniffedType::PowerShell);
    }

    #[test]
    fn sniff_recognizes_json_object() {
        let data = b"{\"hello\": \"world\"}";
        assert_eq!(sniff_content(data), SniffedType::Json);
    }

    #[test]
    fn sniff_recognizes_xml() {
        let data = b"<?xml version=\"1.0\"?>\n<root/>";
        assert_eq!(sniff_content(data), SniffedType::Xml);
    }

    #[test]
    fn sniff_recognizes_plain_text() {
        let data = b"hello world\nthis is text\n";
        assert_eq!(sniff_content(data), SniffedType::Text);
    }

    #[test]
    fn sniff_recognizes_tar_ustar() {
        // Build a minimal tar header: 512 bytes with "ustar" magic at offset 257.
        let mut data = vec![0u8; 512];
        // name at 0..100
        let name = b"payload.sh\0";
        data[..name.len()].copy_from_slice(name);
        // mode at 100..108
        data[100..108].copy_from_slice(b"0000644\0");
        // size at 124..136 (octal)
        data[124..136].copy_from_slice(b"00000000000\0");
        // magic at 257..262
        data[257..262].copy_from_slice(b"ustar");
        // version at 263..265
        data[263..265].copy_from_slice(b"00");
        assert_eq!(sniff_content(&data), SniffedType::TarArchive);
        let members = list_archive_members(&data, SniffedType::TarArchive);
        assert!(members.iter().any(|m| m.contains("payload.sh")));
    }

    #[test]
    fn sniff_empty_returns_unknown() {
        assert_eq!(sniff_content(&[]), SniffedType::Unknown);
    }

    #[test]
    fn sniff_executable_disguised_as_txt_is_caught() {
        // PE disguised as .txt вЂ” content sniff catches it.
        let data = b"MZ\x90\x00";
        assert_eq!(sniff_content(data), SniffedType::WindowsExe);
    }

    #[test]
    fn zip_member_listing_parses_central_directory() {
        // Build a minimal ZIP with one entry in the central directory.
        // Local file header + central dir entry.
        let mut data = Vec::new();
        // Local file header (PK\x03\x04)
        data.extend_from_slice(b"PK\x03\x04");
        data.extend_from_slice(&[0x14, 0x00]); // version
        data.extend_from_slice(&[0x00, 0x00]); // flags
        data.extend_from_slice(&[0x00, 0x00]); // method (stored)
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // time/date
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // crc-32
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // compressed size
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // uncompressed size
        data.extend_from_slice(&[0x04, 0x00]); // name len = 4
        data.extend_from_slice(&[0x00, 0x00]); // extra len = 0
        data.extend_from_slice(b"a.sh"); // name
        // Central directory file header (PK\x01\x02)
        data.extend_from_slice(b"PK\x01\x02");
        data.extend_from_slice(&[0x00, 0x00]); // version made by
        data.extend_from_slice(&[0x14, 0x00]); // version needed
        data.extend_from_slice(&[0x00, 0x00]); // flags
        data.extend_from_slice(&[0x00, 0x00]); // method
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // time/date
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // crc-32
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // compressed size
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // uncompressed size
        data.extend_from_slice(&[0x04, 0x00]); // name len = 4
        data.extend_from_slice(&[0x00, 0x00]); // extra len = 0
        data.extend_from_slice(&[0x00, 0x00]); // comment len = 0
        data.extend_from_slice(&[0x00, 0x00]); // disk start
        data.extend_from_slice(&[0x00, 0x00]); // internal attrs
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // external attrs
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // local offset = 0
        data.extend_from_slice(b"a.sh"); // name
        assert_eq!(sniff_content(&data), SniffedType::ZipArchive);
        let members = list_archive_members(&data, SniffedType::ZipArchive);
        assert!(members.iter().any(|m| m == "a.sh"));
    }

    #[test]
    fn intake_records_sniffed_type() {
        let s = store();
        let entry = s.intake("/tmp/payload.exe", b"MZ\x90\x00\x03\x00").unwrap();
        assert_eq!(entry.sniffed_type, SniffedType::WindowsExe);
        assert!(entry.is_executable);
    }
}
