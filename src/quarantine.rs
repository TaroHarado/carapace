//! Download quarantine pipeline — Layer 5 of the SafeRouter model.
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
//! is diverted to `~/.carapace/quarantine/<sha256>.<ext>` and step 2's
//! target path no longer exists — the original `/tmp/cache.sh` is empty or
//! absent. The artifact can be reviewed, hashed, signature-checked, and
//! either released or purged.

use std::collections::HashSet;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use sha2::{Digest, Sha256};

#[derive(Debug, Clone)]
pub struct QuarantineEntry {
    pub original_path: String,
    pub stored_path: PathBuf,
    pub sha256: String,
    pub size_bytes: usize,
    pub mime_guess: String,
    pub extension: String,
    pub released: bool,
}

pub struct QuarantineStore {
    root: PathBuf,
    entries: Arc<Mutex<Vec<QuarantineEntry>>>,
    /// Hash allowlist — known-good hashes that auto-release on intake.
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
        // Drop write perms on the stored file — make execution harder.
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
    if let Some(home) = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")) {
        PathBuf::from(home).join(".carapace").join("quarantine")
    } else {
        PathBuf::from(".carapace").join("quarantine")
    }
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
}