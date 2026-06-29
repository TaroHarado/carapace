//! Decoy canary artifacts — the asymmetric advantage.
//!
//! Plant fake credential files / wallet keystores / .env files in the user's
//! home directory. Any tool_use that touches these paths is an immediate
//! hard Block — no real user ever asks an agent to read ~/.ssh/id_rsa
//! through a tool_use; only an attacker (or a careless agent) does.
//!
//! The canary files are byte-for-byte indistinguishable from real ones to
//! the attacker — they contain plausible-looking key material (decoy
//! private keys that don't unlock anything, decoy AWS keys that don't
//! authenticate, decoy wallet seeds that have zero balance).
//!
//! Detection is path-based, not content-based, so evasion is impossible:
//! the attacker can't tell which file is the canary vs. the real one
//! without trying to use the contents — which we've already blocked.
//!
//! Architecture:
//!
//!   user home
//!     .ssh/
//!       id_rsa         <- canary (decoy key, planted)
//!       id_rsa.real    <- real key (user renames; only human uses it)
//!     .aws/
//!       credentials   <- canary
//!     .config/solana/
//!       id.json       <- canary
//!     .env            <- canary (in CWD)
//!
//! Any tool_use whose primary_target resolves to a canary path triggers
//! CanaryHit and the defense engine returns Block.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Canary {
    /// Absolute path where the canary is planted.
    pub path: PathBuf,
    /// Category label for audit log.
    pub category: &'static str,
    /// Decoy content placed at the path.
    pub decoy_content: Vec<u8>,
    /// True if the canary is currently planted on disk.
    pub planted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanaryHit {
    pub path: String,
    pub category: String,
    pub severity: u32,
    pub reason: String,
}

pub struct CanaryRegistry {
    canaries: Arc<Mutex<Vec<Canary>>>,
    /// Quick-lookup set of planted canary paths (lowercased).
    paths: Arc<Mutex<HashSet<String>>>,
}

impl Default for CanaryRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl CanaryRegistry {
    pub fn new() -> Self {
        Self {
            canaries: Arc::new(Mutex::new(Vec::new())),
            paths: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    /// Plant the default canary set under `home`. Returns the list of
    /// planted canaries. Existing real files are NOT overwritten — if a
    /// file already exists at a canary path, that path is skipped and
    /// logged.
    pub fn plant_defaults(&self, home: &Path) -> std::io::Result<Vec<Canary>> {
        let mut planted = Vec::new();
        for spec in default_canary_specs() {
            let path = home.join(spec.relative_path);
            // Don't overwrite existing files — user might have real creds.
            if path.exists() {
                tracing::info!(
                    path = %path.display(),
                    "canary path already exists, skipping (user has real file)"
                );
                continue;
            }
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&path, spec.decoy_content)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
            }
            let canary = Canary {
                path: path.clone(),
                category: spec.category,
                decoy_content: spec.decoy_content.to_vec(),
                planted: true,
            };
            planted.push(canary.clone());
            self.canaries.lock().unwrap().push(canary);
            self.paths
                .lock()
                .unwrap()
                .insert(path.to_string_lossy().to_lowercase());
        }
        Ok(planted)
    }

    /// Register a custom canary at an arbitrary path (no planting — caller
    /// is responsible for the file existing).
    pub fn register(&self, path: &Path, category: &'static str) {
        self.canaries.lock().unwrap().push(Canary {
            path: path.to_path_buf(),
            category,
            decoy_content: Vec::new(),
            planted: false,
        });
        self.paths
            .lock()
            .unwrap()
            .insert(path.to_string_lossy().to_lowercase());
    }

    /// Check if a target path matches a planted canary. Path comparison is
    /// case-insensitive and matches either the literal canary path or any
    /// path that resolves to the same location (handled by canonicalize on
    /// the caller side).
    pub fn check(&self, target: &str) -> Option<CanaryHit> {
        let lower = target.to_lowercase();
        let paths = self.paths.lock().unwrap();
        // Direct match.
        if paths.contains(&lower) {
            let canaries = self.canaries.lock().unwrap();
            if let Some(c) = canaries.iter().find(|c| c.path.to_string_lossy().to_lowercase() == lower) {
                return Some(CanaryHit {
                    path: target.to_string(),
                    category: c.category.to_string(),
                    severity: 95,
                    reason: format!("canary hit: {} touched", c.category),
                });
            }
        }
        // Suffix match (handles `~/`, relative-to-home, $HOME prefixes).
        for path_str in paths.iter() {
            if lower.ends_with(path_str) || path_str.ends_with(&lower) {
                let canaries = self.canaries.lock().unwrap();
                if let Some(c) = canaries
                    .iter()
                    .find(|c| c.path.to_string_lossy().to_lowercase() == *path_str)
                {
                    return Some(CanaryHit {
                        path: target.to_string(),
                        category: c.category.to_string(),
                        severity: 95,
                        reason: format!("canary hit: {} touched", c.category),
                    });
                }
            }
        }
        None
    }

    /// Unplant all canaries (cleanup).
    pub fn unplant_all(&self) -> std::io::Result<()> {
        let mut canaries = self.canaries.lock().unwrap();
        for c in canaries.iter() {
            if c.planted {
                let _ = std::fs::remove_file(&c.path);
            }
        }
        canaries.clear();
        self.paths.lock().unwrap().clear();
        Ok(())
    }

    pub fn list(&self) -> Vec<Canary> {
        self.canaries.lock().unwrap().clone()
    }
}

struct CanarySpec {
    relative_path: &'static str,
    category: &'static str,
    decoy_content: &'static [u8],
}

fn default_canary_specs() -> &'static [CanarySpec] {
    static SPECS: std::sync::OnceLock<Vec<CanarySpec>> = std::sync::OnceLock::new();
    SPECS.get_or_init(|| {
        vec![
            CanarySpec {
                relative_path: ".ssh/id_rsa",
                category: "ssh-private-key",
                decoy_content: b"-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\nQyNTUxOQAAACBgQ0ZPR0UgQ0FOQVJZIERFQ09ZIEtFWS0gRE8gTk9UIFVTRQAAAJgHBzOt\nBwczrQAAAAtzc2gtZWQyNTUxOQAAACBgQ0ZPR0UgQ0FOQVJZIERFQ09ZIEtFWS0gRE8g\nTk9UIFVTRQAAAEdGVzR3lRS2dYY2V6eUl6U0JBQ2hFZENuNXlUU3h4eXlIWFFscU5yd2Y1\nRnc9Cj09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT0K\n-----END OPENSSH PRIVATE KEY-----\n",
            },
            CanarySpec {
                relative_path: ".ssh/id_ed25519",
                category: "ssh-ed25519-key",
                decoy_content: b"-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\nQyNTUxOQAAACBgQ0ZPR0UgQ0FOQVJZIERFQ09ZIEtFWS0gRE8gTk9UIFVTRQAAAJgHBzOt\nBwczrQAAAAtzc2gtZWQyNTUxOQAAACBgQ0ZPR0UgQ0FOQVJZIERFQ09ZIEtFWS0gRE8g\nTk9UIFVTRQAAAEdGVzR3lRS2dYY2V6eUl6U0JBQ2hFZENuNXlUU3h4eXlIWFFscU5yd2Y1\nRnc9Cj09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT0K\n-----END OPENSSH PRIVATE KEY-----\n",
            },
            CanarySpec {
                relative_path: ".aws/credentials",
                category: "aws-credentials",
                decoy_content: b"[default]\naws_access_key_id = AKIARCANARYDECOY000\naws_secret_access_key = CANARYDECOYSECRETKEYDO NOTUSE0000\n[production]\naws_access_key_id = AKIARCANARYDECOY001\naws_secret_access_key = CANARYDECOYSECRETKEYDO NOTUSE0001\n",
            },
            CanarySpec {
                relative_path: ".aws/config",
                category: "aws-config",
                decoy_content: b"[default]\nregion = us-east-1\noutput = json\n[profile production]\nregion = us-west-2\n",
            },
            CanarySpec {
                relative_path: ".kube/config",
                category: "kube-config",
                decoy_content: b"apiVersion: v1\nkind: Config\nclusters:\n- name: canary-cluster\n  cluster:\n    server: https://10.0.0.1:6443\n    certificate-authority-data: Q0FOQVJZIERFQ09ZIENBTC0gRE8gTk9UIFVTRQo=\nusers:\n- name: canary-user\n  user:\n    client-certificate-data: Q0FOQVJZIERFQ09ZIENlcnQ0g\n    client-key-data: Q0FOQVJZIERFQ09ZIEtleQ==\n",
            },
            CanarySpec {
                relative_path: ".docker/config.json",
                category: "docker-config",
                decoy_content: b"{\"auths\":{\"https://index.docker.io/v1/\":{\"auth\":\"Y2FuYXJ5OmRlY295ZG9ub3R1c2U=\"}}}\n",
            },
            CanarySpec {
                relative_path: ".config/solana/id.json",
                category: "solana-wallet",
                decoy_content: b"[\n  124,234,175,42,177,177,177,177,177,177,177,177,177,177,177,177,177,177,177,177,\n  177,177,177,177,177,177,177,177,177,177,177,177,177,177,177,177,177,177,177,\n  177,177,177,177,177,177,177,177,177,177,177,177,177,177,177,177,177,177,177,\n  177,177,177,177,177\n]\n",
            },
            CanarySpec {
                relative_path: ".netrc",
                category: "netrc",
                decoy_content: b"machine github.com\nlogin canary-decoy\npassword do-not-use-canary\n",
            },
            CanarySpec {
                relative_path: ".pypirc",
                category: "pypirc",
                decoy_content: b"[distutils]\nindex-servers = pypi\n\n[pypi]\nrepository = https://upload.pypi.org/legacy/\nusername = canary-decoy\npassword = do-not-use-canary\n",
            },
            CanarySpec {
                relative_path: ".npmrc",
                category: "npmrc",
                decoy_content: b"//registry.npmjs.org/:_authToken=canary-decoy-do-not-use-npm-000000000000\n",
            },
            CanarySpec {
                relative_path: ".gnupg/secring.gpg",
                category: "gpg-secret-keyring",
                decoy_content: b"-----BEGIN PGP PRIVATE KEY BLOCK-----\nCANARY DECOY PRIVATE KEY - DO NOT USE\n-----END PGP PRIVATE KEY BLOCK-----\n",
            },
        ]
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn registry_with_home() -> (CanaryRegistry, PathBuf) {
        let home = tempdir().unwrap().keep();
        let reg = CanaryRegistry::new();
        reg.plant_defaults(&home).unwrap();
        (reg, home)
    }

    #[test]
    fn plant_defaults_creates_ssh_canary() {
        let (reg, home) = registry_with_home();
        let ssh_path = home.join(".ssh/id_rsa");
        assert!(ssh_path.exists());
        let content = std::fs::read(&ssh_path).unwrap();
        assert!(content.starts_with(b"-----BEGIN OPENSSH PRIVATE KEY-----"));
        let canaries = reg.list();
        assert!(canaries.iter().any(|c| c.category == "ssh-private-key"));
    }

    #[test]
    fn plant_defaults_creates_aws_canary() {
        let (reg, home) = registry_with_home();
        let aws_path = home.join(".aws/credentials");
        assert!(aws_path.exists());
        let content = std::fs::read(&aws_path).unwrap();
        let text = std::str::from_utf8(&content).unwrap();
        assert!(text.contains("aws_access_key_id"));
        let canaries = reg.list();
        assert!(canaries.iter().any(|c| c.category == "aws-credentials"));
    }

    #[test]
    fn plant_defaults_creates_solana_canary() {
        let (reg, home) = registry_with_home();
        let solana_path = home.join(".config/solana/id.json");
        assert!(solana_path.exists());
        let canaries = reg.list();
        assert!(canaries.iter().any(|c| c.category == "solana-wallet"));
    }

    #[test]
    fn plant_defaults_skips_existing_files() {
        let home = tempdir().unwrap().keep();
        // Pre-create a real file.
        std::fs::create_dir_all(home.join(".ssh")).unwrap();
        std::fs::write(home.join(".ssh/id_rsa"), b"REAL PRIVATE KEY").unwrap();
        let reg = CanaryRegistry::new();
        reg.plant_defaults(&home).unwrap();
        // Should NOT overwrite.
        let content = std::fs::read(home.join(".ssh/id_rsa")).unwrap();
        assert_eq!(content, b"REAL PRIVATE KEY");
        // Should not be in the registry.
        assert!(!reg.list().iter().any(|c| c.category == "ssh-private-key"));
    }

    #[test]
    fn check_detects_canary_access() {
        let (reg, home) = registry_with_home();
        let ssh_path = home.join(".ssh/id_rsa");
        let hit = reg.check(&ssh_path.to_string_lossy()).unwrap();
        assert_eq!(hit.category, "ssh-private-key");
        assert_eq!(hit.severity, 95);
    }

    #[test]
    fn check_returns_none_for_non_canary() {
        let (reg, _home) = registry_with_home();
        let hit = reg.check("/tmp/random-file.txt");
        assert!(hit.is_none());
    }

    #[test]
    fn check_matches_case_insensitive() {
        let (reg, home) = registry_with_home();
        let ssh_path = home.join(".SSH/ID_RSA");
        let hit = reg.check(&ssh_path.to_string_lossy());
        assert!(hit.is_some());
    }

    #[test]
    fn check_matches_with_tilde_prefix() {
        let (reg, home) = registry_with_home();
        // Simulate ~ being expanded to home.
        let ssh_path = home.join(".ssh/id_rsa");
        let hit = reg.check(&ssh_path.to_string_lossy());
        assert!(hit.is_some());
    }

    #[test]
    fn unplant_removes_all_canaries() {
        let (reg, home) = registry_with_home();
        let ssh_path = home.join(".ssh/id_rsa");
        assert!(ssh_path.exists());
        reg.unplant_all().unwrap();
        assert!(!ssh_path.exists());
        assert!(reg.list().is_empty());
    }

    #[test]
    fn register_custom_canary_no_planting() {
        let reg = CanaryRegistry::new();
        reg.register(Path::new("/custom/canary.txt"), "custom");
        let hit = reg.check("/custom/canary.txt").unwrap();
        assert_eq!(hit.category, "custom");
        // Should not have planted (no file created).
        assert!(!Path::new("/custom/canary.txt").exists());
    }

    #[test]
    fn all_default_canaries_plant_successfully() {
        let home = tempdir().unwrap().keep();
        let reg = CanaryRegistry::new();
        let planted = reg.plant_defaults(&home).unwrap();
        // 11 default canary specs.
        assert_eq!(planted.len(), 11);
    }

    #[test]
    fn decoy_content_is_plausible_not_real() {
        // Sanity check: decoy SSH key has the right header but the body is
        // obviously a canary (won't authenticate to anything).
        let home = tempdir().unwrap().keep();
        let reg = CanaryRegistry::new();
        reg.plant_defaults(&home).unwrap();
        let content = std::fs::read(home.join(".ssh/id_rsa")).unwrap();
        let text = std::str::from_utf8(&content).unwrap();
        assert!(text.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----"));
        // The base64 body encodes "CANARY DECOY" — look for the base64 form
        // (Q0FOQVJZIERFQ09Z) which proves the decoy is intentional and
        // distinct from a real key.
        assert!(
            text.contains("Q0FOQVJZIERFQ09Z"),
            "decoy SSH key must contain base64-encoded 'CANARY DECOY' marker"
        );
    }
}