//! Threat-feed manifest + signature primitives.
//!
//! v0.5 introduced the data model; v0.6 makes the signature field actually
//! load-bearing. The OSS core verifies manifests against an **embedded
//! public key** (the carapace feed signing key). Private key is held offline
//! and never shipped — that's the boundary between open core and the
//! proprietary cloud tier: anyone can verify, only the project can sign.
//!
//! v0.6 deliberately stops at *verification*. Remote fetching, key rotation,
//! and the premium "rule detail" layer land in v0.7 — the open core has to
//! be honest about what it can promise before the SaaS pieces plug in.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Carapace demo feed-signing public key (Ed25519, base64).
///
/// This is intentionally the **demo** verification key shipped with the sample
/// registry feed under `examples/demo-feed/`. Production feeds should still be
/// verified with an explicit pubkey (`--pubkey`) or a future rotated trust root.
pub const FEED_PUBLIC_KEY_B64: &str = "oMx4vjrFO5W4LG7U9/ql5wiDW6CFTUjuIgu7h3p3eAI=";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FeedManifest {
    pub version: String,
    pub generated_at: String,
    pub rules_sha256: String,
    pub blocklist_sha256: String,
    /// Base64 Ed25519 detached signature over
    /// `sha256(version || generated_at || rules_sha256 || blocklist_sha256)`.
    pub signature: Option<String>,
}

impl FeedManifest {
    pub fn local(version: &str, generated_at: &str, rules: &str, blocklist: &str) -> Self {
        Self {
            version: version.to_string(),
            generated_at: generated_at.to_string(),
            rules_sha256: sha256_hex(rules.as_bytes()),
            blocklist_sha256: sha256_hex(blocklist.as_bytes()),
            signature: None,
        }
    }

    /// Hash the canonicalised fields — what a signature covers.
    pub fn signing_digest(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(self.version.as_bytes());
        h.update(self.generated_at.as_bytes());
        h.update(self.rules_sha256.as_bytes());
        h.update(self.blocklist_sha256.as_bytes());
        let out = h.finalize();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&out);
        arr
    }

    /// Confirm rules + blocklist hash to the manifest (integrity, not authenticity).
    pub fn verify_integrity(&self, rules: &str, blocklist: &str) -> bool {
        self.rules_sha256 == sha256_hex(rules.as_bytes())
            && self.blocklist_sha256 == sha256_hex(blocklist.as_bytes())
    }

    /// Verify the Ed25519 signature against the embedded feed public key.
    /// Returns `Ok(())` if the signature is valid, `Err` explaining why not.
    pub fn verify_signature(&self) -> Result<(), VerifyError> {
        use base64::Engine as _;
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};

        let sig_b64 = self.signature.as_ref().ok_or(VerifyError::MissingSignature)?;
        let sig_bytes = base64::engine::general_purpose::STANDARD
            .decode(sig_b64.as_bytes())
            .map_err(|_| VerifyError::MalformedSignature)?;
        if sig_bytes.len() != 64 {
            return Err(VerifyError::MalformedSignature);
        }
        let sig = Signature::from_slice(&sig_bytes).map_err(|_| VerifyError::MalformedSignature)?;

        let pk_bytes = base64::engine::general_purpose::STANDARD
            .decode(FEED_PUBLIC_KEY_B64.as_bytes())
            .map_err(|_| VerifyError::MalformedPublicKey)?;
        if pk_bytes.len() != 32 {
            return Err(VerifyError::MalformedPublicKey);
        }
        let pk_bytes_arr: [u8; 32] = pk_bytes.as_slice().try_into().map_err(|_| VerifyError::MalformedPublicKey)?;
        let vk = VerifyingKey::from_bytes(&pk_bytes_arr).map_err(|_| VerifyError::MalformedPublicKey)?;

        vk.verify(&self.signing_digest(), &sig)
            .map_err(|_| VerifyError::SignatureMismatch)
    }

    /// Full check: integrity + signature. The function `cape scan` and the
    /// proxy hot-reload will call before trusting a remote feed.
    pub fn verify_full(&self, rules: &str, blocklist: &str) -> Result<(), VerifyError> {
        self.verify_integrity(rules, blocklist)
            .then_some(())
            .ok_or(VerifyError::IntegrityMismatch)?;
        self.verify_signature()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("manifest has no signature")]
    MissingSignature,
    #[error("signature is malformed")]
    MalformedSignature,
    #[error("embedded public key is malformed")]
    MalformedPublicKey,
    #[error("signature does not match manifest digest")]
    SignatureMismatch,
    #[error("rules or blocklist hash mismatch")]
    IntegrityMismatch,
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

/// A fetched feed bundle: manifest + the two payload files.
pub struct FetchedFeed {
    pub manifest: FeedManifest,
    pub rules: String,
    pub blocklist: String,
}

/// Download a signed remote feed from a manifest URL.
///
/// The URL is expected to return JSON in the shape of `FeedManifest` **plus**
/// two inline string fields `rules` and `blocklist` (each the raw file contents).
/// This keeps the wire format to a single round-trip and lets us verify
/// integrity before ever touching disk.
pub async fn fetch_remote(url: &str) -> anyhow::Result<FetchedFeed> {
    let resp = reqwest::get(url).await?.error_for_status()?;
    let body = resp.text().await?;
    let v: serde_json::Value = serde_json::from_str(&body)?;

    let manifest = FeedManifest {
        version: v["version"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("manifest: missing version"))?
            .to_string(),
        generated_at: v["generated_at"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("manifest: missing generated_at"))?
            .to_string(),
        rules_sha256: v["rules_sha256"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("manifest: missing rules_sha256"))?
            .to_string(),
        blocklist_sha256: v["blocklist_sha256"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("manifest: missing blocklist_sha256"))?
            .to_string(),
        signature: v["signature"].as_str().map(|s| s.to_string()),
    };
    let rules = v["rules"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("manifest: missing rules payload"))?
        .to_string();
    let blocklist = v["blocklist"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("manifest: missing blocklist payload"))?
        .to_string();

    Ok(FetchedFeed {
        manifest,
        rules,
        blocklist,
    })
}

impl FeedManifest {
    /// Verify the signature against an **explicit** base64 Ed25519 public key
    /// (instead of the embedded one). Used by `cape feed fetch --pubkey`.
    pub fn verify_signature_with_pubkey(&self, pk_b64: &str) -> Result<(), VerifyError> {
        use base64::Engine as _;
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};

        let sig_b64 = self.signature.as_ref().ok_or(VerifyError::MissingSignature)?;
        let sig_bytes = base64::engine::general_purpose::STANDARD
            .decode(sig_b64.as_bytes())
            .map_err(|_| VerifyError::MalformedSignature)?;
        if sig_bytes.len() != 64 {
            return Err(VerifyError::MalformedSignature);
        }
        let sig = Signature::from_slice(&sig_bytes).map_err(|_| VerifyError::MalformedSignature)?;

        let pk_bytes = base64::engine::general_purpose::STANDARD
            .decode(pk_b64.as_bytes())
            .map_err(|_| VerifyError::MalformedPublicKey)?;
        if pk_bytes.len() != 32 {
            return Err(VerifyError::MalformedPublicKey);
        }
        let pk_arr: [u8; 32] = pk_bytes
            .as_slice()
            .try_into()
            .map_err(|_| VerifyError::MalformedPublicKey)?;
        let vk = VerifyingKey::from_bytes(&pk_arr).map_err(|_| VerifyError::MalformedPublicKey)?;

        vk.verify(&self.signing_digest(), &sig)
            .map_err(|_| VerifyError::SignatureMismatch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use ed25519_dalek::{SigningKey, Signer};

    #[test]
    fn manifest_verifies_builtin_files() {
        let rules = include_str!("../rules/default.json");
        let blocklist = include_str!("../rules/blocklist.json");
        let mf = FeedManifest::local("v0.6-dev", "2026-06-28T00:00:00Z", rules, blocklist);
        assert!(mf.verify_integrity(rules, blocklist));
    }

    #[test]
    fn manifest_detects_tampering() {
        let rules = include_str!("../rules/default.json");
        let blocklist = include_str!("../rules/blocklist.json");
        let mf = FeedManifest::local("v0.6-dev", "2026-06-28T00:00:00Z", rules, blocklist);
        assert!(!mf.verify_integrity(&(rules.to_owned() + "\n "), blocklist));
    }

    #[test]
    fn signature_round_trip_with_fresh_keypair() {
        // Self-contained: we sign with a freshly generated keypair *and* swap
        // the embedded public key constant locally inside the test by signing
        // and verifying with the same key. Demonstrates the wire format.
        let rules = include_str!("../rules/default.json");
        let blocklist = include_str!("../rules/blocklist.json");
        let mut mf = FeedManifest::local("v0.6-dev", "2026-06-28T00:00:00Z", rules, blocklist);

        let sk = SigningKey::generate(&mut rand_core::OsRng);
        let sig = sk.sign(&mf.signing_digest());
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(sig.to_bytes());
        mf.signature = Some(sig_b64);

        // Verify directly with the matching public key.
        use ed25519_dalek::Verifier;
        let vk = sk.verifying_key();
        assert!(vk.verify(&mf.signing_digest(), &sig).is_ok());

        // The manifest's own verify_signature() uses the built-in demo trust root,
        // so a freshly generated random keypair should fail with a signature mismatch.
        assert!(matches!(mf.verify_signature(), Err(VerifyError::SignatureMismatch)));
    }

    #[test]
    fn missing_signature_is_reported() {
        let rules = include_str!("../rules/default.json");
        let blocklist = include_str!("../rules/blocklist.json");
        let mf = FeedManifest::local("v0.6-dev", "2026-06-28T00:00:00Z", rules, blocklist);
        assert!(matches!(mf.verify_full(rules, blocklist), Err(VerifyError::MissingSignature)));
    }
}
