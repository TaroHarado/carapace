//! Certification / registry artifact generation.
//!
//! `cape score` gives you a local score.
//! `cape certify` turns that score into a publishable artifact:
//!
//! - human-readable report
//! - badge SVG
//! - machine-readable registry entry
//! - optional Ed25519 signature by an auditor / service operator
//!
//! This is the thin edge of the wedge for `Verified Clean` and paid provider
//! audits. The open-source core can build and verify these artifacts locally;
//! a future hosted service can issue them at scale.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

use crate::score::{Grade, ProviderScore};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryEntry {
    pub schema_version: String,
    pub generated_at: String,
    pub upstream: String,
    pub host: String,
    pub total: u32,
    pub grade: Grade,
    pub official: bool,
    pub transport_https: bool,
    pub summary: String,
    pub statement: String,
    pub score_sha256: String,
    pub badge_sha256: String,
    pub signature: Option<String>,
}

impl RegistryEntry {
    pub fn from_score(report: &ProviderScore, badge_svg: &str) -> Self {
        let score_json = serde_json::to_vec(report).expect("score serializes");
        Self {
            schema_version: "1".to_string(),
            generated_at: OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_else(|_| "?".to_string()),
            upstream: report.upstream.clone(),
            host: report.host.clone(),
            total: report.total,
            grade: report.grade,
            official: report.official,
            transport_https: report.transport_https,
            summary: report.summary.clone(),
            statement: statement_for(report),
            score_sha256: hex::encode(Sha256::digest(&score_json)),
            badge_sha256: hex::encode(Sha256::digest(badge_svg.as_bytes())),
            signature: None,
        }
    }

    pub fn signing_digest(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(self.schema_version.as_bytes());
        h.update(self.generated_at.as_bytes());
        h.update(self.upstream.as_bytes());
        h.update(self.host.as_bytes());
        h.update(self.total.to_le_bytes());
        h.update(format!("{:?}", self.grade).as_bytes());
        h.update(if self.official { b"1" } else { b"0" });
        h.update(if self.transport_https { b"1" } else { b"0" });
        h.update(self.summary.as_bytes());
        h.update(self.statement.as_bytes());
        h.update(self.score_sha256.as_bytes());
        h.update(self.badge_sha256.as_bytes());
        let out = h.finalize();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&out);
        arr
    }

    pub fn sign_with_base64_secret(&mut self, secret_b64: &str) -> anyhow::Result<()> {
        use base64::Engine as _;
        use ed25519_dalek::{Signer, SigningKey};

        let secret = base64::engine::general_purpose::STANDARD.decode(secret_b64.as_bytes())?;
        let arr: [u8; 32] = secret
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("signing key must be 32 raw bytes in base64"))?;
        let sk = SigningKey::from_bytes(&arr);
        let sig = sk.sign(&self.signing_digest());
        self.signature = Some(base64::engine::general_purpose::STANDARD.encode(sig.to_bytes()));
        Ok(())
    }

    pub fn verify_with_pubkey(&self, pubkey_b64: &str) -> anyhow::Result<()> {
        use base64::Engine as _;
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};

        let sig_b64 = self.signature.as_ref().ok_or_else(|| anyhow::anyhow!("missing signature"))?;
        let sig_bytes = base64::engine::general_purpose::STANDARD.decode(sig_b64.as_bytes())?;
        let sig = Signature::from_slice(&sig_bytes)?;

        let pk_bytes = base64::engine::general_purpose::STANDARD.decode(pubkey_b64.as_bytes())?;
        let arr: [u8; 32] = pk_bytes
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("pubkey must decode to 32 bytes"))?;
        let vk = VerifyingKey::from_bytes(&arr)?;
        vk.verify(&self.signing_digest(), &sig)?;
        Ok(())
    }
}

fn statement_for(report: &ProviderScore) -> String {
    match report.grade {
        Grade::A => "Canary probe looked clean; this provider is a strong candidate for verification.".to_string(),
        Grade::B => "Canary probe looked decent, but this provider still deserves periodic rescans and manual review.".to_string(),
        Grade::C => "Mixed trust signals. Suitable only for low-sensitivity traffic until further review.".to_string(),
        Grade::D => "Weak trust posture. Do not recommend for general use without remediation.".to_string(),
        Grade::F => "Provider failed active trust checks. Do not recommend.".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::{RiskLevel, ScanReport};
    use crate::score::score_provider;
    use base64::Engine as _;
    use ed25519_dalek::{SigningKey, VerifyingKey};

    fn sample_score() -> ProviderScore {
        let scan = ScanReport {
            upstream: "https://api.deepseek.com".into(),
            protocol: "openai".into(),
            risk_score: 0,
            verdict: RiskLevel::Clean,
            categories: vec![],
            unsolicited_tool_uses: 0,
            bytes_received: 42,
            note: "clean".into(),
        };
        score_provider("https://api.deepseek.com", scan)
    }

    #[test]
    fn registry_entry_signs_and_verifies() {
        let score = sample_score();
        let badge = crate::score::render_badge_svg(&score);
        let mut entry = RegistryEntry::from_score(&score, &badge);

        let sk = SigningKey::generate(&mut rand_core::OsRng);
        let secret_b64 = base64::engine::general_purpose::STANDARD.encode(sk.to_bytes());
        let pub_b64 = base64::engine::general_purpose::STANDARD.encode(VerifyingKey::from(&sk).to_bytes());

        entry.sign_with_base64_secret(&secret_b64).unwrap();
        entry.verify_with_pubkey(&pub_b64).unwrap();
    }

    #[test]
    fn statement_tracks_grade() {
        let score = sample_score();
        let badge = crate::score::render_badge_svg(&score);
        let entry = RegistryEntry::from_score(&score, &badge);
        assert!(entry.statement.contains("strong candidate") || entry.statement.contains("Canary probe"));
    }
}
