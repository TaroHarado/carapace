//! Model identity confidence.
//!
//! This is intentionally framed as *confidence*, not proof.
//! A third-party endpoint can dynamically swap models, downgrade at peak, or
//! special-case our probes. The goal is to give the user a practical answer:
//! how likely is it that the endpoint behaves like the claimed family right now?

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityReport {
    pub claimed_model: Option<String>,
    pub claimed_family: ModelFamily,
    pub observed_family: ModelFamily,
    pub confidence: u32,
    pub risk: IdentityRisk,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ModelFamily {
    Claude,
    OpenAI,
    DeepSeek,
    Qwen,
    GLM,
    Kimi,
    Unknown,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum IdentityRisk {
    Low,
    Medium,
    High,
}

pub fn assess(
    upstream: &str,
    claimed_model: Option<&str>,
    protocol: &str,
    agent_safety_score: u32,
) -> IdentityReport {
    let claimed_family = claimed_model.map(detect_claimed_family).unwrap_or(ModelFamily::Unknown);
    let observed_family = infer_observed_family(upstream, protocol);
    let mut reasons = Vec::new();
    let mut confidence: i32 = 35;

    if is_official_host(upstream) {
        confidence += 35;
        reasons.push("official provider hostname".to_string());
    } else {
        reasons.push("third-party / untrusted hostname".to_string());
    }

    if claimed_family != ModelFamily::Unknown && observed_family != ModelFamily::Unknown {
        if claimed_family == observed_family {
            confidence += 20;
            reasons.push("claimed family matches observed provider family".to_string());
        } else {
            confidence -= 20;
            reasons.push("claimed family does not match observed provider family".to_string());
        }
    } else {
        reasons.push("insufficient family signal".to_string());
    }

    if protocol == "anthropic" && claimed_family == ModelFamily::Claude {
        confidence += 10;
        reasons.push("wire protocol matches Claude-style endpoint".to_string());
    }

    if agent_safety_score < 50 {
        confidence -= 10;
        reasons.push("unsafe agent behaviour lowers identity trust".to_string());
    }

    let confidence = confidence.clamp(5, 95) as u32;
    let risk = match confidence {
        75..=100 => IdentityRisk::Low,
        45..=74 => IdentityRisk::Medium,
        _ => IdentityRisk::High,
    };

    IdentityReport {
        claimed_model: claimed_model.map(|s| s.to_string()),
        claimed_family,
        observed_family,
        confidence,
        risk,
        reasons,
    }
}

fn detect_claimed_family(model: &str) -> ModelFamily {
    let m = model.to_lowercase();
    if m.contains("claude") {
        ModelFamily::Claude
    } else if m.contains("gpt") || m.contains("openai") {
        ModelFamily::OpenAI
    } else if m.contains("deepseek") {
        ModelFamily::DeepSeek
    } else if m.contains("qwen") {
        ModelFamily::Qwen
    } else if m.contains("glm") || m.contains("z.ai") {
        ModelFamily::GLM
    } else if m.contains("kimi") || m.contains("moonshot") {
        ModelFamily::Kimi
    } else {
        ModelFamily::Unknown
    }
}

fn infer_observed_family(upstream: &str, protocol: &str) -> ModelFamily {
    let u = upstream.to_lowercase();
    if u.contains("anthropic") || (u.contains("claude") && protocol == "anthropic") {
        ModelFamily::Claude
    } else if u.contains("openai") {
        ModelFamily::OpenAI
    } else if u.contains("deepseek") {
        ModelFamily::DeepSeek
    } else if u.contains("qwen") {
        ModelFamily::Qwen
    } else if u.contains("z.ai") || u.contains("glm") {
        ModelFamily::GLM
    } else if u.contains("moonshot") || u.contains("kimi") {
        ModelFamily::Kimi
    } else {
        ModelFamily::Unknown
    }
}

fn is_official_host(upstream: &str) -> bool {
    let u = upstream.to_lowercase();
    [
        "api.anthropic.com",
        "api.openai.com",
        "api.deepseek.com",
        "api.z.ai",
        "platform.moonshot.ai",
    ]
    .iter()
    .any(|h| u.contains(h))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn official_matching_claude_scores_high() {
        let r = assess(
            "https://api.anthropic.com/v1/messages",
            Some("Claude Sonnet 4.5"),
            "anthropic",
            90,
        );
        assert!(r.confidence >= 75);
        assert_eq!(r.risk, IdentityRisk::Low);
    }

    #[test]
    fn third_party_claiming_claude_is_low_confidence() {
        let r = assess(
            "https://cheap-claude-api.example/v1",
            Some("Claude Sonnet 4.5"),
            "openai",
            40,
        );
        assert!(r.confidence < 60);
        assert_eq!(r.risk, IdentityRisk::High);
    }

    #[test]
    fn deepseek_host_matches_deepseek_family() {
        let r = assess(
            "https://api.deepseek.com/v1/chat/completions",
            Some("DeepSeek V4 Flash"),
            "openai",
            95,
        );
        assert_eq!(r.claimed_family, ModelFamily::DeepSeek);
        assert_eq!(r.observed_family, ModelFamily::DeepSeek);
    }
}
