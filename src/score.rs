//! Provider scoring / certification foundation.
//!
//! `cape scan` tells you what happened on one canary probe.
//! `cape score` turns that into something product-shaped:
//!
//! - a stable 0-100 score
//! - a letter grade
//! - a machine-readable JSON report
//! - a Markdown report you can ship to users
//! - a tiny SVG badge foundation for future "Verified Clean" style programs
//!
//! This is the first step toward the business layer: reputation, audits,
//! scoring, and eventually a paid certification service.

use serde::Serialize;

use crate::scan::{RiskLevel, ScanReport};

#[derive(Debug, Clone, Serialize)]
pub struct ProviderScore {
    pub upstream: String,
    pub host: String,
    pub official: bool,
    pub transport_https: bool,
    pub total: u32,
    pub grade: Grade,
    pub summary: String,
    pub breakdown: Vec<ScoreItem>,
    pub scan: ScanReport,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub enum Grade {
    A,
    B,
    C,
    D,
    F,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScoreItem {
    pub category: &'static str,
    pub points: i32,
    pub max_points: i32,
    pub reason: String,
}

pub fn score_provider(upstream: &str, scan: ScanReport) -> ProviderScore {
    let host = extract_host(upstream);
    let official = is_official_provider(&host);
    let transport_https = upstream.starts_with("https://");

    let mut breakdown = Vec::new();

    // 1) Transport security: 20 pts
    breakdown.push(ScoreItem {
        category: "transport",
        points: if transport_https { 20 } else { 0 },
        max_points: 20,
        reason: if transport_https {
            "Provider is reached over HTTPS".to_string()
        } else {
            "Provider is reached over plain HTTP".to_string()
        },
    });

    // 2) Provider identity / trust anchor: 20 pts
    breakdown.push(ScoreItem {
        category: "identity",
        points: if official { 20 } else { 5 },
        max_points: 20,
        reason: if official {
            format!("{host} matches a known official provider domain")
        } else {
            format!("{host} is not a known official provider domain")
        },
    });

    // 3) Active behaviour on canary probe: 40 pts
    let active_points = match scan.verdict {
        RiskLevel::Clean => 40,
        RiskLevel::Low => 30,
        RiskLevel::Medium => 15,
        RiskLevel::High => 0,
        RiskLevel::Critical => 0,
    };
    breakdown.push(ScoreItem {
        category: "active-behaviour",
        points: active_points,
        max_points: 40,
        reason: format!(
            "Canary probe verdict = {:?}, risk_score = {}",
            scan.verdict, scan.risk_score
        ),
    });

    // 4) Protocol hygiene: 20 pts
    let protocol_points = if scan.unsolicited_tool_uses == 0 {
        20
    } else {
        0
    };
    breakdown.push(ScoreItem {
        category: "protocol-hygiene",
        points: protocol_points,
        max_points: 20,
        reason: if scan.unsolicited_tool_uses == 0 {
            "No unsolicited tool_use observed on the canary probe".to_string()
        } else {
            format!(
                "Observed {} unsolicited tool_use blocks on the canary probe",
                scan.unsolicited_tool_uses
            )
        },
    });

    let total: u32 = breakdown
        .iter()
        .map(|item| item.points.max(0) as u32)
        .sum();

    let grade = grade_from_total(total);
    let summary = summary_for_grade(grade, official, transport_https, &scan);

    ProviderScore {
        upstream: upstream.to_string(),
        host,
        official,
        transport_https,
        total,
        grade,
        summary,
        breakdown,
        scan,
    }
}

pub fn grade_from_total(score: u32) -> Grade {
    match score {
        85..=100 => Grade::A,
        70..=84 => Grade::B,
        50..=69 => Grade::C,
        30..=49 => Grade::D,
        _ => Grade::F,
    }
}

pub fn render_markdown(report: &ProviderScore) -> String {
    let mut out = String::new();
    out.push_str(&format!("# Provider Score — {}\n\n", report.host));
    out.push_str(&format!("- **Score:** {} / 100\n", report.total));
    out.push_str(&format!("- **Grade:** {:?}\n", report.grade));
    out.push_str(&format!("- **Official domain:** {}\n", report.official));
    out.push_str(&format!("- **HTTPS:** {}\n", report.transport_https));
    out.push_str(&format!("- **Summary:** {}\n\n", report.summary));

    out.push_str("## Breakdown\n\n");
    out.push_str("| Category | Points | Max | Reason |\n");
    out.push_str("|---|---:|---:|---|\n");
    for item in &report.breakdown {
        out.push_str(&format!(
            "| {} | {} | {} | {} |\n",
            item.category, item.points, item.max_points, item.reason
        ));
    }

    out.push_str("\n## Canary scan\n\n");
    out.push_str(&format!(
        "- **Protocol:** {}\n- **Risk verdict:** {:?}\n- **Risk score:** {}\n- **Unsolicited tool_use:** {}\n",
        report.scan.protocol,
        report.scan.verdict,
        report.scan.risk_score,
        report.scan.unsolicited_tool_uses
    ));
    if !report.scan.categories.is_empty() {
        out.push_str(&format!("- **Categories:** {}\n", report.scan.categories.join(", ")));
    }
    out
}

pub fn render_badge_svg(report: &ProviderScore) -> String {
    let color = match report.grade {
        Grade::A => "#16a34a",
        Grade::B => "#65a30d",
        Grade::C => "#ca8a04",
        Grade::D => "#ea580c",
        Grade::F => "#dc2626",
    };

    format!(
        r##"<svg xmlns="http://www.w3.org/2000/svg" width="220" height="40" role="img" aria-label="carapace score {score}">
<rect width="220" height="40" rx="6" fill="#111827"/>
<rect x="120" width="100" height="40" rx="6" fill="{color}"/>
<text x="14" y="25" fill="#f9fafb" font-family="-apple-system,Segoe UI,Arial" font-size="14">carapace score</text>
<text x="170" y="25" text-anchor="middle" fill="#ffffff" font-family="-apple-system,Segoe UI,Arial" font-size="14" font-weight="700">{score} / {grade}</text>
</svg>"##,
        color = color,
        score = report.total,
        grade = match report.grade {
            Grade::A => "A",
            Grade::B => "B",
            Grade::C => "C",
            Grade::D => "D",
            Grade::F => "F",
        },
    )
}

fn summary_for_grade(
    grade: Grade,
    official: bool,
    https: bool,
    scan: &ScanReport,
) -> String {
    match grade {
        Grade::A => {
            if official && https {
                "Strong result. Official HTTPS endpoint with clean canary behaviour.".to_string()
            } else {
                "Strong result on this probe, but still treat it as a point-in-time score.".to_string()
            }
        }
        Grade::B => "Looks healthy enough for non-secret traffic, but keep monitoring and re-scan regularly.".to_string(),
        Grade::C => "Mixed result. This provider may be usable for throwaway traffic, not for sensitive work.".to_string(),
        Grade::D => format!(
            "Weak result. {:?} behaviour or trust gaps were observed.",
            scan.verdict
        ),
        Grade::F => "Do not trust this provider. The canary probe saw malicious or severely unsafe behaviour.".to_string(),
    }
}

fn extract_host(url: &str) -> String {
    let without_scheme = url
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    without_scheme.split('/').next().unwrap_or(without_scheme).to_string()
}

fn is_official_provider(host: &str) -> bool {
    [
        "api.anthropic.com",
        "api.openai.com",
        "api.z.ai",
        "api.deepseek.com",
        "platform.moonshot.ai",
    ]
    .iter()
    .any(|h| host.eq_ignore_ascii_case(h))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::{RiskLevel, ScanReport};

    fn clean_scan() -> ScanReport {
        ScanReport {
            upstream: "https://api.deepseek.com".to_string(),
            protocol: "openai".to_string(),
            risk_score: 0,
            verdict: RiskLevel::Clean,
            categories: vec![],
            unsolicited_tool_uses: 0,
            bytes_received: 123,
            note: "clean".to_string(),
        }
    }

    #[test]
    fn official_https_clean_scores_a() {
        let report = score_provider("https://api.deepseek.com", clean_scan());
        assert_eq!(report.grade, Grade::A);
        assert!(report.total >= 85);
    }

    #[test]
    fn non_https_unofficial_malicious_scores_f() {
        let mut scan = clean_scan();
        scan.risk_score = 85;
        scan.verdict = RiskLevel::High;
        scan.unsolicited_tool_uses = 1;
        scan.categories = vec!["proto-tooluse-unsolicited".to_string()];
        let report = score_provider("http://cheap-claude.example", scan);
        assert_eq!(report.grade, Grade::F);
    }

    #[test]
    fn markdown_contains_score_and_breakdown() {
        let report = score_provider("https://api.deepseek.com", clean_scan());
        let md = render_markdown(&report);
        assert!(md.contains("Provider Score"));
        assert!(md.contains("Breakdown"));
    }

    #[test]
    fn badge_svg_contains_grade() {
        let report = score_provider("https://api.deepseek.com", clean_scan());
        let svg = render_badge_svg(&report);
        assert!(svg.contains("carapace score"));
        assert!(svg.contains("A"));
    }
}
