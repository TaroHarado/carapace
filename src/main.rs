//! `cape` вЂ” carapace CLI entry point.

use std::net::SocketAddr;

use anyhow::Context;
use clap::Parser;
use tracing_subscriber::EnvFilter;

use safeproxy::artifact;
use safeproxy::audit;
use safeproxy::bundle;
use safeproxy::certify;
use safeproxy::cli::{ArtifactCmd, CanaryCmd, Cli, Commands, EnforceCmd, Mode, PolicyCmd, QuarantineCmd, RegistryCmd, SessionCmd};
use safeproxy::deep_scan;
use safeproxy::monitor;
use safeproxy::policy::{Action, ActionKind, ProviderRisk};
use safeproxy::probes;
use safeproxy::proxy::{self, ProxyConfig};
use safeproxy::record::{EncryptedForensics, Recorder};
use safeproxy::registry::{self, Registry};
use safeproxy::scan;
use safeproxy::score;
use safeproxy::secure::Secret;
use safeproxy::session;
use safeproxy::sentinel;
use safeproxy::web;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    init_tracing(cli.verbose, cli.quiet);

    match cli.command {
        Commands::Proxy {
            upstream,
            listen,
            upstream_key,
            mode,
            log,
            rules,
            blocklist,
            forensics,
            forensics_pass,
        } => {
            let listen_addr: SocketAddr = listen
                .parse()
                .with_context(|| format!("invalid --listen `{listen}`"))?;
            let key = match upstream_key {
                Some(k) => Secret::new(k),
                None => Secret::empty(),
            };
            let recorder = Recorder::open(&log).context("open log")?;
            let loaded_rules = safeproxy::inspect::load_from_files(
                rules.as_deref(),
                blocklist.as_deref(),
            )
            .context("load rules/blocklist")?;
            let judge = safeproxy::judge::from_env().map(std::sync::Arc::new);
            let forensics = match (forensics, forensics_pass) {
                (Some(path), Some(pass)) => Some(std::sync::Arc::new(
                    EncryptedForensics::open(
                        path.to_str().unwrap_or(""),
                        &pass,
                    )
                    .context("open forensics store")?,
                )),
                (Some(_), None) => anyhow::bail!("--forensics requires --forensics-pass"),
                (None, _) => None,
            };
let defense = std::sync::Arc::new(safeproxy::defense::DefenseEngine::with_default_provenance());
            let quarantine = match safeproxy::quarantine::QuarantineStore::open_default() {
                Ok(q) => Some(std::sync::Arc::new(q)),
                Err(e) => {
                    eprintln!("carapace: quarantine store open failed: {e}; running without quarantine pipeline");
                    None
                }
            };
            let cfg = ProxyConfig {
                upstream,
                listen: listen_addr,
                upstream_key: key,
                mode,
                recorder: std::sync::Arc::new(recorder),
                forensics,
                rules: std::sync::Arc::new(loaded_rules),
                judge,
                defense: Some(defense),
                quarantine,
            };
            safeproxy::self_fuzz::spawn((*cfg.rules).clone());
            proxy::run(cfg).await
        }
        Commands::Scan { upstream, key } => {
            let key = key.map(Secret::new);
            let report = scan::run(&upstream, key).await?;
            eprintln!("risk: {:?} ({})", report.verdict, report.risk_score);
            if !report.categories.is_empty() {
                eprintln!("categories: {}", report.categories.join(" "));
            }
            eprintln!("protocol: {}", report.protocol);
            eprintln!("bytes: {}", report.bytes_received);
            eprintln!("note: {}", report.note);
            if report.risk_score >= 60 {
                std::process::exit(2);
            }
            Ok(())
        }
        Commands::DeepScan {
            upstream,
            key,
            claimed_model,
            use_case,
            format,
            out,
        } => {
            let report = deep_scan::run(&upstream, key.map(Secret::new), claimed_model, &use_case).await?;
            let rendered = match format.as_str() {
                "json" => serde_json::to_string_pretty(&report)?,
                _ => deep_scan::render_markdown(&report),
            };
            if let Some(path) = out {
                std::fs::write(&path, rendered)?;
                eprintln!("deep-scan: report written -> {}", path.display());
            } else {
                eprintln!("{rendered}");
            }
            if report.verdict == probes::AgentVerdict::DoNotUse {
                std::process::exit(2);
            }
            Ok(())
        }
        Commands::Score {
            upstream,
            key,
            format,
            out,
            badge,
        } => {
            let key = key.map(Secret::new);
            let scan_report = scan::run(&upstream, key).await?;
            let report = score::score_provider(&upstream, scan_report);

            if let Some(path) = badge {
                std::fs::write(&path, score::render_badge_svg(&report))
                    .with_context(|| format!("write badge `{}`", path.display()))?;
                eprintln!("badge written: {}", path.display());
            }

            let rendered = match format.as_str() {
                "json" => serde_json::to_string_pretty(&report)?,
                _ => score::render_markdown(&report),
            };

            if let Some(path) = out {
                std::fs::write(&path, &rendered)
                    .with_context(|| format!("write report `{}`", path.display()))?;
                eprintln!("report written: {}", path.display());
            } else {
                eprintln!("{rendered}");
            }

            if report.total < 50 {
                std::process::exit(2);
            }
            Ok(())
        }
        Commands::Certify {
            upstream,
            key,
            out,
            signing_key,
        } => {
            let (report, badge_svg, report_md, entry) =
                build_certification_bundle(&upstream, key.map(Secret::new), signing_key).await?;
            let bundle = bundle::PublishBundle::write(&out, &report, &report_md, &badge_svg, &entry)?;
            eprintln!("certify: wrote publish bundle to {}", out.display());
            eprintln!("certify: {} files + SHA256SUMS", bundle.metadata.files.len() + 2);
            if report.total < 50 {
                std::process::exit(2);
            }
            Ok(())
        }
        Commands::Verify {
            upstream,
            key,
            out,
            signing_key,
            registry: reg_path,
        } => {
            let (report, badge_svg, report_md, entry) =
                build_certification_bundle(&upstream, key.map(Secret::new), signing_key).await?;

            let bundle = bundle::PublishBundle::write(&out, &report, &report_md, &badge_svg, &entry)?;

            let registry_path = reg_path.unwrap_or_else(registry::default_registry_path);
            let mut reg = Registry::load(&registry_path)?;
            reg.add(entry.clone());
            reg.save(&registry_path)?;

            eprintln!("verify: publish bundle written -> {}", out.display());
            eprintln!("verify: bundle files = {}", bundle.metadata.files.len() + 2);
            eprintln!("verify: registry updated -> {}", registry_path.display());
            if report.total < 50 {
                std::process::exit(2);
            }
            Ok(())
        }
        Commands::Registry { action } => {
            match action {
                RegistryCmd::Add { entry, registry: path } => {
                    let path = path.unwrap_or_else(registry::default_registry_path);
                    let mut reg = Registry::load(&path)?;
                    let raw = std::fs::read_to_string(&entry)?;
                    let artifact: certify::RegistryEntry = serde_json::from_str(&raw)?;
                    reg.add(artifact);
                    reg.save(&path)?;
                    eprintln!("registry: added {} -> {}", entry.display(), path.display());
                    Ok(())
                }
                RegistryCmd::List { registry: path } => {
                    let path = path.unwrap_or_else(registry::default_registry_path);
                    let reg = Registry::load(&path)?;
                    if reg.entries.is_empty() {
                        eprintln!("registry: empty ({})", path.display());
                    } else {
                        for e in reg.list() {
                            eprintln!("{}  {:?}  {}", e.host, e.grade, e.total);
                        }
                    }
                    Ok(())
                }
                RegistryCmd::Show { host, registry: path } => {
                    let path = path.unwrap_or_else(registry::default_registry_path);
                    let reg = Registry::load(&path)?;
                    if let Some(entry) = reg.get_by_host(&host) {
                        eprintln!("{}", serde_json::to_string_pretty(entry)?);
                        Ok(())
                    } else {
                        anyhow::bail!("registry: host not found: {host}");
                    }
                }
                RegistryCmd::Verify { pubkey, registry: path } => {
                    let path = path.unwrap_or_else(registry::default_registry_path);
                    let reg = Registry::load(&path)?;
                    let results = reg.verify_all(&pubkey);
                    let mut failed = 0;
                    for (host, res) in results {
                        match res {
                            Ok(()) => eprintln!("OK   {host}"),
                            Err(e) => {
                                failed += 1;
                                eprintln!("FAIL {host} вЂ” {e}");
                            }
                        }
                    }
                    if failed > 0 {
                        std::process::exit(2);
                    }
                    Ok(())
                }
                RegistryCmd::Sync { url, pubkey, registry: path } => {
                    let path = path.unwrap_or_else(registry::default_registry_path);
                    let remote = registry::fetch_remote_registry(&url).await?;
                    let mut failed = 0;
                    for (host, res) in remote.verify_all(&pubkey) {
                        if let Err(e) = res {
                            failed += 1;
                            eprintln!("FAIL {host} вЂ” {e}");
                        }
                    }
                    if failed > 0 {
                        anyhow::bail!("remote registry contains {failed} invalid entries");
                    }
                    let mut local = Registry::load(&path)?;
                    local.merge(remote);
                    local.save(&path)?;
                    eprintln!("registry: synced -> {}", path.display());
                    Ok(())
                }
                RegistryCmd::Export {
                    out,
                    registry: path,
                    signing_key,
                } => {
                    let path = path.unwrap_or_else(registry::default_registry_path);
                    let reg = Registry::load(&path)?;
                    let mut feed = reg.to_feed();
                    if let Some(sk) = signing_key {
                        feed.sign_with_base64_secret(&sk)?;
                    }
                    std::fs::write(&out, serde_json::to_string_pretty(&feed)?)?;
                    eprintln!("registry: exported -> {}", out.display());
                    Ok(())
                }
            }
        }
        Commands::Artifact { action } => match action {
            ArtifactCmd::Verify { path, pubkey } => {
                let verification = artifact::verify_bundle(&path, pubkey.as_deref())?;
                eprintln!("bundle: {}", verification.path);
                eprintln!("files_ok: {}", verification.files_ok);
                eprintln!("checksums_ok: {}", verification.checksums_ok);
                if let Some(sig_ok) = verification.entry_signature_ok {
                    eprintln!("entry_signature_ok: {}", sig_ok);
                }
                eprintln!("summary: {}", verification.summary);
                if !verification.files_ok
                    || !verification.checksums_ok
                    || verification.entry_signature_ok == Some(false)
                {
                    std::process::exit(2);
                }
                Ok(())
            }
        },
        Commands::Session { action } => match action {
            SessionCmd::Init { task, root } => {
                let root = root.unwrap_or_else(session::default_root);
                let state = session::new(&task);
                session::save(&root, &state)?;
                eprintln!("session_id={}", state.session_id);
                eprintln!("path={}", session::session_path(&root, &state.session_id).display());
                Ok(())
            }
            SessionCmd::Show { session_id, root } => {
                let root = root.unwrap_or_else(session::default_root);
                let state = session::load(&root, &session_id)?;
                eprintln!("{}", serde_json::to_string_pretty(&state)?);
                Ok(())
            }
            SessionCmd::Grant { session_id, name, value, root } => {
                let root = root.unwrap_or_else(session::default_root);
                let mut state = session::load(&root, &session_id)?;
                session::set_grant(&mut state, &name, value);
                session::save(&root, &state)?;
                eprintln!("grant {}={} updated for {}", name, value, session_id);
                Ok(())
            }
            SessionCmd::Mode { session_id, mode, root } => {
                let root = root.unwrap_or_else(session::default_root);
                let mut state = session::load(&root, &session_id)?;
                state.enforcement_mode = match mode.to_lowercase().as_str() {
                    "enforce" => session::EnforcementMode::Enforce,
                    "correct" => session::EnforcementMode::Correct,
                    "observe" => session::EnforcementMode::Observe,
                    "off" => session::EnforcementMode::Off,
                    _ => anyhow::bail!("unknown mode: enforce / correct / observe / off"),
                };
                session::save(&root, &state)?;
                eprintln!("session {} mode -> {:?}", session_id, state.enforcement_mode);
                Ok(())
            }
        },
        Commands::Policy { action } => match action {
            PolicyCmd::Evaluate { session_id, action_kind, target, provider_risk, root } => {
                let root = root.unwrap_or_else(session::default_root);
                let state = session::load(&root, &session_id)?;
                let risk = match provider_risk.to_lowercase().as_str() {
                    "low" => ProviderRisk::Low,
                    "high" => ProviderRisk::High,
                    _ => ProviderRisk::Medium,
                };
                let kind = match action_kind.to_lowercase().as_str() {
                    "file-read" => ActionKind::FileRead { path: target.clone() },
                    "file-write" => ActionKind::FileWrite { path: target.clone() },
                    "command" => ActionKind::Command { command: target.clone() },
                    "outbound-send" => ActionKind::OutboundSend { label: target.clone() },
                    _ => anyhow::bail!("unknown action_kind: {action_kind}"),
                };
                let decision = safeproxy::policy::evaluate(&state, &Action { kind, provider_risk: risk });
                eprintln!("decision={:?}", decision);
                Ok(())
            }
        },
        Commands::Enforce { action } => match action {
            EnforceCmd::Evaluate { session_id, action_kind, target, provider_risk, root } => {
                let root = root.unwrap_or_else(session::default_root);
                let mut state = session::load(&root, &session_id)?;
                let risk = match provider_risk.to_lowercase().as_str() {
                    "low" => ProviderRisk::Low,
                    "high" => ProviderRisk::High,
                    _ => ProviderRisk::Medium,
                };
                let kind = match action_kind.to_lowercase().as_str() {
                    "file-read" => ActionKind::FileRead { path: target.clone() },
                    "file-write" => ActionKind::FileWrite { path: target.clone() },
                    "command" => ActionKind::Command { command: target.clone() },
                    "outbound-send" => ActionKind::OutboundSend { label: target.clone() },
                    _ => anyhow::bail!("unknown action_kind: {action_kind}"),
                };
                let judge_cfg = safeproxy::judge::from_env();
                let outcome = safeproxy::enforcement::evaluate_with_judge(
                    &state,
                    &Action { kind, provider_risk: risk },
                    judge_cfg.as_ref(),
                ).await;
                safeproxy::enforcement::record_outcome(&mut state, &outcome);
                session::save(&root, &state)?;
                eprintln!("{}", serde_json::to_string_pretty(&outcome)?);
                Ok(())
            }
        },
        Commands::Audit => {
            let report = audit::run();
            eprintln!("platform: {}", report.platform);
            eprintln!("risk: {} вЂ” {}", report.risk_score, report.verdict);
            if report.findings.is_empty() {
                eprintln!("no indicators matched");
            } else {
                for f in &report.findings {
                    eprintln!("[{}] {} (sev={})", f.category, f.detail, f.severity);
                }
            }
            if report.risk_score >= 60 {
                std::process::exit(2);
            }
            Ok(())
        }
        Commands::Sentinel { interval } => {
            let dur = sentinel::parse_interval(&interval)
                .with_context(|| format!("invalid --interval `{interval}`"))?;
            sentinel::run(safeproxy::sentinel::SentinelConfig {
                interval: dur,
                max_rounds: None,
            })
            .await
        }
        Commands::Monitor {
            upstream,
            key,
            claimed_model,
            use_case,
            interval,
            max_rounds,
            identity_drop_threshold,
            safety_drop_threshold,
            latency_spike_ms,
            webhook_url,
        } => {
            let dur = monitor::parse_interval(&interval)
                .with_context(|| format!("invalid --interval `{interval}`"))?;
            monitor::run(monitor::MonitorConfig {
                upstream,
                key: key.map(Secret::new),
                claimed_model,
                use_case,
                interval: dur,
                max_rounds,
                identity_drop_threshold,
                safety_drop_threshold,
                latency_spike_ms,
                webhook_url,
            })
            .await
        }
        Commands::Feed { url, pubkey, out } => {
            let out = out.to_str().unwrap_or(".").to_string();
            eprintln!("cape feed: fetching {url}");
            let fetched = safeproxy::feed::fetch_remote(&url)
                .await
                .context("fetch remote feed")?;
            eprintln!(
                "feed: v{} generated {}",
                fetched.manifest.version, fetched.manifest.generated_at
            );
            let pk = pubkey.as_ref().context("--pubkey is required; unsigned feed installs are unsafe")?;
            match fetched.manifest.verify_signature_with_pubkey(pk) {
                Ok(()) => eprintln!("feed: signature OK (pubkey {pk})"),
                Err(e) => {
                    eprintln!("feed: signature FAIL вЂ” {e}");
                    anyhow::bail!("feed signature verification failed");
                }
            }
            if fetched.manifest.verify_integrity(&fetched.rules, &fetched.blocklist) {
                eprintln!("feed: integrity OK");
            } else {
                eprintln!("feed: integrity FAIL вЂ” hashes don't match");
                anyhow::bail!("feed integrity check failed");
            }
            std::fs::write(format!("{out}/rules.json"), &fetched.rules)
                .context("write rules.json")?;
            std::fs::write(format!("{out}/blocklist.json"), &fetched.blocklist)
                .context("write blocklist.json")?;
            std::fs::write(
                format!("{out}/manifest.json"),
                serde_json::to_string_pretty(&fetched.manifest)?,
            )
            .context("write manifest.json")?;
            eprintln!("feed: wrote rules.json, blocklist.json, manifest.json to {out}");
            Ok(())
        }
        Commands::Web { listen, site } => {
            let listen = listen
                .parse()
                .with_context(|| format!("invalid --listen `{listen}`"))?;
            web::run(web::WebConfig {
                listen,
                site_dir: site,
            })
            .await
        }
        Commands::Keygen { out } => {
            use base64::Engine as _;
            use ed25519_dalek::{SigningKey, VerifyingKey};

            if !out.exists() {
                std::fs::create_dir_all(&out)?;
            }
            let sk = SigningKey::generate(&mut rand_core::OsRng);
            let secret_b64 = base64::engine::general_purpose::STANDARD.encode(sk.to_bytes());
            let pub_b64 = base64::engine::general_purpose::STANDARD.encode(VerifyingKey::from(&sk).to_bytes());

            let secret_path = out.join("certify-secret.b64");
            let pub_path = out.join("certify-pubkey.b64");
            std::fs::write(&secret_path, &secret_b64)?;
            std::fs::write(&pub_path, &pub_b64)?;

            eprintln!("wrote {}", secret_path.display());
            eprintln!("wrote {}", pub_path.display());
            Ok(())
        }
        Commands::DemoFeed { out } => {
            use base64::Engine as _;
            use ed25519_dalek::{SigningKey, VerifyingKey};

            if !out.exists() {
                std::fs::create_dir_all(&out)?;
            }

            let sk = SigningKey::generate(&mut rand_core::OsRng);
            let secret_b64 = base64::engine::general_purpose::STANDARD.encode(sk.to_bytes());
            let pub_b64 = base64::engine::general_purpose::STANDARD.encode(VerifyingKey::from(&sk).to_bytes());
            std::fs::write(out.join("certify-secret.b64"), &secret_b64)?;
            std::fs::write(out.join("certify-pubkey.b64"), &pub_b64)?;

            let mut reg = Registry::default();
            for entry in demo_entries(&secret_b64) {
                reg.add(entry);
            }
            reg.save(&out.join("registry.json"))?;

            let mut feed = reg.to_feed();
            feed.sign_with_base64_secret(&secret_b64)?;
            std::fs::write(out.join("providers.json"), serde_json::to_string_pretty(&feed)?)?;

eprintln!("demo feed written -> {}", out.display());
            Ok(())
        }
        Commands::Fuzz { format, out, apply, rules } => {
            let loaded_rules = match rules {
                Some(p) => safeproxy::inspect::load_from_files(Some(&p), None)?,
                None => safeproxy::inspect::BUILTIN.clone(),
            };
            let report = safeproxy::fuzz::fuzz_rules(&loaded_rules);
            eprintln!(
                "fuzz: {} rules, {} mutations, {} evasions (coverage {:.1}%)",
                report.total_rules_fuzzed,
                report.total_mutations_generated,
                report.evasions.len(),
                report.coverage_percent
            );
            let rendered = match format.as_str() {
                "json" => serde_json::to_string_pretty(&report)?,
                _ => safeproxy::fuzz::render_markdown(&report),
            };
            if apply {
                let candidate_json = safeproxy::fuzz::render_candidate_rules_json(&report);
                let dest = std::path::Path::new("rules/fuzz-generated.json");
                std::fs::create_dir_all("rules")?;
                std::fs::write(dest, &candidate_json)?;
                eprintln!(
                    "fuzz: wrote {} candidate rules -> {}",
                    report.evasions.len(),
                    dest.display()
                );
            }
            if let Some(path) = out {
                std::fs::write(&path, &rendered)?;
                eprintln!("fuzz: report written -> {}", path.display());
            } else {
                eprintln!("{rendered}");
            }
            Ok(())
        }
        Commands::Canary { action } => {
            use safeproxy::canary::CanaryRegistry;
            let registry = CanaryRegistry::new();
            match action {
                CanaryCmd::Plant { home } => {
                    let home = home.unwrap_or_else(|| {
                        std::env::var_os("HOME")
                            .or_else(|| std::env::var_os("USERPROFILE"))
                            .map(std::path::PathBuf::from)
                            .unwrap_or_else(|| std::path::PathBuf::from("."))
                    });
                    let planted = registry.plant_defaults(&home)
                        .context("plant canaries")?;
                    eprintln!("canary: planted {} decoys under {}", planted.len(), home.display());
                    for c in &planted {
                        eprintln!("  - [{}] {}", c.category, c.path.display());
                    }
                    if planted.is_empty() {
                        eprintln!("canary: no decoys planted (all paths already had real files?)");
                    }
                    Ok(())
                }
                CanaryCmd::List => {
                    let canaries = registry.list();
                    if canaries.is_empty() {
                        eprintln!("canary: no decoys currently registered");
                    } else {
                        eprintln!("canary: {} decoys registered", canaries.len());
                        for c in canaries {
                            eprintln!("  - [{}] {} (planted={})", c.category, c.path.display(), c.planted);
                        }
                    }
                    Ok(())
                }
                CanaryCmd::Unplant => {
                    registry.unplant_all()
                        .context("unplant canaries")?;
                    eprintln!("canary: all decoys un-planted");
                    Ok(())
                }
            }
        }
        Commands::Quarantine { action } => {
            use safeproxy::quarantine::QuarantineStore;
            let store = QuarantineStore::open_default()
                .context("open quarantine store")?;
            match action {
                QuarantineCmd::List => {
                    let entries = store.list();
                    if entries.is_empty() {
                        eprintln!("quarantine: store empty");
                    } else {
                        eprintln!("quarantine: {} entries", entries.len());
                        for e in entries {
                            let status = if e.released { "released" } else { "held" };
                            eprintln!(
                                "  - [{status}] {} (sha256={}, size={}, sniff={}, executable={})",
                                e.original_path,
                                &e.sha256[..16],
                                e.size_bytes,
                                e.sniffed_type.label(),
                                e.is_executable
                            );
                        }
                    }
                    Ok(())
                }
                QuarantineCmd::Release { sha256 } => {
                    store.release(&sha256)
                        .context("release artifact")?;
                    eprintln!("quarantine: released {} -> original path", &sha256[..16]);
                    Ok(())
                }
                QuarantineCmd::Purge { sha256 } => {
                    store.purge(&sha256)
                        .context("purge artifact")?;
                    eprintln!("quarantine: purged {}", &sha256[..16]);
                    Ok(())
                }
                QuarantineCmd::Clear => {
                    let entries = store.list();
                    let mut removed = 0;
                    for e in entries {
                        if !e.released {
                            let _ = store.purge(&e.sha256);
                            removed += 1;
                        }
                    }
                    eprintln!("quarantine: cleared {} held entries", removed);
                    Ok(())
                }
            }
        }
    }
}

fn demo_entries(signing_key: &str) -> Vec<certify::RegistryEntry> {
    use crate::scan::{RiskLevel, ScanReport};

    let samples = vec![
        ("https://api.deepseek.com", "DeepSeek V4 Flash", 0, RiskLevel::Clean, 0),
        ("https://cheap-claude-api.example", "Claude Sonnet 4.5", 72, RiskLevel::High, 3),
    ];

    let mut out = Vec::new();
    for (upstream, _claimed, risk_score, verdict, unsolicited_tool_uses) in samples {
        let scan_report = ScanReport {
            upstream: upstream.to_string(),
            protocol: "openai".to_string(),
            risk_score,
            verdict,
            categories: if risk_score == 0 {
                vec![]
            } else {
                vec!["proto-tooluse-unsolicited".to_string()]
            },
            unsolicited_tool_uses,
            bytes_received: 1200,
            note: "demo feed entry".to_string(),
        };
        let score = score::score_provider(upstream, scan_report);
        let badge = score::render_badge_svg(&score);
        let mut entry = certify::RegistryEntry::from_score(&score, &badge);
        let _ = entry.sign_with_base64_secret(signing_key);
        out.push(entry);
    }
    out
}

fn init_tracing(verbose: u8, quiet: bool) {
    let filter = if quiet {
        EnvFilter::new("error,carapace=warn")
    } else {
        match verbose {
            0 => EnvFilter::new("info,carapace=info"),
            1 => EnvFilter::new("debug,carapace=debug"),
            _ => EnvFilter::new("trace,carapace=trace"),
        }
    };
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .try_init();
}

async fn build_certification_bundle(
    upstream: &str,
    key: Option<Secret>,
    signing_key: Option<String>,
) -> anyhow::Result<(
    score::ProviderScore,
    String,
    String,
    certify::RegistryEntry,
)> {
    let scan_report = scan::run(upstream, key).await?;
    let report = score::score_provider(upstream, scan_report);
    let badge_svg = score::render_badge_svg(&report);
    let report_md = score::render_markdown(&report);
    let mut entry = certify::RegistryEntry::from_score(&report, &badge_svg);
    if let Some(sk) = signing_key {
        entry.sign_with_base64_secret(&sk)?;
    }
    Ok((report, badge_svg, report_md, entry))
}

// keep `Mode` in scope for `Block` default-checking later
const _: fn(Mode) = |_| {};
