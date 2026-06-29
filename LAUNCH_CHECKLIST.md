# Launch Checklist

## Before first public post

- [ ] Tag `v0.1.0`
- [ ] Wait for GitHub Actions `release.yml` to finish
- [ ] Download at least one built artifact from the release page and smoke test it
- [ ] Verify `cargo binstall carapace` works against the release
- [ ] Run `scripts/capture-demo.ps1` or `scripts/capture-demo.sh` to generate desktop/mobile screenshots
- [ ] Add a real screenshot / asciinema / GIF to README
- [ ] Add a tiny demo of `cape scan` catching a malicious provider
- [ ] Add one screenshot of `cape audit`
- [ ] Decide whether to keep the placeholder feed public key or remove the mention until real cloud feed exists

## First wave distribution

- [ ] Show HN
- [ ] Reddit: r/LocalLLaMA
- [ ] Reddit: r/cybersecurity
- [ ] Twitter/X thread with one real malicious payload demo
- [ ] Habr article draft
- [ ] VC.ru article draft

## Messaging that must stay consistent

- `carapace` protects users from malicious providers
- it is a wire guard, not a model file scanner
- it reduces active injection risk, not passive prompt theft
- open source local proxy, future paid cloud layers

## Do not say

- "guarantees safety"
- "blocks all attacks"
- "safe to use any grey reseller now"

## After launch

- [ ] Triage first 10 issues quickly
- [ ] Label protocol requests separately (Anthropic/OpenAI/z.ai/DeepSeek)
- [ ] Track installs, stars, scans, issues, false positives
- [ ] Decide whether first paid thing is feeds, audits, or provider scoring
