# Repo Scam Shield

A tiny **VirusTotal-lite for GitHub repos** starter: score a repository or URL for scamware risk using transparent heuristics.

## Install

```bash
pip install -e .
```

## Use

```bash
repo-scam-shield https://github.com/example/free-premium-unlocker
repo-scam-shield ./some-cloned-repo
```

Outputs JSON with a risk level, score, and matched signals.

## Heuristics

- Piracy/unlocker keywords
- One-line remote installers (`curl | sh`, `irm ... | iex`)
- Obfuscated script hints
- Suspicious binary/archive names
- Brand impersonation terms

This is a starter project, not a malware verdict engine. Treat results as signals for review.
