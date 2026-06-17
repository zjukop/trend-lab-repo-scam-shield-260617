from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from urllib.parse import urlparse

RULES: list[tuple[str, re.Pattern[str], int]] = [
    ("piracy_or_unlocker_keyword", re.compile(r"\b(crack|unlock|bypass|premium|patcher|keygen|activator|frp)\b", re.I), 25),
    ("remote_shell_installer", re.compile(r"(curl|wget|irm|iwr).{0,80}(\||iex|bash|sh|powershell)", re.I), 30),
    ("obfuscation_hint", re.compile(r"(base64\s+-d|frombase64string|eval\(|exec\(|-enc\b)", re.I), 20),
    ("suspicious_binary_archive", re.compile(r"\b(setup|installer|loader|tool)\.(exe|scr|bat|cmd|ps1|zip|rar|7z)\b", re.I), 15),
    ("brand_impersonation", re.compile(r"\b(microsoft|office|spotify|jetbrains|adobe|windows)\b", re.I), 10),
]

TEXT_EXTENSIONS = {".md", ".txt", ".sh", ".ps1", ".bat", ".cmd", ".py", ".js", ".yml", ".yaml", ".toml"}


def read_target(target: str) -> str:
    """Return lightweight text to scan from a URL string or local path."""
    parsed = urlparse(target)
    if parsed.scheme in {"http", "https"}:
        return " ".join(part for part in [parsed.netloc, parsed.path, parsed.query] if part)

    path = Path(target)
    if path.is_file():
        return path.name + "\n" + path.read_text(errors="ignore")[:100_000]
    if path.is_dir():
        chunks: list[str] = [path.name]
        for child in path.rglob("*"):
            if child.is_file():
                chunks.append(str(child.relative_to(path)))
                if child.suffix.lower() in TEXT_EXTENSIONS:
                    chunks.append(child.read_text(errors="ignore")[:20_000])
        return "\n".join(chunks)
    return target


def scan(target: str) -> dict[str, object]:
    text = read_target(target)
    matches = []
    score = 0
    for name, pattern, weight in RULES:
        found = sorted(set(m.group(0)[:120] for m in pattern.finditer(text)))
        if found:
            score += weight
            matches.append({"rule": name, "weight": weight, "examples": found[:5]})

    score = min(score, 100)
    risk = "low" if score < 30 else "medium" if score < 60 else "high"
    return {"target": target, "risk": risk, "score": score, "matches": matches}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Heuristic scamware risk scanner for repos and install snippets.")
    parser.add_argument("target", help="GitHub URL, local repo path, or install command text")
    args = parser.parse_args(argv)
    print(json.dumps(scan(args.target), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
