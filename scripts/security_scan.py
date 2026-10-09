from __future__ import annotations

import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"

ALLOWED_ENV_FILES = {".env.example", ".env.sample", ".env.template"}
SENSITIVE_NAMES = {
    "id_rsa",
    "id_ed25519",
    "credentials.json",
    ".netrc",
    ".pypirc",
}
SENSITIVE_SUFFIXES = {".pem", ".p12", ".pfx", ".key", ".jks", ".keystore", ".pkcs12"}
TEXT_SUFFIXES = {
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".mjs",
    ".cjs",
    ".json",
    ".yaml",
    ".yml",
    ".toml",
    ".ini",
    ".cfg",
    ".conf",
    ".md",
    ".txt",
    ".sh",
    ".ps1",
    ".html",
    ".css",
    ".xml",
    ".properties",
    ".csv",
    ".env",
}

SECRET_PATTERNS = {
    "GitHub token": re.compile(r"gh[pousr]_[A-Za-z0-9]{30,}"),
    "GitHub fine-grained token": re.compile(r"github_pat_[A-Za-z0-9_]{30,}"),
    "OpenAI-style key": re.compile(r"sk-[A-Za-z0-9_-]{30,}"),
    "AWS access key": re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{16}"),
    "Slack token": re.compile(r"xox[baprs]-[A-Za-z0-9-]{20,}"),
    "Stripe live key": re.compile(r"(?:sk|rk)_live_[A-Za-z0-9]{16,}"),
    "Google API key": re.compile(r"AIza[0-9A-Za-z_-]{30,}"),
    "Hugging Face token": re.compile(r"hf_[A-Za-z0-9]{30,}"),
    "GitLab token": re.compile(r"glpat-[A-Za-z0-9_-]{20,}"),
    "npm token": re.compile(r"npm_[A-Za-z0-9]{30,}"),
    "private key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
}

PINNED_ACTION = re.compile(
    r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*@[0-9a-fA-F]{40}$"
)
PLACEHOLDER_WORDS = (
    "PLACEHOLDER",
    "REDACTED",
    "EXAMPLE",
    "TEST FIXTURE",
    "CHANGEME",
    "REPLACE_ME",
    "REPLACE-WITH",
    "YOUR_",
    "YOUR-",
    "DUMMY",
    "FAKE",
)


def tracked_files() -> list[Path]:
    raw = (
        subprocess.check_output(
            ["git", "-C", str(ROOT), "ls-files", "-z"],
            text=False,
        )
        .decode()
        .split("\0")
    )
    return [ROOT / item for item in raw if item]


def scan_tracked_files() -> list[str]:
    failures: list[str] = []
    for path in tracked_files():
        rel = path.relative_to(ROOT).as_posix()
        name = path.name.lower()

        if name.startswith(".env") and name not in ALLOWED_ENV_FILES:
            failures.append(f"{rel}: tracked environment file")

        if name in SENSITIVE_NAMES or path.suffix.lower() in SENSITIVE_SUFFIXES:
            if ".example." not in name and ".sample." not in name:
                failures.append(f"{rel}: tracked credential/private-key file")

        if name.startswith("service-account") and name.endswith(".json"):
            failures.append(f"{rel}: tracked service-account credential file")

        if not path.is_file() or path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        if path.stat().st_size > 1_000_000:
            continue

        text = path.read_text(encoding="utf-8", errors="ignore")
        for label, pattern in SECRET_PATTERNS.items():
            for match in pattern.finditer(text):
                nearby = text[max(0, match.start() - 100) : match.end() + 100].upper()
                if any(word in nearby for word in PLACEHOLDER_WORDS):
                    continue
                failures.append(f"{rel}: possible {label}")
                break
    return failures


def scan_workflows() -> list[str]:
    failures: list[str] = []
    if not WORKFLOWS.is_dir():
        return failures

    for path in sorted(WORKFLOWS.glob("*.y*ml")):
        rel = path.relative_to(ROOT).as_posix()
        text = path.read_text(encoding="utf-8", errors="replace")
        lines = text.splitlines()

        if re.search(r"(?m)^\s*permissions:\s*write-all\s*$", text):
            failures.append(f"{rel}: write-all workflow permissions are forbidden")
        if re.search(r"(?m)^\s*pull_request_target:\s*$", text):
            failures.append(f"{rel}: pull_request_target is forbidden")
        if re.search(r"(?m)^\s*curl\s+[^\n|]+\|\s*(?:ba)?sh", text, flags=re.IGNORECASE):
            failures.append(f"{rel}: pipe-to-shell install pattern is forbidden")

        for index, line in enumerate(lines):
            match = re.search(r"\buses:\s*([^\s#]+)", line)
            if not match:
                continue
            action = match.group(1)
            if action.startswith("./"):
                continue
            if not PINNED_ACTION.fullmatch(action):
                failures.append(
                    f"{rel}:{index + 1}: action is not pinned to a 40-char commit SHA: {action}"
                )
            if action.lower().startswith("actions/checkout@"):
                block = "\n".join(lines[index : index + 10])
                if not re.search(r"(?m)^\s*persist-credentials:\s*false\s*$", block):
                    failures.append(
                        f"{rel}:{index + 1}: actions/checkout must set persist-credentials: false"
                    )
    return failures


def main() -> int:
    failures = scan_tracked_files() + scan_workflows()
    if failures:
        raise SystemExit("\n".join(sorted(set(failures))))
    print("repository security controls verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
