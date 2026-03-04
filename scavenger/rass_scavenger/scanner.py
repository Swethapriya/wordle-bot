"""
scanner.py — SonarQube REST API issue fetcher.

Replaces the previous regex/AST heuristic scanner.  Issues returned are
identical to what SonarQube (or SonarCloud) reports for the project — same
rule IDs, same severities, same messages.

Required environment variables
────────────────────────────────────────────────────────────────────────────
  SONARQUBE_URL          Base URL of the SonarQube/SonarCloud server.
                         Examples:
                           https://sonarcloud.io          (SonarCloud)
                           https://sonar.mycompany.com    (self-hosted)

  SONARQUBE_TOKEN        User token with "Browse" permission on the project.
                         In SonarQube generate via: My Account → Security → Tokens.
                         In SonarCloud generate via: My Account → Security.

  SONARQUBE_PROJECT_KEY  The project key shown on the project dashboard.
                         Example: "myorg_my-java-repo"

Optional environment variables
────────────────────────────────────────────────────────────────────────────
  SONARQUBE_BRANCH       Branch to query.  Defaults to the project's main
                         branch if omitted.

  SONARQUBE_ORGANIZATION SonarCloud organization key.  Required for
                         SonarCloud; ignored for self-hosted SonarQube.

  SONARQUBE_TYPES        Comma-separated issue types to include.
                         Default: BUG,VULNERABILITY,CODE_SMELL
                         Values:  BUG | VULNERABILITY | CODE_SMELL

  SONARQUBE_MIN_SEVERITY Minimum SonarQube severity to include.
                         Default: INFO  (i.e. include everything)
                         Values:  BLOCKER | CRITICAL | MAJOR | MINOR | INFO

Severity mapping (SonarQube → internal)
────────────────────────────────────────────────────────────────────────────
  BLOCKER   → high
  CRITICAL  → high
  MAJOR     → medium
  MINOR     → low
  INFO      → low
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_SEVERITY_MAP: dict[str, str] = {
    "BLOCKER":  "high",
    "CRITICAL": "high",
    "MAJOR":    "medium",
    "MINOR":    "low",
    "INFO":     "low",
}

# Ordered from highest to lowest — used to filter by minimum severity
_SEVERITY_ORDER = ["BLOCKER", "CRITICAL", "MAJOR", "MINOR", "INFO"]

_PAGE_SIZE = 500  # SonarQube API maximum


# ---------------------------------------------------------------------------
# Data model (unchanged interface — other modules depend on this)
# ---------------------------------------------------------------------------

@dataclass
class Issue:
    check_type: str    # SonarQube issue type: "BUG" | "VULNERABILITY" | "CODE_SMELL"
    filepath: str      # Repo-relative path, e.g. "src/main/java/com/example/Foo.java"
    line: int          # 1-based line number (0 if file-level)
    description: str   # Full SonarQube message prefixed with rule ID
    severity: str      # "high" | "medium" | "low"
    snippet: str = ""  # Optional source context (populated lazily)
    sonar_rule: str = ""  # Short rule ID, e.g. "S2095"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_snippet(source_lines: list[str], lineno: int, context: int = 2) -> str:
    """Return a small source excerpt centred on *lineno* (1-based)."""
    start = max(0, lineno - 1 - context)
    end = min(len(source_lines), lineno + context)
    return "\n".join(
        f"  {start + i + 1}: {ln.rstrip()}"
        for i, ln in enumerate(source_lines[start:end])
    )


def _short_rule(rule_key: str) -> str:
    """'java:S2095'  →  'S2095'"""
    return rule_key.split(":")[-1] if ":" in rule_key else rule_key


def _build_session() -> requests.Session:
    """Return a requests.Session with a sensible retry policy."""
    session = requests.Session()
    retry = Retry(
        total=3,
        backoff_factor=1.0,
        status_forcelist=[429, 500, 502, 503, 504],
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


def _above_min_severity(severity: str, min_severity: str) -> bool:
    """Return True if *severity* is at least as severe as *min_severity*."""
    try:
        return _SEVERITY_ORDER.index(severity) <= _SEVERITY_ORDER.index(min_severity)
    except ValueError:
        return True


# ---------------------------------------------------------------------------
# SonarQube API call
# ---------------------------------------------------------------------------

def _fetch_all_issues(
    base_url: str,
    token: str,
    project_key: str,
    branch: Optional[str],
    organization: Optional[str],
    types: str,
    min_severity: str,
) -> list[dict]:
    """
    Paginate through ``GET /api/issues/search`` and return every matching issue.

    Authentication uses HTTP Basic Auth with the user token as the username and
    an empty password, which works for both SonarQube and SonarCloud.
    """
    session = _build_session()
    session.auth = (token, "")

    base_params: dict[str, str] = {
        "projectKeys": project_key,
        "languages":   "java",
        "resolved":    "false",
        "statuses":    "OPEN,CONFIRMED,REOPENED",
        "types":       types,
        "ps":          str(_PAGE_SIZE),
    }
    if branch:
        base_params["branch"] = branch
    if organization:
        base_params["organization"] = organization

    url = f"{base_url.rstrip('/')}/api/issues/search"
    all_issues: list[dict] = []
    page = 1

    while True:
        params = {**base_params, "p": str(page)}
        response = session.get(url, params=params, timeout=30)
        response.raise_for_status()

        data = response.json()
        batch = data.get("issues", [])
        all_issues.extend(batch)

        total = data.get("total", 0)
        fetched_so_far = page * _PAGE_SIZE
        if fetched_so_far >= total or not batch:
            break

        # SonarQube hard-caps at 10 000 results per query
        if fetched_so_far >= 10_000:
            print(
                f"  ⚠️  SonarQube result cap hit (10 000 issues). "
                f"{total - fetched_so_far} issue(s) not retrieved."
            )
            break

        page += 1

    # Client-side severity filter (API doesn't accept a minimum, only exact values)
    if min_severity != "INFO":
        all_issues = [
            i for i in all_issues
            if _above_min_severity(i.get("severity", "INFO"), min_severity)
        ]

    return all_issues


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------

def scan_repo(root: str) -> dict[str, list[Issue]]:
    """
    Fetch open Java issues from SonarQube for the configured project.

    The *root* argument is accepted for API compatibility with ``main.py``
    (which later reads each file from disk to send to Claude).  It is NOT
    used for scanning — SonarQube already knows the project's file tree.

    Returns
    -------
    dict mapping repo-relative filepath  →  list of Issue objects,
    ordered by descending severity then ascending line number.
    """
    base_url     = "https://sonarcloud.io"
    token        = "b27084fcfb507a97e9909e62038afe670d7c24f8"
    project_key  = "Swethapriya_wordle-bot"
    branch       = os.environ.get("SONARQUBE_BRANCH") or None
    organization = "swethapriya"
    types        = os.environ.get("SONARQUBE_TYPES", "BUG,VULNERABILITY,CODE_SMELL")
    min_severity = os.environ.get("SONARQUBE_MIN_SEVERITY", "INFO").upper()

    if not base_url:
        raise EnvironmentError("SONARQUBE_URL is required.")
    if not token:
        raise EnvironmentError("SONARQUBE_TOKEN is required.")
    if not project_key:
        raise EnvironmentError("SONARQUBE_PROJECT_KEY is required.")

    print(f"  🔗 Querying SonarQube: {base_url}  project={project_key}" +
          (f"  branch={branch}" if branch else ""))

    raw_issues = _fetch_all_issues(
        base_url, token, project_key, branch, organization, types, min_severity
    )

    findings: dict[str, list[Issue]] = {}

    # Also read source files to populate snippets where possible
    root_path = Path(root)

    for raw in raw_issues:
        # component = "projectKey:src/main/java/com/example/Foo.java"
        component: str = raw.get("component", "")
        filepath = component.split(":", 1)[1] if ":" in component else component

        if not filepath.endswith(".java"):
            continue

        rule_key    = raw.get("rule", "")
        sonar_rule  = _short_rule(rule_key)
        sonar_sev   = raw.get("severity", "MAJOR").upper()
        severity    = _SEVERITY_MAP.get(sonar_sev, "low")
        issue_type  = raw.get("type", "CODE_SMELL")   # BUG | VULNERABILITY | CODE_SMELL
        message     = raw.get("message", "(no message)")

        # Line number: prefer explicit line, fall back to textRange.startLine
        line: int = (
            raw.get("line")
            or (raw.get("textRange") or {}).get("startLine")
            or 0
        )

        description = f"[{sonar_rule}] {message}"

        issue = Issue(
            check_type=issue_type,
            filepath=filepath,
            line=line,
            description=description,
            severity=severity,
            sonar_rule=sonar_rule,
        )
        findings.setdefault(filepath, []).append(issue)

    # Populate snippets lazily (best-effort — skip if file not on disk)
    for filepath, issues in findings.items():
        full_path = root_path / filepath
        try:
            lines = full_path.read_text(encoding="utf-8", errors="ignore").splitlines()
            for issue in issues:
                if issue.line:
                    issue.snippet = _get_snippet(lines, issue.line)
        except OSError:
            pass  # File not locally available — snippet stays empty

    # Sort each file's issues: severity desc, then line asc
    _sev_rank = {"high": 3, "medium": 2, "low": 1}
    for filepath in findings:
        findings[filepath].sort(
            key=lambda i: (-_sev_rank.get(i.severity, 0), i.line)
        )

    return findings
