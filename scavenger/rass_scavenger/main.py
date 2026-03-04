#!/usr/bin/env python3
"""
main.py — RASS Scavenger entry point.

Orchestrates the scan → fix → PR pipeline:
  1. Fetch open Java issues directly from SonarQube (or SonarCloud) via REST API.
  2. Group issues by SonarQube rule; select the single most impactful rule for this run.
  3. For up to MAX_FILES (default: 5) files affected by that rule, call Claude to generate fixes.
  4. Open ONE GitHub PR containing all fixed files, scoped to that single SonarQube rule.

Environment variables required
────────────────────────────────────────────────────────────
  ANTHROPIC_API_KEY      — Claude API key
  GITHUB_TOKEN           — GitHub token (contents:write + pull-requests:write)
  GITHUB_REPOSITORY      — e.g. "owner/repo"

Optional environment variables
────────────────────────────────────────────────────────────
  RASS_MAX_FILES           — Max files to include in the single PR per run (default: 5)
  RASS_SCAN_ROOT           — Local repo root for reading source files (default: ".")
  SONARQUBE_BRANCH         — Branch to query (default: project's main branch)
  SONARQUBE_ORGANIZATION   — SonarCloud organisation key (SonarCloud only)
  SONARQUBE_TYPES          — Issue types: BUG,VULNERABILITY,CODE_SMELL (default: all three)
  SONARQUBE_MIN_SEVERITY   — Minimum severity: BLOCKER|CRITICAL|MAJOR|MINOR|INFO (default: INFO)
"""

import os
import sys
from collections import defaultdict
from pathlib import Path

from .fixer import build_pr_body, generate_fix
from .github_pr import create_fix_pr
from .scanner import Issue, scan_repo

MAX_FILES = int(os.environ.get("RASS_MAX_FILES", "5"))
# Default to the repo root: main.py lives at <repo>/scavenger/rass_scavenger/main.py
# so three .parent calls reach <repo>/
SCAN_ROOT = os.environ.get("RASS_SCAN_ROOT", str(Path(__file__).resolve().parent.parent))

_SEVERITY_RANK = {"high": 3, "medium": 2, "low": 1}


_REQUIRED_ENV_VARS = (
    "ANTHROPIC_API_KEY",
    "GITHUB_TOKEN",
    "GITHUB_REPOSITORY",
)


def _check_env() -> bool:
    missing = [v for v in _REQUIRED_ENV_VARS if not os.environ.get(v)]
    if missing:
        print(f"❌ Missing required environment variables: {', '.join(missing)}", file=sys.stderr)
        return False
    return True


def _select_target_rule(findings: dict[str, list[Issue]]) -> tuple[str, dict[str, Issue]]:
    """
    Group all issues across every file by SonarQube rule, then return the single
    most impactful rule together with a mapping of filepath → best matching Issue.

    Selection criteria (descending priority):
      1. Highest individual issue severity for the rule (high > medium > low)
      2. Number of distinct files affected
    """
    # rule → list of (filepath, Issue)
    rule_map: dict[str, list[tuple[str, Issue]]] = defaultdict(list)

    for filepath, issues in findings.items():
        for issue in issues:
            rule_map[issue.sonar_rule].append((filepath, issue))

    def _rule_score(rule_items: tuple[str, list[tuple[str, Issue]]]) -> tuple[int, int]:
        _, items = rule_items
        best_sev = max(_SEVERITY_RANK.get(iss.severity, 0) for _, iss in items)
        file_count = len({fp for fp, _ in items})
        return (best_sev, file_count)

    best_rule, best_items = max(rule_map.items(), key=_rule_score)

    # Per file keep only the highest-severity issue for the selected rule
    file_to_issue: dict[str, Issue] = {}
    for fp, iss in best_items:
        existing = file_to_issue.get(fp)
        if existing is None or _SEVERITY_RANK.get(iss.severity, 0) > _SEVERITY_RANK.get(existing.severity, 0):
            file_to_issue[fp] = iss

    return best_rule, file_to_issue


def main() -> int:
    print("🔍 RASS Scavenger starting…")

    if not _check_env():
        return 1

    print(f"📁 Scanning Java files under '{SCAN_ROOT}'…")
    findings = scan_repo(SCAN_ROOT)

    if not findings:
        print("✅ No reliability issues found. Nothing to do.")
        return 0

    total_issues = sum(len(v) for v in findings.values())
    print(f"📋 Found {total_issues} issue(s) across {len(findings)} file(s).\n")

    # ── Select the single SonarQube rule to address in this run ──────────────
    target_rule, file_to_issue = _select_target_rule(findings)
    all_affected = sorted(file_to_issue.keys())
    selected_files = all_affected[:MAX_FILES]

    representative = next(iter(file_to_issue.values()))
    print(
        f"🎯 Target rule: [{target_rule}] ({representative.check_type}) — "
        f"{len(all_affected)} file(s) affected, fixing up to {MAX_FILES}."
    )
    print(f"   Files selected for this PR ({len(selected_files)}):")
    for fp in selected_files:
        iss = file_to_issue[fp]
        emoji = {"high": "🔴", "medium": "🟡", "low": "🟢"}.get(iss.severity, "⚪")
        print(f"     {emoji} {fp}  (line {iss.line}, {iss.severity.upper()})")
    print()

    # ── Generate fixes ────────────────────────────────────────────────────────
    file_fixes: list[dict] = []

    for filepath in selected_files:
        issues = findings[filepath]
        full_path = Path(SCAN_ROOT) / filepath

        print(f"  📄 {filepath}")
        try:
            source = full_path.read_text(encoding="utf-8", errors="ignore")
        except OSError as exc:
            print(f"     ⚠️  Could not read file: {exc}")
            continue

        print(f"     🤖 Calling Claude to fix [{target_rule}]…")
        fixed_source, fixed_issue = generate_fix(filepath, source, issues, target_rule=target_rule)

        if not fixed_source:
            print("     ⏭️  No fix generated (identical output or API error). Skipping.")
            continue

        print(f"     ✅ Fix generated (line {fixed_issue.line}).")
        file_fixes.append(
            {
                "filepath": filepath,
                "fixed_source": fixed_source,
                "issues": issues,
                "fixed_issue": fixed_issue,
            }
        )

    if not file_fixes:
        print("\n⏭️  No fixes were generated. Nothing to commit.")
        return 0

    # ── Create single PR ──────────────────────────────────────────────────────
    pr_body = build_pr_body(target_rule, file_fixes)

    print(f"\n📬 Creating GitHub PR for [{target_rule}] across {len(file_fixes)} file(s)…")
    try:
        pr_url = create_fix_pr(file_fixes, target_rule, pr_body)
        deferred = len(all_affected) - len(file_fixes)
        print(f"✅ PR created: {pr_url}")
        if deferred:
            print(f"   ⏸️  {deferred} additional file(s) deferred to next run.")
    except Exception as exc:  # noqa: BLE001
        print(f"❌ Failed to create PR: {exc}")
        return 1

    print(f"\n🏁 RASS Scavenger finished. 1 PR created covering {len(file_fixes)} file(s) for rule [{target_rule}].")
    return 0


if __name__ == "__main__":
    sys.exit(main())
