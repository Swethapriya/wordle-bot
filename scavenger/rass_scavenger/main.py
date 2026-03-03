#!/usr/bin/env python3
"""
main.py — RASS Scavenger entry point.

Orchestrates the scan → fix → PR pipeline:
  1. Scan all Java files for reliability issues (SonarQube-compatible static analysis).
  2. For each file with issues, call Claude to generate surgical fixes.
  3. Open a GitHub PR with the fixed file and a descriptive body.

Environment variables required:
  ANTHROPIC_API_KEY  — Claude API key
  GITHUB_TOKEN       — GitHub token with `contents:write` and `pull-requests:write`
  GITHUB_REPOSITORY  — e.g. "owner/repo"

Optional:
  RASS_MAX_PRS       — max PRs to open per run (default: 5)
  RASS_SCAN_ROOT     — root directory to scan (default: ".")
"""

import os
import sys
from pathlib import Path

from .fixer import build_pr_body, generate_fix
from .github_pr import create_fix_pr
from .scanner import scan_repo

MAX_PRS = int(os.environ.get("RASS_MAX_PRS", "5"))
# Default to the repo root: main.py lives at <repo>/scavenger/rass_scavenger/main.py
# so three .parent calls reach <repo>/
SCAN_ROOT = os.environ.get("RASS_SCAN_ROOT", str(Path(__file__).resolve().parent.parent.parent))


def _check_env() -> bool:
    missing = [v for v in ("ANTHROPIC_API_KEY", "GITHUB_TOKEN", "GITHUB_REPOSITORY") if not os.environ.get(v)]
    if missing:
        print(f"❌ Missing required environment variables: {', '.join(missing)}", file=sys.stderr)
        return False
    return True


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

    pr_count = 0

    for filepath, issues in findings.items():
        if pr_count >= MAX_PRS:
            print(f"\n⏸️  Reached PR limit ({MAX_PRS}). Deferring remaining files to next run.")
            break

        print(f"  📄 {filepath} — {len(issues)} issue(s):")
        for issue in issues:
            emoji = {"high": "🔴", "medium": "🟡", "low": "🟢"}.get(issue.severity, "⚪")
            print(f"     {emoji} Line {issue.line}: [{issue.check_type}] {issue.description[:80]}…")

        # filepath is repo-relative (e.g. src/main/java/Foo.java);
        # resolve it against SCAN_ROOT to get the actual path on disk.
        full_path = Path(SCAN_ROOT) / filepath
        try:
            source = full_path.read_text(encoding="utf-8", errors="ignore")
        except OSError as exc:
            print(f"     ⚠️  Could not read file: {exc}")
            continue

        # Identify the top-priority issue before calling Claude
        from .fixer import _top_priority_issue  # local import to avoid circular at module level
        top = _top_priority_issue(issues)
        print(
            f"     🎯 Highest-priority issue: [{top.severity.upper()}] [{top.sonar_rule}] "
            f"{top.check_type} at line {top.line}"
        )

        print("     🤖 Calling Claude to fix the highest-priority issue…")
        fixed_source, fixed_issue = generate_fix(filepath, source, issues)

        if not fixed_source:
            print("     ⏭️  No fix generated (identical output or API error). Skipping.")
            continue

        pr_body = build_pr_body(filepath, issues, fixed_issue)

        print("     📬 Creating GitHub PR…")
        try:
            pr_url = create_fix_pr(filepath, fixed_source, issues, pr_body)
            remaining = len(issues) - 1
            print(f"     ✅ PR created: {pr_url}  ({remaining} issue(s) deferred to next run)")
            pr_count += 1
        except Exception as exc:  # noqa: BLE001
            print(f"     ❌ Failed to create PR: {exc}")

    print(f"\n🏁 RASS Scavenger finished. {pr_count} PR(s) created.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
