"""
fixer.py - Uses Claude to generate targeted reliability fixes.

Design goals:
  - Claude receives the FULL file + the SINGLE highest-priority issue.
  - Claude is instructed to fix ONLY that one issue.
  - Returns the fixed source code as a plain string.
  - Falls back gracefully if the fix is identical or Claude errors out.

Priority order (descending):
  1. Severity: high > medium > low
  2. Within the same severity: first occurrence (lowest line number)
"""

import anthropic

from .scanner import Issue

CLAUDE_MODEL = "claude-opus-4-5-20251101"
MAX_TOKENS = 8192

# Severity rank used for priority sorting (higher = more important)
_SEVERITY_RANK = {"high": 3, "medium": 2, "low": 1}

_FIX_PROMPT = """\
You are a Java reliability engineer performing surgical code fixes aligned with SonarQube rules.

## Your task
Fix ONLY the single issue listed below in the provided Java source file.
Do NOT fix anything else, refactor, rename, reformat, or change any other line.

## Issue to fix
{issue_block}

## Fix guidance by rule
- `java_broad_catch` [S1181]            → Replace Exception/Throwable/RuntimeException with the most specific type that fits the context.
- `java_missing_timeout` [S5527]        → Add a RequestConfig with ConnectTimeout and SocketTimeout (default 30 000 ms) to the HttpClient builder.
- `java_unclosed_resource` [S2095]      → Wrap the resource in a try-with-resources statement.
- `java_empty_catch` [S1602]            → Add at minimum a `logger.warn("...", e)` or `logger.error("...", e)` call.
- `java_hardcoded_credentials` [S2115]  → Replace the literal with `System.getenv("<VAR_NAME>")` and add a TODO comment.
- `java_sql_injection` [S2077]          → Replace Statement with PreparedStatement and use `?` placeholders.
- `java_missing_override` [S1206]       → Add `@Override` on the line immediately above the method declaration.
- `java_switch_default` [S1301]         → Add a `default:` case that throws `IllegalArgumentException` or logs a warning.
- `java_system_out` [S106]              → Replace `System.out.println(...)` with `logger.info(...)` (add field if missing).
- `java_thread_run_direct` [S1217]      → Replace `.run()` with `.start()`.
- `java_interrupted_exception` [S2142]  → Add `Thread.currentThread().interrupt();` inside the catch block.
- `java_double_checked_locking` [S2168] → Add `volatile` to the field declaration.
- `java_bigdecimal_double` [S2111]      → Replace `new BigDecimal(double)` with `new BigDecimal("value")` or `BigDecimal.valueOf(double)`.
- `java_array_hashcode_tostring` [S2116]→ Replace `.hashCode()` / `.toString()` with `Arrays.hashCode()` / `Arrays.toString()`.
- `java_division_by_zero` [S3518]       → Add a guard: `if (denominator == 0) throw new ArithmeticException(...)`.
- `java_tostring_returns_null` [S2225]  → Replace `return null` with `return ""` or a meaningful string.
- `java_wait_outside_loop` [S2274]      → Wrap the `.wait()` / `.await()` call in a `while (condition) {{ ... }}` loop.
- `java_identical_expressions` [S1764]  → Correct the expression so that both operands are distinct and meaningful.
- `java_dead_code_after_return` [S1763] → Remove the unreachable statement(s) after return/throw/break/continue.
- `java_duplicate_string_literal` [S1192]→ Extract the repeated literal to a `private static final String CONST = "value";` constant.
- `java_public_static_nonfinal` [S1444] → Add `final` to the field declaration, or reduce visibility.
- `java_replaceall_with_literal` [S5361]→ Replace `.replaceAll("literal", ...)` with `.replace("literal", ...)`.
- `java_instance_writes_static` [S2696] → Add `synchronized` or refactor to avoid mutating a static field from an instance method.
- `java_getclass_type_check` [S5779]    → Replace `.getClass() == Foo.class` with `instanceof Foo`.
- `java_unused_private_field` [S1068]   → Remove the unused private field declaration.
- `java_cognitive_complexity` [S3776]   → Add a `// TODO(rass-scavenger): refactor to reduce complexity` comment; do not restructure.
- `java_equals_without_hashcode` [S1206]→ Add a `hashCode()` override that is consistent with the `equals()` implementation.
- `java_mutable_public_field` [S1104]   → Change the field to `private` and add a getter/setter.
- `java_string_equality` [S4973]        → Replace `==` / `!=` with `.equals()` / `!str.equals()`.
- `java_unused_imports` [S1128]         → Remove the unused import statement.
- `java_todo_fixme` [S1134]             → Leave as-is; add a `// RASS: tracked` suffix comment.
- `java_nested_try_catch` [S1142]       → Add a `// TODO(rass-scavenger): refactor nested try-catch` comment.
- `java_logging_in_loop` [S1448]        → Add a `// TODO(rass-scavenger): move logging outside loop` comment.

If the fix would require a significant restructure, leave the issue unfixed and add:
  // TODO(rass-scavenger): <brief reason>
at the relevant line instead.

## Rules
1. Return ONLY the complete fixed Java source code — no markdown fences, no explanations.
2. Change as few lines as possible — surgical edits only.
3. Preserve all existing comments, Javadoc, and blank lines.

## Source file: {filepath}
```java
{source}
```

Return the complete fixed file now:"""


def _top_priority_issue(issues: list[Issue]) -> Issue:
    """Return the single highest-priority issue (high > medium > low, then earliest line)."""
    return max(
        issues,
        key=lambda i: (_SEVERITY_RANK.get(i.severity, 0), -i.line),
    )


def generate_fix(filepath: str, source: str, issues: list[Issue]) -> tuple[str | None, Issue | None]:
    """
    Call Claude to fix the single highest-priority issue in the file.

    Returns (fixed_source, fixed_issue) or (None, None) if no change was produced.
    """
    if not issues:
        return None, None

    target = _top_priority_issue(issues)

    issue_block = (
        f"- Line {target.line} [{target.severity.upper()}] [{target.sonar_rule}] "
        f"{target.check_type}: {target.description}"
    )

    prompt = _FIX_PROMPT.format(
        issue_block=issue_block,
        filepath=filepath,
        source=source,
    )

    client = anthropic.Anthropic()

    try:
        message = client.messages.create(
            model=CLAUDE_MODEL,
            max_tokens=MAX_TOKENS,
            messages=[{"role": "user", "content": prompt}],
        )
    except anthropic.APIError as exc:
        print(f"  ⚠️  Claude API error for {filepath}: {exc}")
        return None, None

    fixed = message.content[0].text.strip()

    # Strip accidental markdown fences
    if fixed.startswith("```"):
        lines = fixed.splitlines()
        fixed = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])

    if fixed == source.strip():
        return None, None  # No change produced

    return fixed, target


def build_pr_body(filepath: str, all_issues: list[Issue], fixed_issue: Issue | None = None) -> str:
    """Generate a rich PR description.

    Shows ALL detected issues in a full table, and highlights which one was fixed.
    """
    severity_emoji = {"high": "🔴", "medium": "🟡", "low": "🟢"}

    def _sonar_link(rule: str) -> str:
        if not rule:
            return "—"
        rule_num = rule[1:] if rule.startswith("S") else rule
        return f"[{rule}](https://rules.sonarsource.com/java/RSPEC-{rule_num})"

    issue_rows = []
    for i in sorted(all_issues, key=lambda x: (_SEVERITY_RANK.get(x.severity, 0) * -1, x.line)):
        fixed_marker = " ✅ **FIXED**" if (fixed_issue and i is fixed_issue) else ""
        issue_rows.append(
            f"| {severity_emoji.get(i.severity, '⚪')} {i.severity.upper()}{fixed_marker} "
            f"| `{i.check_type}` | {_sonar_link(i.sonar_rule)} "
            f"| Line {i.line} | {i.description} |"
        )

    issue_table = "\n".join(issue_rows)

    fixed_summary = (
        f"**Fixed in this PR:** `{fixed_issue.check_type}` [{fixed_issue.sonar_rule}] "
        f"at line {fixed_issue.line} (severity: {fixed_issue.severity.upper()})"
        if fixed_issue
        else "**No automatic fix was generated.**"
    )

    remaining = len(all_issues) - (1 if fixed_issue else 0)

    return f"""\
## 🤖 RASS Scavenger — Java Reliability Fix

**File:** `{filepath}`
**Total issues detected:** {len(all_issues)} &nbsp;|&nbsp; **Fixed in this PR:** 1 (highest priority) &nbsp;|&nbsp; **Remaining:** {remaining}

{fixed_summary}

### All detected issues
| Severity | Check | SonarQube Rule | Location | Description |
|----------|-------|----------------|----------|-------------|
{issue_table}

---

### Strategy
RASS Scavenger detects all SonarQube-mapped issues but fixes **only the highest-priority bug per PR**
to keep diffs small, focused, and easy to review. Remaining issues will be addressed in follow-up PRs.

### Checklist before merging
- [ ] Review the diff — confirm only the targeted line(s) changed
- [ ] Run existing tests
- [ ] For `java_missing_timeout` fixes: verify ConnectTimeout/SocketTimeout values are appropriate
- [ ] For `java_hardcoded_credentials` fixes: ensure the environment variable is set in CI/CD

---
> **RASS Coverage:** Reliability ✅ &nbsp;|&nbsp; Availability 🔜 &nbsp;|&nbsp; Security ✅ &nbsp;|&nbsp; Scalability 🔜
>
> *This PR was created automatically. Please review before merging.*
"""
