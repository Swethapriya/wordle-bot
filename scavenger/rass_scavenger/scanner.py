"""
scanner.py - SonarQube-compatible static analysis for Java.

Covers all three SonarQube issue categories: Security Vulnerabilities, Bugs, and Code Smells.

  SECURITY VULNERABILITIES
  - OS command injection (Runtime.exec / ProcessBuilder)  [S2076]
  - Path traversal (user-controlled file paths)           [S2083]
  - Weak PRNG (java.util.Random for security)             [S2245]
  - Weak hashing algorithm (MD5/SHA-1 for passwords)      [S4790]
  - Weak SSL/TLS protocol (TLSv1.0/1.1, SSLv3)           [S4423]
  - ECB cipher mode                                       [S4432]
  - Cookie without HttpOnly flag                          [S3330]
  - Cookie without Secure flag                            [S2092]
  - Log injection (user data in log messages)             [S5145]
  - Hard-coded IP address                                 [S5725]
  - Hard-coded credentials                                [S2115]
  - SQL injection via string concatenation                [S2077]

  BUGS
  - Thread.run() called directly instead of start()       [S1217]
  - InterruptedException ignored                          [S2142]
  - Double-checked locking without volatile               [S2168]
  - BigDecimal(double) constructor loses precision        [S2111]
  - hashCode/toString called on array instance            [S2116]
  - Division by literal zero                              [S3518]
  - toString() returns null                               [S2225]
  - Object.wait() called outside while loop               [S2274]
  - Identical expressions on both sides of operator       [S1764]
  - Dead / unreachable code after return/throw/break      [S1763]
  - Infinite loop without exit path                       [S2189]
  - Boolean method returns null                           [S2447]
  - Float/double used as loop counter                     [S1244]
  - Collection.size()==0 instead of isEmpty()             [S1155]

  CODE SMELLS
  - Missing HTTP timeouts                                 [S5527]
  - Broad catch clauses (Exception/Throwable)             [S1181]
  - Empty catch blocks                                    [S1602]
  - Nested try-catch blocks                               [S1142]
  - Unclosed resources (not in try-with-resources)        [S2095]
  - System.out/err used instead of logger                 [S106]
  - Missing @Override annotation                          [S1206]
  - equals() without hashCode()                           [S1206]
  - Public mutable fields                                 [S1104]
  - Public static non-final fields                        [S1444]
  - Switch without default case                           [S1301]
  - Unused imports                                        [S1128]
  - Unused private fields                                 [S1068]
  - String comparison with == instead of equals()         [S4973]
  - Logging calls inside loops                            [S1448]
  - Duplicate string literals (extract to constant)       [S1192]
  - replaceAll() used with plain literal (use replace())  [S5361]
  - Instance method writes to static field                [S2696]
  - getClass() used for type comparison (use instanceof)  [S5779]
  - Cognitive complexity exceeds threshold                [S3776]
  - Method returns null instead of empty collection       [S1168]
  - Empty non-abstract method body                        [S1186]
  - variable.equals("literal") — literal should be left   [S1132]
  - Legacy synchronized collections (Vector, Hashtable…)  [S1149]
  - Return value of non-mutating method ignored           [S2201]
  - Utility class has public constructor                  [S1118]
  - Explicit type argument instead of diamond operator    [S2293]
  - Redundant cast to same type                           [S1905]
  - TODO/FIXME comments                                   [S1134]

  UNUSED / DEAD CODE  (SonarLint commonly flags these)
  - Unused private methods and constructors               [S1144]
  - Unused local variables                                [S1481]
  - Unused method parameters                              [S1172]
  - Generic exception thrown (Exception/RuntimeException) [S112]
  - Logging argument requires string concatenation        [S2629]
  - toLowerCase/toUpperCase without Locale argument       [S4034]
"""

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Issue:
    check_type: str
    filepath: str
    line: int
    description: str
    severity: str  # "low" | "medium" | "high"
    snippet: str = ""
    sonar_rule: str = ""  # SonarQube rule ID, e.g. "S1181"


def _get_snippet(source_lines: list[str], lineno: int, context: int = 2) -> str:
    start = max(0, lineno - 1 - context)
    end = min(len(source_lines), lineno + context)
    lines = source_lines[start:end]
    return "\n".join(f"  {start + i + 1}: {l.rstrip()}" for i, l in enumerate(lines))


# ---------------------------------------------------------------------------
# Individual checkers
# ---------------------------------------------------------------------------

def check_bare_except(source: str, filepath: str) -> list[Issue]:
    """Bare `except:` catches *everything* including KeyboardInterrupt, SystemExit."""
    issues = []
    lines = source.splitlines()
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return issues

    for node in ast.walk(tree):
        if isinstance(node, ast.ExceptHandler) and node.type is None:
            issues.append(Issue(
                check_type="bare_except",
                filepath=filepath,
                line=node.lineno,
                description=(
                    f"Bare `except:` at line {node.lineno} silently catches ALL exceptions "
                    "(including KeyboardInterrupt/SystemExit). Use `except Exception:` at minimum."
                ),
                severity="medium",
                snippet=_get_snippet(lines, node.lineno),
            ))
    return issues


def check_missing_timeout(source: str, filepath: str) -> list[Issue]:
    """HTTP requests (requests lib) without a timeout can hang indefinitely."""
    issues = []
    lines = source.splitlines()
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return issues

    http_methods = {"get", "post", "put", "delete", "patch", "head", "options", "request"}

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        # requests.get(...), requests.post(...), etc.
        if (
            isinstance(func, ast.Attribute)
            and func.attr in http_methods
            and isinstance(func.value, ast.Name)
            and func.value.id == "requests"
        ):
            has_timeout = any(kw.arg == "timeout" for kw in node.keywords)
            if not has_timeout:
                issues.append(Issue(
                    check_type="missing_timeout",
                    filepath=filepath,
                    line=node.lineno,
                    description=(
                        f"`requests.{func.attr}(...)` at line {node.lineno} has no `timeout=` "
                        "parameter — the call can hang indefinitely if the server is slow."
                    ),
                    severity="high",
                    snippet=_get_snippet(lines, node.lineno),
                ))
    return issues


def check_no_context_manager(source: str, filepath: str) -> list[Issue]:
    """open() assigned directly instead of used in a `with` block risks resource leaks."""
    issues = []
    lines = source.splitlines()
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return issues

    # Collect all `with open(...)` nodes so we can exclude them
    with_opens: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.With):
            for item in node.items:
                ctx = item.context_expr
                if isinstance(ctx, ast.Call):
                    func = ctx.func
                    if isinstance(func, ast.Name) and func.id == "open":
                        with_opens.add(ctx.lineno)

    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AugAssign, ast.AnnAssign)):
            value = getattr(node, "value", None)
            if value is None:
                continue
            if isinstance(value, ast.Call):
                func = value.func
                if (
                    isinstance(func, ast.Name)
                    and func.id == "open"
                    and value.lineno not in with_opens
                ):
                    issues.append(Issue(
                        check_type="no_context_manager",
                        filepath=filepath,
                        line=node.lineno,
                        description=(
                            f"`open()` at line {node.lineno} is not used as a context manager. "
                            "Use `with open(...) as f:` to ensure the file is always closed."
                        ),
                        severity="medium",
                        snippet=_get_snippet(lines, node.lineno),
                    ))
    return issues


def check_broad_exception_raise(source: str, filepath: str) -> list[Issue]:
    """Raising a bare `Exception(...)` instead of a specific type loses context."""
    issues = []
    lines = source.splitlines()
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return issues

    for node in ast.walk(tree):
        if isinstance(node, ast.Raise) and node.exc is not None:
            exc = node.exc
            if isinstance(exc, ast.Call):
                func = exc.func
                if isinstance(func, ast.Name) and func.id == "Exception":
                    issues.append(Issue(
                        check_type="broad_exception_raise",
                        filepath=filepath,
                        line=node.lineno,
                        description=(
                            f"`raise Exception(...)` at line {node.lineno} is too broad. "
                            "Define a specific exception class for clearer error handling."
                        ),
                        severity="low",
                        snippet=_get_snippet(lines, node.lineno),
                    ))
    return issues


def check_missing_docstring(source: str, filepath: str) -> list[Issue]:
    """Functions and classes should have docstrings (S1234)."""
    issues = []
    lines = source.splitlines()
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return issues

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
            docstring = ast.get_docstring(node)
            if docstring is None and not node.name.startswith("_"):
                issues.append(Issue(
                    check_type="missing_docstring",
                    filepath=filepath,
                    line=node.lineno,
                    description=(
                        f"{node.__class__.__name__} '{node.name}' at line {node.lineno} "
                        "is missing a docstring. Add a docstring to document its purpose."
                    ),
                    severity="low",
                    snippet=_get_snippet(lines, node.lineno),
                ))
    return issues


def check_unused_variables(source: str, filepath: str) -> list[Issue]:
    """Detect unused local variables (S1481)."""
    issues = []
    lines = source.splitlines()
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return issues

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            # Get all variable assignments in the function
            assigned = set()
            used = set()

            for child in ast.walk(node):
                if isinstance(child, ast.Name):
                    if isinstance(child.ctx, ast.Store):
                        assigned.add(child.id)
                    elif isinstance(child.ctx, ast.Load):
                        used.add(child.id)

            for unused_var in assigned - used:
                # Skip private/magic variables
                if not unused_var.startswith("_"):
                    for child in ast.walk(node):
                        if isinstance(child, ast.Name) and child.id == unused_var and isinstance(child.ctx, ast.Store):
                            issues.append(Issue(
                                check_type="unused_variable",
                                filepath=filepath,
                                line=child.lineno,
                                description=(
                                    f"Variable '{unused_var}' at line {child.lineno} is assigned "
                                    "but never used. Remove it or use its value."
                                ),
                                severity="low",
                                snippet=_get_snippet(lines, child.lineno),
                            ))
                            break
    return issues


def check_empty_except_block(source: str, filepath: str) -> list[Issue]:
    """Empty except blocks that do nothing (S1602)."""
    issues = []
    lines = source.splitlines()
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return issues

    for node in ast.walk(tree):
        if isinstance(node, ast.ExceptHandler):
            # Check if the body only contains Pass or is empty
            if len(node.body) == 1 and isinstance(node.body[0], ast.Pass):
                issues.append(Issue(
                    check_type="empty_except_block",
                    filepath=filepath,
                    line=node.lineno,
                    description=(
                        f"Empty except block at line {node.lineno} silently ignores exceptions. "
                        "Add exception handling logic or re-raise the exception."
                    ),
                    severity="medium",
                    snippet=_get_snippet(lines, node.lineno),
                ))
    return issues


def check_hardcoded_credentials(source: str, filepath: str) -> list[Issue]:
    """Detect hardcoded passwords and API keys (S2115)."""
    issues = []
    lines = source.splitlines()

    # Patterns for common credential names
    credential_patterns = [
        r'(password|passwd|pwd|secret|api_key|apikey|token|api_token|auth)\s*[=:]\s*["\'][\w\-\.\@]+["\']',
    ]

    for i, line in enumerate(lines, 1):
        # Skip comments
        if line.strip().startswith("#"):
            continue

        for pattern in credential_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                issues.append(Issue(
                    check_type="hardcoded_credentials",
                    filepath=filepath,
                    line=i,
                    description=(
                        f"Hardcoded credentials at line {i}. "
                        "Use environment variables or secure credential storage instead."
                    ),
                    severity="high",
                    snippet=_get_snippet(lines, i),
                ))
                break
    return issues


def check_sql_injection_python(source: str, filepath: str) -> list[Issue]:
    """Python SQL injection via string concatenation (S2077)."""
    issues = []
    lines = source.splitlines()

    # Pattern: SQL query with string concatenation
    sql_patterns = [
        r'(execute|executemany|query)\s*\(["\'].*\+',
    ]

    for i, line in enumerate(lines, 1):
        for pattern in sql_patterns:
            if re.search(pattern, line):
                issues.append(Issue(
                    check_type="sql_injection",
                    filepath=filepath,
                    line=i,
                    description=(
                        f"Potential SQL injection at line {i}. "
                        "Use parameterized queries with placeholders (?) instead of string concatenation."
                    ),
                    severity="high",
                    snippet=_get_snippet(lines, i),
                ))
                break
    return issues


def check_weak_cryptography(source: str, filepath: str) -> list[Issue]:
    """Detect weak cryptography usage (S2104)."""
    issues = []
    lines = source.splitlines()

    # Weak algorithms
    weak_patterns = [
        r'(md5|sha1|des|rc4|md4)',
    ]

    for i, line in enumerate(lines, 1):
        # Skip comments
        if line.strip().startswith("#"):
            continue

        for pattern in weak_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                issues.append(Issue(
                    check_type="weak_cryptography",
                    filepath=filepath,
                    line=i,
                    description=(
                        f"Weak cryptographic algorithm at line {i}. "
                        "Use SHA-256 or stronger algorithms instead."
                    ),
                    severity="high",
                    snippet=_get_snippet(lines, i),
                ))
                break
    return issues


def check_eval_usage(source: str, filepath: str) -> list[Issue]:
    """Detect dangerous eval() usage (S5632)."""
    issues = []
    lines = source.splitlines()

    for i, line in enumerate(lines, 1):
        match = re.search(r'\b(eval|exec|compile|__import__)\s*\(', line)
        if match:
            func_name = match.group(1)
            issues.append(Issue(
                check_type="eval_usage",
                filepath=filepath,
                line=i,
                description=(
                    f"Dangerous {func_name}() at line {i}. "
                    "This can execute arbitrary code. Use safer alternatives."
                ),
                severity="high",
                snippet=_get_snippet(lines, i),
            ))
    return issues


def check_assert_usage(source: str, filepath: str) -> list[Issue]:
    """Detect assert statements used in production (S5045)."""
    issues = []
    lines = source.splitlines()
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return issues

    for node in ast.walk(tree):
        if isinstance(node, ast.Assert):
            issues.append(Issue(
                check_type="assert_usage",
                filepath=filepath,
                line=node.lineno,
                description=(
                    f"Assert statement at line {node.lineno} should not be used for validation. "
                    "Assertions can be disabled at runtime with -O flag. Use proper exceptions instead."
                ),
                severity="medium",
                snippet=_get_snippet(lines, node.lineno),
            ))
    return issues


def check_input_without_sanitization(source: str, filepath: str) -> list[Issue]:
    """Detect input() calls that might need sanitization (S5632)."""
    issues = []
    lines = source.splitlines()

    for i, line in enumerate(lines, 1):
        if re.search(r'\binput\s*\(', line):
            # Check if the input is directly used in eval, exec, or similar
            issues.append(Issue(
                check_type="input_sanitization",
                filepath=filepath,
                line=i,
                description=(
                    f"User input at line {i} should be sanitized before use. "
                    "Validate and sanitize all user inputs to prevent injection attacks."
                ),
                severity="medium",
                snippet=_get_snippet(lines, i),
            ))
    return issues


def check_hardcoded_paths(source: str, filepath: str) -> list[Issue]:
    """Detect hardcoded file paths (S1075)."""
    issues = []
    lines = source.splitlines()

    # Common hardcoded path patterns
    path_patterns = [
        r'["\']/(home|var|opt|srv|usr|etc)/',
        r'["\']C:\\',
        r'["\']\\\\(server|machine)',
    ]

    for i, line in enumerate(lines, 1):
        if line.strip().startswith("#"):
            continue

        for pattern in path_patterns:
            if re.search(pattern, line):
                issues.append(Issue(
                    check_type="hardcoded_paths",
                    filepath=filepath,
                    line=i,
                    description=(
                        f"Hardcoded file path at line {i}. "
                        "Use configuration files or environment variables for paths."
                    ),
                    severity="medium",
                    snippet=_get_snippet(lines, i),
                ))
                break
    return issues


def check_multiple_returns(source: str, filepath: str) -> list[Issue]:
    """Detect functions with too many return statements (S1141)."""
    issues = []
    lines = source.splitlines()
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return issues

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return_count = 0
            for child in ast.walk(node):
                if isinstance(child, ast.Return):
                    return_count += 1

            # Flag functions with more than 4 return statements
            if return_count > 4:
                issues.append(Issue(
                    check_type="multiple_returns",
                    filepath=filepath,
                    line=node.lineno,
                    description=(
                        f"Function '{node.name}' at line {node.lineno} has {return_count} return statements. "
                        "Refactor to reduce control flow complexity."
                    ),
                    severity="low",
                    snippet=_get_snippet(lines, node.lineno),
                ))
    return issues


def check_function_too_long(source: str, filepath: str) -> list[Issue]:
    """Detect overly long functions (S138)."""
    issues = []
    lines = source.splitlines()
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return issues

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            # Calculate function length
            if hasattr(node, 'end_lineno') and node.end_lineno:
                func_length = node.end_lineno - node.lineno
                # Flag functions longer than 50 lines
                if func_length > 50:
                    issues.append(Issue(
                        check_type="function_too_long",
                        filepath=filepath,
                        line=node.lineno,
                        description=(
                            f"Function '{node.name}' at line {node.lineno} is {func_length} lines long. "
                            "Functions should be shorter and more focused. Refactor into smaller functions."
                        ),
                        severity="low",
                        snippet=_get_snippet(lines, node.lineno),
                    ))
    return issues


# ...existing code...


# ---------------------------------------------------------------------------
# Java-specific checkers
# ---------------------------------------------------------------------------

def check_java_broad_catch(source: str, filepath: str) -> list[Issue]:
    """Java catch clauses catching Exception or Throwable are too broad (S1181)."""
    issues = []
    lines = source.splitlines()

    # Pattern: catch (Exception | Throwable | RuntimeException e)
    pattern = r"catch\s*\(\s*(Exception|Throwable|RuntimeException)\s+\w+\s*\)"

    for i, line in enumerate(lines, 1):
        matches = re.finditer(pattern, line)
        for match in matches:
            exception_type = match.group(1)
            issues.append(Issue(
                check_type="java_broad_catch",
                filepath=filepath,
                line=i,
                description=(
                    f"[S1181] Catching `{exception_type}` at line {i} is too broad. "
                    "Catch specific exception types instead."
                ),
                severity="medium",
                snippet=_get_snippet(lines, i),
                sonar_rule="S1181",
            ))
    return issues


def check_java_missing_timeout(source: str, filepath: str) -> list[Issue]:
    """Java HTTP calls without timeout configuration (S5527)."""
    issues = []
    lines = source.splitlines()

    # Pattern: .get() or .post() or .execute() on HttpClient or CloseableHttpClient without timeout
    # Look for HttpClient calls that might be missing timeout
    http_patterns = [
        r"\.get\(\s*\)",
        r"\.post\(\s*\)",
        r"\.put\(\s*\)",
        r"\.delete\(\s*\)",
        r"\.execute\(\s*\w+\s*\)",
    ]

    for i, line in enumerate(lines, 1):
        # Skip lines that have timeout configuration
        if "timeout" in line.lower() or "connecttimeout" in line.lower():
            continue

        for pattern in http_patterns:
            if re.search(pattern, line):
                issues.append(Issue(
                    check_type="java_missing_timeout",
                    filepath=filepath,
                    line=i,
                    description=(
                        f"[S5527] HTTP call at line {i} may be missing timeout configuration. "
                        "Use ConnectTimeout and SocketTimeout to prevent hanging connections."
                    ),
                    severity="high",
                    snippet=_get_snippet(lines, i),
                    sonar_rule="S5527",
                ))
                break  # Only report once per line
    return issues


def check_java_unclosed_resource(source: str, filepath: str) -> list[Issue]:
    """Java resources (Stream, Reader, Connection) not closed in try-with-resources (S2095)."""
    issues = []
    lines = source.splitlines()

    # Pattern: new FileInputStream, new FileReader, new FileWriter, new FileOutputStream
    # or new Connection, new Statement without try-with-resources
    resource_patterns = [
        r"=\s*new\s+(FileInputStream|FileOutputStream|FileReader|FileWriter|Socket)",
    ]

    # Track try-with-resources blocks
    in_try_with_resources = set()
    for i, line in enumerate(lines, 1):
        if re.search(r"try\s*\(\s*\w+.*=", line):
            in_try_with_resources.add(i)

    for i, line in enumerate(lines, 1):
        # Skip if in try-with-resources
        if i in in_try_with_resources:
            continue

        for pattern in resource_patterns:
            if re.search(pattern, line):
                issues.append(Issue(
                    check_type="java_unclosed_resource",
                    filepath=filepath,
                    line=i,
                    description=(
                        f"[S2095] Resource at line {i} should be used in try-with-resources block. "
                        "Use `try (ResourceType var = new ResourceType(...))` to ensure closure."
                    ),
                    severity="medium",
                    snippet=_get_snippet(lines, i),
                    sonar_rule="S2095",
                ))
    return issues


def check_java_empty_catch(source: str, filepath: str) -> list[Issue]:
    """Java empty catch blocks (S1602)."""
    issues = []
    lines = source.splitlines()

    pattern = r"catch\s*\([^)]+\)\s*\{\s*\}"

    for i, line in enumerate(lines, 1):
        if re.search(pattern, line):
            issues.append(Issue(
                check_type="java_empty_catch",
                filepath=filepath,
                line=i,
                description=(
                    f"[S1602] Empty catch block at line {i} silently ignores exceptions. "
                    "Add logging or rethrow the exception."
                ),
                severity="medium",
                snippet=_get_snippet(lines, i),
                sonar_rule="S1602",
            ))
    return issues


def check_java_todo_fixme(source: str, filepath: str) -> list[Issue]:
    """Java TODO and FIXME comments (S1134)."""
    issues = []
    lines = source.splitlines()

    for i, line in enumerate(lines, 1):
        if re.search(r"//\s*(TODO|FIXME)", line, re.IGNORECASE):
            issues.append(Issue(
                check_type="java_todo_fixme",
                filepath=filepath,
                line=i,
                description=(
                    f"[S1134] TODO/FIXME comment at line {i} should be addressed or removed. "
                    "Open an issue to track the work."
                ),
                severity="low",
                snippet=_get_snippet(lines, i),
                sonar_rule="S1134",
            ))
    return issues


def check_java_nested_try_catch(source: str, filepath: str) -> list[Issue]:
    """Java nested try-catch blocks (S1142)."""
    issues = []
    lines = source.splitlines()

    # Simple heuristic: count try/catch depth on each line
    in_try_count = 0
    for i, line in enumerate(lines, 1):
        try_count = line.count("try")
        catch_count = line.count("catch")
        in_try_count += try_count - catch_count

        if in_try_count > 1 and catch_count > 0:
            issues.append(Issue(
                check_type="java_nested_try_catch",
                filepath=filepath,
                line=i,
                description=(
                    f"[S1142] Nested try-catch block at line {i}. "
                    "Refactor to reduce nesting and improve readability."
                ),
                severity="low",
                snippet=_get_snippet(lines, i),
                sonar_rule="S1142",
            ))
    return issues


def check_java_hardcoded_credentials(source: str, filepath: str) -> list[Issue]:
    """Java hardcoded credentials (S2115)."""
    issues = []
    lines = source.splitlines()

    credential_patterns = [
        r'(password|passwd|pwd|secret|api_key|apikey|token|api_token|auth)\s*[=:]\s*["\'][\w\-\.\@]+["\']',
    ]

    for i, line in enumerate(lines, 1):
        # Skip comments
        if line.strip().startswith("//"):
            continue

        for pattern in credential_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                issues.append(Issue(
                    check_type="java_hardcoded_credentials",
                    filepath=filepath,
                    line=i,
                    description=(
                        f"[S2115] Hardcoded credentials at line {i}. "
                        "Use environment variables or configuration files instead."
                    ),
                    severity="high",
                    snippet=_get_snippet(lines, i),
                    sonar_rule="S2115",
                ))
                break
    return issues


def check_java_sql_injection(source: str, filepath: str) -> list[Issue]:
    """Java SQL Injection vulnerabilities (S2077)."""
    issues = []
    lines = source.splitlines()

    # Pattern: String concatenation in SQL queries
    sql_patterns = [
        r'(executeQuery|executeUpdate|execute|executeStatement)\s*\(\s*["\'].*\+',
        r'Statement\s*=\s*connection\.(createStatement|prepareStatement)\s*\(["\'].*\+',
    ]

    for i, line in enumerate(lines, 1):
        for pattern in sql_patterns:
            if re.search(pattern, line):
                issues.append(Issue(
                    check_type="java_sql_injection",
                    filepath=filepath,
                    line=i,
                    description=(
                        f"[S2077] Potential SQL injection at line {i}. "
                        "Use parameterized queries with PreparedStatement instead."
                    ),
                    severity="high",
                    snippet=_get_snippet(lines, i),
                    sonar_rule="S2077",
                ))
                break
    return issues


def check_java_missing_override(source: str, filepath: str) -> list[Issue]:
    """Java missing @Override annotation (S1206)."""
    issues = []
    lines = source.splitlines()

    for i, line in enumerate(lines, 1):
        # Look for method definitions that might be overriding
        if re.search(r'(public|protected)\s+(static\s+)?(void|String|int|boolean|Object|List|Map)\s+\w+\s*\(', line):
            # Check if line above has @Override
            if i > 1 and "@Override" not in lines[i-2]:
                # Simple heuristic: methods with common override names
                if re.search(r'\b(equals|hashCode|toString|compareTo|run|call)\s*\(', line):
                    issues.append(Issue(
                        check_type="java_missing_override",
                        filepath=filepath,
                        line=i,
                        description=(
                            f"[S1206] Method at line {i} may be overriding a superclass method. "
                            "Add @Override annotation for clarity."
                        ),
                        severity="low",
                        snippet=_get_snippet(lines, i),
                        sonar_rule="S1206",
                    ))
    return issues


def check_java_equals_without_hashcode(source: str, filepath: str) -> list[Issue]:
    """Java class with equals() but no hashCode() (S1206)."""
    issues = []
    lines = source.splitlines()

    has_equals = False
    has_hashcode = False
    class_line = 0

    for i, line in enumerate(lines, 1):
        if re.search(r'class\s+\w+', line):
            class_line = i
            has_equals = False
            has_hashcode = False

        if re.search(r'\bequals\s*\(', line):
            has_equals = True

        if re.search(r'\bhashCode\s*\(\s*\)', line):
            has_hashcode = True

        # At end of class or new class declaration
        if class_line > 0 and has_equals and not has_hashcode and i > class_line + 1:
            issues.append(Issue(
                check_type="java_equals_without_hashcode",
                filepath=filepath,
                line=class_line,
                description=(
                    f"[S1206] Class at line {class_line} overrides equals() but not hashCode(). "
                    "Both must be overridden together."
                ),
                severity="medium",
                snippet=_get_snippet(lines, class_line),
                sonar_rule="S1206",
            ))
            class_line = 0

    return issues


def check_java_mutable_public_field(source: str, filepath: str) -> list[Issue]:
    """Java public mutable fields (S1104)."""
    issues = []
    lines = source.splitlines()

    # Pattern: public non-final fields
    pattern = r'public\s+(?!final|static\s+final)[\w<>\[\]]+\s+\w+\s*[=;]'

    for i, line in enumerate(lines, 1):
        if re.search(pattern, line):
            issues.append(Issue(
                check_type="java_mutable_public_field",
                filepath=filepath,
                line=i,
                description=(
                    f"[S1104] Public mutable field at line {i}. "
                    "Use private fields with getters/setters for better encapsulation."
                ),
                severity="medium",
                snippet=_get_snippet(lines, i),
                sonar_rule="S1104",
            ))
    return issues


def check_java_switch_default(source: str, filepath: str) -> list[Issue]:
    """Java switch statements without default case (S1301)."""
    issues = []
    lines = source.splitlines()

    in_switch = 0
    has_default = False
    switch_line = 0

    for i, line in enumerate(lines, 1):
        if "switch" in line:
            in_switch += 1
            switch_line = i
            has_default = False

        if "default:" in line:
            has_default = True

        if "}" in line and in_switch > 0:
            in_switch -= 1
            if not has_default and switch_line > 0:
                issues.append(Issue(
                    check_type="java_switch_default",
                    filepath=filepath,
                    line=switch_line,
                    description=(
                        f"[S1301] Switch statement at line {switch_line} is missing a default case. "
                        "Add a default case to handle unexpected values."
                    ),
                    severity="medium",
                    snippet=_get_snippet(lines, switch_line),
                    sonar_rule="S1301",
                ))
            switch_line = 0

    return issues


def check_java_unused_imports(source: str, filepath: str) -> list[Issue]:
    """Java unused import statements (S1128)."""
    issues = []
    lines = source.splitlines()

    # Extract all imports
    imports = {}
    for i, line in enumerate(lines, 1):
        match = re.search(r'import\s+([\w\.]+)', line)
        if match:
            class_name = match.group(1).split('.')[-1]
            imports[class_name] = i

    # Check which imports are used
    source_text = "\n".join(lines)
    for class_name, import_line in imports.items():
        # Simple heuristic: search for class usage (not perfect but useful)
        if re.search(r'\b' + class_name + r'\s*[(<\[]', source_text) is None:
            issues.append(Issue(
                check_type="java_unused_imports",
                filepath=filepath,
                line=import_line,
                description=(
                    f"[S1128] Unused import for '{class_name}' at line {import_line}. "
                    "Remove unused imports to keep code clean."
                ),
                severity="low",
                snippet=_get_snippet(lines, import_line),
                sonar_rule="S1128",
            ))

    return issues


def check_java_string_literal_equality(source: str, filepath: str) -> list[Issue]:
    """Java using == for string comparison instead of .equals() (S4973)."""
    issues = []
    lines = source.splitlines()

    # Pattern: == or != with string literals
    pattern = r'(==|!=)\s*["\']'

    for i, line in enumerate(lines, 1):
        if re.search(pattern, line) and "//" not in line[:line.find(pattern) if pattern in line else len(line)]:
            issues.append(Issue(
                check_type="java_string_equality",
                filepath=filepath,
                line=i,
                description=(
                    f"[S4973] String comparison using == at line {i}. "
                    "Use .equals() or .equalsIgnoreCase() for string comparison."
                ),
                severity="medium",
                snippet=_get_snippet(lines, i),
                sonar_rule="S4973",
            ))

    return issues


def check_java_logging_in_loop(source: str, filepath: str) -> list[Issue]:
    """Java logging calls inside loops (S1448)."""
    issues = []
    lines = source.splitlines()

    in_loop = 0
    for i, line in enumerate(lines, 1):
        if re.search(r'\b(for|while)\s*[\(\[]', line):
            in_loop += 1

        if re.search(r'\blog\.|logger\.|System\.out', line) and in_loop > 0:
            issues.append(Issue(
                check_type="java_logging_in_loop",
                filepath=filepath,
                line=i,
                description=(
                    f"[S1448] Logging at line {i} inside a loop. "
                    "This can cause performance issues. Consider logging outside the loop or use batch logging."
                ),
                severity="medium",
                snippet=_get_snippet(lines, i),
                sonar_rule="S1448",
            ))

        if "}" in line:
            in_loop = max(0, in_loop - 1)

    return issues


def check_java_generic_exception_catch(source: str, filepath: str) -> list[Issue]:
    """Java catching generic Exception instead of specific (S1181)."""
    issues = []
    lines = source.splitlines()

    # Already covered by check_java_broad_catch, but let's keep separate for clarity
    return issues


# ---------------------------------------------------------------------------
# Additional SonarQube Java rule checks
# ---------------------------------------------------------------------------

def check_java_system_out(source: str, filepath: str) -> list[Issue]:
    """System.out/System.err used instead of a proper logger (S106)."""
    issues = []
    lines = source.splitlines()

    pattern = r'\bSystem\.(out|err)\.(print|println|printf|format)\s*\('

    for i, line in enumerate(lines, 1):
        if line.strip().startswith("//"):
            continue
        if re.search(pattern, line):
            issues.append(Issue(
                check_type="java_system_out",
                filepath=filepath,
                line=i,
                description=(
                    f"[S106] System.out/err at line {i} should not be used for logging. "
                    "Use a proper logging framework (SLF4J, Log4j, java.util.logging)."
                ),
                severity="medium",
                snippet=_get_snippet(lines, i),
                sonar_rule="S106",
            ))
    return issues


def check_java_thread_run_direct(source: str, filepath: str) -> list[Issue]:
    """Thread.run() called directly instead of Thread.start() (S1217)."""
    issues = []
    lines = source.splitlines()

    pattern = r'\.\s*run\s*\(\s*\)\s*;'

    for i, line in enumerate(lines, 1):
        if line.strip().startswith("//"):
            continue
        # Look for .run() where the variable is a Thread-like name
        if re.search(pattern, line) and re.search(r'\b(thread|Thread|worker|Worker|task|Task|runnable)\b', line, re.IGNORECASE):
            issues.append(Issue(
                check_type="java_thread_run_direct",
                filepath=filepath,
                line=i,
                description=(
                    f"[S1217] Thread.run() called directly at line {i}. "
                    "Call Thread.start() instead to execute in a new thread."
                ),
                severity="high",
                snippet=_get_snippet(lines, i),
                sonar_rule="S1217",
            ))
    return issues


def check_java_interrupted_exception(source: str, filepath: str) -> list[Issue]:
    """InterruptedException caught and ignored without restoring interrupt status (S2142)."""
    issues = []
    lines = source.splitlines()

    in_interrupted_catch = False
    catch_brace_depth = 0
    catch_start_line = 0
    has_interrupt_restore = False

    for i, line in enumerate(lines, 1):
        if re.search(r'catch\s*\(\s*InterruptedException\s+\w+\s*\)', line):
            in_interrupted_catch = True
            catch_brace_depth = 0
            catch_start_line = i
            has_interrupt_restore = False

        if in_interrupted_catch:
            catch_brace_depth += line.count('{') - line.count('}')
            if re.search(r'Thread\.currentThread\(\)\.interrupt\(\)', line):
                has_interrupt_restore = True
            if catch_brace_depth <= 0 and i > catch_start_line:
                if not has_interrupt_restore:
                    issues.append(Issue(
                        check_type="java_interrupted_exception",
                        filepath=filepath,
                        line=catch_start_line,
                        description=(
                            f"[S2142] InterruptedException caught at line {catch_start_line} "
                            "without restoring interrupt status. Call Thread.currentThread().interrupt()."
                        ),
                        severity="high",
                        snippet=_get_snippet(lines, catch_start_line),
                        sonar_rule="S2142",
                    ))
                in_interrupted_catch = False

    return issues


def check_java_double_checked_locking(source: str, filepath: str) -> list[Issue]:
    """Double-checked locking without volatile keyword (S2168)."""
    issues = []
    lines = source.splitlines()

    source_text = "\n".join(lines)

    # Detect double-checked locking: if (field == null) { synchronized ... if (field == null) { field = new ... } }
    dcl_pattern = r'if\s*\(\s*\w+\s*==\s*null\s*\).*synchronized'
    for i, line in enumerate(lines, 1):
        if re.search(r'if\s*\(\s*\w+\s*==\s*null\s*\)', line):
            # Check nearby lines for synchronized
            context = "\n".join(lines[i-1:min(len(lines), i+6)])
            if 'synchronized' in context:
                # Check that the field is not declared volatile
                field_match = re.search(r'if\s*\(\s*(\w+)\s*==\s*null\s*\)', line)
                if field_match:
                    field_name = field_match.group(1)
                    if not re.search(r'volatile\s+\w[\w<>\[\]]*\s+' + re.escape(field_name), source_text):
                        issues.append(Issue(
                            check_type="java_double_checked_locking",
                            filepath=filepath,
                            line=i,
                            description=(
                                f"[S2168] Possible double-checked locking at line {i}. "
                                f"Field '{field_name}' should be declared volatile, or use an Initialization-On-Demand Holder."
                            ),
                            severity="high",
                            snippet=_get_snippet(lines, i),
                            sonar_rule="S2168",
                        ))
                        break  # One report per suspicious block
    return issues


def check_java_bigdecimal_double(source: str, filepath: str) -> list[Issue]:
    """BigDecimal constructed from a double literal (S2111)."""
    issues = []
    lines = source.splitlines()

    # Pattern: new BigDecimal(0.1) — a double literal, not a String
    pattern = r'new\s+BigDecimal\s*\(\s*\d+\.\d+'

    for i, line in enumerate(lines, 1):
        if line.strip().startswith("//"):
            continue
        if re.search(pattern, line):
            issues.append(Issue(
                check_type="java_bigdecimal_double",
                filepath=filepath,
                line=i,
                description=(
                    f"[S2111] BigDecimal constructed from double at line {i} loses precision. "
                    "Use new BigDecimal(\"value\") or BigDecimal.valueOf(double) instead."
                ),
                severity="high",
                snippet=_get_snippet(lines, i),
                sonar_rule="S2111",
            ))
    return issues


def check_java_array_hashcode_tostring(source: str, filepath: str) -> list[Issue]:
    """hashCode() or toString() called directly on an array instance (S2116)."""
    issues = []
    lines = source.splitlines()

    pattern = r'\w+\[\s*\]\s*\w+.*\.(hashCode|toString)\s*\(\s*\)'

    for i, line in enumerate(lines, 1):
        if line.strip().startswith("//"):
            continue
        if re.search(pattern, line):
            issues.append(Issue(
                check_type="java_array_hashcode_tostring",
                filepath=filepath,
                line=i,
                description=(
                    f"[S2116] .hashCode()/.toString() called on array at line {i}. "
                    "Use Arrays.hashCode(arr) / Arrays.toString(arr) instead."
                ),
                severity="high",
                snippet=_get_snippet(lines, i),
                sonar_rule="S2116",
            ))
    return issues


def check_java_division_by_zero(source: str, filepath: str) -> list[Issue]:
    """Potential division by zero with literal 0 denominator (S3518)."""
    issues = []
    lines = source.splitlines()

    pattern = r'[/%]\s*0\b(?!\s*\.\d)'  # / 0 or % 0 but not 0.something

    for i, line in enumerate(lines, 1):
        if line.strip().startswith("//"):
            continue
        if re.search(pattern, line):
            issues.append(Issue(
                check_type="java_division_by_zero",
                filepath=filepath,
                line=i,
                description=(
                    f"[S3518] Possible division by zero at line {i}. "
                    "The denominator evaluates to a literal 0."
                ),
                severity="high",
                snippet=_get_snippet(lines, i),
                sonar_rule="S3518",
            ))
    return issues


def check_java_tostring_returns_null(source: str, filepath: str) -> list[Issue]:
    """toString() method contains a 'return null' statement (S2225)."""
    issues = []
    lines = source.splitlines()

    in_tostring = False
    brace_depth = 0
    method_start = 0

    for i, line in enumerate(lines, 1):
        if re.search(r'(public|protected)\s+String\s+toString\s*\(\s*\)', line):
            in_tostring = True
            brace_depth = 0
            method_start = i

        if in_tostring:
            brace_depth += line.count('{') - line.count('}')
            if re.search(r'\breturn\s+null\s*;', line):
                issues.append(Issue(
                    check_type="java_tostring_returns_null",
                    filepath=filepath,
                    line=i,
                    description=(
                        f"[S2225] toString() returns null at line {i}. "
                        "Return an empty string or a meaningful representation instead."
                    ),
                    severity="high",
                    snippet=_get_snippet(lines, i),
                    sonar_rule="S2225",
                ))
            if brace_depth <= 0 and i > method_start:
                in_tostring = False

    return issues


def check_java_wait_outside_loop(source: str, filepath: str) -> list[Issue]:
    """Object.wait() or Condition.await() called outside a while loop (S2274)."""
    issues = []
    lines = source.splitlines()

    in_while = 0
    for i, line in enumerate(lines, 1):
        if re.search(r'\bwhile\s*\(', line):
            in_while += 1
        if re.search(r'\.(wait|await)\s*\(', line) and in_while == 0:
            if not line.strip().startswith("//"):
                issues.append(Issue(
                    check_type="java_wait_outside_loop",
                    filepath=filepath,
                    line=i,
                    description=(
                        f"[S2274] .wait()/.await() called outside a while loop at line {i}. "
                        "Wrap in a while(condition) loop to guard against spurious wakeups."
                    ),
                    severity="high",
                    snippet=_get_snippet(lines, i),
                    sonar_rule="S2274",
                ))
        if "}" in line:
            in_while = max(0, in_while - 1)

    return issues


def check_java_identical_expressions(source: str, filepath: str) -> list[Issue]:
    """Identical expressions on both sides of a binary operator (S1764)."""
    issues = []
    lines = source.splitlines()

    # Pattern: expr OP expr where both sides are identical simple tokens
    pattern = r'\b(\w+)\s*(==|!=|\|\||&&|&|\|)\s*\1\b'

    for i, line in enumerate(lines, 1):
        if line.strip().startswith("//"):
            continue
        match = re.search(pattern, line)
        if match:
            expr = match.group(1)
            op = match.group(2)
            issues.append(Issue(
                check_type="java_identical_expressions",
                filepath=filepath,
                line=i,
                description=(
                    f"[S1764] Identical expressions '{expr} {op} {expr}' at line {i}. "
                    "This is likely a bug — check both operands."
                ),
                severity="high",
                snippet=_get_snippet(lines, i),
                sonar_rule="S1764",
            ))
    return issues


def check_java_dead_code_after_return(source: str, filepath: str) -> list[Issue]:
    """Statements after return/throw/break/continue are unreachable (S1763)."""
    issues = []
    lines = source.splitlines()

    terminator_pattern = re.compile(r'^\s*(return|throw|break|continue)\b.*;')
    code_pattern = re.compile(r'^\s*(?!//)(?!\s*\{)(?!\s*\})(?!\s*$)(?!\s*//)')

    for i, line in enumerate(lines[:-1], 1):
        if terminator_pattern.match(line):
            next_line = lines[i]  # i is 0-based index of next line
            # next_line is not a closing brace, blank, comment, or another terminator
            if (next_line.strip()
                    and not next_line.strip().startswith("//")
                    and not next_line.strip().startswith("}")
                    and not next_line.strip().startswith("{")
                    and not next_line.strip().startswith("case ")
                    and not next_line.strip().startswith("default")
                    and not next_line.strip().startswith("catch")
                    and not next_line.strip().startswith("finally")):
                issues.append(Issue(
                    check_type="java_dead_code_after_return",
                    filepath=filepath,
                    line=i + 1,
                    description=(
                        f"[S1763] Unreachable code at line {i + 1} — "
                        f"the previous line terminates execution with '{line.strip()[:40]}'."
                    ),
                    severity="medium",
                    snippet=_get_snippet(lines, i + 1),
                    sonar_rule="S1763",
                ))
    return issues


def check_java_duplicate_string_literal(source: str, filepath: str) -> list[Issue]:
    """String literals duplicated 3+ times should be extracted to a constant (S1192)."""
    issues = []
    lines = source.splitlines()

    literal_positions: dict[str, list[int]] = {}
    for i, line in enumerate(lines, 1):
        if line.strip().startswith("//"):
            continue
        for match in re.finditer(r'"([^"]{4,})"', line):  # Only strings with 4+ chars
            literal = match.group(1)
            literal_positions.setdefault(literal, []).append(i)

    reported: set[str] = set()
    for literal, positions in literal_positions.items():
        if len(positions) >= 3 and literal not in reported:
            reported.add(literal)
            issues.append(Issue(
                check_type="java_duplicate_string_literal",
                filepath=filepath,
                line=positions[0],
                description=(
                    f'[S1192] String literal "{literal}" is duplicated {len(positions)} times '
                    f"(lines {', '.join(str(p) for p in positions[:5])}). "
                    "Extract it to a static final constant."
                ),
                severity="low",
                snippet=_get_snippet(lines, positions[0]),
                sonar_rule="S1192",
            ))
    return issues


def check_java_public_static_nonfinal(source: str, filepath: str) -> list[Issue]:
    """Public static non-final fields should be constants (S1444)."""
    issues = []
    lines = source.splitlines()

    # Match: public static <type> <name> but NOT public static final
    pattern = r'public\s+static\s+(?!final\b)(?!class\b)(?!void\b)([\w<>\[\]]+)\s+(\w+)\s*[=;]'

    for i, line in enumerate(lines, 1):
        if line.strip().startswith("//"):
            continue
        if re.search(pattern, line):
            issues.append(Issue(
                check_type="java_public_static_nonfinal",
                filepath=filepath,
                line=i,
                description=(
                    f"[S1444] Public static non-final field at line {i}. "
                    "Make it final or reduce its visibility."
                ),
                severity="medium",
                snippet=_get_snippet(lines, i),
                sonar_rule="S1444",
            ))
    return issues


def check_java_replaceall_with_literal(source: str, filepath: str) -> list[Issue]:
    """String.replaceAll() called with a non-regex literal pattern (S5361)."""
    issues = []
    lines = source.splitlines()

    # Pattern: .replaceAll("literal", ...) where the first arg has no regex metacharacters
    pattern = r'\.replaceAll\s*\(\s*"([^"\\]*)"\s*,'

    regex_metacharacters = re.compile(r'[.+*?^${}()\[\]|\\]')

    for i, line in enumerate(lines, 1):
        if line.strip().startswith("//"):
            continue
        match = re.search(pattern, line)
        if match:
            literal = match.group(1)
            if not regex_metacharacters.search(literal):
                issues.append(Issue(
                    check_type="java_replaceall_with_literal",
                    filepath=filepath,
                    line=i,
                    description=(
                        f'[S5361] .replaceAll("{literal}", ...) at line {i} uses a plain literal, not a regex. '
                        "Use .replace() instead for clarity and performance."
                    ),
                    severity="low",
                    snippet=_get_snippet(lines, i),
                    sonar_rule="S5361",
                ))
    return issues


def check_java_instance_writes_static(source: str, filepath: str) -> list[Issue]:
    """Instance method writes to a static field directly (S2696)."""
    issues = []
    lines = source.splitlines()

    # Heuristic: assignment to a known static field pattern (ClassName.field = or bare uppercase field =)
    # Look for static field declarations first
    static_fields: set[str] = set()
    for line in lines:
        m = re.search(r'private\s+static\s+(?!final)[\w<>\[\]]+\s+(\w+)\s*[=;]', line)
        if m:
            static_fields.add(m.group(1))

    if not static_fields:
        return issues

    in_static_method = False
    for i, line in enumerate(lines, 1):
        if re.search(r'\bstatic\b.*\{', line):
            in_static_method = True
        if in_static_method and "}" in line:
            in_static_method = False

        if not in_static_method:
            for field in static_fields:
                if re.search(r'\b' + re.escape(field) + r'\s*[+\-*/&|^]?=(?!=)', line):
                    if not line.strip().startswith("//"):
                        issues.append(Issue(
                            check_type="java_instance_writes_static",
                            filepath=filepath,
                            line=i,
                            description=(
                                f"[S2696] Instance code writes to static field '{field}' at line {i}. "
                                "This causes shared mutable state; consider synchronization or a different design."
                            ),
                            severity="medium",
                            snippet=_get_snippet(lines, i),
                            sonar_rule="S2696",
                        ))
                        break
    return issues


def check_java_getclass_type_check(source: str, filepath: str) -> list[Issue]:
    """getClass() used for type checking instead of instanceof (S5779)."""
    issues = []
    lines = source.splitlines()

    pattern = r'\.getClass\s*\(\s*\)\s*(==|!=)\s*\w+\.class'

    for i, line in enumerate(lines, 1):
        if line.strip().startswith("//"):
            continue
        if re.search(pattern, line):
            issues.append(Issue(
                check_type="java_getclass_type_check",
                filepath=filepath,
                line=i,
                description=(
                    f"[S5779] getClass() used for type comparison at line {i}. "
                    "Use instanceof instead, which also handles null safely."
                ),
                severity="low",
                snippet=_get_snippet(lines, i),
                sonar_rule="S5779",
            ))
    return issues


def check_java_unused_private_field(source: str, filepath: str) -> list[Issue]:
    """Private fields declared but never read (S1068).

    Improved: strips comments and string literals before counting usages to
    avoid false positives where the name appears only in a comment or string.
    """
    issues = []
    lines = source.splitlines()

    # Build a version of the source with string literals and line comments blanked out
    # so that identifier searches don't match inside them.
    clean_lines: list[str] = []
    for line in lines:
        # Remove line comments
        cl = re.sub(r'//.*$', '', line)
        # Remove string literals (simple single-line)
        cl = re.sub(r'"[^"\\]*(?:\\.[^"\\]*)*"', '""', cl)
        clean_lines.append(cl)
    clean_text = "\n".join(clean_lines)

    field_pattern = re.compile(
        r'private\s+(?:static\s+)?(?:final\s+)?[\w<>\[\]]+\s+(\w+)\s*(?:=|;)'
    )

    declared: dict[str, int] = {}
    for i, line in enumerate(clean_lines, 1):
        m = field_pattern.search(line)
        if m:
            name = m.group(1)
            # Skip logger/log fields — they're declared once and used via the framework
            if name.lower() not in ('log', 'logger', 'serialversionuid'):
                declared[name] = i

    for field_name, decl_line in declared.items():
        uses = len(re.findall(r'\b' + re.escape(field_name) + r'\b', clean_text))
        if uses <= 1:   # only the declaration itself
            issues.append(Issue(
                check_type="java_unused_private_field",
                filepath=filepath,
                line=decl_line,
                description=(
                    f"[S1068] Private field '{field_name}' at line {decl_line} is never used. "
                    "Remove it or use it."
                ),
                severity="low",
                snippet=_get_snippet(lines, decl_line),
                sonar_rule="S1068",
            ))
    return issues


def check_java_cognitive_complexity(source: str, filepath: str) -> list[Issue]:
    """Methods with high cognitive complexity (S3776, threshold: 15)."""
    issues = []
    lines = source.splitlines()

    COMPLEXITY_THRESHOLD = 15
    NESTING_KEYWORDS = re.compile(
        r'\b(if|else|for|while|do|switch|catch|case|break|continue|return|&&|\|\||\?)\b'
    )

    method_pattern = re.compile(
        r'(public|private|protected)\s+(?:static\s+)?(?:final\s+)?[\w<>\[\]]+\s+(\w+)\s*\('
    )

    in_method = False
    brace_depth = 0
    method_start = 0
    method_name = ""
    complexity = 0
    nesting_level = 0

    for i, line in enumerate(lines, 1):
        m = method_pattern.search(line)
        if m and not in_method and '{' in line:
            in_method = True
            brace_depth = line.count('{') - line.count('}')
            method_start = i
            method_name = m.group(2)
            complexity = 0
            nesting_level = 0
            continue

        if in_method:
            opens = line.count('{')
            closes = line.count('}')
            for kw_match in NESTING_KEYWORDS.finditer(line):
                kw = kw_match.group(1)
                if kw in ('if', 'for', 'while', 'do', 'switch', 'catch'):
                    complexity += 1 + nesting_level
                    nesting_level += 1
                elif kw in ('else',):
                    complexity += 1
                elif kw in ('&&', '||', '?'):
                    complexity += 1
            nesting_level = max(0, nesting_level - closes + opens)
            brace_depth += opens - closes
            if brace_depth <= 0:
                if complexity > COMPLEXITY_THRESHOLD:
                    issues.append(Issue(
                        check_type="java_cognitive_complexity",
                        filepath=filepath,
                        line=method_start,
                        description=(
                            f"[S3776] Method '{method_name}' at line {method_start} has cognitive "
                            f"complexity of ~{complexity} (threshold: {COMPLEXITY_THRESHOLD}). "
                            "Refactor into smaller, focused methods."
                        ),
                        severity="medium",
                        snippet=_get_snippet(lines, method_start),
                        sonar_rule="S3776",
                    ))
                in_method = False

    return issues


# ---------------------------------------------------------------------------
# Unused code / dead code checks (commonly flagged by SonarLint)
# ---------------------------------------------------------------------------

def check_java_unused_private_method(source: str, filepath: str) -> list[Issue]:
    """Unused private methods and constructors (S1144).

    Covers what SonarLint flags that S1068 does not: private *methods* and
    private *constructors* that are declared but never invoked.
    """
    issues = []
    lines = source.splitlines()
    source_text = "\n".join(lines)

    # Find private method/constructor declarations
    method_decl = re.compile(
        r'private\s+(?:static\s+)?(?:final\s+)?(?:[\w<>\[\]]+\s+)?(\w+)\s*\([^)]*\)\s*(?:throws\s+[\w,\s]+)?\s*\{'
    )

    declared: dict[str, int] = {}
    for i, line in enumerate(lines, 1):
        if line.strip().startswith("//"):
            continue
        m = method_decl.search(line)
        if m:
            name = m.group(1)
            # Skip common boilerplate: main, toString, equals, hashCode, constructors
            # that share the class name are tracked separately
            if name not in ('main', 'toString', 'equals', 'hashCode', 'compareTo',
                            'clone', 'finalize', 'readObject', 'writeObject'):
                declared[name] = i

    for method_name, decl_line in declared.items():
        # Count call-sites: methodName( — exclude the declaration line itself
        call_pattern = r'\b' + re.escape(method_name) + r'\s*\('
        all_matches = list(re.finditer(call_pattern, source_text))
        # If only 1 match it's just the declaration; 2+ means it's called somewhere
        if len(all_matches) <= 1:
            issues.append(Issue(
                check_type="java_unused_private_method",
                filepath=filepath,
                line=decl_line,
                description=(
                    f"[S1144] Private method/constructor '{method_name}' at line {decl_line} "
                    "is never called. Remove it or make it accessible."
                ),
                severity="medium",
                snippet=_get_snippet(lines, decl_line),
                sonar_rule="S1144",
            ))
    return issues


def check_java_unused_local_variable(source: str, filepath: str) -> list[Issue]:
    """Unused local variables inside method bodies (S1481)."""
    issues = []
    lines = source.splitlines()

    # Pattern: type varName = ...; or type varName;  inside a method body
    local_var_pattern = re.compile(
        r'^\s+(?!return\b|throw\b|//)'     # indented (inside a block), not a statement keyword
        r'(?:final\s+)?'
        r'(?!public|private|protected|static|class|interface|enum|@)'
        r'([A-Z]\w*(?:<[^>]+>)?(?:\[\])*|int|long|double|float|boolean|char|byte|short|String)\s+'
        r'(\w+)\s*(?:=|;)'
    )

    # We scan each method body independently to limit scope
    method_body_start = re.compile(
        r'(public|private|protected)\s+(?:static\s+)?(?:final\s+)?[\w<>\[\]]+\s+\w+\s*\('
    )

    in_method = False
    brace_depth = 0
    method_vars: dict[str, int] = {}   # varName -> line number
    method_source_lines: list[str] = []
    method_start_idx = 0

    for i, line in enumerate(lines, 1):
        if method_body_start.search(line) and '{' in line and not in_method:
            in_method = True
            brace_depth = line.count('{') - line.count('}')
            method_vars = {}
            method_source_lines = [line]
            method_start_idx = i
            continue

        if in_method:
            method_source_lines.append(line)
            brace_depth += line.count('{') - line.count('}')

            m = local_var_pattern.match(line)
            if m:
                var_name = m.group(2)
                if var_name not in ('e', 'ex', 'err', 'ignored', '_'):
                    method_vars[var_name] = i

            if brace_depth <= 0:
                # End of method — check which vars were used
                method_text = "\n".join(method_source_lines)
                for var_name, decl_line in method_vars.items():
                    uses = len(re.findall(r'\b' + re.escape(var_name) + r'\b', method_text))
                    if uses <= 1:   # only the declaration
                        issues.append(Issue(
                            check_type="java_unused_local_variable",
                            filepath=filepath,
                            line=decl_line,
                            description=(
                                f"[S1481] Local variable '{var_name}' at line {decl_line} "
                                "is assigned but never used. Remove it."
                            ),
                            severity="low",
                            snippet=_get_snippet(lines, decl_line),
                            sonar_rule="S1481",
                        ))
                in_method = False

    return issues


def check_java_unused_method_parameter(source: str, filepath: str) -> list[Issue]:
    """Method parameters that are declared but never used in the body (S1172)."""
    issues = []
    lines = source.splitlines()

    method_sig = re.compile(
        r'(public|private|protected)\s+(?:static\s+)?(?:final\s+)?[\w<>\[\]]+\s+(\w+)\s*\(([^)]+)\)'
    )
    param_token = re.compile(r'(?:final\s+)?[\w<>\[\]]+\s+(\w+)(?:\s*,|\s*$)')

    for i, line in enumerate(lines, 1):
        if line.strip().startswith("//"):
            continue
        sig_match = method_sig.search(line)
        if not sig_match:
            continue
        param_str = sig_match.group(3).strip()
        if not param_str or param_str in ('void', ''):
            continue

        # Collect parameter names
        param_names = [m.group(1) for m in param_token.finditer(param_str)
                       if m.group(1) not in ('void',)]

        # Extract method body (lines until matching closing brace)
        brace_depth = line.count('{') - line.count('}')
        body_lines = [line]
        j = i  # 0-based index into lines
        while brace_depth > 0 and j < len(lines):
            j += 1
            if j >= len(lines):
                break
            body_lines.append(lines[j])
            brace_depth += lines[j].count('{') - lines[j].count('}')

        body_text = "\n".join(body_lines)

        for param in param_names:
            # Skip common convention names for unused params
            if param.startswith('_') or param in ('ignored', 'unused'):
                continue
            uses = len(re.findall(r'\b' + re.escape(param) + r'\b', body_text))
            # uses == 1 means only in the signature line
            if uses <= 1:
                issues.append(Issue(
                    check_type="java_unused_method_parameter",
                    filepath=filepath,
                    line=i,
                    description=(
                        f"[S1172] Parameter '{param}' of method at line {i} is never used. "
                        "Remove it, or prefix with '_' if intentionally unused."
                    ),
                    severity="low",
                    snippet=_get_snippet(lines, i),
                    sonar_rule="S1172",
                ))
    return issues


def check_java_generic_exception_thrown(source: str, filepath: str) -> list[Issue]:
    """Generic exceptions (Exception, RuntimeException, Throwable) should not be thrown (S112)."""
    issues = []
    lines = source.splitlines()

    # throw new Exception / throw new RuntimeException / throw new Throwable
    throw_pattern = re.compile(r'\bthrow\s+new\s+(Exception|RuntimeException|Throwable)\s*\(')
    # throws clause: public void foo() throws Exception
    throws_clause = re.compile(r'\bthrows\s+(.*)')

    generic = {'Exception', 'RuntimeException', 'Throwable'}

    for i, line in enumerate(lines, 1):
        if line.strip().startswith("//"):
            continue

        m = throw_pattern.search(line)
        if m:
            exc = m.group(1)
            issues.append(Issue(
                check_type="java_generic_exception_thrown",
                filepath=filepath,
                line=i,
                description=(
                    f"[S112] Generic exception '{exc}' thrown at line {i}. "
                    "Define and throw a specific exception class instead."
                ),
                severity="medium",
                snippet=_get_snippet(lines, i),
                sonar_rule="S112",
            ))
            continue

        tc = throws_clause.search(line)
        if tc:
            declared_throws = {t.strip().split('<')[0] for t in tc.group(1).split(',')}
            found = declared_throws & generic
            for exc in found:
                issues.append(Issue(
                    check_type="java_generic_exception_thrown",
                    filepath=filepath,
                    line=i,
                    description=(
                        f"[S112] Method declares 'throws {exc}' at line {i}. "
                        "Declare specific checked exceptions instead."
                    ),
                    severity="medium",
                    snippet=_get_snippet(lines, i),
                    sonar_rule="S112",
                ))
    return issues


def check_java_logging_string_concat(source: str, filepath: str) -> list[Issue]:
    """Logging arguments built with string concatenation instead of parameterized format (S2629).

    logger.debug("val: " + x)  →  logger.debug("val: {}", x)
    The string is always evaluated even when the log level is disabled.
    """
    issues = []
    lines = source.splitlines()

    # log/logger call with a string-concat argument (contains " + )
    pattern = re.compile(
        r'\b(log|logger|LOG|LOGGER)\s*\.\s*(trace|debug|info|warn|error|fatal)\s*\([^)]*"\s*\+'
    )

    for i, line in enumerate(lines, 1):
        if line.strip().startswith("//"):
            continue
        if pattern.search(line):
            issues.append(Issue(
                check_type="java_logging_string_concat",
                filepath=filepath,
                line=i,
                description=(
                    f"[S2629] Log message at line {i} uses string concatenation. "
                    'Use parameterized format: logger.debug("msg {}", value) '
                    "to avoid building the string when the level is disabled."
                ),
                severity="medium",
                snippet=_get_snippet(lines, i),
                sonar_rule="S2629",
            ))
    return issues


def check_java_missing_locale(source: str, filepath: str) -> list[Issue]:
    """String.toLowerCase() / toUpperCase() called without a Locale argument (S4034).

    Without a Locale these methods use the default system locale, which can
    produce unexpected results in Turkish or other locales.
    """
    issues = []
    lines = source.splitlines()

    # Match .toLowerCase() or .toUpperCase() with empty parens (no Locale passed)
    pattern = re.compile(r'\.(toLowerCase|toUpperCase)\s*\(\s*\)')

    for i, line in enumerate(lines, 1):
        if line.strip().startswith("//"):
            continue
        m = pattern.search(line)
        if m:
            method = m.group(1)
            issues.append(Issue(
                check_type="java_missing_locale",
                filepath=filepath,
                line=i,
                description=(
                    f"[S4034] {method}() at line {i} uses the default system Locale. "
                    f"Pass an explicit Locale: {method}(Locale.ROOT) or {method}(Locale.ENGLISH)."
                ),
                severity="low",
                snippet=_get_snippet(lines, i),
                sonar_rule="S4034",
            ))
    return issues


# ---------------------------------------------------------------------------
# Security Vulnerability checks
# ---------------------------------------------------------------------------

def check_java_os_command_injection(source: str, filepath: str) -> list[Issue]:
    """OS command injection via Runtime.exec() or ProcessBuilder with concatenation (S2076)."""
    issues = []
    lines = source.splitlines()

    patterns = [
        r'Runtime\.getRuntime\(\)\.exec\s*\(\s*\w+\s*\+',
        r'new\s+ProcessBuilder\s*\([^)]*\+',
        r'Runtime\.getRuntime\(\)\.exec\s*\(.*\bstring\b',
    ]

    for i, line in enumerate(lines, 1):
        if line.strip().startswith("//"):
            continue
        for pattern in patterns:
            if re.search(pattern, line, re.IGNORECASE):
                issues.append(Issue(
                    check_type="java_os_command_injection",
                    filepath=filepath,
                    line=i,
                    description=(
                        f"[S2076] OS command injection risk at line {i}. "
                        "User-controlled data passed to Runtime.exec()/ProcessBuilder. "
                        "Validate and sanitize all inputs, or use a safe API."
                    ),
                    severity="high",
                    snippet=_get_snippet(lines, i),
                    sonar_rule="S2076",
                ))
                break
    return issues


def check_java_path_traversal(source: str, filepath: str) -> list[Issue]:
    """Path traversal via user-controlled file paths (S2083)."""
    issues = []
    lines = source.splitlines()

    patterns = [
        r'new\s+File\s*\([^)]*\+',
        r'Paths\.get\s*\([^)]*\+',
        r'new\s+FileInputStream\s*\([^)]*\+',
    ]

    for i, line in enumerate(lines, 1):
        if line.strip().startswith("//"):
            continue
        for pattern in patterns:
            if re.search(pattern, line):
                issues.append(Issue(
                    check_type="java_path_traversal",
                    filepath=filepath,
                    line=i,
                    description=(
                        f"[S2083] Potential path traversal at line {i}. "
                        "File path constructed with string concatenation. "
                        "Validate and canonicalize all paths before use."
                    ),
                    severity="high",
                    snippet=_get_snippet(lines, i),
                    sonar_rule="S2083",
                ))
                break
    return issues


def check_java_weak_random(source: str, filepath: str) -> list[Issue]:
    """java.util.Random used where cryptographically secure random is needed (S2245)."""
    issues = []
    lines = source.splitlines()

    pattern = r'new\s+Random\s*\(\s*\)'

    for i, line in enumerate(lines, 1):
        if line.strip().startswith("//"):
            continue
        if re.search(pattern, line):
            # Only flag if context suggests security usage (token, key, secret, password, id)
            context = "\n".join(lines[max(0, i-3):min(len(lines), i+3)])
            if re.search(r'\b(token|secret|password|key|nonce|salt|session|auth|id|uuid)\b',
                         context, re.IGNORECASE):
                issues.append(Issue(
                    check_type="java_weak_random",
                    filepath=filepath,
                    line=i,
                    description=(
                        f"[S2245] java.util.Random at line {i} is not cryptographically secure. "
                        "Use java.security.SecureRandom for security-sensitive random values."
                    ),
                    severity="high",
                    snippet=_get_snippet(lines, i),
                    sonar_rule="S2245",
                ))
    return issues


def check_java_weak_hash_password(source: str, filepath: str) -> list[Issue]:
    """MD5 or SHA-1 used for password hashing (S4790)."""
    issues = []
    lines = source.splitlines()

    pattern = r'MessageDigest\.getInstance\s*\(\s*"(MD5|SHA-1|SHA1)"'

    for i, line in enumerate(lines, 1):
        if line.strip().startswith("//"):
            continue
        match = re.search(pattern, line, re.IGNORECASE)
        if match:
            algo = match.group(1).upper()
            issues.append(Issue(
                check_type="java_weak_hash_password",
                filepath=filepath,
                line=i,
                description=(
                    f"[S4790] Weak hashing algorithm {algo} at line {i}. "
                    "Use SHA-256 or stronger (or bcrypt/Argon2 for passwords)."
                ),
                severity="high",
                snippet=_get_snippet(lines, i),
                sonar_rule="S4790",
            ))
    return issues


def check_java_weak_ssl_protocol(source: str, filepath: str) -> list[Issue]:
    """Weak SSL/TLS protocol versions used (S4423)."""
    issues = []
    lines = source.splitlines()

    pattern = r'"(SSL|SSLv2|SSLv3|TLSv1|TLSv1\.1|TLSv1\.0)"'

    for i, line in enumerate(lines, 1):
        if line.strip().startswith("//"):
            continue
        match = re.search(pattern, line)
        if match:
            proto = match.group(1)
            issues.append(Issue(
                check_type="java_weak_ssl_protocol",
                filepath=filepath,
                line=i,
                description=(
                    f"[S4423] Weak TLS/SSL protocol '{proto}' at line {i}. "
                    "Use TLSv1.2 or TLSv1.3 only."
                ),
                severity="high",
                snippet=_get_snippet(lines, i),
                sonar_rule="S4423",
            ))
    return issues


def check_java_ecb_cipher_mode(source: str, filepath: str) -> list[Issue]:
    """ECB cipher mode should not be used (S4432)."""
    issues = []
    lines = source.splitlines()

    pattern = r'Cipher\.getInstance\s*\(\s*"[^"]*(/ECB/|AES")'

    for i, line in enumerate(lines, 1):
        if line.strip().startswith("//"):
            continue
        if re.search(pattern, line, re.IGNORECASE):
            issues.append(Issue(
                check_type="java_ecb_cipher_mode",
                filepath=filepath,
                line=i,
                description=(
                    f"[S4432] ECB cipher mode at line {i} is insecure — "
                    "identical plaintext blocks produce identical ciphertext. "
                    'Use AES/GCM/NoPadding or AES/CBC/PKCS5Padding instead.'
                ),
                severity="high",
                snippet=_get_snippet(lines, i),
                sonar_rule="S4432",
            ))
    return issues


def check_java_cookie_no_httponly(source: str, filepath: str) -> list[Issue]:
    """Cookie created without HttpOnly flag (S3330)."""
    issues = []
    lines = source.splitlines()

    for i, line in enumerate(lines, 1):
        if line.strip().startswith("//"):
            continue
        if re.search(r'new\s+Cookie\s*\(', line):
            # Check the next ~5 lines for setHttpOnly(true)
            context = "\n".join(lines[i - 1:min(len(lines), i + 6)])
            if not re.search(r'setHttpOnly\s*\(\s*true\s*\)', context):
                issues.append(Issue(
                    check_type="java_cookie_no_httponly",
                    filepath=filepath,
                    line=i,
                    description=(
                        f"[S3330] Cookie created at line {i} without setHttpOnly(true). "
                        "HttpOnly cookies cannot be accessed by JavaScript, reducing XSS risk."
                    ),
                    severity="high",
                    snippet=_get_snippet(lines, i),
                    sonar_rule="S3330",
                ))
    return issues


def check_java_cookie_no_secure(source: str, filepath: str) -> list[Issue]:
    """Cookie created without Secure flag (S2092)."""
    issues = []
    lines = source.splitlines()

    for i, line in enumerate(lines, 1):
        if line.strip().startswith("//"):
            continue
        if re.search(r'new\s+Cookie\s*\(', line):
            context = "\n".join(lines[i - 1:min(len(lines), i + 6)])
            if not re.search(r'setSecure\s*\(\s*true\s*\)', context):
                issues.append(Issue(
                    check_type="java_cookie_no_secure",
                    filepath=filepath,
                    line=i,
                    description=(
                        f"[S2092] Cookie created at line {i} without setSecure(true). "
                        "Secure cookies are only sent over HTTPS, preventing interception."
                    ),
                    severity="high",
                    snippet=_get_snippet(lines, i),
                    sonar_rule="S2092",
                ))
    return issues


def check_java_log_injection(source: str, filepath: str) -> list[Issue]:
    """User-controlled data logged without sanitization (S5145)."""
    issues = []
    lines = source.splitlines()

    # Logging calls that include string concatenation with likely user-input variables
    log_pattern = r'\b(log|logger)\.(info|warn|error|debug|trace)\s*\([^)]*\+'
    param_pattern = re.compile(
        r'\b(request|req|param|input|query|body|header|user|username|email|name|value|data)\b',
        re.IGNORECASE,
    )

    for i, line in enumerate(lines, 1):
        if line.strip().startswith("//"):
            continue
        if re.search(log_pattern, line, re.IGNORECASE) and param_pattern.search(line):
            issues.append(Issue(
                check_type="java_log_injection",
                filepath=filepath,
                line=i,
                description=(
                    f"[S5145] Potential log injection at line {i}. "
                    "User-controlled data is concatenated into a log message. "
                    "Sanitize inputs or use parameterized logging: logger.info(\"{}\", value)."
                ),
                severity="high",
                snippet=_get_snippet(lines, i),
                sonar_rule="S5145",
            ))
    return issues


def check_java_hardcoded_ip(source: str, filepath: str) -> list[Issue]:
    """Hard-coded IP addresses (S5725)."""
    issues = []
    lines = source.splitlines()

    # Match IPv4 literals in strings, excluding 127.0.0.1 and 0.0.0.0 only if clearly test code
    ip_pattern = re.compile(
        r'"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"'
    )

    for i, line in enumerate(lines, 1):
        if line.strip().startswith("//"):
            continue
        match = ip_pattern.search(line)
        if match:
            ip = match.group(1)
            issues.append(Issue(
                check_type="java_hardcoded_ip",
                filepath=filepath,
                line=i,
                description=(
                    f"[S5725] Hard-coded IP address '{ip}' at line {i}. "
                    "Use a configuration property or environment variable instead."
                ),
                severity="medium",
                snippet=_get_snippet(lines, i),
                sonar_rule="S5725",
            ))
    return issues


# ---------------------------------------------------------------------------
# Additional Bug checks
# ---------------------------------------------------------------------------

def check_java_size_vs_isempty(source: str, filepath: str) -> list[Issue]:
    """Collection.size() == 0 should use isEmpty() (S1155)."""
    issues = []
    lines = source.splitlines()

    pattern = r'\.\s*size\s*\(\s*\)\s*(==|!=)\s*0\b'

    for i, line in enumerate(lines, 1):
        if line.strip().startswith("//"):
            continue
        if re.search(pattern, line):
            issues.append(Issue(
                check_type="java_size_vs_isempty",
                filepath=filepath,
                line=i,
                description=(
                    f"[S1155] .size() == 0 comparison at line {i}. "
                    "Use .isEmpty() or !.isEmpty() for clarity and potential performance."
                ),
                severity="low",
                snippet=_get_snippet(lines, i),
                sonar_rule="S1155",
            ))
    return issues


def check_java_infinite_loop(source: str, filepath: str) -> list[Issue]:
    """Unconditional infinite loops without clear exit path (S2189)."""
    issues = []
    lines = source.splitlines()

    for i, line in enumerate(lines, 1):
        if re.search(r'\bwhile\s*\(\s*true\s*\)', line):
            # Check for a break/return/throw inside the loop body (next ~20 lines)
            body = "\n".join(lines[i:min(len(lines), i + 20)])
            if not re.search(r'\b(break|return|throw)\b', body):
                issues.append(Issue(
                    check_type="java_infinite_loop",
                    filepath=filepath,
                    line=i,
                    description=(
                        f"[S2189] Potentially infinite loop at line {i} — "
                        "while(true) with no visible break/return/throw in the body."
                    ),
                    severity="high",
                    snippet=_get_snippet(lines, i),
                    sonar_rule="S2189",
                ))
    return issues


def check_java_boolean_returns_null(source: str, filepath: str) -> list[Issue]:
    """Boolean method returning null (S2447)."""
    issues = []
    lines = source.splitlines()

    in_bool_method = False
    brace_depth = 0
    method_start = 0

    for i, line in enumerate(lines, 1):
        if re.search(r'(public|private|protected)\s+Boolean\s+\w+\s*\(', line):
            in_bool_method = True
            brace_depth = 0
            method_start = i

        if in_bool_method:
            brace_depth += line.count('{') - line.count('}')
            if re.search(r'\breturn\s+null\s*;', line):
                issues.append(Issue(
                    check_type="java_boolean_returns_null",
                    filepath=filepath,
                    line=i,
                    description=(
                        f"[S2447] Boolean method returns null at line {i}. "
                        "Return Boolean.TRUE or Boolean.FALSE instead to prevent NullPointerException."
                    ),
                    severity="high",
                    snippet=_get_snippet(lines, i),
                    sonar_rule="S2447",
                ))
            if brace_depth <= 0 and i > method_start:
                in_bool_method = False

    return issues


def check_java_float_loop_counter(source: str, filepath: str) -> list[Issue]:
    """Float or double used as a for-loop counter (S1244)."""
    issues = []
    lines = source.splitlines()

    # Pattern: for (float|double x = ...; ...)
    pattern = r'for\s*\(\s*(float|double)\s+\w+\s*='

    for i, line in enumerate(lines, 1):
        if line.strip().startswith("//"):
            continue
        match = re.search(pattern, line)
        if match:
            type_name = match.group(1)
            issues.append(Issue(
                check_type="java_float_loop_counter",
                filepath=filepath,
                line=i,
                description=(
                    f"[S1244] {type_name} used as loop counter at line {i}. "
                    "Floating-point precision errors can cause incorrect iteration counts. "
                    "Use an integer counter instead."
                ),
                severity="high",
                snippet=_get_snippet(lines, i),
                sonar_rule="S1244",
            ))
    return issues


# ---------------------------------------------------------------------------
# Additional Code Smell checks
# ---------------------------------------------------------------------------

def check_java_return_null_collection(source: str, filepath: str) -> list[Issue]:
    """Method returning null instead of an empty collection or array (S1168)."""
    issues = []
    lines = source.splitlines()

    in_collection_method = False
    brace_depth = 0
    method_start = 0

    collection_return_pattern = re.compile(
        r'(public|private|protected)\s+'
        r'(List|Set|Map|Collection|Iterable|Iterator|Optional|[\w<>]+\[\])\s+\w+\s*\('
    )

    for i, line in enumerate(lines, 1):
        if collection_return_pattern.search(line):
            in_collection_method = True
            brace_depth = 0
            method_start = i

        if in_collection_method:
            brace_depth += line.count('{') - line.count('}')
            if re.search(r'\breturn\s+null\s*;', line):
                issues.append(Issue(
                    check_type="java_return_null_collection",
                    filepath=filepath,
                    line=i,
                    description=(
                        f"[S1168] Collection/array method returns null at line {i}. "
                        "Return Collections.emptyList(), new ArrayList<>(), or an empty array instead."
                    ),
                    severity="medium",
                    snippet=_get_snippet(lines, i),
                    sonar_rule="S1168",
                ))
            if brace_depth <= 0 and i > method_start:
                in_collection_method = False

    return issues


def check_java_empty_method(source: str, filepath: str) -> list[Issue]:
    """Non-abstract, non-override methods with empty bodies (S1186)."""
    issues = []
    lines = source.splitlines()

    # Match method declarations that open and close on adjacent lines with nothing inside
    for i, line in enumerate(lines[:-1], 1):
        if re.search(r'(public|private|protected)\s+(?!abstract)', line):
            if '{' in line and re.search(r'\{\s*\}', line):
                # Exclude constructors, getters/setters heuristic
                if not re.search(r'(abstract|interface|@Override)', line):
                    issues.append(Issue(
                        check_type="java_empty_method",
                        filepath=filepath,
                        line=i,
                        description=(
                            f"[S1186] Empty method body at line {i}. "
                            "Add implementation, throw UnsupportedOperationException, or add a comment explaining the intent."
                        ),
                        severity="medium",
                        snippet=_get_snippet(lines, i),
                        sonar_rule="S1186",
                    ))
    return issues


def check_java_string_literal_left(source: str, filepath: str) -> list[Issue]:
    """String.equals() called on a variable that could be null — literal should be on left (S1132)."""
    issues = []
    lines = source.splitlines()

    # Pattern: variable.equals("literal") — risky if variable is null
    pattern = r'\b(\w+)\.equals\s*\(\s*"'

    for i, line in enumerate(lines, 1):
        if line.strip().startswith("//"):
            continue
        match = re.search(pattern, line)
        if match:
            var = match.group(1)
            # Skip if variable is 'this' or looks like a constant (ALL_CAPS)
            if var not in ('this', 'super') and not var.isupper():
                issues.append(Issue(
                    check_type="java_string_literal_left",
                    filepath=filepath,
                    line=i,
                    description=(
                        f"[S1132] '{var}.equals(\"...\")' at line {i} will throw NullPointerException if '{var}' is null. "
                        'Use "literal".equals(var) to avoid NPE.'
                    ),
                    severity="medium",
                    snippet=_get_snippet(lines, i),
                    sonar_rule="S1132",
                ))
    return issues


def check_java_legacy_collections(source: str, filepath: str) -> list[Issue]:
    """Synchronized legacy collections (Vector, Hashtable, Stack, StringBuffer) should not be used (S1149)."""
    issues = []
    lines = source.splitlines()

    pattern = r'\bnew\s+(Vector|Hashtable|Stack|StringBuffer)\s*[<(]'

    for i, line in enumerate(lines, 1):
        if line.strip().startswith("//"):
            continue
        match = re.search(pattern, line)
        if match:
            cls = match.group(1)
            replacements = {
                'Vector': 'ArrayList or CopyOnWriteArrayList',
                'Hashtable': 'HashMap or ConcurrentHashMap',
                'Stack': 'ArrayDeque',
                'StringBuffer': 'StringBuilder',
            }
            replacement = replacements.get(cls, 'a modern equivalent')
            issues.append(Issue(
                check_type="java_legacy_collections",
                filepath=filepath,
                line=i,
                description=(
                    f"[S1149] {cls} at line {i} is a legacy synchronized class. "
                    f"Use {replacement} instead."
                ),
                severity="low",
                snippet=_get_snippet(lines, i),
                sonar_rule="S1149",
            ))
    return issues


def check_java_ignored_return_value(source: str, filepath: str) -> list[Issue]:
    """Return value of a method with no side-effects is ignored (S2201)."""
    issues = []
    lines = source.splitlines()

    # Methods whose return value is almost always needed
    no_side_effect_methods = [
        r'\bString\.format\s*\(',
        r'\bString\.valueOf\s*\(',
        r'\.replace\s*\(',
        r'\.trim\s*\(',
        r'\.toLowerCase\s*\(',
        r'\.toUpperCase\s*\(',
        r'\.strip\s*\(',
        r'\.intern\s*\(',
        r'\.concat\s*\(',
        r'\.substring\s*\(',
    ]

    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("//"):
            continue
        # Statement starts without an assignment
        if not re.search(r'(=|\breturn\b)', stripped):
            for method_pattern in no_side_effect_methods:
                if re.search(method_pattern, line):
                    issues.append(Issue(
                        check_type="java_ignored_return_value",
                        filepath=filepath,
                        line=i,
                        description=(
                            f"[S2201] Return value of a non-mutating method ignored at line {i}. "
                            "Strings are immutable — the result must be assigned to have any effect."
                        ),
                        severity="medium",
                        snippet=_get_snippet(lines, i),
                        sonar_rule="S2201",
                    ))
                    break
    return issues


def check_java_utility_class_constructor(source: str, filepath: str) -> list[Issue]:
    """Utility classes (only static members) should have a private constructor (S1118)."""
    issues = []
    lines = source.splitlines()
    source_text = "\n".join(lines)

    # Find classes with only static methods/fields and a public/default constructor
    class_matches = list(re.finditer(r'\bclass\s+(\w+)', source_text))
    for cm in class_matches:
        class_name = cm.group(1)
        # Heuristic: all methods are static and there's a public constructor
        non_static = re.search(
            r'(?<!static\s)(public|private|protected)\s+(?!static)[\w<>\[\]]+\s+\w+\s*\(',
            source_text[cm.start():cm.start() + 2000]
        )
        has_public_ctor = re.search(
            r'public\s+' + re.escape(class_name) + r'\s*\(\s*\)',
            source_text[cm.start():cm.start() + 2000]
        )
        all_static = not non_static

        if all_static and has_public_ctor:
            # Find line number
            line_no = source_text[:cm.start()].count('\n') + 1
            issues.append(Issue(
                check_type="java_utility_class_constructor",
                filepath=filepath,
                line=line_no,
                description=(
                    f"[S1118] Utility class '{class_name}' at line {line_no} has a public constructor. "
                    "Add a private no-arg constructor to prevent instantiation."
                ),
                severity="low",
                snippet=_get_snippet(lines, line_no),
                sonar_rule="S1118",
            ))
    return issues


def check_java_diamond_operator(source: str, filepath: str) -> list[Issue]:
    """Explicit type parameter in generic instantiation should use diamond operator (S2293)."""
    issues = []
    lines = source.splitlines()

    # Pattern: new ArrayList<String>() — should be new ArrayList<>()
    pattern = r'new\s+\w+\s*<[A-Z][\w<>, ]+>\s*\('

    for i, line in enumerate(lines, 1):
        if line.strip().startswith("//"):
            continue
        if re.search(pattern, line):
            issues.append(Issue(
                check_type="java_diamond_operator",
                filepath=filepath,
                line=i,
                description=(
                    f"[S2293] Explicit type argument in generic instantiation at line {i}. "
                    "Use the diamond operator <> to let the compiler infer the type."
                ),
                severity="low",
                snippet=_get_snippet(lines, i),
                sonar_rule="S2293",
            ))
    return issues


def check_java_redundant_cast(source: str, filepath: str) -> list[Issue]:
    """Redundant casts to the same type (S1905)."""
    issues = []
    lines = source.splitlines()

    # Heuristic: (String) someString, (int) someInt assignment patterns
    pattern = r'\((\w+)\)\s+\1\b'

    for i, line in enumerate(lines, 1):
        if line.strip().startswith("//"):
            continue
        if re.search(pattern, line):
            issues.append(Issue(
                check_type="java_redundant_cast",
                filepath=filepath,
                line=i,
                description=(
                    f"[S1905] Redundant cast to the same type at line {i}. "
                    "Remove the unnecessary cast."
                ),
                severity="low",
                snippet=_get_snippet(lines, i),
                sonar_rule="S1905",
            ))
    return issues


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

ALL_CHECKS_PYTHON = [
    check_bare_except,
    check_missing_timeout,
    check_no_context_manager,
    check_broad_exception_raise,
    check_missing_docstring,
    check_unused_variables,
    check_empty_except_block,
    check_hardcoded_credentials,
    check_sql_injection_python,
    check_weak_cryptography,
    check_eval_usage,
    check_assert_usage,
    check_input_without_sanitization,
    check_hardcoded_paths,
    check_multiple_returns,
    check_function_too_long,
]

ALL_CHECKS_JAVA = [
    # -----------------------------------------------------------------------
    # SECURITY VULNERABILITIES (highest priority)
    # -----------------------------------------------------------------------
    check_java_os_command_injection,       # S2076
    check_java_path_traversal,             # S2083
    check_java_weak_random,                # S2245
    check_java_weak_hash_password,         # S4790
    check_java_weak_ssl_protocol,          # S4423
    check_java_ecb_cipher_mode,            # S4432
    check_java_cookie_no_httponly,         # S3330
    check_java_cookie_no_secure,           # S2092
    check_java_log_injection,              # S5145
    check_java_hardcoded_ip,               # S5725
    check_java_hardcoded_credentials,      # S2115
    check_java_sql_injection,              # S2077
    # -----------------------------------------------------------------------
    # BUGS
    # -----------------------------------------------------------------------
    check_java_thread_run_direct,          # S1217
    check_java_interrupted_exception,      # S2142
    check_java_double_checked_locking,     # S2168
    check_java_bigdecimal_double,          # S2111
    check_java_array_hashcode_tostring,    # S2116
    check_java_division_by_zero,           # S3518
    check_java_tostring_returns_null,      # S2225
    check_java_wait_outside_loop,          # S2274
    check_java_identical_expressions,      # S1764
    check_java_dead_code_after_return,     # S1763
    check_java_infinite_loop,              # S2189
    check_java_boolean_returns_null,       # S2447
    check_java_float_loop_counter,         # S1244
    check_java_size_vs_isempty,            # S1155
    # -----------------------------------------------------------------------
    # CODE SMELLS
    # -----------------------------------------------------------------------
    check_java_missing_timeout,            # S5527
    check_java_broad_catch,                # S1181
    check_java_empty_catch,                # S1602
    check_java_nested_try_catch,           # S1142
    check_java_unclosed_resource,          # S2095
    check_java_system_out,                 # S106
    check_java_missing_override,           # S1206
    check_java_equals_without_hashcode,    # S1206
    check_java_mutable_public_field,       # S1104
    check_java_public_static_nonfinal,     # S1444
    check_java_switch_default,             # S1301
    check_java_unused_imports,             # S1128
    check_java_unused_private_field,       # S1068
    check_java_string_literal_equality,    # S4973
    check_java_logging_in_loop,            # S1448
    check_java_duplicate_string_literal,   # S1192
    check_java_replaceall_with_literal,    # S5361
    check_java_instance_writes_static,     # S2696
    check_java_getclass_type_check,        # S5779
    check_java_cognitive_complexity,       # S3776
    check_java_return_null_collection,     # S1168
    check_java_empty_method,               # S1186
    check_java_string_literal_left,        # S1132
    check_java_legacy_collections,         # S1149
    check_java_ignored_return_value,       # S2201
    check_java_utility_class_constructor,  # S1118
    check_java_diamond_operator,           # S2293
    check_java_redundant_cast,             # S1905
    check_java_todo_fixme,                 # S1134
    # --- Unused / dead code (SonarLint commonly flags these) ---
    check_java_unused_private_method,      # S1144
    check_java_unused_local_variable,      # S1481
    check_java_unused_method_parameter,    # S1172
    check_java_generic_exception_thrown,   # S112
    check_java_logging_string_concat,      # S2629
    check_java_missing_locale,             # S4034
]


def scan_file(filepath: Path) -> list[Issue]:
    """Scan a single Java file and return a list of issues."""
    if filepath.suffix != ".java":
        return []

    try:
        source = filepath.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []

    issues: list[Issue] = []
    for check in ALL_CHECKS_JAVA:
        issues.extend(check(source, str(filepath)))

    return issues


EXCLUDE_DIRS = {".git", "__pycache__", ".venv", "venv", "env", "node_modules", ".tox", "dist", "build"}


def scan_repo(root: str = ".") -> dict[str, list[Issue]]:
    """Scan all Java files under *root* and return a dict of filepath -> issues.

    Keys in the returned dict are always paths **relative to root**, e.g.
    ``src/main/java/com/example/Foo.java``.  This is important for the GitHub
    API: ``repo.get_contents(filepath)`` expects a repo-root-relative path,
    so callers should pass the absolute path to the repo root as *root*.
    """
    root_path = Path(root).resolve()
    results: dict[str, list[Issue]] = {}

    for path in root_path.rglob("*.java"):
        if any(part in EXCLUDE_DIRS for part in path.parts):
            continue
        issues = scan_file(path)
        if issues:
            # Always store as a repo-root-relative POSIX path
            rel = path.relative_to(root_path).as_posix()
            results[rel] = issues

    return results
