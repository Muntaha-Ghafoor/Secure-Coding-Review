"""
security_scanner.py
A custom static analysis security scanner for Python code.
Mimics Bandit's detection approach using Python's AST module.
Author: Muntaha Ghafoor | CodeAlpha Internship Task 3
"""

import ast
import re
import sys
import json
from pathlib import Path

SEVERITY = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢"}

findings = []

def add_finding(vuln_id, severity, cwe, title, line, code, description, recommendation):
    findings.append({
        "id": vuln_id,
        "severity": severity,
        "cwe": cwe,
        "title": title,
        "line": line,
        "code": code.strip(),
        "description": description,
        "recommendation": recommendation
    })

def scan_file(filepath):
    source = Path(filepath).read_text()
    lines  = source.splitlines()
    tree   = ast.parse(source)

    # ── 1. Hardcoded credentials ──────────────────────────────
    cred_patterns = re.compile(
        r'(?i)(password|passwd|secret|api_key|token|db_pass)\s*=\s*["\'][^"\']+["\']'
    )
    for i, line in enumerate(lines, 1):
        if cred_patterns.search(line) and not line.strip().startswith("#"):
            add_finding(
                "V-01", "HIGH", "CWE-798",
                "Hardcoded Credentials",
                i, line,
                "Sensitive credential stored directly in source code. If the repo is public, attackers gain immediate access.",
                "Store secrets in environment variables or a vault (e.g. python-dotenv, AWS Secrets Manager)."
            )

    # ── 2. SQL Injection ──────────────────────────────────────
    sql_pattern = re.compile(r'(execute|executemany)\s*\(\s*["\'].*(%s|["\'\s]*\+)', re.IGNORECASE)
    for i, line in enumerate(lines, 1):
        if sql_pattern.search(line) or ("execute" in line and ("+ " in line or "format(" in line or "f\"" in line or "f'" in line)):
            if "execute" in line.lower():
                add_finding(
                    "V-02", "HIGH", "CWE-89",
                    "SQL Injection",
                    i, line,
                    "User-supplied input is concatenated directly into SQL query. Attacker can bypass auth, dump or delete entire database.",
                    "Use parameterized queries: cursor.execute('SELECT * FROM users WHERE username = ?', (username,))"
                )
                break

    # ── 3. Weak hashing ───────────────────────────────────────
    weak_hash = re.compile(r'hashlib\.(md5|sha1)\s*\(')
    for i, line in enumerate(lines, 1):
        m = weak_hash.search(line)
        if m:
            add_finding(
                "V-03", "HIGH", "CWE-327",
                f"Weak Cryptographic Hash ({m.group(1).upper()})",
                i, line,
                f"{m.group(1).upper()} is cryptographically broken. Passwords hashed with MD5/SHA1 can be cracked in seconds using rainbow tables.",
                "Use bcrypt, argon2, or hashlib.pbkdf2_hmac with salt: import bcrypt; bcrypt.hashpw(password, bcrypt.gensalt())"
            )

    # ── 4. Command Injection ──────────────────────────────────
    shell_pattern = re.compile(r'(subprocess\.(call|run|Popen|check_output)|os\.system)\s*\(')
    for i, line in enumerate(lines, 1):
        if shell_pattern.search(line) and "shell=True" in line:
            add_finding(
                "V-04", "HIGH", "CWE-78",
                "Command Injection via shell=True",
                i, line,
                "User input passed to shell command. Attacker can execute arbitrary OS commands: hostname='google.com; rm -rf /'",
                "Use shell=False with a list: subprocess.call(['ping', '-c', '1', hostname], shell=False). Validate input with allowlist."
            )

    # ── 5. Insecure Deserialization ───────────────────────────
    for i, line in enumerate(lines, 1):
        if "pickle.loads" in line or "pickle.load(" in line:
            add_finding(
                "V-05", "HIGH", "CWE-502",
                "Insecure Deserialization (pickle)",
                i, line,
                "pickle.loads() on untrusted data allows attackers to execute arbitrary Python code during deserialization (Remote Code Execution).",
                "Never deserialize untrusted data with pickle. Use JSON for data exchange: json.loads(data). If pickle is needed, sign the payload with HMAC."
            )

    # ── 6. Path Traversal ─────────────────────────────────────
    for i, line in enumerate(lines, 1):
        if ("open(" in line and ("+" in line or "format(" in line or "f\"" in line)):
            if "base_path" in line or "filename" in line or "path" in line.lower():
                add_finding(
                    "V-06", "MEDIUM", "CWE-22",
                    "Path Traversal",
                    i, line,
                    "Unsanitized filename concatenated into file path. Attacker can use '../../etc/passwd' to read sensitive system files.",
                    "Use os.path.realpath() and verify the resolved path starts with the intended base directory. Use pathlib.Path for safe joins."
                )

    # ── 7. Sensitive Data in Logs ─────────────────────────────
    log_pattern = re.compile(r'(print|logging\.(info|debug|warning|error))\s*\(.*password', re.IGNORECASE)
    for i, line in enumerate(lines, 1):
        if log_pattern.search(line):
            add_finding(
                "V-07", "HIGH", "CWE-532",
                "Sensitive Data Logged (Password)",
                i, line,
                "Password or other sensitive data is written to logs in plaintext. Log files are often accessible to attackers or stored insecurely.",
                "Never log passwords, tokens, or PII. Log only: username + timestamp + action. Redact sensitive fields before logging."
            )

    # ── 8. Broad Exception Handling ───────────────────────────
    for node in ast.walk(tree):
        if isinstance(node, ast.ExceptHandler) and node.type is None:
            line = lines[node.lineno - 1] if node.lineno <= len(lines) else ""
            add_finding(
                "V-08", "LOW", "CWE-390",
                "Overly Broad Exception Handling",
                node.lineno, line,
                "Bare 'except:' clause silently swallows ALL exceptions including KeyboardInterrupt and SystemExit, hiding real errors and bugs.",
                "Catch specific exceptions: except ZeroDivisionError as e: logger.error(f'Division error: {e}'). Never use bare except."
            )

    # ── 9. Weak Random ────────────────────────────────────────
    for i, line in enumerate(lines, 1):
        if re.search(r'random\.(random|randint|choice|randrange)\s*\(', line):
            if "token" in "".join(lines[max(0,i-5):i+2]).lower() or "session" in "".join(lines[max(0,i-5):i+2]).lower():
                add_finding(
                    "V-09", "MEDIUM", "CWE-338",
                    "Cryptographically Weak PRNG",
                    i, line,
                    "Python's random module is a pseudo-random number generator NOT suitable for security. Tokens generated this way are predictable.",
                    "Use secrets module: import secrets; secrets.token_hex(32) — this uses OS-level CSPRNG."
                )

    # ── 10. Debug Mode ────────────────────────────────────────
    for i, line in enumerate(lines, 1):
        if re.search(r'DEBUG\s*=\s*True', line):
            add_finding(
                "V-10", "MEDIUM", "CWE-215",
                "Debug Mode Enabled",
                i, line,
                "DEBUG=True in production exposes full stack traces, internal paths, and config data to end users, aiding attacker reconnaissance.",
                "Set DEBUG=False in production. Load environment-specific config: DEBUG = os.getenv('DEBUG', 'False') == 'True'"
            )

    return findings

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "vulnerable_app.py"
    results = scan_file(target)

    print(f"\n{'='*70}")
    print(f"  SECURE CODE REVIEW — SCAN RESULTS")
    print(f"  File: {target}")
    print(f"  Total Vulnerabilities Found: {len(results)}")
    print(f"{'='*70}\n")

    high   = [f for f in results if f["severity"] == "HIGH"]
    medium = [f for f in results if f["severity"] == "MEDIUM"]
    low    = [f for f in results if f["severity"] == "LOW"]

    print(f"  🔴 HIGH:   {len(high)}")
    print(f"  🟡 MEDIUM: {len(medium)}")
    print(f"  🟢 LOW:    {len(low)}")
    print()

    for f in results:
        icon = SEVERITY[f["severity"]]
        print(f"{'─'*70}")
        print(f"  {icon} [{f['severity']}] {f['id']} — {f['title']}  ({f['cwe']})")
        print(f"  📍 Line {f['line']}: {f['code'][:80]}")
        print(f"  ⚠  {f['description'][:120]}")
        print(f"  ✅  FIX: {f['recommendation'][:120]}")
        print()

    # Save JSON report
    with open("scan_results.json", "w") as jf:
        json.dump(results, jf, indent=2)
    print(f"\n  📄 JSON report saved: scan_results.json")
    print(f"{'='*70}\n")
