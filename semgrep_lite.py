#!/usr/bin/env python3
"""semgrep_lite - lightweight code pattern scanner for security and quality issues."""

import argparse, sys, os, re, json
from collections import Counter

RULES = {
    "python": [
        {"id": "PY001", "severity": "HIGH", "name": "eval() usage",
         "pattern": r'\beval\s*\(', "desc": "eval() executes arbitrary code"},
        {"id": "PY002", "severity": "HIGH", "name": "exec() usage",
         "pattern": r'\bexec\s*\(', "desc": "exec() executes arbitrary code"},
        {"id": "PY003", "severity": "HIGH", "name": "SQL injection risk",
         "pattern": r'execute\s*\(\s*[f"\'].*%s|\.format\(|' + r'\+.*\bquery\b',
         "desc": "String interpolation in SQL query"},
        {"id": "PY004", "severity": "MEDIUM", "name": "Hardcoded password",
         "pattern": r'(?i)(password|passwd|pwd|secret)\s*=\s*["\'][^"\']{3,}["\']',
         "desc": "Password hardcoded in source"},
        {"id": "PY005", "severity": "MEDIUM", "name": "Bare except",
         "pattern": r'except\s*:', "desc": "Catches all exceptions silently"},
        {"id": "PY006", "severity": "LOW", "name": "print() in production",
         "pattern": r'^\s*print\s*\(', "desc": "Debug print statement"},
        {"id": "PY007", "severity": "HIGH", "name": "Pickle usage",
         "pattern": r'\bpickle\.(loads?|dumps?)\b', "desc": "Pickle can execute arbitrary code on load"},
        {"id": "PY008", "severity": "MEDIUM", "name": "Shell injection risk",
         "pattern": r'subprocess\.\w+\(.*shell\s*=\s*True', "desc": "Shell=True allows injection"},
        {"id": "PY009", "severity": "MEDIUM", "name": "Temp file race condition",
         "pattern": r'tempfile\.mktemp\b', "desc": "mktemp is insecure, use mkstemp"},
        {"id": "PY010", "severity": "LOW", "name": "TODO/FIXME",
         "pattern": r'#\s*(TODO|FIXME|HACK|XXX)\b', "desc": "Unresolved code annotation"},
        {"id": "PY011", "severity": "HIGH", "name": "SSL verification disabled",
         "pattern": r'verify\s*=\s*False', "desc": "TLS certificate verification disabled"},
        {"id": "PY012", "severity": "MEDIUM", "name": "Assert in production",
         "pattern": r'^\s*assert\s+', "desc": "Assert removed with -O flag"},
    ],
    "javascript": [
        {"id": "JS001", "severity": "HIGH", "name": "eval() usage",
         "pattern": r'\beval\s*\(', "desc": "eval() executes arbitrary code"},
        {"id": "JS002", "severity": "HIGH", "name": "innerHTML assignment",
         "pattern": r'\.innerHTML\s*=', "desc": "XSS risk via innerHTML"},
        {"id": "JS003", "severity": "MEDIUM", "name": "console.log",
         "pattern": r'\bconsole\.(log|debug|info)\s*\(', "desc": "Debug logging in production"},
        {"id": "JS004", "severity": "HIGH", "name": "document.write",
         "pattern": r'document\.write\s*\(', "desc": "XSS risk via document.write"},
        {"id": "JS005", "severity": "MEDIUM", "name": "var declaration",
         "pattern": r'\bvar\s+\w', "desc": "Use let/const instead of var"},
        {"id": "JS006", "severity": "LOW", "name": "== instead of ===",
         "pattern": r'[^!=]==[^=]', "desc": "Loose equality comparison"},
        {"id": "JS007", "severity": "HIGH", "name": "Hardcoded secret",
         "pattern": r'(?i)(api_key|apikey|secret|token)\s*[:=]\s*["\'][a-zA-Z0-9]{10,}',
         "desc": "Hardcoded API key or secret"},
    ],
    "generic": [
        {"id": "GEN001", "severity": "HIGH", "name": "Private key",
         "pattern": r'-----BEGIN (RSA |EC |DSA |)PRIVATE KEY-----', "desc": "Private key in source"},
        {"id": "GEN002", "severity": "HIGH", "name": "AWS access key",
         "pattern": r'AKIA[0-9A-Z]{16}', "desc": "AWS access key ID"},
        {"id": "GEN003", "severity": "MEDIUM", "name": "IP address",
         "pattern": r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', "desc": "Hardcoded IP address"},
        {"id": "GEN004", "severity": "HIGH", "name": "JWT token",
         "pattern": r'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}', "desc": "JWT token in source"},
    ]
}

EXT_MAP = {
    ".py": "python", ".pyw": "python",
    ".js": "javascript", ".jsx": "javascript", ".ts": "javascript", ".tsx": "javascript",
    ".mjs": "javascript", ".cjs": "javascript",
}

IGNORE_DIRS = {".git", "__pycache__", "node_modules", ".venv", "venv", "dist", "build"}
BINARY_EXTS = {".png", ".jpg", ".gif", ".ico", ".woff", ".ttf", ".pdf", ".zip", ".gz", ".pyc", ".so"}

def scan_file(filepath, lang_rules):
    findings = []
    try:
        with open(filepath, errors="replace") as f:
            for i, line in enumerate(f, 1):
                for rule in lang_rules:
                    if re.search(rule["pattern"], line):
                        findings.append({
                            "file": filepath, "line": i, "rule": rule["id"],
                            "severity": rule["severity"], "name": rule["name"],
                            "desc": rule["desc"], "code": line.rstrip()[:120]
                        })
    except OSError:
        pass
    return findings

def cmd_scan(args):
    paths = args.paths or ["."]
    all_findings = []

    for path in paths:
        if os.path.isfile(path):
            files = [path]
        else:
            files = []
            for root, dirs, fnames in os.walk(path):
                dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
                for f in fnames:
                    _, ext = os.path.splitext(f)
                    if ext not in BINARY_EXTS:
                        files.append(os.path.join(root, f))

        for fp in files:
            _, ext = os.path.splitext(fp)
            lang = EXT_MAP.get(ext)
            rules = RULES.get("generic", [])[:]
            if lang:
                rules.extend(RULES.get(lang, []))
            if not rules:
                continue
            if args.severity:
                min_sev = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}
                threshold = min_sev.get(args.severity.upper(), 0)
                rules = [r for r in rules if min_sev.get(r["severity"], 0) >= threshold]
            all_findings.extend(scan_file(fp, rules))

    if args.json:
        print(json.dumps(all_findings, indent=2))
        return

    if not all_findings:
        print("  ✅ No issues found")
        return

    # Sort by severity
    sev_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    all_findings.sort(key=lambda x: (sev_order.get(x["severity"], 3), x["file"], x["line"]))

    colors = {"HIGH": "\033[31m", "MEDIUM": "\033[33m", "LOW": "\033[36m"}
    for f in all_findings:
        rel = os.path.relpath(f["file"])
        c = colors.get(f["severity"], "")
        print(f"  {c}{f['severity']:<6}\033[0m {f['rule']} {f['name']}")
        print(f"         {rel}:{f['line']}")
        if args.verbose:
            print(f"         {f['code'][:80]}")
        print()

    # Summary
    severities = Counter(f["severity"] for f in all_findings)
    rules = Counter(f["rule"] for f in all_findings)
    files = len(set(f["file"] for f in all_findings))
    print("  " + "─" * 40)
    print(f"  {len(all_findings)} findings in {files} files")
    print(f"  \033[31mHIGH: {severities.get('HIGH', 0)}\033[0m  "
          f"\033[33mMEDIUM: {severities.get('MEDIUM', 0)}\033[0m  "
          f"\033[36mLOW: {severities.get('LOW', 0)}\033[0m")

def cmd_rules(args):
    print(f"\n  Available Rules ({sum(len(v) for v in RULES.values())} total)\n")
    for lang, lang_rules in sorted(RULES.items()):
        print(f"  {lang}:")
        for r in lang_rules:
            colors = {"HIGH": "\033[31m", "MEDIUM": "\033[33m", "LOW": "\033[36m"}
            c = colors.get(r["severity"], "")
            print(f"    {r['id']:<8} {c}{r['severity']:<6}\033[0m {r['name']}: {r['desc']}")
        print()

def main():
    p = argparse.ArgumentParser(description="Code pattern scanner")
    sp = p.add_subparsers(dest="cmd")

    s = sp.add_parser("scan", help="Scan for issues")
    s.add_argument("paths", nargs="*", default=["."])
    s.add_argument("-s", "--severity", choices=["low", "medium", "high"], help="Minimum severity")
    s.add_argument("-v", "--verbose", action="store_true")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_scan)

    r = sp.add_parser("rules", help="List rules")
    r.set_defaults(func=cmd_rules)

    args = p.parse_args()
    if not args.cmd:
        p.print_help()
        sys.exit(1)
    args.func(args)

if __name__ == "__main__":
    main()
