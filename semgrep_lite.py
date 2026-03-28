#!/usr/bin/env python3
"""semgrep_lite - Simple pattern-based source code scanner."""
import sys, os, re, json, pathlib

RULES = {
    'hardcoded-password': r'''(?:password|passwd|pwd|secret)\s*=\s*['\"][^'\"]{4,}['\"]''',
    'todo-fixme': r'(?:#|//|/\*)\s*(?:TODO|FIXME|HACK|XXX|BUG)',
    'eval-usage': r'\beval\s*\(',
    'sql-injection': r'(?:execute|cursor\.execute)\s*\(\s*[f"\'].*%[sd]',
    'debug-print': r'\bprint\s*\(\s*[f"\'].*(?:debug|DEBUG)',
    'bare-except': r'except\s*:',
    'assert-in-prod': r'^\s*assert\b',
    'http-url': r'''['\"]http://[^'\"]+['\"]''',
}
SKIP = {'.git','node_modules','__pycache__','venv','.venv'}

def scan(root, rules=None, exts=None):
    root = pathlib.Path(root)
    findings = []
    active = {k:re.compile(v, re.IGNORECASE) for k,v in RULES.items() if not rules or k in rules}
    for p in root.rglob('*'):
        if any(s in p.parts for s in SKIP): continue
        if not p.is_file(): continue
        if exts and p.suffix not in exts: continue
        try: lines = p.read_text(errors='replace').splitlines()
        except: continue
        for i, line in enumerate(lines, 1):
            for name, pat in active.items():
                if pat.search(line):
                    findings.append({'rule':name,'file':str(p),'line':i,'code':line.strip()[:120]})
    return findings

def main():
    args = sys.argv[1:]
    if not args or '-h' in args or '--help' in args:
        print("Usage: semgrep_lite.py <DIR> [--rules r1,r2] [--ext .py] [--json]")
        print(f"Rules: {', '.join(RULES.keys())}"); return
    root = args[0]
    rules = args[args.index('--rules')+1].split(',') if '--rules' in args else None
    exts = {args[args.index('--ext')+1]} if '--ext' in args else None
    as_json = '--json' in args
    findings = scan(root, rules, exts)
    if as_json:
        print(json.dumps(findings, indent=2))
    else:
        for f in findings:
            print(f"[{f['rule']}] {f['file']}:{f['line']}: {f['code']}")
        print(f"\n{len(findings)} findings")

if __name__ == '__main__': main()
