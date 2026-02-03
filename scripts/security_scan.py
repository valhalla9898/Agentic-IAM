#!/usr/bin/env python3
"""
Lightweight security scanner for this repository.

Features:
- Detect likely hard-coded secrets (API keys, private keys, tokens)
- Flag use of dangerous functions (eval, exec, pickle.loads, shell=True)
- Scan common config files and requirements.txt
- Produce a JSON report and a short console summary

Usage: python scripts/security_scan.py [--output report.json]

Run this only on code you own or have explicit permission to test.
"""
import argparse
import json
import os
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXCLUDE_DIRS = {'.git', '__pycache__', 'venv', '.venv', 'env'}

SECRET_PATTERNS = [
    r"AKIA[0-9A-Z]{16}",
    r"(?i)aws(.{0,20})?(secret|access|key)",
    r"(?i)api[_-]?key",
    r"(?i)secret[_-]?key",
    r"(?i)token",
    r"-----BEGIN (RSA |)PRIVATE KEY-----",
    r"(?i)password\s*[:=]",
    r"(?i)client[_-]?secret",
]

DANGEROUS_USAGE = [
    (r"\beval\s*\(", "eval(...)"),
    (r"\bexec\s*\(", "exec(...)"),
    (r"pickle\.loads\s*\(", "pickle.loads(...)"),
    (r"subprocess\.[Pp]open\s*\(([^)]*shell\s*=\s*True)", "subprocess(..., shell=True)"),
    (r"os\.system\s*\(", "os.system(...)"),
]

TEXT_FILE_EXTS = {'.py', '.env', '.ini', '.cfg', '.txt', '.md', '.yaml', '.yml', '.json', '.sh'}


def walk_files(root: Path):
    for dirpath, dirnames, filenames in os.walk(root):
        parts = set(Path(dirpath).parts)
        if parts & EXCLUDE_DIRS:
            continue
        for fn in filenames:
            yield Path(dirpath) / fn


def scan_file(path: Path):
    findings = []
    try:
        text = path.read_text(errors='ignore')
    except Exception:
        return findings

    lname = path.name.lower()
    # Quick binary skip heuristic
    if path.suffix and path.suffix.lower() not in TEXT_FILE_EXTS:
        return findings

    # Secret patterns
    for pat in SECRET_PATTERNS:
        for m in re.finditer(pat, text, flags=re.MULTILINE):
            snippet = text[max(0, m.start()-40):m.end()+40].strip().replace('\n', ' ')
            findings.append({
                'type': 'secret',
                'pattern': pat,
                'match': m.group(0)[:200],
                'snippet': snippet,
            })

    # Dangerous usage
    for pat, label in DANGEROUS_USAGE:
        for m in re.finditer(pat, text):
            line_no = text[:m.start()].count('\n') + 1
            findings.append({
                'type': 'dangerous',
                'pattern': label,
                'line': line_no,
                'context': text.splitlines()[line_no-1].strip()[:400],
            })

    # HTTP URL literal (insecure)
    for m in re.finditer(r"http://[\w\-\.\/:?&=%]+", text):
        findings.append({'type': 'insecure-url', 'match': m.group(0)})

    return findings


def scan_requirements(path: Path):
    findings = []
    try:
        lines = path.read_text().splitlines()
    except Exception:
        return findings
    for i, ln in enumerate(lines, 1):
        ln = ln.strip()
        if not ln or ln.startswith('#'):
            continue
        # crude check for very old pins
        m = re.search(r'([A-Za-z0-9_.+-]+)==([0-9]+)\.([0-9]+)(?:\.([0-9]+))?', ln)
        if m:
            pkg, maj, mino, patch = m.group(1,2,3,4)
            try:
                if int(maj) < 1:
                    findings.append({'type': 'old-pin', 'package': pkg, 'version': ln, 'line': i})
            except Exception:
                pass
    return findings


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--output', '-o', help='Write JSON report to file', default='security_report.json')
    args = ap.parse_args()

    report = {'scanned_files': 0, 'findings': []}

    # Scan files
    for f in walk_files(ROOT):
        if f.is_dir():
            continue
        report['scanned_files'] += 1
        findings = scan_file(f)
        if findings:
            report['findings'].append({'file': str(f.relative_to(ROOT)), 'issues': findings})

    # requirements
    req = ROOT / 'requirements.txt'
    if req.exists():
        req_find = scan_requirements(req)
        if req_find:
            report['findings'].append({'file': 'requirements.txt', 'issues': req_find})

    # Summary
    total_issues = sum(len(x['issues']) for x in report['findings'])
    summary = {
        'total_files_scanned': report['scanned_files'],
        'total_issues': total_issues,
        'files_with_issues': len(report['findings']),
    }
    report['summary'] = summary

    # Write report
    outp = Path(args.output)
    outp.write_text(json.dumps(report, indent=2, ensure_ascii=False))

    # Print concise console summary
    print('Scan complete')
    print(f"Files scanned: {summary['total_files_scanned']}")
    print(f"Files with issues: {summary['files_with_issues']}")
    print(f"Total issues: {summary['total_issues']}")
    if summary['total_issues'] > 0:
        print(f"Report saved to: {outp}")
    else:
        print('No obvious issues detected by this lightweight scan.')


if __name__ == '__main__':
    main()
