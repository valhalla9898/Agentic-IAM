# Incident Report (Sample)

This is a template for documenting a security incident detected during lab testing. Use this file as a starting point for your thesis deliverable or incident post-mortem. Store evidence and exported reports under `data/reports/<target>/<timestamp>/` and include alert JSON under `data/alerts/` if needed.

---

## 1. Executive Summary

- Incident ID: IR-<target>-<YYYYMMDD>-<NN>
- Target system: <e.g. juice-shop>
- Date/Time (first detected): <YYYY-MM-DD HH:MM:SS UTC>
- Severity: Low / Medium / High / Critical
- Short description: One-sentence summary of what happened

## 2. Scope & Impact

- Affected components: (container, service, host VM, ports)
- Estimated impact: (data exposure, integrity loss, availability impact)
- Number of affected instances (if applicable)
- Business impact: (for lab use, describe academic impact)

## 3. Detection

- Detector used: `scripts/attack_detector.ps1` (or manual observation / ZAP findings)
- Detection method: log-monitoring, ZAP automated scan, manual report
- Detection timestamp: <YYYY-MM-DD HH:MM:SS UTC>
- Alert summary: (severity, message)
- Evidence files saved:
  - `data/reports/<target>/<timestamp>/zap-report.html`
  - `data/reports/<target>/<timestamp>/*` (logs, screenshots)
  - `data/alerts/alert_<target>_<timestamp>.json`

## 4. Timeline of Events

Provide a chronological timeline with timestamps (UTC) of all notable actions:

- T0: Service started (Docker run command)
- T1: Scanner/ZAP executed
- T2: Detector observed suspicious log lines
- T3: Alert posted to API `POST /alerts`
- T4: Evidence copied to `data/reports/...`
- T5: Investigator reviewed evidence and captured VM/container snapshot

(Replace with actual timestamps and descriptions.)

## 5. Technical Analysis

- Logs & snippets: include relevant log lines and file references.
- Reproduction steps (lab-only):
  1. Start the target container: `docker run -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop:latest`
  2. Run ZAP full scan: `docker run --rm -v ${PWD}:/zap/wrk/:rw -t owasp/zap2docker-stable zap-full-scan.py -t http://127.0.0.1:3000 -r zap-report.html`
  3. Import results: `.\scripts\import_scan.ps1 -target "juice-shop" -scanFile "zap-report.html"`
  4. Start detector: `.\scripts\attack_detector.ps1 -ContainerName juice-shop -ApiBase http://127.0.0.1:8000`
  5. Review evidence under `data/reports/juice-shop/<timestamp>/`

- Evidence summary: list filenames and short notes (e.g., `zap-report.html` shows reflected XSS in endpoint /search)

## 6. Remediation & Mitigation

- Immediate actions taken:
  - Isolate the affected container (stop container, remove network access)
  - Capture container/VM snapshot for forensics
  - Preserve log files and evidence folder
- Short-term fixes (config/dev):
  - Apply input validation and output encoding
  - Harden permissions and network restrictions
- Long-term recommendations:
  - Add authenticated access to admin endpoints
  - Integrate continuous monitoring and alerting

## 7. Evidence Packaging and Repository Inclusion

To include the incident as part of your thesis repository (safe demo only):

1. Copy the evidence folder to `data/reports/<target>/<timestamp>/` in the repo.
2. Ensure sensitive secrets are redacted before committing.
3. Add the alert JSON from `data/alerts/` if relevant.
4. Add a short summary file next to the evidence (`data/reports/<target>/<timestamp>/README.md`) describing what the files are.

Example Git commands:

```powershell
# Review files
ls data\reports\juice-shop\20250101_120000\

# Add only non-sensitive evidence
git add data/reports/juice-shop/20250101_120000
git commit -m "Add sample incident evidence for juice-shop (redacted)"
git push origin main
```

## 8. Appendix

- API endpoints used in the integration:
  - `GET /reports/list` — list imported reports
  - `GET /reports/static/<path>` — static access to evidence files
  - `POST /alerts` — submit an alert JSON to the system
  - `GET /alerts/list` — list recorded alerts

- Useful scripts in this repo:
  - `scripts/import_scan.ps1` — import scanner outputs into the repo
  - `scripts/attack_detector.ps1` — simple log-based detector that POSTs alerts
  - `scripts/commit_and_push.ps1` — helper to commit and optionally push changes

---

**Ethics & Legal**: Only include evidence in the public repository if it contains no sensitive personal data or credentials and you have permission to publish. Prefer redacted samples for public deliverables.
