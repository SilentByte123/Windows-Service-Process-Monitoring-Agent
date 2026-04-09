# Technical Documentation — Windows Service & Process Monitoring Agent

## Project Overview / Description
Agent monitors Windows processes and services to surface malicious, unauthorized, or suspicious behavior. It inspects parent-child process chains, startup services, and process locations to flag anomalies and produces human-readable and JSON reports.

## Practical Motivation
- Windows compromise paths often rely on malicious services, abnormal parent-child chains, persistence via startup entries, or fake executables in user-writable paths.
- Early detection of those behaviors reduces risk of malware execution, privilege escalation, and stealth persistence.

## Project Objectives
- Monitor active processes and evaluate parent-child behavior.
- Audit startup services for suspicious, newly registered, or modified entries.
- Detect unauthorized or unknown processes using whitelist and blacklist logic.
- Generate alerts from rule-based triggers and summarize them in reports.
- Produce a detailed report of anomalies and threats each sweep.

## Practical Scope of the Project
- Parent-Child Relationship Monitor: tracks PID and PPID, compares against `SUSPICIOUS_PARENT_CHILD` rules.
- Startup Service Audit: enumerates services via WMI, flags unusual paths or auto-start services from non-system locations, detects new or modified services using a baseline.
- Unauthorized Process Detection: maintains whitelist/blacklist, flags unsigned or unknown processes especially in user-writable directories (Temp/AppData/Public/Downloads).
- Reporting and Alert System: logs every alert to `logs/detections.log` and writes JSON and TXT reports under `reports/`.

## Tools & Technologies Used
- Python 3.9+.
- Modules: `psutil`, `wmi`, `pywin32`, `colorama`.
- PowerShell optional for operational use.
- Documentation/diagrams: Markdown (this file), README, and text flowchart.

## Practical Techniques Implemented
- Detection: behavior monitoring of parent-child process trees, service configuration auditing, whitelist/blacklist-driven detection, path-based persistence and escalation heuristics.
- Blue Team Focus: near real-time sweeps with interval control, high-severity flagging for suspicious runtime activity, identification of malicious service entries, reinforcement of system security baselines through service baselining.

## Workflow / Architecture (Practical Explanation)
- Step 1: Enumerate active processes with PID, PPID, name, exe path, cmdline, user, and start time (`process_snapshot` in `src/monitor.py`).
- Step 2: Build and evaluate parent-child chains (`detect_parent_child`) against rules in `src/config.py`.
- Step 3: Audit startup services via WMI (`collect_services`), reading baseline from `state/service_baseline.json` when `--use-baseline` is set.
- Step 4: Detect unauthorized processes with whitelist/blacklist plus user-writable path heuristics (`detect_unauthorized`).
- Step 5: Generate alerts, log them, and print console-friendly summaries (`format_alerts_for_console`, `setup_logging`).
- Step 6: Export structured JSON and human-readable TXT reports per sweep (`write_reports`).

## Flowchart (Text Version)
START → Enumerate Processes & Services → Analyze Parent-Child Chains → Audit Startup Services → Detect Unauthorized or Anomalous Processes → Generate Alerts → Export Reports → END

## Expected Practical Output
- Parent-child relationship anomalies with parent and child PIDs.
- Suspicious or newly added startup services and modified service configurations.
- Unauthorized or blacklisted processes, especially from Temp/AppData/Public/Downloads.
- Timestamped monitoring logs in `logs/detections.log`.
- Sweep reports in `reports/report-YYYYMMDD-HHMMSS.{json,txt}` containing alerts and metadata.

## Learning Outcomes
- Understanding Windows process architecture and service internals.
- Recognizing how malware abuses services and process trees for execution and persistence.
- Applying real-time monitoring techniques and rule-based detection logic.
- Practicing defensive security engineering with baselines and heuristic checks.

## Project Deliverables
- Monitoring agent toolkit: `src/monitor.py`, `src/config.py`, `src/reporting.py`, `requirements.txt`, optional whitelist at `whitelist.txt`.
- Baseline data: `state/service_baseline.json` for service drift detection.
- Logs and reports: `logs/detections.log`, `reports/` folder with JSON and TXT outputs.
- Project documentation: `README.md` and this `TECHNICAL_DOCUMENTATION.md`.
- Flowchart and workflow description: included in this documentation.
- Detection rules: embedded in `src/config.py` and extendable via CLI flags (`--whitelist`, `--blacklist`).

## How to Run and Validate
- Single sweep: `python -m src.monitor --once`.
- Continuous monitoring: `python -m src.monitor --interval 15`.
- Service drift detection: supply `--use-baseline --baseline-file state/service_baseline.json` and optionally `--update-baseline` after trusted runs.
- Custom lists: add entries to `whitelist.txt` or provide external files via CLI.

## Current Compliance Status
- Parent-child detection: Implemented and active.
- Startup service audit: Implemented; requires `wmi` availability; baseline support included.
- Unauthorized process monitoring: Implemented with whitelist/blacklist and path heuristics.
- Alerting and reporting: Implemented with console, log, JSON, and TXT outputs.
- Documentation and deliverables: Provided in `README.md` and this file; flowchart covered above.