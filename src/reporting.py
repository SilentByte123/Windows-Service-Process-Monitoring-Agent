import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

def setup_logging(log_dir: Path) -> logging.Logger:
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / "detections.log"
    logger = logging.getLogger("monitor")
    logger.setLevel(logging.INFO)
    if not logger.handlers:
        handler = logging.FileHandler(log_file, encoding="utf-8")
        formatter = logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        console = logging.StreamHandler()
        console.setFormatter(formatter)
        logger.addHandler(console)
    return logger

def write_reports(report_dir: Path, alerts: list[dict[str, Any]], metadata: dict[str, Any]) -> tuple[Path, Path]:
    report_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    json_path = report_dir / f"report-{ts}.json"
    txt_path = report_dir / f"report-{ts}.txt"

    payload = {"generated_utc": ts, "metadata": metadata, "alerts": alerts}
    json_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    # severity counts
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for a in alerts:
        sev_counts[a.get("severity", "low").lower()] = sev_counts.get(a.get("severity", "low").lower(), 0) + 1

    lines = [
        f"Detection Report @ {ts}Z",
        "-" * 60,
        f"Host: {metadata.get('hostname')}",
        f"User: {metadata.get('username')}",
        f"Sweep duration: {metadata.get('duration_seconds', 'n/a')}s",
        f"Alerts: {len(alerts)}",
        f"By severity: critical={sev_counts['critical']} high={sev_counts['high']} medium={sev_counts['medium']} low={sev_counts['low']}",
        f"Processes scanned: {metadata.get('process_count','n/a')}",
        "",
    ]
    for idx, alert in enumerate(alerts, 1):
        lines.append(f"[{idx}] {alert.get('severity','info').upper()} | {alert.get('type')} | {alert.get('summary')}")
        for k in ("process", "parent", "path", "details", "reason"):
            if alert.get(k):
                lines.append(f"    {k}: {alert[k]}")
        lines.append("")
    txt_path.write_text("\n".join(lines), encoding="utf-8")
    return json_path, txt_path

def format_alerts_for_console(alerts: Iterable[dict[str, Any]]) -> str:
    parts = []
    for alert in alerts:
        parts.append(
            f"{alert.get('severity','info').upper():<7} | {alert.get('type','?'):<18} | {alert.get('summary','')}"
        )
    return "\n".join(parts)
