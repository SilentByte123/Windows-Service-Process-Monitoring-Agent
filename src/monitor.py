import argparse
import getpass
import json
import platform
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import psutil
from colorama import Fore, Style, init as colorama_init

import src.config as cfg
from src.reporting import format_alerts_for_console, setup_logging, write_reports


def base_dir() -> Path:
    """Return directory to use for default artifacts (works in PyInstaller)."""
    if hasattr(sys, "_MEIPASS"):  # PyInstaller temp extract dir
        return Path(sys._MEIPASS)  # type: ignore[attr-defined]
    return Path(__file__).resolve().parent


def process_snapshot() -> list[dict[str, Any]]:
    snapshot: list[dict[str, Any]] = []
    for proc in psutil.process_iter(
        attrs=["pid", "ppid", "name", "exe", "cmdline", "username", "create_time"], ad_value=None
    ):
        info = proc.info
        info["name"] = (info.get("name") or "").lower()
        exe = info.get("exe") or ""
        info["exe"] = exe
        snapshot.append(info)
    return snapshot


def detect_parent_child(processes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    alerts: list[dict[str, Any]] = []
    by_pid = {p["pid"]: p for p in processes}
    for child in processes:
        parent = by_pid.get(child.get("ppid"))
        if not parent:
            continue
        parent_name = (parent.get("name") or "").lower()
        child_name = child.get("name") or ""
        suspicious_children = cfg.SUSPICIOUS_PARENT_CHILD.get(parent_name, [])
        if child_name in suspicious_children:
            alerts.append(
                {
                    "type": "parent_child",
                    "severity": "high",
                    "summary": f"Suspicious child process: {parent_name} -> {child_name}",
                    "parent": f"{parent_name} (PID {parent.get('pid')})",
                    "process": f"{child_name} (PID {child.get('pid')})",
                    "path": child.get("exe"),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
            )
    return alerts


def detect_unauthorized(
    processes: list[dict[str, Any]], whitelist: set[str], blacklist: set[str]
) -> list[dict[str, Any]]:
    alerts: list[dict[str, Any]] = []
    by_pid = {p["pid"]: p for p in processes}
    for proc in processes:
        name = proc.get("name") or ""
        exe = (proc.get("exe") or "").lower()
        if not name:
            continue
        if name in blacklist:
            alerts.append(
                {
                    "type": "blacklist",
                    "severity": "critical",
                    "summary": f"Blacklisted process running: {name}",
                    "process": f"{name} (PID {proc.get('pid')})",
                    "path": proc.get("exe"),
                    "reason": "process name in blacklist",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
            )
            continue

        if name in whitelist:
            continue

        path_flag = any(keyword in exe for keyword in cfg.USER_WRITABLE_DIR_KEYWORDS)
        system_path_flag = exe.startswith("c:\\windows\\") or exe.startswith("c:\\program files")
        suspicious_name = any(name == pat for pat in cfg.SUSPICIOUS_NAME_PATTERNS)

        parent = by_pid.get(proc.get("ppid"))
        parent_name = (parent.get("name") or "") if parent else ""

        if suspicious_name:
            severity = "high"
            reason = "lookalike/suspicious process name"
        elif path_flag:
            severity = "high"
            reason = "unauthorized process in user-writable path"
        elif system_path_flag:
            severity = "low"
            reason = "unauthorized process in system/program files path"
        else:
            severity = "medium"
            reason = "unauthorized process"
        alerts.append(
            {
                "type": "unauthorized_process",
                "severity": severity,
                "summary": f"{reason}: {name}",
                "process": f"{name} (PID {proc.get('pid')})",
                "path": proc.get("exe"),
                "parent": f"{parent_name} (PID {parent.get('pid')})" if parent else None,
                "reason": reason,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )
    return alerts


def collect_services() -> tuple[list[dict[str, Any]], str | None]:
    """Return list of services with basic metadata. Uses WMI, falls back to psutil."""
    # Try WMI first (richer data on Windows)
    try:
        import wmi  # type: ignore

        c = wmi.WMI()
        services = c.Win32_Service()
        svc_list: list[dict[str, Any]] = []
        for svc in services:
            try:
                svc_list.append(
                    {
                        "name": (svc.Name or "").lower(),
                        "display": (svc.DisplayName or svc.Name or "").strip(),
                        "path": (svc.PathName or "").lower(),
                        "start_mode": (svc.StartMode or "").lower(),
                        "state": (svc.State or "").lower(),
                    }
                )
            except Exception:
                continue
        return svc_list, None
    except Exception:
        pass  # fall through to psutil

    # Fallback: psutil service iterator (may miss some fields but avoids hard fail)
    svc_list: list[dict[str, Any]] = []
    try:
        for svc in psutil.win_service_iter():  # type: ignore[attr-defined]
            try:
                info = svc.as_dict()
                svc_list.append(
                    {
                        "name": (info.get("name") or "").lower(),
                        "display": (info.get("display_name") or info.get("name") or "").strip(),
                        "path": (info.get("binpath") or "").lower(),
                        "start_mode": (info.get("start_type") or "").lower(),
                        "state": (info.get("status") or "").lower(),
                    }
                )
            except Exception:
                continue
        if not svc_list:
            return [], "Service audit skipped (psutil returned no services)"
        return svc_list, None
    except Exception as exc:  # pragma: no cover
        return [], f"Service audit skipped (no provider available: {exc})"


def detect_service_anomalies(services: list[dict[str, Any]]) -> list[dict[str, Any]]:
    alerts: list[dict[str, Any]] = []
    for svc in services:
        path_flag = any(keyword in svc.get("path", "") for keyword in cfg.SERVICE_SUSPICIOUS_PATH_KEYWORDS)
        mode_flag = svc.get("start_mode") in cfg.SERVICE_START_MODE_SUSPICIOUS
        if path_flag and mode_flag:
            alerts.append(
                {
                    "type": "service_anomaly",
                    "severity": "high",
                    "summary": f"Auto-start service from unusual path: {svc.get('display') or svc.get('name')}",
                    "details": svc.get("path"),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
            )
    return alerts


def load_service_baseline(path: Path) -> dict[str, dict[str, str]]:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return {k.lower(): {"path": v.get("path", "").lower(), "start_mode": v.get("start_mode", "").lower()} for k, v in data.items()}
    except Exception:
        return {}


def save_service_baseline(path: Path, services: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        svc.get("name", "").lower(): {
            "path": svc.get("path", ""),
            "start_mode": svc.get("start_mode", ""),
        }
        for svc in services
        if svc.get("name")
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def detect_service_drift(
    services: list[dict[str, Any]], baseline: dict[str, dict[str, str]] | None
) -> list[dict[str, Any]]:
    if baseline is None:
        return []
    alerts: list[dict[str, Any]] = []
    for svc in services:
        name = svc.get("name")
        if not name:
            continue
        record = baseline.get(name)
        if record is None:
            alerts.append(
                {
                    "type": "service_new",
                    "severity": "medium",
                    "summary": f"New service detected since baseline: {svc.get('display') or name}",
                    "details": svc.get("path"),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
            )
            continue

        path_changed = record.get("path") != svc.get("path")
        mode_changed = record.get("start_mode") != svc.get("start_mode")
        if path_changed or mode_changed:
            reason = []
            if path_changed:
                reason.append("path")
            if mode_changed:
                reason.append("start mode")
            alerts.append(
                {
                    "type": "service_modified",
                    "severity": "high",
                    "summary": f"Service changed ({', '.join(reason)}): {svc.get('display') or name}",
                    "details": f"path='{svc.get('path')}', start_mode='{svc.get('start_mode')}'",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
            )
    return alerts


def merge_lists(*lists: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for lst in lists:
        out.extend(lst)
    return out


def load_lists(whitelist_path: Path | None, blacklist_path: Path | None) -> tuple[set[str], set[str]]:
    whitelist = set(cfg.DEFAULT_WHITELIST)
    blacklist = set(cfg.DEFAULT_BLACKLIST)
    if whitelist_path:
        whitelist |= cfg.load_custom_list(whitelist_path)
    if blacklist_path:
        blacklist |= cfg.load_custom_list(blacklist_path)
    return set(map(str.lower, whitelist)), set(map(str.lower, blacklist))


def gather_metadata() -> dict[str, Any]:
    return {
        "hostname": platform.node(),
        "username": getpass.getuser(),
        "platform": platform.platform(),
        "python": sys.version.split()[0],
    }


def sweep(args: argparse.Namespace, logger) -> list[dict[str, Any]]:
    start = time.time()
    processes = process_snapshot()
    whitelist, blacklist = load_lists(args.whitelist, args.blacklist)

    pc_alerts = detect_parent_child(processes)
    unauth_alerts = detect_unauthorized(processes, whitelist, blacklist)
    service_alerts: list[dict[str, Any]] = []
    service_skip_reason = None
    if not args.no_services:
        baseline = None
        if args.use_baseline:
            baseline = load_service_baseline(args.baseline_file)

        services, service_skip_reason = collect_services()
        if service_skip_reason:
            logger.info(service_skip_reason)
        else:
            service_alerts = detect_service_anomalies(services)
            service_alerts += detect_service_drift(services, baseline)

            if args.update_baseline:
                save_service_baseline(args.baseline_file, services)
                logger.info(f"Service baseline updated: {args.baseline_file}")

    alerts = merge_lists(pc_alerts, unauth_alerts, service_alerts)

    metadata = gather_metadata()
    metadata["duration_seconds"] = round(time.time() - start, 2)
    metadata["process_count"] = len(processes)
    metadata["alerts"] = len(alerts)

    json_path, txt_path = write_reports(args.report_dir, alerts, metadata)
    for alert in alerts:
        logger.warning(f"{alert.get('severity','info').upper()} | {alert.get('summary')}")
    logger.info(f"Sweep finished in {metadata['duration_seconds']}s | alerts: {len(alerts)} | report: {txt_path.name}")
    return alerts


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Windows Service & Process Monitoring Agent")
    parser.add_argument("--interval", type=int, default=10, help="Seconds between sweeps (ignored with --once)")
    parser.add_argument("--once", action="store_true", help="Run a single sweep and exit")
    parser.add_argument(
        "--whitelist",
        type=Path,
        default=base_dir() / "whitelist.txt",
        help="Path to additional whitelist file (one name per line)",
    )
    parser.add_argument("--blacklist", type=Path, help="Path to additional blacklist file (one name per line)")
    parser.add_argument(
        "--log-dir", type=Path, default=base_dir() / "logs", help="Directory for detection.log"
    )
    parser.add_argument(
        "--report-dir", type=Path, default=base_dir() / "reports", help="Directory for sweep reports"
    )
    parser.add_argument("--no-services", action="store_true", help="Skip startup/service audit")
    parser.add_argument(
        "--use-baseline",
        action="store_true",
        help="Compare services against baseline file to flag new/modified entries",
    )
    parser.add_argument(
        "--baseline-file",
        type=Path,
        default=base_dir() / "state" / "service_baseline.json",
        help="Path to service baseline JSON (used with --use-baseline)",
    )
    parser.add_argument(
        "--update-baseline",
        action="store_true",
        help="Write current services to the baseline file after the sweep",
    )
    return parser.parse_args()


def main() -> None:
    colorama_init(autoreset=True)
    args = parse_args()
    logger = setup_logging(args.log_dir)

    while True:
        alerts = sweep(args, logger)
        if alerts:
            print(Fore.RED + format_alerts_for_console(alerts))
        else:
            print(Fore.GREEN + "No alerts this sweep.")

        if args.once:
            break
        time.sleep(max(1, args.interval))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(Style.RESET_ALL + "\nInterrupted. Exiting.")
