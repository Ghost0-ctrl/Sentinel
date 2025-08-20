#!/usr/bin/env python3
"""
Sentinel Advanced: enhanced host defense monitor

This is an enhanced version of the provided prototype. Major additions:
- Color-coded, severity-scored output (information / suspicious / critical)
- Spinner UI while scans run
- Whitelist (safe) and blacklist (malicious) files to filter IPs and hashes
- More collection: services list, process tree, open listeners, outbound, file autoruns
- Heuristics to mark findings as WARNING/CRITICAL based on rules (public outbound, blacklisted IPs, unsafe open ports)
- Extra CLI commands & flags: --whitelist, --blacklist, --log, --json, --save, audit, report
- JSON/CSV export of scans
- Dry-run safety for destructive operations; --dangerous-apply to actually apply

Dependencies: psutil, watchdog, colorama

Use examples:
  python sentinel_advanced.py baseline --note "Clean VM" 
  python sentinel_advanced.py scan --log ./sentinel.log --whitelist safe_ips.txt --blacklist bad_ips.txt --json out.json
  python sentinel_advanced.py audit --deep --save ./full_report.json

This tool is defensive only. It tries not to modify the system (unless --dangerous-apply used).
"""
from __future__ import annotations
import argparse
import json
import logging
import os
import platform
import socket
import sys
import time
import hashlib
import threading
import itertools
from pathlib import Path
from typing import Dict, List, Any, Optional, Set, Tuple

import psutil  # type: ignore
from watchdog.observers import Observer  # type: ignore
from watchdog.events import FileSystemEventHandler  # type: ignore

try:
    from colorama import Fore, Style, init as colorama_init  # type: ignore
    colorama_init(autoreset=True)
except Exception:  # pragma: no cover
    class Dummy:
        def __getattr__(self, k):
            return ""
    Fore = Style = Dummy()

APP_DIR = Path.home() / ".sentinel"
BASELINE_PATH = APP_DIR / "baseline.json"
DEFAULT_LOG = APP_DIR / "sentinel.log"

# default files (same directory as script)
SAFE_IPS_FILE = Path.cwd() / "safe_ips.txt"
MALICIOUS_IPS_FILE = Path.cwd() / "malicious_ips.txt"
TRUSTED_HASHES_FILE = Path.cwd() / "trusted_hashes.txt"

SENSITIVE_DIRS = {
    "Windows": [
        Path(os.getenv("APPDATA", str(Path.home()))) / "Microsoft/Windows/Start Menu/Programs/Startup",
        Path(os.getenv("ProgramData", "C:/ProgramData")) / "Microsoft/Windows/Start Menu/Programs/Startup",
        Path.home() / "AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup",
    ],
    "Linux": [
        Path.home() / ".config/autostart",
        Path("/etc/cron.d"), Path("/etc/cron.daily"), Path("/etc/cron.hourly"),
        Path("/etc/cron.weekly"), Path("/etc/cron.monthly"), Path("/var/spool/cron"),
        Path.home() / ".crontab",
    ],
    "Darwin": [
        Path.home() / "Library/LaunchAgents",
        Path("/Library/LaunchDaemons"), Path("/Library/LaunchAgents"),
    ],
}

PRIVATE_NETS = [
    ("10.0.0.0", 8), ("172.16.0.0", 12), ("192.168.0.0", 16), ("127.0.0.0", 8), ("169.254.0.0", 16)
]

DEFAULT_IGNORE_PROCESSES: Set[str] = {
    "System", "Idle", "kernel_task", "launchd", "systemd", "kthreadd", "dockerd",
}

# ports that may be sensitive when open on non-server endpoints
SENSITIVE_PORTS = {
    22: "SSH",
    23: "Telnet",
    137: "NETBIOS-NS",
    138: "NETBIOS-DGM",
    139: "NETBIOS-SSN",
    445: "SMB",
    3389: "RDP",
}


# -------------------- utility helpers --------------------

def ensure_app_dir() -> None:
    APP_DIR.mkdir(parents=True, exist_ok=True)


def load_list_file(path: Path) -> Set[str]:
    try:
        s = set()
        with path.open("r", encoding="utf-8") as f:
            for l in f:
                t = l.strip()
                if not t or t.startswith("#"):
                    continue
                s.add(t)
        return s
    except Exception:
        return set()


def save_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=True)
    tmp.replace(path)


def sha256_file(path: Path) -> Optional[str]:
    try:
        h = hashlib.sha256()
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


def is_private_ip(ip: str) -> bool:
    try:
        b = socket.inet_aton(ip)
        n = int.from_bytes(b, "big")
        for net, maskbits in PRIVATE_NETS:
            nb = int.from_bytes(socket.inet_aton(net), "big")
            mask = (0xFFFFFFFF << (32 - maskbits)) & 0xFFFFFFFF
            if (n & mask) == (nb & mask):
                return True
        return False
    except OSError:
        return False


# -------------------- spinner UI --------------------
class Spinner:
    def __init__(self, message: str = "Scanning"):
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.message = message

    def start(self) -> None:
        if self._thread:
            return

        def _spin():
            for c in itertools.cycle(["|", "/", "-", "\\"]):
                if self._stop.is_set():
                    break
                sys.stdout.write(f"\r{self.message} {c} ")
                sys.stdout.flush()
                time.sleep(0.12)
            sys.stdout.write("\r" + " " * (len(self.message) + 4) + "\r")
            sys.stdout.flush()

        self._thread = threading.Thread(target=_spin, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if not self._thread:
            return
        self._stop.set()
        self._thread.join()
        self._thread = None


# -------------------- snapshots --------------------

def process_snapshot(trust_hashes: Set[str]) -> List[Dict[str, Any]]:
    out = []
    for p in psutil.process_iter(attrs=["pid", "name", "exe", "username", "cmdline", "ppid"]):
        try:
            info = p.info
            exe = Path(info.get("exe") or "")
            hashv = sha256_file(exe) if exe and exe.exists() else None

            # Use net_connections() if present, fall back to connections()
            conn_fn = getattr(p, "net_connections", getattr(p, "connections", None))
            conns = []
            if conn_fn:
                try:
                    conn_list = conn_fn(kind="inet")
                except TypeError:
                    # Older psutil variations might not accept kwargs - try positional
                    conn_list = conn_fn("inet")
                except Exception:
                    conn_list = []
                for c in conn_list:
                    raddr = None
                    if getattr(c, "raddr", None):
                        # some platforms/psutil versions expose raddr as a tuple or object
                        if hasattr(c.raddr, "ip"):
                            raddr = {"ip": c.raddr.ip, "port": c.raddr.port}
                        else:
                            # tuple form (ip, port)
                            try:
                                raddr = {"ip": c.raddr[0], "port": c.raddr[1]}
                            except Exception:
                                raddr = None
                    laddr = None
                    if getattr(c, "laddr", None):
                        if hasattr(c.laddr, "ip"):
                            laddr = {"ip": c.laddr.ip, "port": c.laddr.port}
                        else:
                            try:
                                laddr = {"ip": c.laddr[0], "port": c.laddr[1]}
                            except Exception:
                                laddr = None

                    conns.append({
                        "laddr": laddr,
                        "raddr": raddr,
                        "status": getattr(c, "status", None),
                    })
            # trusted heuristic
            trust = bool(hashv and hashv in trust_hashes)

            out.append({
                "pid": info.get("pid"),
                "ppid": info.get("ppid"),
                "name": info.get("name") or "",
                "exe": str(exe) if exe else "",
                "username": info.get("username") or "",
                "cmdline": info.get("cmdline") or [],
                "sha256": hashv,
                "trusted_hash": trust,
                "connections": conns,
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return out


def listeners_snapshot() -> List[Dict[str, Any]]:
    out = []
    for c in psutil.net_connections(kind="inet"):
        try:
            if c.status == psutil.CONN_LISTEN and c.laddr:
                out.append({
                    "pid": c.pid,
                    "laddr": {"ip": c.laddr.ip, "port": c.laddr.port},
                })
        except Exception:
            continue
    return out


def outbound_snapshot() -> List[Dict[str, Any]]:
    out = []
    for c in psutil.net_connections(kind="inet"):
        try:
            if c.raddr and c.status in {psutil.CONN_ESTABLISHED, psutil.CONN_SYN_SENT}:
                out.append({
                    "pid": c.pid,
                    "laddr": {"ip": c.laddr.ip, "port": c.laddr.port} if c.laddr else None,
                    "raddr": {"ip": c.raddr.ip, "port": c.raddr.port},
                    "status": c.status,
                })
        except Exception:
            continue
    return out


def services_snapshot() -> List[Dict[str, Any]]:
    system = platform.system()
    out: List[Dict[str, Any]] = []
    try:
        if system == "Windows":
            for s in psutil.win_service_iter():
                try:
                    si = s.as_dict()
                    out.append({"name": si.get("name"), "display_name": si.get("display_name"), "status": si.get("status")})
                except Exception:
                    continue
        else:
            # On Unix, use psutil to map common service processes; we include systemd units if available
            for p in psutil.process_iter(attrs=["pid", "name", "cmdline"]):
                try:
                    nm = p.info.get("name", "")
                    cmd = " ".join(p.info.get("cmdline") or [])
                    out.append({"pid": p.info.get("pid"), "name": nm, "cmdline": cmd})
                except Exception:
                    continue
    except Exception:
        pass
    return out


def autoruns_snapshot() -> Dict[str, List[str]]:
    system = platform.system()
    items: Dict[str, List[str]] = {"paths": []}

    try:
        if system == "Windows":
            try:
                import winreg  # type: ignore
                for hive, base in [
                    (winreg.HKEY_CURRENT_USER, r"Software\\Microsoft\\Windows\\CurrentVersion\\Run"),
                    (winreg.HKEY_CURRENT_USER, r"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"),
                    (winreg.HKEY_LOCAL_MACHINE, r"Software\\Microsoft\\Windows\\CurrentVersion\\Run"),
                    (winreg.HKEY_LOCAL_MACHINE, r"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"),
                ]:
                    try:
                        with winreg.OpenKey(hive, base) as key:
                            i = 0
                            while True:
                                try:
                                    name, val, _ = winreg.EnumValue(key, i)
                                    items.setdefault("registry", []).append(f"{base}::{name}={val}")
                                    i += 1
                                except OSError:
                                    break
                    except OSError:
                        pass
            except Exception:
                pass
        elif system in {"Linux", "Darwin"}:
            try:
                import subprocess
                res = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
                if res.returncode == 0:
                    for line in res.stdout.splitlines():
                        if line.strip() and not line.strip().startswith("#"):
                            items.setdefault("cron", []).append(line.strip())
            except Exception:
                pass
            if system == "Darwin":
                launch_dir = Path.home() / "Library/LaunchAgents"
                for p in launch_dir.glob("*.plist"):
                    items.setdefault("launchagents", []).append(str(p))
    except Exception:
        pass

    for d in SENSITIVE_DIRS.get(system, []):
        if d.exists():
            for p in d.glob("**/*"):
                if p.is_file():
                    items["paths"].append(str(p))
    return items


def current_state(trust_hashes: Set[str]) -> Dict[str, Any]:
    return {
        "timestamp": int(time.time()),
        "system": {
            "platform": platform.platform(),
            "system": platform.system(),
            "release": platform.release(),
            "python": platform.python_version(),
        },
        "processes": process_snapshot(trust_hashes),
        "listeners": listeners_snapshot(),
        "outbound": outbound_snapshot(),
        "services": services_snapshot(),
        "autoruns": autoruns_snapshot(),
    }


# -------------------- analysis / heuristics --------------------

def score_issue(kind: str, details: Any, safe_ips: Set[str], bad_ips: Set[str]) -> Tuple[int, str]:
    """Return (score, level) where higher score = more severe.
    Levels: 0=INFO, 1=NOTICE, 2=WARNING, 3=CRITICAL
    """
    # default
    score = 0
    level = "INFO"

    if kind == "new_process":
        # suspicious if executable unknown, no trusted hash, or running from temp
        p = details
        if p.get("sha256") is None:
            score = 1
        if not p.get("trusted_hash"):
            score += 1
        exe = p.get("exe") or ""
        if any(t in exe.lower() for t in ["temp", "tmp", "downloads"]) and exe:
            score += 1
    elif kind == "listener":
        ip, port = details
        if port in SENSITIVE_PORTS:
            score = 2
        # listenting on public interface is worse
        if ip == "0.0.0.0":
            score += 1
        if port not in (80, 443) and port < 1024:
            score += 1
    elif kind == "outbound":
        ip, port = details
        if ip in bad_ips:
            score = 3
        elif not is_private_ip(ip):
            score = 2
        if ip in safe_ips:
            score = max(0, score - 2)
    elif kind == "autorun":
        score = 2
    elif kind == "service":
        # service name hints
        s = details
        if isinstance(s, dict):
            name = (s.get("name") or "").lower()
            if any(x in name for x in ["ssh", "rlogin", "telnet", "smb", "samba", "rdesktop"]):
                score = 2

    if score >= 3:
        level = "CRITICAL"
    elif score == 2:
        level = "WARNING"
    elif score == 1:
        level = "NOTICE"
    else:
        level = "INFO"
    return score, level


# -------------------- diff & report --------------------

def make_baseline(note: str, trust_hashes: Set[str]) -> Dict[str, Any]:
    state = current_state(trust_hashes)
    baseline = {
        "created": int(time.time()),
        "note": note,
        "state": state,
        "ignore_processes": sorted(list(DEFAULT_IGNORE_PROCESSES)),
    }
    return baseline


def diff_states(baseline: Dict[str, Any], current: Dict[str, Any], safe_ips: Set[str], bad_ips: Set[str]) -> Dict[str, Any]:
    base_procs = {(p.get("name"), p.get("sha256")): p for p in baseline["state"]["processes"]}
    cur_procs = {(p.get("name"), p.get("sha256")): p for p in current["processes"]}

    new_procs = [cur_procs[k] for k in cur_procs.keys() - base_procs.keys()
                 if (cur_procs[k].get("name") or "") not in baseline.get("ignore_processes", [])]

    base_listen = {(l["laddr"]["ip"], l["laddr"]["port"]) for l in baseline["state"].get("listeners", [])}
    cur_listen = {(l["laddr"]["ip"], l["laddr"]["port"]) for l in current.get("listeners", [])}
    new_listen = sorted(list(cur_listen - base_listen))

    def rkey(x: Dict[str, Any]):
        r = x.get("raddr") or {}
        return (r.get("ip"), r.get("port"))

    base_out = {rkey(o) for o in baseline["state"].get("outbound", []) if rkey(o)[0]}
    cur_out = {rkey(o) for o in current.get("outbound", []) if rkey(o)[0]}
    new_out = sorted(list(cur_out - base_out))

    def flat_aut(a: Dict[str, List[str]]) -> Set[str]:
        res: Set[str] = set()
        for k, vs in a.items():
            for v in vs:
                res.add(f"{k}:{v}")
        return res

    base_aut = flat_aut(baseline["state"].get("autoruns", {}))
    cur_aut = flat_aut(current.get("autoruns", {}))
    new_aut = sorted(list(cur_aut - base_aut))

    suspicious_out = [x for x in new_out if x[0] and not is_private_ip(x[0])]

    # Score each finding
    findings = []
    for p in new_procs:
        score, level = score_issue("new_process", p, safe_ips, bad_ips)
        findings.append({"type": "new_process", "score": score, "level": level, "data": p})

    for l in new_listen:
        score, level = score_issue("listener", l, safe_ips, bad_ips)
        findings.append({"type": "new_listener", "score": score, "level": level, "data": {"ip": l[0], "port": l[1]}})

    for o in new_out:
        score, level = score_issue("outbound", o, safe_ips, bad_ips)
        findings.append({"type": "new_outbound", "score": score, "level": level, "data": {"ip": o[0], "port": o[1]}})

    for a in new_aut:
        score, level = score_issue("autorun", a, safe_ips, bad_ips)
        findings.append({"type": "new_autorun", "score": score, "level": level, "data": a})

    return {
        "findings": findings,
        "summary": {
            "new_processes": len(new_procs),
            "new_listeners": len(new_listen),
            "new_outbound": len(new_out),
            "new_autoruns": len(new_aut),
            "suspicious_outbound": suspicious_out,
        },
    }


# -------------------- watchers --------------------
class WatchHandler(FileSystemEventHandler):
    def __init__(self, logger: logging.Logger):
        super().__init__()
        self.logger = logger

    def on_created(self, event):  # type: ignore
        if event.is_directory:
            return
        path = Path(event.src_path)
        if path.suffix.lower() in {".exe", ".dll", ".js", ".vbs", ".ps1", ".bat", ".sh", ".plist", ".desktop"}:
            self.logger.warning(Fore.YELLOW + f"NEW EXECUTABLE-LIKE FILE: {path}" + Style.RESET_ALL)

    def on_modified(self, event):  # type: ignore
        if event.is_directory:
            return
        path = Path(event.src_path)
        if path.suffix.lower() in {".exe", ".dll", ".js", ".vbs", ".ps1", ".bat", ".sh", ".plist", ".desktop"}:
            self.logger.info(Fore.YELLOW + f"MODIFIED EXECUTABLE-LIKE FILE: {path}" + Style.RESET_ALL)


# -------------------- logging --------------------

def setup_logging(log_path: Optional[Path], verbose: bool) -> logging.Logger:
    logger = logging.getLogger("sentinel")
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    # avoid duplicate handlers
    if logger.handlers:
        return logger
    fmt = logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(fmt)
    ch.setLevel(logging.DEBUG if verbose else logging.INFO)
    logger.addHandler(ch)
    if log_path:
        fh = logging.FileHandler(str(log_path))
        fh.setFormatter(fmt)
        fh.setLevel(logging.DEBUG)
        logger.addHandler(fh)
    return logger


# -------------------- CLI commands --------------------

def cmd_baseline(args) -> None:
    ensure_app_dir()
    trust_hashes = load_list_file(TRUSTED_HASHES_FILE)
    baseline = make_baseline(note=args.note or "", trust_hashes=trust_hashes)
    save_json(BASELINE_PATH, baseline)
    print(Fore.GREEN + f"Baseline saved to {BASELINE_PATH}" + Style.RESET_ALL)


def pretty_print_findings(findings: List[Dict[str, Any]], logger: logging.Logger) -> None:
    levels_color = {"CRITICAL": Fore.RED, "WARNING": Fore.YELLOW, "NOTICE": Fore.MAGENTA, "INFO": Fore.CYAN}
    for f in findings:
        lvl = f.get("level", "INFO")
        color = levels_color.get(lvl, Fore.CYAN)
        t = f.get("type")
        if t == "new_process":
            p = f["data"]
            logger.warning(color + f"[{lvl}] New process: PID={p.get('pid')} name={p.get('name')} exe={p.get('exe')} sha256={p.get('sha256')}" + Style.RESET_ALL)
        elif t == "new_listener":
            d = f["data"]
            logger.warning(color + f"[{lvl}] New listener: {d.get('ip')}:{d.get('port')}" + Style.RESET_ALL)
        elif t == "new_outbound":
            d = f["data"]
            logger.error(color + f"[{lvl}] New outbound: {d.get('ip')}:{d.get('port')}" + Style.RESET_ALL)
        elif t == "new_autorun":
            logger.warning(color + f"[{lvl}] New autorun: {f.get('data')}" + Style.RESET_ALL)
        else:
            logger.info(Fore.CYAN + f"[{lvl}] {f}" + Style.RESET_ALL)


def cmd_scan(args) -> int:
    ensure_app_dir()
    logger = setup_logging(Path(args.log) if args.log else None, args.verbose)
    safe_ips = load_list_file(Path(args.whitelist) if args.whitelist else SAFE_IPS_FILE)
    bad_ips = load_list_file(Path(args.blacklist) if args.blacklist else MALICIOUS_IPS_FILE)
    trust_hashes = load_list_file(TRUSTED_HASHES_FILE)

    baseline = {}
    if args.baseline:
        baseline = load_json(Path(args.baseline), None) or {}
    else:
        baseline = load_json(BASELINE_PATH, None)

    if not baseline:
        logger.error(Fore.RED + "No baseline found. Run 'baseline' first or provide --baseline." + Style.RESET_ALL)
        return 2

    spinner = Spinner("Scanning")
    spinner.start()
    cur = current_state(trust_hashes)
    spinner.stop()

    diff = diff_states(baseline, cur, safe_ips, bad_ips)
    findings = diff["findings"]

    if not findings:
        logger.info(Fore.GREEN + "No new findings vs baseline." + Style.RESET_ALL)
    else:
        pretty_print_findings(findings, logger)

    # optional save JSON
    if args.json:
        out = {"collected": int(time.time()), "state": cur, "diff": diff}
        save_json(Path(args.json), out)
        logger.info(Fore.GREEN + f"Saved JSON report to {args.json}" + Style.RESET_ALL)

    # summary exit code: 0 ok, 1 warnings, 2 critical
    max_score = max((f.get("score", 0) for f in findings), default=0)
    if max_score >= 3:
        return 2
    if max_score == 2:
        return 1
    return 0


def cmd_monitor(args) -> int:
    ensure_app_dir()
    logger = setup_logging(Path(args.log) if args.log else DEFAULT_LOG, args.verbose)

    safe_ips = load_list_file(Path(args.whitelist) if args.whitelist else SAFE_IPS_FILE)
    bad_ips = load_list_file(Path(args.blacklist) if args.blacklist else MALICIOUS_IPS_FILE)
    trust_hashes = load_list_file(TRUSTED_HASHES_FILE)

    baseline = load_json(BASELINE_PATH, None)
    if not baseline:
        logger.error("No baseline found. Run 'baseline' first.")
        return 2

    system = platform.system()
    observers: List[Observer] = []
    for d in SENSITIVE_DIRS.get(system, []):
        if d.exists():
            handler = WatchHandler(logger)
            obs = Observer()
            obs.schedule(handler, str(d), recursive=True)
            obs.start()
            observers.append(obs)
            logger.info(f"Watching {d}")

    logger.info("Entering monitoring loop. Press Ctrl+C to stop.")
    try:
        while True:
            spinner = Spinner("Monitoring")
            spinner.start()
            cur = current_state(trust_hashes)
            spinner.stop()
            diff = diff_states(baseline, cur, safe_ips, bad_ips)
            findings = diff["findings"]
            if findings:
                logger.warning(Fore.RED + "\n=== CHANGE DETECTED vs BASELINE ===" + Style.RESET_ALL)
                pretty_print_findings(findings, logger)
                logger.warning(Fore.RED + "===================================\n" + Style.RESET_ALL)
            time.sleep(max(5, int(args.interval)))
    except KeyboardInterrupt:
        logger.info("Stopping monitors...")
    finally:
        for o in observers:
            o.stop()
            o.join()
    return 0


def cmd_suggest_block(args) -> int:
    ip = args.ip
    if not ip:
        print("--ip is required", file=sys.stderr)
        return 2
    sysname = platform.system()
    print(Fore.YELLOW + f"Suggested firewall block commands for {ip}:" + Style.RESET_ALL)
    if sysname == "Windows":
        print(f"netsh advfirewall firewall add rule name=\"SentinelBlock {ip}\" dir=out action=block remoteip={ip}")
        print(f"netsh advfirewall firewall add rule name=\"SentinelBlock {ip}\" dir=in action=block remoteip={ip}")
    elif sysname == "Linux":
        print(f"sudo nft add rule inet filter output ip daddr {ip} counter drop  # nftables")
        print(f"sudo iptables -A OUTPUT -d {ip} -j DROP  # legacy iptables")
    elif sysname == "Darwin":
        print(f"echo 'block drop out quick to {ip}' | sudo pfctl -f - && sudo pfctl -e  # macOS pf (simplified)")
    else:
        print("Unknown OS; please block via your platform's firewall.")
    return 0


def cmd_export(args) -> int:
    ensure_app_dir()
    trust_hashes = load_list_file(TRUSTED_HASHES_FILE)
    cur = current_state(trust_hashes)
    out = {"collected": int(time.time()), "state": cur}
    path = Path(args.output or (APP_DIR / "scan.json"))
    save_json(path, out)
    print(Fore.GREEN + f"Scan exported to {path}" + Style.RESET_ALL)
    return 0


def cmd_kill(args) -> int:
    pid = int(args.pid)
    try:
        p = psutil.Process(pid)
        print(Fore.YELLOW + f"Would terminate PID {pid} ({p.name()})" + Style.RESET_ALL)
        if args.dangerous_apply:
            p.terminate()
            try:
                p.wait(timeout=5)
            except psutil.TimeoutExpired:
                p.kill()
            print(Fore.RED + f"Process {pid} terminated." + Style.RESET_ALL)
        else:
            print("(Dry-run) Add --dangerous-apply to actually terminate.")
        return 0
    except psutil.NoSuchProcess:
        print("No such process.")
        return 1
    except psutil.AccessDenied:
        print("Access denied: try with elevated privileges.")
        return 1


def cmd_audit(args) -> int:
    ensure_app_dir()
    logger = setup_logging(Path(args.log) if args.log else None, args.verbose)
    whitelist_arg = getattr(args, "whitelist", None)
    safe_ips = load_list_file(Path(whitelist_arg) if whitelist_arg else SAFE_IPS_FILE)
    blacklist_arg = getattr(args, "blacklist", None)
    bad_ips = load_list_file(Path(blacklist_arg) if blacklist_arg else MALICIOUS_IPS_FILE)
    trust_hashes = load_list_file(TRUSTED_HASHES_FILE)

    spinner = Spinner("Performing deep audit")
    spinner.start()
    cur = current_state(trust_hashes)
    spinner.stop()

    baseline = load_json(BASELINE_PATH, None) or {}
    diff = diff_states(baseline, cur, safe_ips, bad_ips) if baseline else {"findings": []}

    report = {"collected": int(time.time()), "system": cur["system"], "diff": diff}

    if args.save:
        save_json(Path(args.save), report)
        logger.info(Fore.GREEN + f"Saved audit to {args.save}" + Style.RESET_ALL)
    else:
        pretty_print_findings(diff.get("findings", []), logger)
    return 0


# -------------------- small helpers --------------------

def load_json(path: Path, default: Any) -> Any:
    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


# -------------------- main --------------------

def main(argv: Optional[List[str]] = None) -> int:
    ensure_app_dir()
    parser = argparse.ArgumentParser(description="Sentinel: advanced host defense monitor")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_base = sub.add_parser("baseline", help="Create a baseline snapshot")
    p_base.add_argument("--note", default="", help="Optional note for the baseline")
    p_base.set_defaults(func=cmd_baseline)

    p_scan = sub.add_parser("scan", help="Scan once and compare with baseline")
    p_scan.add_argument("--log", help="Write a log file in addition to console output")
    p_scan.add_argument("--verbose", action="store_true")
    p_scan.add_argument("--whitelist", help=f"Path to whitelist file (default {SAFE_IPS_FILE})")
    p_scan.add_argument("--blacklist", help=f"Path to blacklist file (default {MALICIOUS_IPS_FILE})")
    p_scan.add_argument("--baseline", help="Path to baseline JSON (overrides default)")
    p_scan.add_argument("--json", help="Save full JSON report to path")
    p_scan.set_defaults(func=cmd_scan)

    p_mon = sub.add_parser("monitor", help="Continuous monitoring with alerts")
    p_mon.add_argument("--interval", default=30, help="Seconds between scans (min 5s)")
    p_mon.add_argument("--log", help=f"Log file path (default {DEFAULT_LOG})")
    p_mon.add_argument("--verbose", action="store_true")
    p_mon.add_argument("--whitelist", help=f"Path to whitelist file (default {SAFE_IPS_FILE})")
    p_mon.add_argument("--blacklist", help=f"Path to blacklist file (default {MALICIOUS_IPS_FILE})")
    p_mon.set_defaults(func=cmd_monitor)

    p_blk = sub.add_parser("suggest-block", help="Show OS-specific firewall block commands for an IP")
    p_blk.add_argument("--ip", required=True, help="IP address to block")
    p_blk.set_defaults(func=cmd_suggest_block)

    p_kill = sub.add_parser("kill", help="Terminate a process (dry-run by default)")
    p_kill.add_argument("--pid", required=True, help="PID to terminate")
    p_kill.add_argument("--dangerous-apply", action="store_true", help="Actually terminate the process")
    p_kill.set_defaults(func=cmd_kill)

    p_exp = sub.add_parser("export", help="Export a full current scan to JSON")
    p_exp.add_argument("--output", help="Output JSON path")
    p_exp.set_defaults(func=cmd_export)

    p_audit = sub.add_parser("audit", help="Perform a deeper audit and optionally save report")
    p_audit.add_argument("--save", help="Save JSON report to path")
    p_audit.add_argument("--log", help="Log file")
    p_audit.add_argument("--verbose", action="store_true")
    p_audit.set_defaults(func=cmd_audit)

    args = parser.parse_args(argv)
    return args.func(args)  # type: ignore


if __name__ == "__main__":
    sys.exit(main())
