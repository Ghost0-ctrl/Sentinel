# Sentinel
Sentinel is a defensive, cross-platform host monitoring tool that collects runtime state (processes, listeners, outbound connections, services, autoruns), compares to a saved baseline, and surfaces suspicious changes with severity scoring and a spinner-style CLI UI.

> Defensive-only by design: Sentinel defaults to dry-run behavior for any destructive actions. Use `--dangerous-apply` only when you understand the action and run with appropriate privileges.
---
## Features
- Create and save a system baseline snapshot (processes, services, listeners, autoruns, connections).
- Scan once and diff live state against baseline.
- Continuous monitor mode with filesystem watchers for autostart folders.
- Heuristic scoring (INFO / NOTICE / WARNING / CRITICAL) and colorized console output.
- Whitelist / blacklist support for IPs and trusted file hashes.
- JSON/CSV export of reports for ingestion.
- Dry-run default for destructive actions; opt-in flags for remediation.
- Minimal external dependencies for easy deployment.

---

## Quick start (installation)

```bash
git clone https://github.com/Ghost0-ctrl/sentinel.git
cd sentinel

# Create and activate virtualenv (recommended)
python3 -m venv .venv
source .venv/bin/activate   # Linux/Mac
# .venv\Scripts\activate    # Windows PowerShell

pip install -r requirements.txt
chmod +x sentinel.py        # optional
```
---

## Usage & essential CLI commands
> Replace python sentinel.py with ./sentinel.py if executable.
### Create baseline
Save a baseline snapshot to the default store (~/.sentinel/baseline.json).
```bash
python sentinel.py baseline --note "Clean VM snapshot"
```
### Scan (compare against baseline)
```bash
python sentinel.py scan
```
### Flags
```bash
--baseline <path>        # use specific baseline file
--log <path>             # write log file
--json <path>            # save full JSON report
--whitelist <path>       # path to safe IPs file
--blacklist <path>       # path to malicious IPs file
--verbose                # verbose/debug logging
```
Example:
```bash
python sentinel.py scan --json ./out_report.json --log ./sentinel.log --whitelist safe_ips.txt
```

### Monitor (continuous)
Run periodic scans with an optional filesystem watcher for autoruns:
```bash
python sentinel.py monitor --interval 60 --log ./monitor.log
```

### Audit (deep)
Run a deeper audit and optionally save the audit report:
```bash
python sentinel.py audit --save ./full_audit.json --verbose
```

### Export (snapshot)
Export a full current snapshot to JSON:
```bash
python sentinel.py export --output ./snapshot.json
```

### Suggest-Block (OS-specific firewall command)
Print helpful commands to block a remote IP:
```bash
python sentinel.py suggest-block --ip 203.0.113.45
```

### Kill (Terminate Process)
Dry-run by default. Use '--dangerous-apply' to actually act:
```bash
python sentinel.py kill --pid 12345
python sentinel.py kill --pid 12345 --dangerous-apply
```
---

## Configuration files & examples
Sentinel looks for helper files in the working directory be default, or use flags to specify custom paths.

### safe_ips.txt (whitelist)
```bash
# Whitelisted IPs / CIDR (one per line)
127.0.0.1
192.168.1.0/24
10.0.0.0/8
```

### malicious_ips.txt (blacklist)
```bash
# Known-bad IPs (one per line)
203.0.113.45
198.51.100.12
```

### trusted_hashes.txt (trusted binaries - SHA256)
```bash
# SHA256 hashes of binaries to trust
d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2
```
---

## How it works 
1. 'baseline': collect processes, services, listeners, autoruns, outbound connections, file hashes and save JSON baseline.
2. 'scan' / 'monitor': collect current snapshot, diff against baseline, compute heuristics and severity score, present findings.
3. 'audit' / 'export': provide a detailed report for offline analysis.
Heuristics include suspicious executable locations, unknown hashes, new autoruns, connections to blacklisted IPs, and unexpected open ports.

### Platform & permissions notes
- Linux/macOS: Elevated privileges (sudo) may be required to observe all processes, raw sockets, or inspect protected files.
- Windows: Running as Administrator required for full visibility (registry autoruns, service details).
- Killing processes or applying firewall rules requires elevated privileges — Sentinel defaults to dry-run to avoid accidental disruption.

### Troubleshooting & tips
- "No baseline found": run 'python sentinel.py baseline' first or pass '--baseline <path>'.
- Permission errors: run with elevated privileges.
- False positives: add hashes to 'trusted_hashes.txt' and IPs to 'safe_ips.txt'.
- To run as a service: use the systemd snippet in 'contrib/systemd/sentinel.service' or create a scheduled task on Windows.
---

## Example Workflows
Create baseline on a clean host:
```bash
sudo python sentinel.py baseline --note "Clean image - post-install"
```
Daily scan via cron and write JSON:
```bash
python sentinel.py scan --json /var/reports/sentinel_daily.json --log /var/log/sentinel_scan.log
```
Continuous monitoring daemon (systemd):
```bash
sudo cp contrib/systemd/sentinel.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now sentinel.service
```

## Requirements
```text
# requirements.txt
psutil>=5.9.0
watchdog>=2.1.0
colorama>=0.4.6
python-dateutil>=2.8.2
```
---

# Thank you for you support!
If there are any bugs or errors, feel free to reach out to me.


