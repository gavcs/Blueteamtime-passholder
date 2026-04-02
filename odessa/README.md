# Odessa

Blue team toolkit for CDT competitions.

## Tools

| Tool | What it does | Usage |
|------|-------------|-------|
| `shell-jail/jail.sh` | Jails an SSH user into a locked Alpine container | `sudo ./shell-jail/jail.sh <user>` |
| `shell-jail/trap.sh` | Interactive picker to jail multiple users | `sudo ./shell-jail/trap.sh` |
| `triage/triage.sh` | Hardens an Ubuntu 24.04 box and runs baseline scans | `sudo ./triage/triage.sh [interface]` |
| `triage/stop-revshells.sh` | Detects (and optionally kills) active reverse shells | `sudo ./triage/stop-revshells.sh -k -v` |
