#!/usr/bin/env bash
set -Eeuo pipefail
DIR=$(cd "$(dirname "$0")" && pwd); source "$DIR/lib.sh"; root_only; privileged_entry_guard
[[ ${1:-} == --locked ]] || with_lock
require_paths; control_ready; storage_verified || die 'quota storage not verified'
no_live_default_or_custom_daemon || die 'default or custom daemon/socket already active'
DOCKERD=$(command -v dockerd); DOCKER=$(command -v docker); PYTHON=$(command -v python3)
[[ -x "$DOCKERD" && -x "$DOCKER" && -x "$PYTHON" && -r "$DIR/bounded-log.py" ]] || die executables
[[ "$(hash "$DAEMON_JSON")" == "$(state_get CONFIG_HASH)" ]] || die daemon_config
daemon_pid=; launcher_pid=; logger_pid=
rollback(){ local rc=$? target=${daemon_pid:-${launcher_pid:-}}; trap - EXIT; if [[ -n "$target" && -r /proc/$target/stat ]]; then kill -TERM "$target" 2>/dev/null || true; for _ in $(seq 1 10); do kill -0 "$target" 2>/dev/null || break; sleep 1; done; kill -0 "$target" 2>/dev/null && kill -KILL "$target" 2>/dev/null || true; fi; [[ -n ${logger_pid:-} ]] && kill -TERM "$logger_pid" 2>/dev/null || true; rm -f "$SOCKET" "$PID" "$LOG_FIFO"; exit "$rc"; }; trap rollback EXIT INT TERM
rm -f "$LOG" "$LOG_FIFO"; mkfifo -m 0600 "$LOG_FIFO"; "$PYTHON" "$DIR/bounded-log.py" --input "$LOG_FIFO" --output "$LOG" --maximum 1048576 & logger_pid=$!
setsid "$DOCKERD" --config-file "$DAEMON_JSON" --pidfile "$PID" >"$LOG_FIFO" 2>&1 & launcher_pid=$!
for _ in $(seq 1 30); do [[ -S "$SOCKET" ]] && break; sleep 1; done; [[ -S "$SOCKET" ]] || die daemon_start
daemon_pid=$(cat "$PID"); [[ "$daemon_pid" =~ ^[1-9][0-9]*$ && -r /proc/$daemon_pid/stat ]] || die daemon_pid
if [[ "$TEST_MODE" != 1 ]]; then chown root:root "$SOCKET"; fi; chmod 0600 "$SOCKET"; state_put DAEMON_PID "$daemon_pid"; state_put DAEMON_START "$(pid_start "$daemon_pid")"; state_put DOCKERD_EXE "$(readlink -f "$DOCKERD")"; state_put DOCKER_CLI "$(readlink -f "$DOCKER")"; state_put LOG_PID "$logger_pid"; state_put LOG_START "$(pid_start "$logger_pid")"
daemon_verified || die daemon_identity
timeout 10 "$DOCKER" --host "unix://$SOCKET" info >/dev/null || die daemon_health
journal DAEMON "$daemon_pid"; trap - EXIT INT TERM; exit 0
