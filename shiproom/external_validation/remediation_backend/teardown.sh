#!/usr/bin/env bash
set -Eeuo pipefail
DIR=$(cd "$(dirname "$0")" && pwd); source "$DIR/lib.sh"; root_only; privileged_entry_guard
[[ ${1:-} == --locked ]] || with_lock
recovery=${2:-}; state_validate || die malformed_state
# An unresolved backend incident may only be inspected/recovered, never used
# to start, allocate, release, or qualify new work.
if [[ "$recovery" != --recovery ]]; then control_ready; fi
# Live cleanup only signals a process whose PID/start/executable/argv match state.
if daemon_probe; then
  cli=$(state_try DOCKER_CLI) || die missing_docker_cli; ids=$(timeout 10 "$cli" --host "unix://$SOCKET" ps -aq) || die docker_list
  [[ -z "$ids" ]] || timeout 20 "$cli" --host "unix://$SOCKET" rm -f $ids || die docker_remove
  [[ -z "$(timeout 10 "$cli" --host "unix://$SOCKET" ps -aq)" ]] || die 'custom containers remain'
  p=$(state_try DAEMON_PID); kill -TERM "$p"; for _ in $(seq 1 20); do kill -0 "$p" 2>/dev/null || break; sleep 1; done; kill -0 "$p" 2>/dev/null && kill -KILL "$p"
else
  [[ ! -S "$SOCKET" || -z "$(ss -xlpn | grep -F "$SOCKET" || true)" ]] || die 'unverified live socket'
  ! pgrep -af "containerd.*$RUN" >/dev/null || die 'managed containerd remains'
  ! pgrep -af "dockerd.*--config-file $DAEMON_JSON" >/dev/null || die 'unverified managed dockerd'
fi
stop_or_absent_logger || die 'unverified logger pid'
rm -f "$SOCKET" "$PID" "$LOG_FIFO"
! pgrep -af "dockerd.*--config-file $DAEMON_JSON" >/dev/null || die 'daemon remains'; ! pgrep -af "containerd.*$RUN" >/dev/null || die 'managed containerd remains'
# LOOP-but-never-MOUNTED and MOUNTED states are distinct, recoverable paths.
if loop_probe; then
  if mount_probe; then umount "$MOUNT"; fi
  loop=$(state_try LOOP); losetup -d "$loop"; [[ -z "$(losetup -j "$IMAGE")" ]] || die detach
fi
restore_units
root_residual_absence_proven "$MOUNT" && root_residual_absence_proven "$RUN" || die 'residual absence unproven'
safe_remove_owned_root "$RUN" && safe_remove_owned_root "$MOUNT" && safe_remove_owned_root "$ROOT" || die 'safe root cleanup failed'
echo 'packages retained; default units restored to recorded state'
