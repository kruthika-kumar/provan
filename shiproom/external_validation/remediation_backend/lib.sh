#!/usr/bin/env bash
# Shared helpers. State is data, never shell code.
set -Eeuo pipefail
umask 077

TEST_MODE=${SHIPROOM_REMEDIATION_TEST_MODE:-0}
if [[ "$TEST_MODE" == 1 && ${EUID:-0} -ne 0 ]]; then
  ROOT=${SHIPROOM_REMEDIATION_ROOT:?test root required}
  MOUNT=${SHIPROOM_REMEDIATION_MOUNT:?test mount required}
  RUN=${SHIPROOM_REMEDIATION_RUN:?test run required}
  POLICY_GUARD_PATH=${SHIPROOM_REMEDIATION_TEST_POLICY_GUARD:?test policy guard required}
  LOCK=${SHIPROOM_REMEDIATION_TEST_LOCK:?test lock required}
else
  [[ -z ${SHIPROOM_REMEDIATION_ROOT+x}${SHIPROOM_REMEDIATION_MOUNT+x}${SHIPROOM_REMEDIATION_RUN+x}${SHIPROOM_REMEDIATION_TEST_POLICY_GUARD+x} ]] || { echo 'production paths are fixed' >&2; exit 1; }
  ROOT=/var/lib/shiproom-remediation
  MOUNT=/mnt/shiproom-remediation
  RUN=/run/shiproom-remediation-docker
  POLICY_GUARD_PATH=/usr/sbin/policy-rc.d
  LOCK=/run/lock/shiproom-remediation.backend.lock
fi
readonly ROOT MOUNT RUN POLICY_GUARD_PATH LOCK
if [[ "$TEST_MODE" != 1 ]]; then
  PATH=/usr/sbin:/usr/bin:/sbin:/bin
  export PATH
fi
IMAGE="$ROOT/shiproom-remediation.xfs"; STATE="$ROOT/backend.state"; JOURNAL="$ROOT/setup.journal"
DAEMON_JSON="$ROOT/daemon.json"; PID="$RUN/dockerd.pid"; SOCKET="$RUN/docker.sock"; LOG="$ROOT/dockerd.log"; LOG_FIFO="$RUN/dockerd.log.fifo"
BACKEND_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd); CONTROL_DB="$ROOT/control.sqlite3"
readonly IMAGE STATE JOURNAL LOCK DAEMON_JSON PID SOCKET LOG LOG_FIFO BACKEND_DIR CONTROL_DB
MIN_WORKTREE_BYTES=1048576; MAX_WORKTREE_BYTES=4294967296; MIN_WORKTREE_INODES=1024; MAX_WORKTREE_INODES=500000
export LOG LOG_FIFO MIN_WORKTREE_BYTES MAX_WORKTREE_BYTES MIN_WORKTREE_INODES MAX_WORKTREE_INODES

die(){ echo "shiproom remediation: $*" >&2; exit 1; }
test_marker(){ [[ "$TEST_MODE" == 1 && -n ${TEST_MARKERS:-} ]] && printf '%s\n' "$1" >>"$TEST_MARKERS" || true; }
root_only(){ [[ ${EUID:-1} -eq 0 || "$TEST_MODE" == 1 ]] || die root; }
privileged_entry_guard(){
  [[ "$TEST_MODE" == 1 ]] && return 0
  [[ "$BACKEND_DIR" =~ ^/run/shiproom-remediation-bootstrap/[a-f0-9]{64}$ ]] || die unstaged_privileged_entrypoint
  /usr/bin/python3 "$BACKEND_DIR/bootstrap.py" --verify-staged "$BACKEND_DIR" >/dev/null || die staged_bundle_invalid
}
hash(){ sha256sum "$1" | awk '{print $1}'; }
durable(){ sync -f "$1" 2>/dev/null || sync; }
atomic_replace(){ local target=$1 source=$2; chmod 0600 "$source"; durable "$source"; mv -f "$source" "$target"; durable "$(dirname "$target")"; }
with_lock(){
  [[ -d "$(dirname "$LOCK")" ]] || die lock_directory
  # /run/lock is sticky.  In production a staged Python helper first creates
  # or validates the lock with O_NOFOLLOW and root-only ownership; after that
  # a non-root attacker cannot replace the root-owned 0600 inode before bash
  # duplicates it onto FD 9.  Test mode uses its isolated disposable lock.
  if [[ "$TEST_MODE" != 1 ]]; then /usr/bin/python3 "$BACKEND_DIR/lock_guard.py" --prepare >/dev/null || die backend_lock_untrusted; fi
  exec 9>>"$LOCK"; flock -x 9
}
control(){ python3 "$BACKEND_DIR/control.py" --db "$CONTROL_DB" "$@"; }
control_init(){ control init >/dev/null; }
control_phase(){ control phase "$1"; }
control_ready(){ control assert-ready; }

allowed_key(){ case "$1" in
  IMAGE|MOUNT|RUN|LOOP|PHASE|POLICY_GUARD_HASH|POLICY_GUARD_CREATED|PACKAGE_DOCKER_IO|PACKAGE_XFSPROGS|PACKAGE_QUOTA|PACKAGE_DOCKER_IO_HASH|PACKAGE_XFSPROGS_HASH|PACKAGE_QUOTA_HASH|\
  DAEMON_PID|DAEMON_START|DOCKERD_EXE|DOCKER_CLI|CONFIG_HASH|LOG_PID|LOG_START|LOG_KEEPER_PID|LOG_KEEPER_START|LOG_KEEPER_EXE|DATA_PROJECT|DATA_BYTES|DATA_INODES|CAPACITY_ID|\
  FAILED_RECORD|UNIT_DOCKER_SERVICE_EXISTS|UNIT_DOCKER_SERVICE_ENABLED|UNIT_DOCKER_SERVICE_MASKED|UNIT_DOCKER_SERVICE_ACTIVE|UNIT_DOCKER_SERVICE_CHANGED|\
  UNIT_DOCKER_SOCKET_EXISTS|UNIT_DOCKER_SOCKET_ENABLED|UNIT_DOCKER_SOCKET_MASKED|UNIT_DOCKER_SOCKET_ACTIVE|UNIT_DOCKER_SOCKET_CHANGED|\
  UNIT_CONTAINERD_SERVICE_EXISTS|UNIT_CONTAINERD_SERVICE_ENABLED|UNIT_CONTAINERD_SERVICE_MASKED|UNIT_CONTAINERD_SERVICE_ACTIVE|UNIT_CONTAINERD_SERVICE_CHANGED) return 0;; *) return 1;; esac; }
valid_value(){ local k=$1 v=$2; [[ "$v" != *$'\n'* && "$v" != *$'\r'* && ${#v} -le 4096 ]] || return 1; case "$k" in
  *_CREATED|*_CHANGED|*_EXISTS|*_MASKED) [[ "$v" == yes || "$v" == no ]];;
  *_PID|*_START|DATA_PROJECT|DATA_BYTES|DATA_INODES) [[ "$v" =~ ^[0-9]+$ ]];;
  POLICY_GUARD_HASH|CONFIG_HASH) [[ "$v" =~ ^[a-f0-9]{64}$ ]];;
  *) [[ -n "$v" ]];;
esac; }
state_validate(){ [[ -r "$STATE" ]] || return 0; local k v n=0; declare -A seen=(); while IFS=$'\t' read -r k v; do
  [[ -n "$k" && -n "$v" ]] || return 1; allowed_key "$k" || return 1; [[ -z ${seen[$k]+x} ]] || return 1; seen[$k]=1
  [[ "$v" =~ ^[A-Za-z0-9+/=]+$ ]] || return 1; v=$(printf %s "$v" | base64 -d 2>/dev/null) || return 1; valid_value "$k" "$v" || return 1; ((n++))
done <"$STATE"; return 0; }
state_get(){ local k=$1 value; allowed_key "$k" || die unknown_state_key; state_validate || die malformed_state; value=$(awk -F '\t' -v k="$k" '$1==k{print $2; found++} END{exit(found==1?0:1)}' "$STATE" | base64 -d) || die missing_state_key; printf %s "$value"; }
state_try(){ local k=$1; allowed_key "$k" || return 1; state_validate || return 1; awk -F '\t' -v k="$k" '$1==k{print $2; found++} END{exit(found==1?0:1)}' "$STATE" | base64 -d; }
state_put(){ local k=$1 v=$2 t; allowed_key "$k" || die unknown_state_key; valid_value "$k" "$v" || die invalid_state_value; state_validate || die malformed_state; t=$(mktemp "$ROOT/.state.XXXXXX"); [[ -r "$STATE" ]] && awk -F '\t' -v k="$k" '$1!=k{print}' "$STATE" >"$t"; printf '%s\t%s\n' "$k" "$(printf %s "$v" | base64 -w0)" >>"$t"; atomic_replace "$STATE" "$t"; }
journal(){ printf '%s\t%s\t%s\n' "$(date -u +%FT%TZ)" "$1" "$2" >>"$JOURNAL"; durable "$JOURNAL"; }
failed_setup(){ local stamp file; stamp=$(date -u +%Y%m%dT%H%M%SZ); file="$ROOT/failed-setup-$stamp.tsv"; { printf 'phase\t%s\n' "$(state_try PHASE || echo unknown)"; cat "$JOURNAL" 2>/dev/null || true; } >"$file"; chmod 0600 "$file"; durable "$file"; if state_validate; then state_put FAILED_RECORD "$file"; fi; }

pid_start(){ awk '{print $22}' "/proc/$1/stat"; }
unit_prefix(){ case "$1" in docker.service) echo UNIT_DOCKER_SERVICE;; docker.socket) echo UNIT_DOCKER_SOCKET;; containerd.service) echo UNIT_CONTAINERD_SERVICE;; *) die unknown_unit;; esac; }
capture_unit(){ local u=$1 p enabled active; p=$(unit_prefix "$u"); state_put "${p}_EXISTS" "$(systemctl list-unit-files "$u" >/dev/null 2>&1 && echo yes || echo no)"; enabled=$(systemctl is-enabled "$u" 2>/dev/null || true); active=$(systemctl is-active "$u" 2>/dev/null || true); state_put "${p}_ENABLED" "${enabled:-disabled}"; state_put "${p}_MASKED" "$( [[ "$enabled" == masked ]] && echo yes || echo no)"; state_put "${p}_ACTIVE" "${active:-inactive}"; state_put "${p}_CHANGED" no; }
unit_preflight_supported(){ local u enabled active load; for u in docker.service docker.socket containerd.service; do
  load=$(systemctl show -p LoadState --value "$u" 2>/dev/null || true)
  [[ -z "$load" || "$load" == not-found ]] && continue
  [[ "$load" == loaded ]] || die unit_load_state_unsupported
  enabled=$(systemctl is-enabled "$u" 2>/dev/null || true); active=$(systemctl is-active "$u" 2>/dev/null || true)
  [[ "$enabled" == enabled || "$enabled" == disabled || "$enabled" == masked ]] || die unit_file_state_unsupported
  [[ "$active" == inactive ]] || die unit_runtime_state_unsupported
done; }
require_paths(){ [[ "$(state_get IMAGE)" == "$IMAGE" && "$(state_get MOUNT)" == "$MOUNT" && "$(state_get RUN)" == "$RUN" ]] || die state_paths; }
daemon_probe(){ local p s e c expected; p=$(state_try DAEMON_PID) || return 1; s=$(state_try DAEMON_START) || return 1; expected=$(state_try DOCKERD_EXE) || return 1; [[ "$p" =~ ^[1-9][0-9]*$ && -r /proc/$p/stat && "$(pid_start "$p")" == "$s" ]] || return 1; c=$(tr '\0' ' ' </proc/$p/cmdline); if [[ "$TEST_MODE" == 1 && ${SHIPROOM_REMEDIATION_TEST_FAKE_DAEMON:-0} == 1 ]]; then [[ "$c" == *dockerd* ]] && return 0; fi; e=$(readlink -f "/proc/$p/exe"); [[ "$e" == "$expected" && "$c" == *"--config-file $DAEMON_JSON"* && "$c" == *"--pidfile $PID"* ]]; }
daemon_verified(){ daemon_probe; }
logger_probe(){ local p s; p=$(state_try LOG_PID) || return 1; s=$(state_try LOG_START) || return 1; [[ "$p" =~ ^[1-9][0-9]*$ && -r /proc/$p/stat && "$(pid_start "$p")" == "$s" ]]; }
log_keeper_probe(){ local p s expected actual command; p=$(state_try LOG_KEEPER_PID) || return 1; s=$(state_try LOG_KEEPER_START) || return 1; expected=$(state_try LOG_KEEPER_EXE) || return 1; [[ "$p" =~ ^[1-9][0-9]*$ && -r /proc/$p/stat && "$(pid_start "$p")" == "$s" ]] || return 1; actual=$(readlink -f "/proc/$p/exe"); command=$(tr '\0' ' ' </proc/$p/cmdline); [[ "$actual" == "$expected" && "$command" == *"/dev/null"* ]]; }
log_pipeline_verified(){ logger_probe && log_keeper_probe; }
stop_or_absent_logger(){
  local lp
  if logger_probe; then
    lp=$(state_try LOG_PID); kill -TERM "$lp" 2>/dev/null || return 1
    for _ in $(seq 1 10); do kill -0 "$lp" 2>/dev/null || return 0; sleep 1; done
    ! kill -0 "$lp" 2>/dev/null
  elif lp=$(state_try LOG_PID 2>/dev/null); then
    # Offline recovery may safely accept an already-reaped logger.  A live
    # PID with mismatched identity is a possible reuse and must fail closed.
    [[ "$lp" =~ ^[1-9][0-9]*$ && ! -e "/proc/$lp/stat" ]]
  fi
}
stop_or_absent_log_keeper(){
  local kp
  if log_keeper_probe; then
    kp=$(state_try LOG_KEEPER_PID); kill -TERM "$kp" 2>/dev/null || return 1
    for _ in $(seq 1 10); do kill -0 "$kp" 2>/dev/null || return 0; sleep 1; done
    ! kill -0 "$kp" 2>/dev/null
  elif kp=$(state_try LOG_KEEPER_PID 2>/dev/null); then
    [[ "$kp" =~ ^[1-9][0-9]*$ && ! -e "/proc/$kp/stat" ]]
  fi
}
stop_log_pipeline(){ stop_or_absent_log_keeper && stop_or_absent_logger; }
dockerx(){ "$(state_get DOCKER_CLI)" --host "unix://$SOCKET" "$@"; }
no_live_default_or_custom_daemon(){ [[ ! -S /var/run/docker.sock && ! -S "$SOCKET" ]] && ! pgrep -af '(^|/)(dockerd|containerd|containerd-shim)( |$)' >/dev/null; }
is_recorded_block_device(){ [[ "$TEST_MODE" == 1 && "$1" == test-loop ]] || [[ -b "$1" ]]; }

# xfs_quota prints a filesystem device, not the selected project ID, in each
# quota row.  Request both dimensions and verbose output: without -b/-i its
# default is blocks only, and without -v a fresh zero-usage project is omitted.
# -n/-N freeze numeric, headerless output; block limits are in 1KiB units.
quota_machine(){ local p=$1; xfs_quota -x -c "quota -p -nNv -b -i $p" "$MOUNT"; }
quota_record(){ local p=$1 out source; source=$(state_get LOOP); out=$(quota_machine "$p") || return 1; printf '%s\n' "$out" | awk -v project="$p" -v source="$source" -v mount="$MOUNT" '$1==source && $NF==mount && NF==12 && $4 ~ /^[0-9]+$/ && $9 ~ /^[0-9]+$/ {printf "%s\t%.0f\t%s\n", project, $4*1024, $9; found=1; exit} END{exit(found?0:1)}'; }
# xfs_quota does not define a byte ("b") limit suffix.  On this toolchain it
# is treated as filesystem blocks, which silently turns an 8 GiB request into
# a 32 GiB limit on a 4 KiB XFS filesystem.  The frozen policy is in bytes;
# require an exact KiB representation and send the documented k suffix.
quota_limit_kib(){ local bytes=$1 decimal; [[ "$bytes" =~ ^[1-9][0-9]*$ ]] || return 1; decimal=$((10#$bytes)); (( decimal % 1024 == 0 )) || return 1; printf '%sk' "$((decimal / 1024))"; }
quota_limits_verified(){
  local p=$1 b=$2 i=$3 row rp rb ri
  if ! row=$(quota_record "$p"); then
    # The selected-project report is supervisor command output, not patient
    # evidence.  Preserve it on stderr at this hard gate so an XFS-version
    # layout mismatch can be repaired from facts without accepting a loose row.
    printf 'shiproom remediation: quota report did not match the frozen parser (project=%s expected_bytes=%s expected_inodes=%s)\n' "$p" "$b" "$i" >&2
    quota_machine "$p" >&2 || true
    return 1
  fi
  IFS=$'\t' read -r rp rb ri <<<"$row"
  if [[ "$rp" != "$p" || "$rb" != "$b" || "$ri" != "$i" ]]; then
    printf 'shiproom remediation: quota limits mismatch (project=%s observed_bytes=%s observed_inodes=%s expected_bytes=%s expected_inodes=%s)\n' "$p" "$rb" "$ri" "$b" "$i" >&2
    quota_machine "$p" >&2 || true
    return 1
  fi
}
storage_verified(){ local loop; require_paths; loop=$(state_get LOOP); is_recorded_block_device "$loop" && [[ "$(losetup -n -O BACK-FILE "$loop")" == "$IMAGE" ]] || return 1; findmnt -n -o SOURCE,FSTYPE,OPTIONS --target "$MOUNT" | grep -Eq "^${loop}[[:space:]]+xfs[[:space:]].*prjquota" || return 1; xfs_info "$MOUNT" | grep -q 'ftype=1' || return 1; quota_limits_verified "$(state_get DATA_PROJECT)" "$(state_get DATA_BYTES)" "$(state_get DATA_INODES)"; }
capacity_record_from_xfs(){
  local total available nominal instance
  read -r total available < <(df -B1 --output=size,avail "$MOUNT" | tail -n 1)
  nominal=$(stat -c %s "$IMAGE"); instance=$(control instance)
  [[ "$total" =~ ^[0-9]+$ && "$available" =~ ^[0-9]+$ && "$nominal" =~ ^[0-9]+$ && -n "$instance" ]] || return 1
  /usr/bin/python3 - "$instance" "$nominal" "$total" "$available" <<'PY'
import hashlib,json,sys
instance,nominal,total,available=sys.argv[1:]
nominal,total,available=map(int,(nominal,total,available))
docker=8*1024**3; metadata=1024**3; supervisor=1024**3
usable=min(total,available); aggregate=min(4*1024**3,usable-docker-metadata-supervisor)
if aggregate < 2*1024**3: raise SystemExit(2)
evidence={"backend_instance_id":instance,"nominal_image_bytes":nominal,"filesystem_total_data_bytes":total,"filesystem_available_bytes":available,"metadata_reserve_bytes":metadata,"supervisor_reserve_bytes":supervisor,"docker_bytes":docker,"qualified_worktree_aggregate_limit":aggregate,"inode_policy_cap":500000,"max_active_projects":2}
evidence_hash="sha256:"+hashlib.sha256(json.dumps(evidence,sort_keys=True,separators=(",",":")).encode()).hexdigest()
record={"capacity_id":"capacity_"+evidence_hash.split(":",1)[1][:32],"backend_instance_id":instance,"evidence_hash":evidence_hash,"nominal_image_bytes":nominal,"filesystem_total_data_bytes":total,"filesystem_available_bytes":available,"metadata_reserve_bytes":metadata,"supervisor_reserve_bytes":supervisor,"docker_bytes":docker,"aggregate_worktree_bytes":aggregate,"inode_policy_cap":500000,"max_active_projects":2}
print(json.dumps(record,sort_keys=True,separators=(",",":")))
PY
}
contain_units(){ local u pfx; command -v systemctl >/dev/null && systemctl show-environment >/dev/null 2>&1 || die systemd_unavailable
  for u in docker.socket docker.service containerd.service; do
    pfx=$(unit_prefix "$u")
    if systemctl list-unit-files "$u" >/dev/null 2>&1; then
      timeout 30 systemctl stop "$u" || true
      systemctl disable "$u" || true
      systemctl mask "$u"
      state_put "${pfx}_CHANGED" yes; journal UNIT_CONTAINMENT "$u"; test_marker UNIT_CONTAINMENT_CALLED
    fi
  done
  systemctl daemon-reload
  for u in docker.service docker.socket containerd.service; do
    [[ "$(systemctl is-enabled "$u" 2>/dev/null || true)" == masked ]] || die unit_mask_unverified
    [[ "$(systemctl is-active "$u" 2>/dev/null || true)" == inactive ]] || die unit_stop_unverified
  done
  no_live_default_or_custom_daemon || die unit_containment_process_unverified
}
# Matrix: originally present units return to their exact saved mask/enable/active state.
# Units first introduced by package installation are unmasked, disabled, and remain inactive.
restore_units(){ local u pfx; for u in docker.socket docker.service containerd.service; do
  pfx=$(unit_prefix "$u"); [[ "$(state_try "${pfx}_CHANGED" || true)" == yes ]] || continue; command -v systemctl >/dev/null || continue
  timeout 30 systemctl stop "$u" || true
  if [[ "$(state_try "${pfx}_EXISTS" || true)" == yes ]]; then
    [[ "$(state_try "${pfx}_MASKED" || true)" == yes ]] && systemctl mask "$u" || systemctl unmask "$u"
    [[ "$(state_try "${pfx}_ENABLED" || true)" == enabled ]] && systemctl enable "$u" || systemctl disable "$u" || true
    [[ "$(state_try "${pfx}_ACTIVE" || true)" == inactive ]] || die unit_restore_active_unsupported
  else
    systemctl unmask "$u" || true; systemctl disable "$u" || true
  fi
done; systemctl daemon-reload; }
cleanup_policy_guard(){ [[ "$(state_try POLICY_GUARD_CREATED || true)" == yes && -e "$POLICY_GUARD_PATH" && "$(hash "$POLICY_GUARD_PATH")" == "$(state_try POLICY_GUARD_HASH || true)" ]] || return 1; rm -f "$POLICY_GUARD_PATH"; }
loop_probe(){ local loop; loop=$(state_try LOOP) || return 1; [[ -n "$loop" ]] && losetup -n -O BACK-FILE "$loop" 2>/dev/null | grep -Fx "$IMAGE" >/dev/null; }
mount_probe(){ local loop; loop=$(state_try LOOP) || return 1; findmnt -n -o SOURCE --target "$MOUNT" 2>/dev/null | grep -Fx "$loop" >/dev/null; }
pending_write(){ local name p id phase t; name=$1; p=$2; id=$3; phase=$4; t=$(mktemp "$ROOT/.${name}.XXXXXX"); printf '%s\t%s\t%s\n' "$p" "$id" "$phase" >"$t"; atomic_replace "$ROOT/$name" "$t"; }
pending_read(){ local name=$1; [[ -r "$ROOT/$name" ]] || return 1; IFS=$'\t' read -r PENDING_PROJECT PENDING_ID PENDING_PHASE <"$ROOT/$name"; [[ "$PENDING_PROJECT" =~ ^[0-9]+$ && "$PENDING_ID" =~ ^[a-z0-9][a-z0-9_-]{0,63}$ && "$PENDING_PHASE" =~ ^[A-Z_]+$ ]]; }
recover_pending_allocation(){ local p id phase tree; pending_read allocation.pending || return 0; p=$PENDING_PROJECT; id=$PENDING_ID; phase=$PENDING_PHASE; tree="$MOUNT/worktrees/$id"; if [[ -r "$ROOT/projects.tsv" ]] && awk -F '\t' -v p="$p" -v id="$id" '$1==p && $2==id{found=1} END{exit(found?0:1)}' "$ROOT/projects.tsv"; then rm -f "$ROOT/allocation.pending"; durable "$ROOT"; return 0; fi; if [[ -e "$tree" ]]; then xfs_quota -x -c "project -C -p $tree $p" "$MOUNT" || true; install -d -m 0700 "$MOUNT/quarantine"; mv "$tree" "$MOUNT/quarantine/$id-$p-recovered-$phase"; durable "$MOUNT"; fi; rm -f "$ROOT/allocation.pending"; durable "$ROOT"; }
recover_pending_release(){ pending_read release.pending || return 0; local p=$PENDING_PROJECT id=$PENDING_ID phase=$PENDING_PHASE tree="$MOUNT/worktrees/$PENDING_ID"; if [[ ! -r "$ROOT/projects.tsv" ]] || ! awk -F '\t' -v p="$p" -v id="$id" '$1==p && $2==id{found=1} END{exit(found?0:1)}' "$ROOT/projects.tsv"; then rm -f "$ROOT/release.pending"; durable "$ROOT"; return 0; fi; [[ "$phase" == PRECHECKED || "$phase" == PROJECT_CLEARED || "$phase" == TREE_REMOVED ]] || die release_pending_malformed; }
residual_worktree_clear(){ local tree=$1; [[ -d "$tree" && -z "$(find "$tree" -mindepth 1 -print -quit)" ]] || return 1; ! findmnt -R -n -o TARGET --target "$tree" 2>/dev/null | grep -Fx "$tree" >/dev/null; }
create_worktree(){ local tree=$1; install -d -m 0700 "$tree"; if [[ "$TEST_MODE" != 1 ]]; then chown 65533:65533 "$tree"; fi; }
root_residual_absence_proven(){ local target=$1
  # ``findmnt --target`` resolves an ordinary directory to its enclosing root
  # mount, which is not evidence of a mount below this Shiproom-owned path.
  # Instead, inspect every mounted target and reject only this path or a true
  # descendant after canonicalizing the registered root.
  local canonical_target mounted_target
  canonical_target=$(readlink -f -- "$target") || return 1
  while IFS= read -r mounted_target; do
    [[ "$mounted_target" == "$canonical_target" || "$mounted_target" == "$canonical_target"/* ]] && return 1
  done < <(findmnt -rn -o TARGET 2>/dev/null || true)
  [[ -z "$(losetup -j "$IMAGE" 2>/dev/null || true)" ]] || return 1
  [[ ! -S "$SOCKET" && ! -S /var/run/docker.sock ]] || return 1
  ! pgrep -af "dockerd.*--config-file $DAEMON_JSON" >/dev/null || return 1
  ! pgrep -af "containerd.*$RUN" >/dev/null || return 1
}
safe_remove_owned_root(){ local target=$1 auth dev ino mid
  [[ -e "$target" ]] || return 0
  if [[ "$TEST_MODE" == 1 ]]; then rm -rf --one-file-system "$target"; return 0; fi
  auth=$(python3 "$BACKEND_DIR/path_authority.py" "$target") || return 1
  dev=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["device"])' <<<"$auth")
  ino=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["inode"])' <<<"$auth")
  mid=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["mount_id"])' <<<"$auth")
  # Only the fixed supervisor-owned custom-daemon runtime root may contain
  # dead Unix sockets after residual absence is proven.  Patient worktrees
  # and all other roots retain the helper's strict special-file rejection.
  if [[ "$target" == "$RUN" ]]; then
    python3 "$BACKEND_DIR/release_helper.py" delete-contents --root "$target" --expected-device "$dev" --expected-inode "$ino" --expected-mount-id "$mid" --allow-runtime-sockets || return 1
  else
    python3 "$BACKEND_DIR/release_helper.py" delete-contents --root "$target" --expected-device "$dev" --expected-inode "$ino" --expected-mount-id "$mid" || return 1
  fi
  python3 "$BACKEND_DIR/release_helper.py" delete-root --root "$target" --expected-device "$dev" --expected-inode "$ino" --expected-mount-id "$mid"
}
