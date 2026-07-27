#!/usr/bin/env bash
# Safely reactivate a previously provisioned, currently detached XFS backend.
# This is intentionally narrower than setup: it never formats an image, never
# installs packages, and refuses any mounted or live runtime ambiguity.
set -Eeuo pipefail
DIR=$(cd "$(dirname "$0")" && pwd)
source "$DIR/lib.sh"
root_only; privileged_entry_guard; with_lock

require_paths
control_ready
[[ -f "$IMAGE" && ! -L "$IMAGE" && $(stat -c '%U:%G:%a' "$IMAGE") == root:root:600 ]] || die resume_image_untrusted
[[ ! -S /var/run/docker.sock ]] || die resume_default_socket
no_live_default_or_custom_daemon || die resume_live_daemon

# A true mount at the dedicated target is an authority conflict.  The host
# root filesystem containing an ordinary empty mount-point directory is not.
if mountpoint -q "$MOUNT"; then die resume_mount_already_active; fi
root_residual_absence_proven "$MOUNT" || die resume_mount_residual_unproven
install -d -o root -g root -m 0700 "$RUN"

loop=
cleanup() {
  local rc=$?
  trap - EXIT INT TERM
  if [[ -n ${loop:-} ]]; then
    mountpoint -q "$MOUNT" && umount "$MOUNT" || true
    losetup -d "$loop" || true
  fi
  exit "$rc"
}
trap cleanup EXIT INT TERM

loop=$(losetup --find --show "$IMAGE")
findmnt -n -o SOURCE --target "$MOUNT" 2>/dev/null | grep -q . && die resume_mount_raced
mount -o prjquota,noatime "$loop" "$MOUNT"
findmnt -n -o SOURCE,FSTYPE,OPTIONS --target "$MOUNT" | grep -Eq "^${loop}[[:space:]]+xfs[[:space:]].*prjquota" || die resume_quota_mount
xfs_info "$MOUNT" | grep -q 'ftype=1' || die resume_ftype
state_put LOOP "$loop"
"$DIR/start.sh" --locked
"$DIR/status.sh" --locked
trap - EXIT INT TERM
printf 'resumed:%s\n' "$loop"
