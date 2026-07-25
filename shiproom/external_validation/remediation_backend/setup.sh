#!/usr/bin/env bash
set -Eeuo pipefail
DIR=$(cd "$(dirname "$0")" && pwd); source "$DIR/lib.sh"; root_only; privileged_entry_guard; with_lock
PACKAGE_CONTRACT=${1:?root-owned-package-contract-required}
[[ -f "$PACKAGE_CONTRACT" ]] || die package_contract_missing
python3 "$DIR/package_contract.py" "$PACKAGE_CONTRACT" >/dev/null || die package_contract_invalid
if [[ "$TEST_MODE" != 1 ]]; then
  [[ "$PACKAGE_CONTRACT" == /run/shiproom-remediation-bootstrap/* ]] || die package_contract_outside_staged_root
  [[ $(stat -c '%u:%a' "$PACKAGE_CONTRACT") == 0:400 ]] || die package_contract_not_root_owned
  /usr/bin/python3 "$DIR/package_contract.py" "$PACKAGE_CONTRACT" --verify-live || die package_contract_drift
fi
mapfile -t PACKAGE_ARGS < <(python3 "$DIR/package_contract.py" "$PACKAGE_CONTRACT" --install-args)

# Read-only preflight deliberately precedes every package/systemd mutation.
[[ ! -e "$ROOT" && ! -e "$MOUNT" && ! -e "$RUN" ]] || die 'existing approved path; use recovery/teardown'
command -v systemctl >/dev/null && systemctl show-environment >/dev/null 2>&1 || die 'working systemd required'
unit_preflight_supported
grep -qi microsoft /proc/version || die 'not intended WSL2 Linux host'; [[ -e /dev/loop-control ]] || die 'loop support absent'
command -v losetup >/dev/null || die 'losetup absent'; free=$(df --output=avail -B1 / | tail -1 | tr -d ' '); (( free > 18*1024*1024*1024 )) || die 'insufficient free space'
preflight=$(mktemp /tmp/shiproom-remediation-preflight.XXXXXX)
{ for p in docker.io xfsprogs quota; do printf '%s\t' "$p"; dpkg-query -W -f='${Status} ${Version}' "$p" 2>/dev/null || echo absent; done; systemctl is-system-running 2>/dev/null || true; for u in docker.service docker.socket containerd.service; do printf '%s\t' "$u"; systemctl is-enabled "$u" 2>&1 || true; printf '%s\t' "$u"; systemctl is-active "$u" 2>&1 || true; done; } >"$preflight"
[[ ! -S /var/run/docker.sock ]] || die 'default docker socket active'; ! pgrep -af '(^|/)(dockerd|containerd|containerd-shim)( |$)' || die 'existing Docker/containerd active'

# Install the transactional EXIT trap before the first approved-root mutation.
success=no
finish(){ local rc=$?; trap - EXIT; rm -f "$preflight"; if [[ $success != yes || $rc -ne 0 ]]; then if [[ -r "$JOURNAL" ]]; then "$DIR/recover.sh" --rollback --locked || failed_setup; else printf '%s\n' "bootstrap failure before state journal; no automatic deletion" >&2; fi; fi; exit "$rc"; }; trap finish EXIT
install -d -m 0700 "$ROOT" "$MOUNT" "$RUN"
: >"$STATE"; chmod 0600 "$STATE"; : >"$JOURNAL"; chmod 0600 "$JOURNAL"; cp "$preflight" "$ROOT/preflight.tsv"; durable "$ROOT/preflight.tsv"
control_init; control_phase ROOTS_CREATED; state_put IMAGE "$IMAGE"; state_put MOUNT "$MOUNT"; state_put RUN "$RUN"; state_put PHASE PREFLIGHT; control_phase STATE_INITIALIZED; journal PREPARED 'preflight passed'
state_put PACKAGE_DOCKER_IO "$(dpkg-query -W -f='${Status} ${Version}' docker.io 2>/dev/null || echo absent)"
state_put PACKAGE_XFSPROGS "$(dpkg-query -W -f='${Status} ${Version}' xfsprogs 2>/dev/null || echo absent)"
state_put PACKAGE_QUOTA "$(dpkg-query -W -f='${Status} ${Version}' quota 2>/dev/null || echo absent)"
for u in docker.service docker.socket containerd.service; do command -v systemctl >/dev/null && capture_unit "$u" || true; done
[[ ! -e "$POLICY_GUARD_PATH" ]] || die 'administrator-owned policy-rc.d exists'
printf '#!/bin/sh\n# Shiproom remediation install guard\nexit 101\n' >"$POLICY_GUARD_PATH"; chmod 0755 "$POLICY_GUARD_PATH"; state_put POLICY_GUARD_HASH "$(hash "$POLICY_GUARD_PATH")"; state_put POLICY_GUARD_CREATED yes; journal POLICY_GUARD created; test_marker POLICY_GUARD_VERIFIED; state_put PHASE POLICY_GUARD; control_phase POLICY_GUARD_CREATED
state_put PHASE PACKAGE_INSTALL_ATTEMPTED; control_phase PACKAGE_INSTALL_ATTEMPTED; journal PACKAGE_INSTALL_ATTEMPTED called; test_marker PACKAGE_INSTALL_ATTEMPTED
export DEBIAN_FRONTEND=noninteractive; apt-get --no-install-recommends install -y "${PACKAGE_ARGS[@]}"; journal PACKAGES installed; state_put PHASE PACKAGES; control_phase PACKAGES_CONFIGURED
for spec in "${PACKAGE_ARGS[@]}"; do
  package=${spec%%=*}; expected=${spec#*=}; installed=$(dpkg-query -W -f='${Status} ${Version}' "$package") || die package_query
  [[ "$installed" == "install ok installed $expected" ]] || die package_version_drift
done
state_put PACKAGE_DOCKER_IO "$(dpkg-query -W -f='${Status} ${Version}' docker.io)"; state_put PACKAGE_XFSPROGS "$(dpkg-query -W -f='${Status} ${Version}' xfsprogs)"; state_put PACKAGE_QUOTA "$(dpkg-query -W -f='${Status} ${Version}' quota)"
state_put PACKAGE_DOCKER_IO_HASH "$(hash "$(command -v dockerd)")"; state_put PACKAGE_XFSPROGS_HASH "$(hash "$(command -v xfs_quota)")"; state_put PACKAGE_QUOTA_HASH "$(hash "$(command -v quota)")"
# Contain any package-introduced units while the policy guard is still active.
contain_units; state_put PHASE UNITS_CONTAINED; control_phase UNITS_CONTAINED
cleanup_policy_guard || die policy_guard_integrity; state_put POLICY_GUARD_CREATED no; state_put PHASE POLICY_GUARD_REMOVED; control_phase POLICY_GUARD_REMOVED; journal POLICY_GUARD removed
truncate -s 16G "$IMAGE"; control_phase IMAGE_CREATED; LOOP=$(losetup --find --show "$IMAGE"); state_put LOOP "$LOOP"; journal LOOP "$LOOP"; state_put PHASE LOOP; control_phase LOOP_ATTACHED
mkfs.xfs -f -n ftype=1 "$LOOP"; control_phase FILESYSTEM_FORMATTED; mount -o prjquota,noatime "$LOOP" "$MOUNT"; journal MOUNT "$MOUNT"; state_put PHASE MOUNT; control_phase FILESYSTEM_MOUNTED
findmnt -n -o SOURCE,FSTYPE,OPTIONS --target "$MOUNT" | grep -Eq "^${LOOP}[[:space:]]+xfs[[:space:]].*prjquota" || die quota_mount; xfs_info "$MOUNT" | grep -q 'ftype=1' || die ftype
install -d -m 0700 "$MOUNT/docker-data" "$MOUNT/worktrees" "$MOUNT/quarantine"; xfs_quota -x -c "project -s -p $MOUNT/docker-data 10000" "$MOUNT"; control_phase DATA_PROJECT_ASSIGNED; xfs_quota -x -c 'limit -p bhard=8589934592b ihard=200000 10000' "$MOUNT"; state_put DATA_PROJECT 10000; state_put DATA_BYTES 8589934592; state_put DATA_INODES 200000; quota_limits_verified 10000 8589934592 200000 || die data_quota; journal DATA_QUOTA assigned; state_put PHASE QUOTA; control_phase DATA_LIMITS_VERIFIED
cat >"$DAEMON_JSON" <<EOF
{"data-root":"$MOUNT/docker-data","exec-root":"$RUN/exec","hosts":["unix://$SOCKET"],"storage-driver":"overlay2","features":{"containerd-snapshotter":false},"iptables":false,"bridge":"none","ip-forward":false,"ip-masq":false,"log-driver":"local","log-opts":{"max-size":"1m","max-file":"1"}}
EOF
state_put CONFIG_HASH "$(hash "$DAEMON_JSON")"; state_put PHASE DAEMON_CONFIG; control_phase DAEMON_CONFIG_WRITTEN; "$DIR/start.sh" --locked; control_phase DAEMON_STARTED; "$DIR/status.sh" --locked; control_phase STATUS_VERIFIED; journal COMPLETE ready; state_put PHASE COMPLETE; control_phase SETUP_COMPLETE; success=yes
