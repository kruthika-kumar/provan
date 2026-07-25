#!/usr/bin/env bash
# Non-privileged command-shim tests. They never call a real package, systemd,
# mount, loop, XFS, quota, Docker, or daemon command.
set -Eeuo pipefail
DIR=$(cd "$(dirname "$0")" && pwd); tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
for f in "$DIR"/*.sh; do bash -n "$f"; done
if command -v shellcheck >/dev/null; then shellcheck -S warning "$DIR"/*.sh; else echo 'ShellCheck unavailable: syntax and behavioral tests still run' >&2; fi
python3 "$DIR/control_contract_tests.py"
export SHIPROOM_REMEDIATION_TEST_MODE=1 SHIPROOM_REMEDIATION_ROOT="$tmp/root" SHIPROOM_REMEDIATION_MOUNT="$tmp/mount" SHIPROOM_REMEDIATION_RUN="$tmp/run" SHIPROOM_REMEDIATION_TEST_POLICY_GUARD="$tmp/policy-rc.d" SHIPROOM_REMEDIATION_TEST_LOCK="$tmp/backend-global.lock"
mkdir -p "$SHIPROOM_REMEDIATION_ROOT" "$SHIPROOM_REMEDIATION_MOUNT" "$SHIPROOM_REMEDIATION_RUN"; : >"$SHIPROOM_REMEDIATION_ROOT/backend.state"
source "$DIR/lib.sh"
SOURCE_HASH="sha256:$(printf 'a%.0s' {1..64})"
PACKAGE_CONTRACT="$tmp/package-contract.json"
cat >"$PACKAGE_CONTRACT" <<EOF
{"schema_id":"remediation_package_contract.v1","schema_version":"1","distribution_id":"ubuntu","release":"noble","apt_sources_hash":"$SOURCE_HASH","apt_sources_artifact":"/stage/sources.bin","simulation_hash":"$SOURCE_HASH","simulation_artifact":"/stage/simulation.txt","packages":[{"name":"docker.io","version":"1.0","source":"fixture"},{"name":"xfsprogs","version":"1.0","source":"fixture"},{"name":"quota","version":"1.0","source":"fixture"}],"created_at":"2026-07-25T00:00:00Z"}
EOF
lib(){ bash -c "source '$DIR/lib.sh'; $*"; }
state(){ lib "state_put IMAGE '$SHIPROOM_REMEDIATION_ROOT/shiproom-remediation.xfs'; state_put MOUNT '$SHIPROOM_REMEDIATION_MOUNT'; state_put RUN '$SHIPROOM_REMEDIATION_RUN'; $*"; }
echo '[1/10] typed state round trip and malformed-key rejection'
lib 'state_put IMAGE alpha; [[ $(state_get IMAGE) == alpha ]]; ! ( state_put lower bad ) 2>/dev/null'
printf 'IMAGE\tYWxwaGE=\nIMAGE\tYmV0YQ==\n' >"$SHIPROOM_REMEDIATION_ROOT/backend.state"; ! lib 'state_validate'
: >"$SHIPROOM_REMEDIATION_ROOT/backend.state"; state 'state_put PHASE PREFLIGHT; [[ $(state_get PHASE) == PREFLIGHT ]]'
echo '[2/10] production root is not environment-overridable'
! env -u SHIPROOM_REMEDIATION_TEST_MODE SHIPROOM_REMEDIATION_ROOT=/tmp/escaped bash -c "source '$DIR/lib.sh'" 2>/dev/null
! env -u SHIPROOM_REMEDIATION_TEST_MODE bash -c "source '$DIR/lib.sh'; privileged_entry_guard" 2>/dev/null
env -u SHIPROOM_REMEDIATION_TEST_MODE -u SHIPROOM_REMEDIATION_ROOT -u SHIPROOM_REMEDIATION_MOUNT -u SHIPROOM_REMEDIATION_RUN -u SHIPROOM_REMEDIATION_TEST_POLICY_GUARD -u SHIPROOM_REMEDIATION_TEST_LOCK PATH="$tmp/hostile" /bin/bash -c "source '$DIR/lib.sh'; [[ \$PATH == /usr/sbin:/usr/bin:/sbin:/bin ]]"

shim="$tmp/shim"; mkdir "$shim"; export PATH="$shim:$PATH"
for dangerous in apt-get docker dockerd mkfs.xfs mount umount losetup systemctl xfs_quota; do
  cat >"$shim/$dangerous" <<'EOF'
#!/bin/sh
echo "UNSHIMMED_PRIVILEGED_COMMAND:$0" >&2
exit 97
EOF
  chmod +x "$shim/$dangerous"
done
cat >"$shim/losetup" <<'EOF'
#!/bin/sh
case "$*" in *BACK-FILE*) printf '%s\n' "$SHIPROOM_REMEDIATION_ROOT/shiproom-remediation.xfs";; *) exit 0;; esac
EOF
cat >"$shim/findmnt" <<'EOF'
#!/bin/sh
case "$*" in *"-R"*) exit 1;; esac
printf 'test-loop xfs rw,prjquota\n'
EOF
cat >"$shim/xfs_info" <<'EOF'
#!/bin/sh
printf 'naming   =version 2              bsize=4096   ascii-ci=0, ftype=1\n'
EOF
cat >"$shim/xfs_quota" <<'EOF'
#!/bin/sh
id=; for a in "$@"; do case "$a" in 'quota -p -nNv -b -i '*) id=${a##* };; esac; done
case "$*" in *'quota -p -nNv -b -i'*) if [ "$id" = 10000 ]; then b=8388608; i=200000; else b=${TEST_QUOTA_BLOCKS:-8388608}; i=${TEST_QUOTA_INODES:-200000}; fi; printf 'test-loop 0 0 %s 0 - 0 0 %s 0 - %s\n' "$b" "$i" "$SHIPROOM_REMEDIATION_MOUNT";; *) exit 0;; esac
EOF
cat >"$shim/systemctl" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >>"$SYSTEMCTL_LOG"
case "$1" in
  list-unit-files|show|show-environment|daemon-reload|stop|disable|unmask|enable) exit 0;;
  mask) printf masked >"$SYSTEMCTL_STATE"; exit 0;;
  is-enabled) if [ -r "$SYSTEMCTL_STATE" ] && [ "$(cat "$SYSTEMCTL_STATE")" = masked ]; then echo masked; exit 0; fi; echo disabled; exit 1;;
  is-active) echo inactive; exit 3;;
  *) exit 0;;
esac
EOF
cat >"$shim/pgrep" <<'EOF'
#!/bin/sh
exit "${TEST_PGREP_EXIT:-1}"
EOF
cat >"$shim/ss" <<'EOF'
#!/bin/sh
exit 0
EOF
chmod +x "$shim"/*; export SYSTEMCTL_LOG="$tmp/systemctl.log" SYSTEMCTL_STATE="$tmp/systemctl.state"

echo '[3/10] numeric headerless project-quota parser and storage verification'
: >"$SHIPROOM_REMEDIATION_ROOT/backend.state"; state_put LOOP test-loop; state_put DATA_PROJECT 10000; state_put DATA_BYTES 8589934592; state_put DATA_INODES 200000; quota_limits_verified 10000 8589934592 200000
! quota_limits_verified 10000 1 1

echo '[4/10] concurrent quota allocation has distinct, durable project IDs'
control_init; instance=$(control instance); capacity=$(python3 - "$instance" <<'PY'
import json,sys
print(json.dumps({'capacity_id':'test_capacity','backend_instance_id':sys.argv[1],'evidence_hash':'sha256:'+'0'*64,'nominal_image_bytes':17179869184,'filesystem_total_data_bytes':17179869184,'filesystem_available_bytes':17179869184,'metadata_reserve_bytes':1073741824,'supervisor_reserve_bytes':1073741824,'docker_bytes':8589934592,'aggregate_worktree_bytes':6442450944,'inode_policy_cap':1000000,'max_active_projects':4}))
PY
); control install-capacity "$capacity" >/dev/null; state 'state_put CAPACITY_ID test_capacity'
export TEST_QUOTA_BLOCKS=1024 TEST_QUOTA_INODES=1024
"$DIR/quota-worktree.sh" allocate casea 1048576 1024 "$SOURCE_HASH" >"$tmp/a" & a=$!
"$DIR/quota-worktree.sh" allocate caseb 1048576 1024 "$SOURCE_HASH" >"$tmp/b" & b=$!
wait "$a"; wait "$b"; awk -F '\t' 'NR==2 {if ($1 <= prior) exit 1} {prior=$1} END {exit(NR==2?0:1)}' "$SHIPROOM_REMEDIATION_ROOT/projects.tsv"
[[ ! -e "$SHIPROOM_REMEDIATION_ROOT/allocation.pending" ]]; [[ $(awk -F '\t' 'END{print NR}' "$SHIPROOM_REMEDIATION_ROOT/projects.tsv") -eq 2 ]]
unset TEST_QUOTA_BLOCKS TEST_QUOTA_INODES

echo '[5/10] partial allocation stays quarantined on the controlled XFS root'
cat >"$shim/xfs_quota" <<'EOF'
#!/bin/sh
id=; for a in "$@"; do case "$a" in 'quota -p -nNv -b -i '*) id=${a##* };; esac; done
case "$*" in *'limit -p'*) exit 9;; *'quota -p -nNv -b -i'*) if [ "$id" = 10000 ]; then printf 'test-loop 0 0 8388608 0 - 0 0 200000 0 - %s\n' "$SHIPROOM_REMEDIATION_MOUNT"; else printf 'test-loop 0 0 1024 0 - 0 0 1024 0 - %s\n' "$SHIPROOM_REMEDIATION_MOUNT"; fi;; *) exit 0;; esac
EOF
chmod +x "$shim/xfs_quota"; ! "$DIR/quota-worktree.sh" allocate casec 1048576 1024 "$SOURCE_HASH" 2>/dev/null; [[ -d "$SHIPROOM_REMEDIATION_MOUNT/quarantine/casec-20002-quota_limit" ]]

echo '[6/10] setup package-failure EXIT recovery removes only its marked guard'
cat >"$shim/apt-get" <<'EOF'
#!/bin/sh
printf 'APT_CALLED\n' >>"$TEST_MARKERS"
exit 71
EOF
cat >"$shim/dpkg-query" <<'EOF'
#!/bin/sh
echo absent
EOF
chmod +x "$shim/apt-get" "$shim/dpkg-query"; export TEST_MARKERS="$tmp/markers"; : >"$TEST_MARKERS"; rm -rf "$SHIPROOM_REMEDIATION_ROOT" "$SHIPROOM_REMEDIATION_MOUNT" "$SHIPROOM_REMEDIATION_RUN"; ! "$DIR/setup.sh" "$PACKAGE_CONTRACT"; grep -qx APT_CALLED "$TEST_MARKERS"; grep -qx PACKAGE_INSTALL_ATTEMPTED "$TEST_MARKERS"; grep -qx POLICY_GUARD_VERIFIED "$TEST_MARKERS"; grep -qx UNIT_CONTAINMENT_CALLED "$TEST_MARKERS"; grep -qx ROLLBACK_STARTED "$TEST_MARKERS"; grep -qx ROLLBACK_COMPLETED "$TEST_MARKERS"; grep -qx 'mask docker.service' "$SYSTEMCTL_LOG"; [[ ! -e "$SHIPROOM_REMEDIATION_TEST_POLICY_GUARD" ]]; [[ ! -e "$SHIPROOM_REMEDIATION_ROOT" ]]

echo '[7/10] recovery accepts absent optional loop/daemon fields and restores a marked guard'
mkdir -p "$SHIPROOM_REMEDIATION_ROOT" "$SHIPROOM_REMEDIATION_MOUNT" "$SHIPROOM_REMEDIATION_RUN"; : >"$SHIPROOM_REMEDIATION_ROOT/backend.state"; : >"$SHIPROOM_REMEDIATION_ROOT/setup.journal"
printf '#!/bin/sh\nexit 101\n' >"$SHIPROOM_REMEDIATION_TEST_POLICY_GUARD"; chmod 700 "$SHIPROOM_REMEDIATION_TEST_POLICY_GUARD"; state 'state_put PHASE POLICY_GUARD; state_put POLICY_GUARD_HASH "$(hash "$POLICY_GUARD_PATH")"; state_put POLICY_GUARD_CREATED yes'; "$DIR/recover.sh" --rollback; [[ ! -e "$SHIPROOM_REMEDIATION_TEST_POLICY_GUARD" ]]; [[ ! -e "$SHIPROOM_REMEDIATION_ROOT" ]]

echo '[8/10] supported inactive unit state is restored with command shims'
mkdir -p "$SHIPROOM_REMEDIATION_ROOT" "$SHIPROOM_REMEDIATION_MOUNT" "$SHIPROOM_REMEDIATION_RUN"; : >"$SHIPROOM_REMEDIATION_ROOT/backend.state"; : >"$SYSTEMCTL_LOG"
state 'state_put UNIT_DOCKER_SERVICE_EXISTS yes; state_put UNIT_DOCKER_SERVICE_ENABLED enabled; state_put UNIT_DOCKER_SERVICE_MASKED no; state_put UNIT_DOCKER_SERVICE_ACTIVE inactive; state_put UNIT_DOCKER_SERVICE_CHANGED yes; restore_units'
grep -qx 'unmask docker.service' "$SYSTEMCTL_LOG"; grep -qx 'enable docker.service' "$SYSTEMCTL_LOG"; ! grep -qx 'start docker.service' "$SYSTEMCTL_LOG"

echo '[9/10] PID reuse and missing storage/default-daemon start refusal'
state 'state_put LOOP test-loop; state_put DATA_PROJECT 10000; state_put DATA_BYTES 8589934592; state_put DATA_INODES 200000; state_put DAEMON_PID $$; state_put DAEMON_START 0; state_put DOCKERD_EXE /bin/false; state_put DOCKER_CLI /bin/false; ! daemon_verified'
( export TEST_PGREP_EXIT=0; ! "$DIR/start.sh" 2>/dev/null )
cat >"$shim/findmnt" <<'EOF'
#!/bin/sh
exit 1
EOF
chmod +x "$shim/findmnt"; ( export TEST_PGREP_EXIT=1; ! "$DIR/start.sh" 2>/dev/null )

echo '[10/17] bounded log capture enforces a byte ceiling'
fifo="$tmp/log.fifo"; mkfifo "$fifo"; python3 "$DIR/bounded-log.py" --input "$fifo" --output "$tmp/log" --maximum 13 & logger=$!; printf 'abcdefghijklmnopqrstuvwxyz' >"$fifo"; wait "$logger"; [[ $(wc -c <"$tmp/log") -eq 13 ]]
echo '[11/17] successful fake start persists daemon/socket/PID/FIFO after return'
cat >"$shim/findmnt" <<'EOF'
#!/bin/sh
case "$*" in *"-R"*) exit 1;; esac
printf 'test-loop xfs rw,prjquota\n'
EOF
cat >"$shim/xfs_quota" <<'EOF'
#!/bin/sh
id=; for a in "$@"; do case "$a" in 'quota -p -nNv -b -i '*) id=${a##* };; esac; done
case "$*" in *'quota -p -nNv -b -i'*) printf 'test-loop 0 0 8388608 0 - 0 0 200000 0 - %s\n' "$SHIPROOM_REMEDIATION_MOUNT";; *) exit 0;; esac
EOF
cat >"$shim/fake-dockerd" <<'EOF'
#!/bin/sh
cfg= pidfile=; while [ $# -gt 0 ]; do case "$1" in --config-file) cfg=$2; shift 2;; --pidfile) pidfile=$2; shift 2;; *) shift;; esac; done
sock=$(sed -n 's/.*unix:\/\/\([^\"]*\).*/\1/p' "$cfg"); echo $$ >"$pidfile"
python3 - "$sock" <<'PY' &
import os, socket, sys, time
try: os.unlink(sys.argv[1])
except FileNotFoundError: pass
s=socket.socket(socket.AF_UNIX); s.bind(sys.argv[1]); s.listen(1)
while True: time.sleep(1)
PY
child=$!; trap 'kill "$child" 2>/dev/null; exit 0' TERM INT; wait "$child"
EOF
cat >"$shim/docker" <<'EOF'
#!/bin/sh
exit 0
EOF
chmod +x "$shim/findmnt" "$shim/xfs_quota" "$shim/fake-dockerd" "$shim/docker"
ln -sf "$shim/fake-dockerd" "$shim/dockerd"
rm -rf "$SHIPROOM_REMEDIATION_ROOT" "$SHIPROOM_REMEDIATION_MOUNT" "$SHIPROOM_REMEDIATION_RUN"; mkdir -p "$SHIPROOM_REMEDIATION_ROOT" "$SHIPROOM_REMEDIATION_MOUNT" "$SHIPROOM_REMEDIATION_RUN"; : >"$SHIPROOM_REMEDIATION_ROOT/backend.state"; : >"$SHIPROOM_REMEDIATION_ROOT/setup.journal"; control_init
cat >"$SHIPROOM_REMEDIATION_ROOT/daemon.json" <<EOF
{"hosts":["unix://$SHIPROOM_REMEDIATION_RUN/docker.sock"]}
EOF
state 'state_put LOOP test-loop; state_put DATA_PROJECT 10000; state_put DATA_BYTES 8589934592; state_put DATA_INODES 200000; state_put CONFIG_HASH "$(hash "$DAEMON_JSON")"'
( export SHIPROOM_REMEDIATION_TEST_FAKE_DAEMON=1 TEST_PGREP_EXIT=1; PATH="$shim:$PATH" "$DIR/start.sh" )
[[ -S "$SHIPROOM_REMEDIATION_RUN/docker.sock" ]]; [[ -s "$SHIPROOM_REMEDIATION_RUN/dockerd.pid" ]]; [[ -p "$SHIPROOM_REMEDIATION_RUN/dockerd.log.fifo" ]]; fakepid=$(lib 'state_get DAEMON_PID'); kill -0 "$fakepid"; fakelog=$(lib 'state_get LOG_PID'); kill -0 "$fakelog"
kill -TERM "$fakepid" "$fakelog" 2>/dev/null || true; rm -f "$SHIPROOM_REMEDIATION_RUN/docker.sock" "$SHIPROOM_REMEDIATION_RUN/dockerd.pid" "$SHIPROOM_REMEDIATION_RUN/dockerd.log.fifo"
echo '[12/17] loop-only and mounted recovery paths are distinct'
cat >"$shim/losetup" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >>"$RECOVERY_LOG"; case "$*" in *BACK-FILE*) printf '%s\n' "$SHIPROOM_REMEDIATION_ROOT/shiproom-remediation.xfs";; *) exit 0;; esac
EOF
cat >"$shim/umount" <<'EOF'
#!/bin/sh
printf 'umount %s\n' "$*" >>"$RECOVERY_LOG"
EOF
chmod +x "$shim/losetup" "$shim/umount"; export RECOVERY_LOG="$tmp/recovery.log"
rm -rf "$SHIPROOM_REMEDIATION_ROOT" "$SHIPROOM_REMEDIATION_MOUNT" "$SHIPROOM_REMEDIATION_RUN"; mkdir -p "$SHIPROOM_REMEDIATION_ROOT" "$SHIPROOM_REMEDIATION_MOUNT" "$SHIPROOM_REMEDIATION_RUN"; : >"$SHIPROOM_REMEDIATION_ROOT/backend.state"; : >"$SHIPROOM_REMEDIATION_ROOT/setup.journal"; state 'state_put LOOP test-loop; state_put PHASE LOOP'; "$DIR/recover.sh" --rollback; grep -q -- '-d test-loop' "$RECOVERY_LOG"
cat >"$shim/findmnt" <<'EOF'
#!/bin/sh
case "$*" in *"-R"*) exit 1;; esac
printf 'test-loop\n'
EOF
chmod +x "$shim/findmnt"; rm -rf "$SHIPROOM_REMEDIATION_ROOT" "$SHIPROOM_REMEDIATION_MOUNT" "$SHIPROOM_REMEDIATION_RUN"; mkdir -p "$SHIPROOM_REMEDIATION_ROOT" "$SHIPROOM_REMEDIATION_MOUNT" "$SHIPROOM_REMEDIATION_RUN"; : >"$SHIPROOM_REMEDIATION_ROOT/backend.state"; : >"$SHIPROOM_REMEDIATION_ROOT/setup.journal"; state 'state_put LOOP test-loop; state_put PHASE MOUNT'; "$DIR/recover.sh" --rollback; grep -q 'umount ' "$RECOVERY_LOG"
echo '[13/17] allocation pending recognizes committed registry and retires failed IDs'
mkdir -p "$SHIPROOM_REMEDIATION_ROOT" "$SHIPROOM_REMEDIATION_MOUNT/worktrees/pending" "$SHIPROOM_REMEDIATION_MOUNT/quarantine"; : >"$SHIPROOM_REMEDIATION_ROOT/backend.state"; state 'state_put LOOP test-loop; state_put DATA_PROJECT 10000; state_put DATA_BYTES 8589934592; state_put DATA_INODES 200000'
printf '20009\tpending\t1048576\t1024\n' >"$SHIPROOM_REMEDIATION_ROOT/projects.tsv"; printf '20009\tpending\tREGISTRY_COMMITTED\n' >"$SHIPROOM_REMEDIATION_ROOT/allocation.pending"; lib 'recover_pending_allocation'; [[ ! -e "$SHIPROOM_REMEDIATION_ROOT/allocation.pending" ]]; [[ -d "$SHIPROOM_REMEDIATION_MOUNT/worktrees/pending" ]]
printf '20010\torphan\tTREE_CREATED\n' >"$SHIPROOM_REMEDIATION_ROOT/allocation.pending"; mkdir "$SHIPROOM_REMEDIATION_MOUNT/worktrees/orphan"; lib 'recover_pending_allocation'; [[ -d "$SHIPROOM_REMEDIATION_MOUNT/quarantine/orphan-20010-recovered-TREE_CREATED" ]]
echo '[14/17] release pending preserves registry authority until its committed removal'
printf '20009\tpending\t1048576\t1024\n' >"$SHIPROOM_REMEDIATION_ROOT/projects.tsv"; printf '20009\tpending\tTREE_REMOVED\n' >"$SHIPROOM_REMEDIATION_ROOT/release.pending"; lib 'recover_pending_release'; [[ -e "$SHIPROOM_REMEDIATION_ROOT/release.pending" ]]; : >"$SHIPROOM_REMEDIATION_ROOT/projects.tsv"; lib 'recover_pending_release'; [[ ! -e "$SHIPROOM_REMEDIATION_ROOT/release.pending" ]]
echo '[15/17] logger PID-reuse is rejected'
state 'state_put LOG_PID $$; state_put LOG_START 0; ! logger_probe'
echo '[16/17] concurrent setup attempts serialize on the non-removable global lock'
cat >"$shim/apt-get" <<'EOF'
#!/bin/sh
if mkdir "$SETUP_INFLIGHT" 2>/dev/null; then echo enter >>"$SETUP_LOG"; sleep .2; rmdir "$SETUP_INFLIGHT"; exit 71; fi
echo overlap >>"$SETUP_LOG"; exit 72
EOF
chmod +x "$shim/apt-get"; export SETUP_INFLIGHT="$tmp/setup-inflight" SETUP_LOG="$tmp/setup.log"; rm -rf "$SHIPROOM_REMEDIATION_ROOT" "$SHIPROOM_REMEDIATION_MOUNT" "$SHIPROOM_REMEDIATION_RUN"
( "$DIR/setup.sh" "$PACKAGE_CONTRACT" >/dev/null 2>&1 || exit 0 ) & s1=$!; ( "$DIR/setup.sh" "$PACKAGE_CONTRACT" >/dev/null 2>&1 || exit 0 ) & s2=$!; wait "$s1"; wait "$s2"; [[ $(grep -c '^enter$' "$SETUP_LOG") -eq 2 ]]; ! grep -q overlap "$SETUP_LOG"
echo '[17/17] release-pending terminal state keeps authority until registry removal is durable'
mkdir -p "$SHIPROOM_REMEDIATION_ROOT" "$SHIPROOM_REMEDIATION_MOUNT/worktrees/releasecase"; : >"$SHIPROOM_REMEDIATION_ROOT/backend.state"; state 'state_put LOOP test-loop; state_put DATA_PROJECT 10000; state_put DATA_BYTES 8589934592; state_put DATA_INODES 200000'; printf '20011\treleasecase\t1048576\t1024\n' >"$SHIPROOM_REMEDIATION_ROOT/projects.tsv"; printf '20011\treleasecase\tTREE_REMOVED\n' >"$SHIPROOM_REMEDIATION_ROOT/release.pending"; lib 'recover_pending_release'; [[ -e "$SHIPROOM_REMEDIATION_ROOT/release.pending" ]]; [[ -s "$SHIPROOM_REMEDIATION_ROOT/projects.tsv" ]]
echo 'behavioral command-shim fixtures passed (no privileged lifecycle command was invoked)'
