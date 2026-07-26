#!/usr/bin/env bash
set -Eeuo pipefail; DIR=$(cd "$(dirname "$0")"&&pwd); source "$DIR/lib.sh"; root_only; privileged_entry_guard; [[ ${1:-} == --locked ]] || with_lock; require_paths; control_ready; daemon_verified || die daemon_identity; log_pipeline_verified || die logger_identity; storage_verified || die quota_storage
[[ "$(hash "$DAEMON_JSON")" == "$(state_get CONFIG_HASH)" ]]||die config; [[ "$(stat -c %U:%G:%a "$SOCKET")" == root:root:600 ]]||die socket; [[ ! -S /var/run/docker.sock ]]||die default_socket
ss -xlpn | grep -F "$SOCKET" | grep -F "pid=$(state_get DAEMON_PID)" >/dev/null || die socket_owner
timeout 10 "$(state_get DOCKER_CLI)" --host "unix://$SOCKET" info --format '{{.Driver}}|{{.DriverStatus}}|{{.DockerRootDir}}'|grep -Eq "^overlay2\|.*Backing Filesystem.*xfs.*Supports d_type.*true.*\|$MOUNT/docker-data$"||die overlay
quota_record "$(state_get DATA_PROJECT)"
