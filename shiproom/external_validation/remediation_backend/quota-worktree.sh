#!/usr/bin/env bash
# Allocation adapter.  SQLite is authority; TSV files are evidence projections.
set -Eeuo pipefail
DIR=$(cd "$(dirname "$0")" && pwd)
source "$DIR/lib.sh"
root_only; privileged_entry_guard; with_lock; require_paths; storage_verified; control_ready

action=${1:?allocate|report|release}
attempt=${2:?attempt-id-required}
[[ "$attempt" =~ ^[a-z0-9][a-z0-9_-]{0,63}$ ]] || die attempt_id
tree="$MOUNT/worktrees/$attempt"; quarantine="$MOUNT/quarantine"

projection_append() {
  local project=$1 bytes=$2 inodes=$3 temp
  temp=$(mktemp "$ROOT/.projects.XXXXXX")
  [[ -r "$ROOT/projects.tsv" ]] && cat "$ROOT/projects.tsv" >"$temp"
  printf '%s\t%s\t%s\t%s\n' "$project" "$attempt" "$bytes" "$inodes" >>"$temp"
  atomic_replace "$ROOT/projects.tsv" "$temp"
}

allocation_failure() {
  local project=$1 reason=$2
  if [[ -e "$tree" ]]; then
    install -d -m 0700 "$quarantine"
    mv -- "$tree" "$quarantine/$attempt-$project-$reason"
  fi
  control incident allocation_failure QUOTA_STATE_UNCERTAIN "{\"attempt_id\":\"$attempt\",\"project_id\":$project,\"reason\":\"$reason\"}" >/dev/null || true
  die "allocation_$reason"
}

case "$action" in
  allocate)
    bytes=${3:?bytes-required}; inodes=${4:?inodes-required}; snapshot=${5:?source-snapshot-hash-required}
    [[ "$bytes" =~ ^[0-9]+$ && "$inodes" =~ ^[0-9]+$ && "$snapshot" =~ ^sha256:[a-f0-9]{64}$ && $bytes -ge $MIN_WORKTREE_BYTES && $bytes -le $MAX_WORKTREE_BYTES && $((bytes%1024)) -eq 0 && $inodes -ge $MIN_WORKTREE_INODES && $inodes -le $MAX_WORKTREE_INODES ]] || die allocation_input
    [[ ! -e "$tree" ]] || die attempt_reused
    capacity_id=$(state_try CAPACITY_ID) || die capacity_unqualified
    available=$(df -B1 --output=avail "$MOUNT" | tail -n 1 | tr -d '[:space:]')
    [[ "$available" =~ ^[0-9]+$ ]] || die capacity_runtime_unknown
    path_hash="sha256:$(printf %s "$tree" | sha256sum | awk '{print $1}')"
    project=$(control reserve "$attempt" "$bytes" "$inodes" "$path_hash" "$capacity_id" --runtime-available "$available") || die capacity_reservation
    create_worktree "$tree" || allocation_failure "$project" tree_create
    authority=$(python3 "$DIR/worktree_authority.py" --backend-instance "$(control instance)" --attempt "$attempt" --project "$project" --path "$tree" --source-snapshot-hash "$snapshot") || allocation_failure "$project" authority_capture
    control allocation-phase "$attempt" TREE_CREATED "$authority" --pending-json "{\"project_id\":$project,\"attempt_id\":\"$attempt\",\"phase\":\"TREE_CREATED\",\"requested_bytes\":$bytes,\"requested_inodes\":$inodes,\"worktree_path_hash\":\"$path_hash\"}" || allocation_failure "$project" state_tree
    if ! xfs_quota -x -c "project -s -p $tree $project" "$MOUNT"; then allocation_failure "$project" project_assign; fi
    control allocation-phase "$attempt" PROJECT_ASSIGNED "$authority" || allocation_failure "$project" state_project
    if ! xfs_quota -x -c "limit -p bhard=${bytes}b ihard=$inodes $project" "$MOUNT" || ! quota_limits_verified "$project" "$bytes" "$inodes"; then
      xfs_quota -x -c "project -C -p $tree $project" "$MOUNT" || true
      allocation_failure "$project" quota_limit
    fi
    quota="{\"project_id\":$project,\"byte_limit\":$bytes,\"inode_limit\":$inodes}"
    control allocation-phase "$attempt" LIMIT_ASSIGNED "$authority" --quota-json "$quota" || allocation_failure "$project" state_limit
    projection_append "$project" "$bytes" "$inodes"
    control allocation-phase "$attempt" REGISTRY_COMMITTED "$authority" --quota-json "$quota" || allocation_failure "$project" state_registry
    printf '%s\n' "$tree"
    ;;
  report)
    quota_record "${2:?project-id-required}"
    ;;
  release)
    authorization=${3:?root-owned-authorization-path-required}
    [[ -f "$authorization" ]] || die authorization_missing
    exec python3 "$DIR/release.py" --db "$CONTROL_DB" --authorization "$authorization" --authorization-root "$ROOT/supervisor-owned/authorizations" --supervisor-root "$ROOT/supervisor-owned" --mount "$MOUNT" --helper "$DIR/release_helper.py"
    ;;
  *) die action_invalid ;;
esac
