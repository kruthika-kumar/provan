#!/usr/bin/env bash
set -Eeuo pipefail
DIR=$(cd "$(dirname "$0")" && pwd); source "$DIR/lib.sh"; root_only; privileged_entry_guard
action=${1:---inspect}; locked=${2:-}; [[ "$locked" == --locked ]] || with_lock
[[ -r "$JOURNAL" ]] || die 'no Shiproom journal'
if [[ "$action" != --rollback ]]; then cat "$JOURNAL"; echo 'use --rollback only after reviewing the immutable journal'; exit 2; fi
state_validate || { failed_setup; die 'malformed state retained for manual recovery'; }
phase=$(state_try PHASE || echo UNKNOWN); journal RECOVERY "$phase"
test_marker ROLLBACK_STARTED
# Package changes are handled first, even when no loop exists. The policy guard
# stays installed until package-introduced service units are contained.
if [[ "$phase" == PACKAGE_INSTALL_ATTEMPTED || "$phase" == PACKAGES || "$phase" == UNITS_CONTAINED || "$phase" == POLICY_GUARD_REMOVED ]]; then contain_units || { failed_setup; die 'cannot contain package units'; }; fi
if ! dpkg --audit | grep -q .; then :; else
  control incident package_recovery PACKAGE_STATE_UNCERTAIN '{"reason":"dpkg_audit_nonempty"}' >/dev/null 2>&1 || true
  failed_setup; die 'package state uncertain; guard retained'
fi
if [[ "$(state_try POLICY_GUARD_CREATED || true)" == yes ]]; then cleanup_policy_guard || { failed_setup; die 'policy guard integrity'; }; fi
if loop_probe; then "$DIR/teardown.sh" --locked --recovery || { failed_setup; die 'rollback incomplete; failed record preserved'; }; else
  # No loop was ever allocated: prove absence before descriptor-relative cleanup.
  root_residual_absence_proven "$MOUNT" && root_residual_absence_proven "$RUN" || { control incident no_loop_recovery CONTAINMENT_UNPROVEN '{"reason":"root_residual_absence_unproven"}' >/dev/null 2>&1 || true; failed_setup; die 'RECOVERY_CONTAINMENT_UNPROVEN'; }
  restore_units || { control incident unit_restore UNIT_RESTORATION_UNPROVEN '{"reason":"restore_failed"}' >/dev/null 2>&1 || true; failed_setup; die 'unit restoration unproven'; }
  safe_remove_owned_root "$RUN" && safe_remove_owned_root "$MOUNT" && safe_remove_owned_root "$ROOT" || { failed_setup; die 'safe root cleanup failed'; }
  test_marker ROLLBACK_COMPLETED
fi
