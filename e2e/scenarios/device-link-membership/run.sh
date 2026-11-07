#!/bin/sh
# Real API/DB membership tests. This is component evidence, never native-client certification.
set -eu
: "${TEST_DATABASE_URL_MIGRATE:?set an owned disposable Postgres owner URL with CREATEDB}"
: "${TEST_DATABASE_URL:?set the matching disposable Postgres runtime URL}"
cd "$(dirname "$0")/../../.."
log=$(mktemp)
trap 'rm -f "$log"' EXIT HUP INT TERM
run() {
    name=$1
    target=${2:-e2ee_text}
    [ -n "$name" ] || { echo "FAIL: empty test filter" >&2; return 1; }
    printf '%s\n' "linked-device membership API integration: $name"
    if ! cargo test --locked -p api --test "$target" "$name" -- --exact --nocapture --test-threads=1 >"$log" 2>&1; then
        cat "$log"
        return 1
    fi
    cat "$log"
    grep -Fq 'running 1 test' "$log"
    grep -Fq "test $name ..." "$log"
    grep -Fq 'test result: ok. 1 passed; 0 failed;' "$log"
    if grep -Eq '(^|[[:space:]])skipped:' "$log"; then
        echo 'FAIL: database fixture skipped' >&2
        return 1
    fi
}
run a_self_conversation_is_one_per_person_and_always_encrypted
run a_self_conversation_holds_only_that_persons_devices_as_they_come_and_go
run self_conversation_messages_go_after_their_retention_and_with_the_account
run a_canary_said_to_your_own_devices_is_nowhere_on_the_server
run the_initial_audience_is_urgent_and_must_join_before_the_first_message
run the_initial_audience_stays_urgent_across_bounded_commits
run an_established_shared_group_keeps_batching_after_all_messages_expire
run an_encrypted_reaction_establishes_the_canonical_shared_group
run registration_and_revoke_serialize_with_concurrent_ciphertext_posts
run a_cross_signed_sibling_is_proposed_without_waiting_for_the_batch
run an_urgent_sibling_never_extends_an_outstanding_signed_batch
run an_urgent_sibling_does_not_accelerate_a_new_persons_pending_add
run a_shared_group_split_while_waiting_for_the_lock_rejects_old_group_ciphertext
run a_linked_device_receives_every_post_accepted_after_its_registration
run a_revoke_immediately_fences_messages_edits_and_reactions_until_the_remove_commits
run repair_generations_are_durable_and_fence_legacy_requests
run repair_current_and_history_are_generation_scoped
run repair_refuses_aliases_and_repaired_groups_cannot_acquire_aliases
run repair_requires_the_exact_active_old_leaf_and_current_epoch
run repair_reserves_retired_ids_against_other_conversations
run repair_signs_current_uuid_and_preserves_strict_welcome_and_tree_flow
run repair_availability_refuses_unsupported_audience_group_framing
run repair_competing_cas_has_one_winner
run repair_winning_while_issuance_waits_fences_the_old_generation
run repair_creator_loss_keeps_the_durable_head_and_cannot_restart_epoch_zero
run repair_routes_bound_queries_bodies_and_reject_private_state_fields
run repair_generation_zero_alias_metadata_keeps_the_canonical_group_uuid
run repair_rechecks_speak_permission_after_waiting_for_the_lock
run repair_current_generation_malformed_ciphertext_does_not_report_a_head_change
run repair_cannot_reuse_a_genesis_created_before_the_first_info_read
run a_self_conversation_cannot_ring_or_make_its_person_busy self_calls
printf '%s\n' 'PASS: 31 linked-device membership API component tests; exact-head native-client/history proof and MERGE HOLD remain pending.'
