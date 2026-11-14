"""Tests for Hash-Locked Approval Queue and Idempotent Executor."""

import time
import pytest
from sentinelops.approval_queue import (
    ApprovalError,
    ApprovalQueue,
    canonical_json,
    hash_payload,
)


def test_canonical_json_and_hash_payload_are_deterministic():
    data1 = {"b": 2, "a": 1, "nested": {"y": 20, "x": 10}}
    data2 = {"a": 1, "nested": {"x": 10, "y": 20}, "b": 2}

    assert canonical_json(data1) == canonical_json(data2)
    assert hash_payload(data1) == hash_payload(data2)


def test_propose_and_approve_lifecycle():
    queue = ApprovalQueue(default_ttl_seconds=3600)
    payload = {"ticket_id": "TCK-1", "recipient": "user@corp.com", "body": "Draft"}

    item = queue.propose("reply", payload, proposed_by="agent_alpha")
    assert item.status == "proposed"
    assert item.action_id.startswith("act_")
    assert item.initial_hash == hash_payload(payload)

    # Approve with matching seen_hash
    approved = queue.approve(item.action_id, by="supervisor_jane", seen_hash=item.seen_hash)
    assert approved.status == "approved"
    assert approved.approved_by == "supervisor_jane"
    assert approved.approved_hash == item.seen_hash


def test_approve_with_mismatched_hash_fails():
    queue = ApprovalQueue()
    payload = {"msg": "original"}
    item = queue.propose("task", payload)

    with pytest.raises(ApprovalError) as exc_info:
        queue.approve(item.action_id, by="jane", seen_hash="fake_hash_1234567890abcdef")
    assert "Seen hash mismatch" in str(exc_info.value)


def test_reject_records_reason_and_audit():
    queue = ApprovalQueue()
    item = queue.propose("test", {"field": 1})
    rejected = queue.reject(item.action_id, by="lead", reason="Policy violation RB-001")
    assert rejected.status == "rejected"
    assert rejected.rejection_reason == "Policy violation RB-001"

    audits = queue.get_audit_log(item.action_id)
    event_types = [a.event_type for a in audits]
    assert event_types == ["proposed", "rejected"]


def test_edit_recalculates_hash_and_resets_approval():
    queue = ApprovalQueue()
    item = queue.propose("task", {"amount": 100})
    queue.approve(item.action_id, by="lead", seen_hash=item.seen_hash)

    # Edit changes payload
    new_payload = {"amount": 50}
    edited = queue.edit(item.action_id, by="lead", new_payload=new_payload)
    assert edited.status == "proposed"
    assert edited.approved_by is None
    assert edited.seen_hash == hash_payload(new_payload)


def test_ttl_expiration_blocks_approve_and_execute():
    # 0.1 second TTL
    queue = ApprovalQueue(default_ttl_seconds=1)
    item = queue.propose("quick_task", {"run": True}, ttl_seconds=0)

    # Allow time to pass
    time.sleep(0.05)

    with pytest.raises(ApprovalError) as exc_info:
        queue.approve(item.action_id, by="lead", seen_hash=item.seen_hash)
    assert "expired" in str(exc_info.value)


def test_post_approval_tamper_detection_blocks_execution():
    queue = ApprovalQueue()
    payload = {"recipient": "alice@corp.com", "credit_percent": 10}
    item = queue.propose("grant_credit", payload)

    # Legitimate approval
    queue.approve(item.action_id, by="manager_bob", seen_hash=item.seen_hash)
    assert item.status == "approved"

    # Simulate unauthorized tampering of payload post-approval
    item.payload["credit_percent"] = 99  # Tampered!

    # Execution must detect hash mismatch and block
    with pytest.raises(ApprovalError) as exc_info:
        queue.execute(item.action_id)

    assert "Execution blocked: payload has been tampered with post-approval" in str(exc_info.value)
    assert item.status == "blocked"

    # Verify "blocked" event in audit trail
    audits = queue.get_audit_log(item.action_id)
    blocked_events = [a for a in audits if a.event_type == "blocked"]
    assert len(blocked_events) == 1
    assert "Payload hash mismatch" in blocked_events[0].details.get("reason", "")


def test_idempotent_execution_executes_at_most_once():
    queue = ApprovalQueue()
    payload = {"job": "dispatch_email", "seq": 42}
    item = queue.propose("dispatch", payload)
    queue.approve(item.action_id, by="lead", seen_hash=item.seen_hash)

    execution_counter = {"calls": 0}

    def my_executor(p):
        execution_counter["calls"] += 1
        return {"dispatched_seq": p["seq"], "call_count": execution_counter["calls"]}

    # Call 1
    res1 = queue.execute(item.action_id, executor_fn=my_executor)
    assert res1["status"] == "success"
    assert res1["idempotency_key"] == item.action_id
    assert execution_counter["calls"] == 1

    # Call 2 (Duplicate execution call)
    res2 = queue.execute(item.action_id, executor_fn=my_executor)
    # Must return cached result without calling my_executor again!
    assert res2 == res1
    assert execution_counter["calls"] == 1


def test_audit_trail_records_full_lifecycle():
    queue = ApprovalQueue()
    item = queue.propose("full_cycle", {"msg": "v1"})
    queue.edit(item.action_id, by="agent", new_payload={"msg": "v2"})
    queue.approve(item.action_id, by="lead", seen_hash=item.seen_hash)
    queue.execute(item.action_id)

    audits = queue.get_audit_log(item.action_id)
    event_types = [a.event_type for a in audits]
    assert event_types == ["proposed", "edited", "approved", "executed"]
