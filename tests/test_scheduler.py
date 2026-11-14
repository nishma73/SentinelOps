"""Tests for Idempotent Periodic Scheduler, Pause Switch, and Circuit Breaker."""

from datetime import datetime, timezone
import pytest
from sentinelops.scheduler import (
    SchedulerState,
    get_period_key,
    is_paused,
    run_job,
    set_paused,
)


def test_period_keys_are_deterministic():
    dt = datetime(2026, 11, 14, 22, 45, 0, tzinfo=timezone.utc)
    daily_key = get_period_key("triage", "daily", dt)
    hourly_key = get_period_key("triage", "hourly", dt)

    assert daily_key == "triage:daily:2026-11-14"
    assert hourly_key == "triage:hourly:2026-11-14-22"


def test_pause_switch_skips_job_without_deleting_state(tmp_path):
    pause_file = tmp_path / "PAUSE"
    state = SchedulerState()

    # Activate pause switch
    pause_file.write_text("PAUSED", encoding="utf-8")
    assert is_paused(str(pause_file)) is True

    call_count = {"count": 0}

    def my_job():
        call_count["count"] += 1
        return "done"

    res = run_job(
        job_fn=my_job,
        job_name="triage",
        period="hourly",
        pause_file_path=str(pause_file),
        state=state,
    )

    assert res["status"] == "skipped"
    assert res["reason"] == "pause_switch_active"
    assert call_count["count"] == 0

    # Deactivate pause
    pause_file.unlink()
    assert is_paused(str(pause_file)) is False

    res_resumed = run_job(
        job_fn=my_job,
        job_name="triage",
        period="hourly",
        pause_file_path=str(pause_file),
        state=state,
    )
    assert res_resumed["status"] == "completed"
    assert call_count["count"] == 1


def test_per_period_deduplication(tmp_path):
    pause_file = tmp_path / "PAUSE"
    state = SchedulerState()
    dt = datetime(2026, 11, 14, 10, 0, 0, tzinfo=timezone.utc)

    call_count = {"count": 0}

    def sample_job():
        call_count["count"] += 1
        return {"triaged": 5}

    # Run 1
    res1 = run_job(
        sample_job,
        job_name="triage",
        period="hourly",
        dt=dt,
        pause_file_path=str(pause_file),
        state=state,
    )
    assert res1["status"] == "completed"
    assert call_count["count"] == 1

    # Run 2 with same period key -> must deduplicate and skip
    res2 = run_job(
        sample_job,
        job_name="triage",
        period="hourly",
        dt=dt,
        pause_file_path=str(pause_file),
        state=state,
    )
    assert res2["status"] == "skipped"
    assert res2["reason"] == "already_executed"
    assert res2["result"] == {"triaged": 5}
    assert call_count["count"] == 1


def test_circuit_breaker_trips_and_emits_alert_after_3_failures(tmp_path):
    pause_file = tmp_path / "PAUSE"
    state = SchedulerState()
    dt = datetime(2026, 11, 14, 12, 0, 0, tzinfo=timezone.utc)

    alerts_received = []

    def on_alert_cb(period_key, attempts, error):
        alerts_received.append((period_key, attempts, error))

    def failing_job():
        raise RuntimeError("Transient backend timeout")

    # Attempt 1
    res1 = run_job(
        failing_job,
        job_name="triage",
        period="hourly",
        dt=dt,
        max_attempts=3,
        pause_file_path=str(pause_file),
        on_alert=on_alert_cb,
        state=state,
    )
    assert res1["status"] == "failed"
    assert res1["attempts"] == 1

    # Attempt 2
    res2 = run_job(
        failing_job,
        job_name="triage",
        period="hourly",
        dt=dt,
        max_attempts=3,
        pause_file_path=str(pause_file),
        on_alert=on_alert_cb,
        state=state,
    )
    assert res2["status"] == "failed"
    assert res2["attempts"] == 2

    # Attempt 3 -> Circuit breaker trips!
    res3 = run_job(
        failing_job,
        job_name="triage",
        period="hourly",
        dt=dt,
        max_attempts=3,
        pause_file_path=str(pause_file),
        on_alert=on_alert_cb,
        state=state,
    )
    assert res3["status"] == "tripped"
    assert res3["reason"] == "circuit_breaker_tripped"
    assert res3["attempts"] == 3
    assert len(alerts_received) == 1
    assert "triage:hourly:2026-11-14-12" in alerts_received[0][0]

    # Subsequent attempt -> Disabled by circuit breaker
    res4 = run_job(
        failing_job,
        job_name="triage",
        period="hourly",
        dt=dt,
        max_attempts=3,
        pause_file_path=str(pause_file),
        state=state,
    )
    assert res4["status"] == "disabled"
    assert res4["reason"] == "circuit_breaker_tripped"
