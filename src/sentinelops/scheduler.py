"""Idempotent Periodic Scheduler with Pause Switch and Circuit Breaker.

Provides deterministic period keys (daily/hourly), graceful pause switch,
per-period deduplication, and max_attempts=3 circuit breaker protection.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set

from sentinelops.config import get_settings

logger = logging.getLogger("sentinelops.scheduler")


def is_paused(pause_file_path: Optional[str] = None) -> bool:
    """Check if the pause switch is currently active via PAUSE file."""
    path_str = pause_file_path or get_settings().PAUSE_FILE_PATH
    return Path(path_str).exists()


def set_paused(paused: bool, pause_file_path: Optional[str] = None) -> bool:
    """Activate or deactivate the pause switch by manipulating the PAUSE file."""
    path = Path(pause_file_path or get_settings().PAUSE_FILE_PATH)
    if paused:
        path.write_text("PAUSED\n", encoding="utf-8")
        logger.warning("Pause switch ACTIVATED (PAUSE file created at %s)", path)
        return True
    else:
        if path.exists():
            path.unlink()
            logger.info("Pause switch DEACTIVATED (PAUSE file removed at %s)", path)
        return False


def get_period_key(
    job_name: str, period: str, dt: Optional[datetime] = None
) -> str:
    """Generate deterministic period key (e.g., triage:daily:2026-11-14)."""
    now = dt or datetime.now(timezone.utc)
    p_norm = period.strip().lower()

    if p_norm == "daily":
        date_str = now.strftime("%Y-%m-%d")
        return f"{job_name}:daily:{date_str}"
    elif p_norm == "hourly":
        hour_str = now.strftime("%Y-%m-%d-%H")
        return f"{job_name}:hourly:{hour_str}"
    else:
        minute_str = now.strftime("%Y-%m-%d-%H-%M")
        return f"{job_name}:{p_norm}:{minute_str}"


@dataclass
class SchedulerState:
    """In-memory tracking for job execution, circuit breaking, and deduplication."""
    executed_keys: Set[str] = field(default_factory=set)
    executed_results: Dict[str, Any] = field(default_factory=dict)
    failure_counts: Dict[str, int] = field(default_factory=dict)
    tripped_keys: Set[str] = field(default_factory=set)
    alerts: List[Dict[str, Any]] = field(default_factory=list)

    def reset(self):
        """Reset all scheduler state."""
        self.executed_keys.clear()
        self.executed_results.clear()
        self.failure_counts.clear()
        self.tripped_keys.clear()
        self.alerts.clear()


_global_scheduler_state = SchedulerState()


def get_scheduler_state() -> SchedulerState:
    """Retrieve singleton scheduler state."""
    return _global_scheduler_state


def run_job(
    job_fn: Callable[[], Any],
    job_name: str = "triage",
    period: str = "hourly",
    dt: Optional[datetime] = None,
    max_attempts: int = 3,
    pause_file_path: Optional[str] = None,
    on_alert: Optional[Callable[[str, int, str], None]] = None,
    state: Optional[SchedulerState] = None,
) -> Dict[str, Any]:
    """Execute a periodic job with deduplication, pause check, and circuit breaker.

    - Computes period key: `job_name:period:timestamp`
    - Checks PAUSE file switch: skips execution if active without altering state
    - Deduplicates: if period key already executed successfully, skips execution
    - Circuit breaker: if period key fails >= max_attempts times, trips and disables key
    """
    s = state if state is not None else _global_scheduler_state
    period_key = get_period_key(job_name, period, dt)

    # 1. Pause Switch Check
    if is_paused(pause_file_path):
        logger.info("Scheduler: PAUSE active. Skipping job '%s' for key '%s'", job_name, period_key)
        return {
            "status": "skipped",
            "reason": "pause_switch_active",
            "period_key": period_key,
        }

    # 2. Per-period Deduplication
    if period_key in s.executed_keys:
        logger.info("Scheduler: Key '%s' already executed. Skipping.", period_key)
        return {
            "status": "skipped",
            "reason": "already_executed",
            "period_key": period_key,
            "result": s.executed_results.get(period_key),
        }

    # 3. Circuit Breaker Check
    if period_key in s.tripped_keys:
        attempts = s.failure_counts.get(period_key, max_attempts)
        logger.error(
            "Scheduler: Key '%s' is DISABLED by circuit breaker (failures=%d)",
            period_key,
            attempts,
        )
        return {
            "status": "disabled",
            "reason": "circuit_breaker_tripped",
            "period_key": period_key,
            "attempts": attempts,
        }

    # 4. Attempt execution
    try:
        result = job_fn()
        s.executed_keys.add(period_key)
        s.executed_results[period_key] = result
        # Clear failure counts on success
        s.failure_counts.pop(period_key, None)
        logger.info("Scheduler: Job '%s' successfully completed for key '%s'", job_name, period_key)
        return {
            "status": "completed",
            "period_key": period_key,
            "result": result,
        }
    except Exception as exc:
        current_failures = s.failure_counts.get(period_key, 0) + 1
        s.failure_counts[period_key] = current_failures
        err_msg = f"{type(exc).__name__}: {str(exc)}"

        logger.warning(
            "Scheduler: Job attempt %d/%d failed for key '%s': %s",
            current_failures,
            max_attempts,
            period_key,
            err_msg,
        )

        if current_failures >= max_attempts:
            s.tripped_keys.add(period_key)
            alert_payload = {
                "period_key": period_key,
                "job_name": job_name,
                "attempts": current_failures,
                "error": err_msg,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            s.alerts.append(alert_payload)
            logger.critical(
                "CIRCUIT BREAKER TRIPPED for key '%s' after %d consecutive failures. Emitting alert.",
                period_key,
                current_failures,
            )
            if on_alert:
                try:
                    on_alert(period_key, current_failures, err_msg)
                except Exception as alert_err:
                    logger.error("Alert callback failed: %s", alert_err)

            return {
                "status": "tripped",
                "reason": "circuit_breaker_tripped",
                "period_key": period_key,
                "attempts": current_failures,
                "error": err_msg,
            }

        return {
            "status": "failed",
            "reason": "attempt_failed",
            "period_key": period_key,
            "attempts": current_failures,
            "error": err_msg,
        }
