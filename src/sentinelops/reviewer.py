"""Independent QA Gate and Reviewer Protocol for SentinelOps.

Enforces strict separation of concerns between draft writers and reviewers,
isolates writer reasoning, validates integer rubric scoring, and manages
single-rewrite remediation loops.
"""

from __future__ import annotations

import logging
from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence, Union

logger = logging.getLogger("sentinelops.reviewer")

DEFAULT_RUBRIC = ("facts", "policy", "fit", "clarity")


class ReviewError(Exception):
    """Raised when review process encounters unrecoverable structural errors."""
    pass


@dataclass
class ReviewAttempt:
    """Record of a single draft and its independent QA review."""
    attempt_number: int
    draft: str
    scores: Dict[str, int]
    notes: str
    passed: bool
    malformed: bool = False
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ReviewResult:
    """Final verdict and execution history of the QA gate."""
    passed: bool
    status: str  # "approved", "held", "failed"
    final_draft: str
    attempts: List[ReviewAttempt] = field(default_factory=list)
    reason: Optional[str] = None
    scores: Dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "passed": self.passed,
            "status": self.status,
            "final_draft": self.final_draft,
            "attempts": [a.to_dict() for a in self.attempts],
            "reason": self.reason,
            "scores": self.scores,
        }


def _validate_scores(
    raw_scores: Any, rubric: Sequence[str]
) -> tuple[bool, Dict[str, int], str]:
    """Validate reviewer scores strictly.

    Enforces:
    - Dict structure
    - All rubric criteria present
    - Integer types only (rejecting bools)
    - Value range 1..10
    """
    if not isinstance(raw_scores, dict):
        return False, {}, f"Reviewer output must be a dict, got {type(raw_scores).__name__}"

    cleaned_scores: Dict[str, int] = {}
    for criterion in rubric:
        if criterion not in raw_scores:
            return False, {}, f"Missing required rubric criterion: '{criterion}'"

        val = raw_scores[criterion]
        # In Python, bool is a subclass of int. Reject bool explicitly.
        if type(val) is bool or not isinstance(val, int):
            return False, {}, f"Score for '{criterion}' must be an integer, got {type(val).__name__}"

        if val < 1 or val > 10:
            return False, {}, f"Score for '{criterion}' must be between 1 and 10, got {val}"

        cleaned_scores[criterion] = val

    return True, cleaned_scores, ""


def gate(
    task: Any,
    writer: Callable[..., str],
    reviewer: Callable[..., Union[Dict[str, Any], Any]],
    sources: Any,
    rubric: Optional[Sequence[str]] = None,
    threshold: int = 8,
    log: Optional[logging.Logger] = None,
) -> ReviewResult:
    """Execute the Independent QA Gate.

    Rules:
    1. Writer and Reviewer must be completely independent entities (writer is not reviewer).
    2. Reviewer is shown ONLY (draft, rubric, sources)—never writer reasoning or thoughts.
    3. Scores for 4 criteria (facts, policy, fit, clarity) must be integers 1..10 (bool rejected).
    4. Malformed reviewer output fails closed immediately.
    5. At most one rewrite is allowed (writer(task, feedback=notes)) if attempt 1 fails.
    6. If attempt 2 fails, hold with a clear reason.
    """
    active_log = log or logger

    # Rule 1: Independent entities enforcement
    if writer is reviewer:
        raise ValueError("Writer and reviewer must be independent entities")

    rubric_criteria = tuple(rubric or DEFAULT_RUBRIC)
    attempts: List[ReviewAttempt] = []

    # ------------------------------------------------------------------
    # Attempt 1: Initial Draft & Evaluation
    # ------------------------------------------------------------------
    try:
        draft_1 = writer(task, feedback=None)
        if not isinstance(draft_1, str) or not draft_1.strip():
            return ReviewResult(
                passed=False,
                status="held",
                final_draft="",
                attempts=[],
                reason="Writer produced empty or non-string draft",
            )
    except Exception as exc:
        active_log.error("Writer failed on attempt 1: %s", exc)
        return ReviewResult(
            passed=False,
            status="held",
            final_draft="",
            attempts=[],
            reason=f"Writer failed on attempt 1: {type(exc).__name__}",
        )

    # Show reviewer ONLY (draft, rubric, sources)
    try:
        rev_output_1 = reviewer(draft_1, rubric_criteria, sources)
    except Exception as exc:
        active_log.error("Reviewer raised exception on attempt 1: %s", exc)
        # Fail closed on reviewer failure
        attempt_record = ReviewAttempt(
            attempt_number=1,
            draft=draft_1,
            scores={},
            notes="Reviewer failed with exception",
            passed=False,
            malformed=True,
            error=type(exc).__name__,
        )
        return ReviewResult(
            passed=False,
            status="held",
            final_draft=draft_1,
            attempts=[attempt_record],
            reason=f"Reviewer execution failed closed: {type(exc).__name__}",
        )

    # Validate reviewer scores strictly
    raw_scores_1 = rev_output_1.get("scores") if isinstance(rev_output_1, dict) else rev_output_1
    is_valid_1, scores_1, val_err_1 = _validate_scores(raw_scores_1, rubric_criteria)

    notes_1 = ""
    if isinstance(rev_output_1, dict):
        notes_1 = str(rev_output_1.get("notes", ""))

    if not is_valid_1:
        # Fail closed on malformed reviewer output
        attempt_record = ReviewAttempt(
            attempt_number=1,
            draft=draft_1,
            scores={},
            notes=notes_1,
            passed=False,
            malformed=True,
            error=val_err_1,
        )
        return ReviewResult(
            passed=False,
            status="held",
            final_draft=draft_1,
            attempts=[attempt_record],
            reason=f"Malformed reviewer output on attempt 1: {val_err_1}",
        )

    # Check passing threshold
    attempt_1_passed = all(scores_1[c] >= threshold for c in rubric_criteria)
    attempts.append(
        ReviewAttempt(
            attempt_number=1,
            draft=draft_1,
            scores=scores_1,
            notes=notes_1,
            passed=attempt_1_passed,
        )
    )

    if attempt_1_passed:
        active_log.info("QA Gate: Attempt 1 passed threshold %d with scores %s", threshold, scores_1)
        return ReviewResult(
            passed=True,
            status="approved",
            final_draft=draft_1,
            attempts=attempts,
            scores=scores_1,
        )

    # ------------------------------------------------------------------
    # Attempt 2: Single Rewrite Loop
    # ------------------------------------------------------------------
    failing_criteria = [c for c in rubric_criteria if scores_1[c] < threshold]
    feedback_notes = (
        f"Attempt 1 scored below threshold ({threshold}/10) on: {', '.join(failing_criteria)}. "
        f"Reviewer notes: {notes_1}. Please address these criteria and improve factual precision and policy alignment."
    )
    active_log.info("QA Gate: Attempt 1 failed (%s). Triggering single rewrite.", failing_criteria)

    try:
        draft_2 = writer(task, feedback=feedback_notes)
        if not isinstance(draft_2, str) or not draft_2.strip():
            return ReviewResult(
                passed=False,
                status="held",
                final_draft=draft_1,
                attempts=attempts,
                reason="Writer produced empty or non-string draft on rewrite attempt 2",
            )
    except Exception as exc:
        active_log.error("Writer failed on attempt 2 rewrite: %s", exc)
        return ReviewResult(
            passed=False,
            status="held",
            final_draft=draft_1,
            attempts=attempts,
            reason=f"Writer failed on rewrite attempt 2: {type(exc).__name__}",
        )

    # Show reviewer ONLY (draft_2, rubric, sources)
    try:
        rev_output_2 = reviewer(draft_2, rubric_criteria, sources)
    except Exception as exc:
        active_log.error("Reviewer raised exception on attempt 2: %s", exc)
        attempt_2_record = ReviewAttempt(
            attempt_number=2,
            draft=draft_2,
            scores={},
            notes="Reviewer failed with exception on rewrite",
            passed=False,
            malformed=True,
            error=type(exc).__name__,
        )
        attempts.append(attempt_2_record)
        return ReviewResult(
            passed=False,
            status="held",
            final_draft=draft_2,
            attempts=attempts,
            reason=f"Reviewer execution failed closed on attempt 2: {type(exc).__name__}",
        )

    raw_scores_2 = rev_output_2.get("scores") if isinstance(rev_output_2, dict) else rev_output_2
    is_valid_2, scores_2, val_err_2 = _validate_scores(raw_scores_2, rubric_criteria)

    notes_2 = ""
    if isinstance(rev_output_2, dict):
        notes_2 = str(rev_output_2.get("notes", ""))

    if not is_valid_2:
        attempt_2_record = ReviewAttempt(
            attempt_number=2,
            draft=draft_2,
            scores={},
            notes=notes_2,
            passed=False,
            malformed=True,
            error=val_err_2,
        )
        attempts.append(attempt_2_record)
        return ReviewResult(
            passed=False,
            status="held",
            final_draft=draft_2,
            attempts=attempts,
            reason=f"Malformed reviewer output on attempt 2: {val_err_2}",
        )

    attempt_2_passed = all(scores_2[c] >= threshold for c in rubric_criteria)
    attempts.append(
        ReviewAttempt(
            attempt_number=2,
            draft=draft_2,
            scores=scores_2,
            notes=notes_2,
            passed=attempt_2_passed,
        )
    )

    if attempt_2_passed:
        active_log.info("QA Gate: Attempt 2 rewrite passed threshold %d with scores %s", threshold, scores_2)
        return ReviewResult(
            passed=True,
            status="approved",
            final_draft=draft_2,
            attempts=attempts,
            scores=scores_2,
        )

    # Attempt 2 failed: Hold with clear reason
    failed_2 = [c for c in rubric_criteria if scores_2[c] < threshold]
    hold_reason = (
        f"Held by QA Gate after 2 attempts: failed criteria {failed_2} "
        f"with scores {scores_2} (threshold: {threshold}). Notes: {notes_2}"
    )
    active_log.warning("QA Gate: %s", hold_reason)

    return ReviewResult(
        passed=False,
        status="held",
        final_draft=draft_2,
        attempts=attempts,
        reason=hold_reason,
        scores=scores_2,
    )
