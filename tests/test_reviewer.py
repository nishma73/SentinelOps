"""Tests for Independent QA Gate and Reviewer Protocol."""

import pytest
from sentinelops.reviewer import DEFAULT_RUBRIC, ReviewResult, gate


def test_gate_enforces_writer_is_not_reviewer():
    def writer_and_reviewer(*args, **kwargs):
        return "Draft or scores"

    with pytest.raises(ValueError) as exc_info:
        gate(
            task="Triage ticket",
            writer=writer_and_reviewer,
            reviewer=writer_and_reviewer,
            sources={},
        )
    assert "Writer and reviewer must be independent entities" in str(exc_info.value)


def test_gate_isolates_writer_reasoning():
    observed_args = []

    def writer_fn(task, feedback=None):
        return "Clean professional customer reply draft."

    def reviewer_fn(draft, rubric, sources):
        observed_args.append((draft, rubric, sources))
        return {
            "scores": {"facts": 9, "policy": 9, "fit": 9, "clarity": 9},
            "notes": "Looks solid",
        }

    res = gate(
        task={"issue": "outage"},
        writer=writer_fn,
        reviewer=reviewer_fn,
        sources={"doc": "policy_123"},
        threshold=8,
    )

    assert res.passed is True
    assert len(observed_args) == 1
    # Check that reviewer received only (draft, rubric, sources)
    draft, rubric, sources = observed_args[0]
    assert draft == "Clean professional customer reply draft."
    assert rubric == DEFAULT_RUBRIC
    assert sources == {"doc": "policy_123"}


def test_gate_rejects_bool_in_rubric_scores():
    def writer_fn(task, feedback=None):
        return "Draft"

    def reviewer_with_bool(draft, rubric, sources):
        # In Python, True is an instance of int; gate must strictly reject it
        return {
            "scores": {
                "facts": True,  # INVALID: bool rejected
                "policy": 9,
                "fit": 9,
                "clarity": 9,
            },
            "notes": "Score had bool",
        }

    res = gate(
        task="Test",
        writer=writer_fn,
        reviewer=reviewer_with_bool,
        sources={},
        threshold=8,
    )

    assert res.passed is False
    assert res.status == "held"
    assert "Malformed reviewer output" in res.reason
    assert "must be an integer, got bool" in res.reason


def test_gate_fails_closed_on_malformed_reviewer_output():
    def writer_fn(task, feedback=None):
        return "Draft content"

    # Reviewer returns invalid type
    res1 = gate(
        task="Test",
        writer=writer_fn,
        reviewer=lambda d, r, s: "not a dict",
        sources={},
    )
    assert res1.passed is False
    assert res1.status == "held"
    assert "Malformed reviewer output" in res1.reason

    # Reviewer raises exception
    def failing_reviewer(d, r, s):
        raise RuntimeError("Network failure in LLM reviewer call")

    res2 = gate(
        task="Test",
        writer=writer_fn,
        reviewer=failing_reviewer,
        sources={},
    )
    assert res2.passed is False
    assert res2.status == "held"
    assert "Reviewer execution failed closed" in res2.reason


def test_gate_passes_on_attempt_1():
    def writer_fn(task, feedback=None):
        return "High quality customer reply"

    def reviewer_fn(draft, rubric, sources):
        return {
            "scores": {"facts": 9, "policy": 8, "fit": 10, "clarity": 9},
            "notes": "Excellent alignment with runbook",
        }

    res = gate(
        task="Test",
        writer=writer_fn,
        reviewer=reviewer_fn,
        sources={},
        threshold=8,
    )
    assert res.passed is True
    assert res.status == "approved"
    assert len(res.attempts) == 1
    assert res.attempts[0].passed is True


def test_gate_executes_single_rewrite_and_passes_attempt_2():
    writer_calls = []

    def writer_fn(task, feedback=None):
        writer_calls.append(feedback)
        if feedback is None:
            return "Attempt 1: weak draft"
        return "Attempt 2: polished draft addressing feedback"

    def reviewer_fn(draft, rubric, sources):
        if "Attempt 1" in draft:
            return {
                "scores": {"facts": 6, "policy": 7, "fit": 8, "clarity": 8},
                "notes": "Missing incident ID and policy citation",
            }
        else:
            return {
                "scores": {"facts": 9, "policy": 9, "fit": 9, "clarity": 10},
                "notes": "Addressed all feedback",
            }

    res = gate(
        task="Test task",
        writer=writer_fn,
        reviewer=reviewer_fn,
        sources={},
        threshold=8,
    )

    assert res.passed is True
    assert res.status == "approved"
    assert len(res.attempts) == 2
    assert res.attempts[0].passed is False
    assert res.attempts[1].passed is True
    assert len(writer_calls) == 2
    assert "scored below threshold" in writer_calls[1]


def test_gate_holds_when_attempt_2_fails():
    writer_calls = []

    def writer_fn(task, feedback=None):
        writer_calls.append(feedback)
        return "Stubborn draft that ignores policy"

    def reviewer_fn(draft, rubric, sources):
        return {
            "scores": {"facts": 5, "policy": 5, "fit": 5, "clarity": 5},
            "notes": "Consistently failing policy standards",
        }

    res = gate(
        task="Test task",
        writer=writer_fn,
        reviewer=reviewer_fn,
        sources={},
        threshold=8,
    )

    assert res.passed is False
    assert res.status == "held"
    assert len(res.attempts) == 2
    # Ensure at most 1 rewrite was attempted (total 2 writer calls)
    assert len(writer_calls) == 2
    assert "Held by QA Gate after 2 attempts" in res.reason
