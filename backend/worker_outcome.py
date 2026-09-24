"""Shared process outcomes and structured worker summaries."""

from dataclasses import asdict, dataclass, field
from enum import Enum
import json
import os
import sys
from typing import Any, Mapping, Optional, TextIO


SUMMARY_PREFIX = "ASIP_WORKER_SUMMARY "
_EX_TEMPFAIL_FALLBACK = 75  # POSIX sysexits.h EX_TEMPFAIL.


def _resolve_retryable_exit_code(platform_os=os):
    return getattr(platform_os, "EX_TEMPFAIL", _EX_TEMPFAIL_FALLBACK)


RETRYABLE_INCOMPLETE_EXIT_CODE = _resolve_retryable_exit_code()


class WorkerOutcome(str, Enum):
    SUCCESS = "success"
    RETRYABLE_INCOMPLETE = "retryable_incomplete"
    FATAL = "fatal"


@dataclass(frozen=True)
class WorkerSummary:
    stage: str
    outcome: WorkerOutcome
    candidates: Optional[int]
    attempted: int = 0
    positive: int = 0
    definitive_negative: int = 0
    operational_errors: int = 0
    skipped: int = 0
    committed: int = 0
    details: Mapping[str, Any] = field(default_factory=dict)
    version: int = 1

    def __post_init__(self):
        if not self.stage:
            raise ValueError("stage must not be empty")
        if not isinstance(self.outcome, WorkerOutcome):
            raise TypeError("outcome must be a WorkerOutcome")
        if self.candidates is not None and self.candidates < 0:
            raise ValueError("candidates must be non-negative or None")
        for name in (
            "attempted",
            "positive",
            "definitive_negative",
            "operational_errors",
            "skipped",
            "committed",
        ):
            if getattr(self, name) < 0:
                raise ValueError(f"{name} must be non-negative")

    def as_dict(self):
        result = asdict(self)
        result["outcome"] = self.outcome.value
        return result


def emit_worker_summary(summary: WorkerSummary, stream: Optional[TextIO] = None):
    """Emit one stable, single-line summary without affecting exit semantics."""
    if stream is None:
        stream = sys.stdout
    payload = json.dumps(summary.as_dict(), sort_keys=True, separators=(",", ":"))
    print(f"{SUMMARY_PREFIX}{payload}", file=stream)
