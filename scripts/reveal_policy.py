"""Reveal policy: who may see a model answer, how often, and when.

Why this exists
    The security audit found that ``POST /api/reveal`` was anonymous and
    unthrottled: 46 of 46 model solutions came back in half a second to any
    caller, which defeats the entire point of an answer-checking lab. This
    module holds the rules that close that hole.

The rules
    1. A caller must have a valid session. Authentication itself is enforced in
       ``serve_training.py``; this module only sees an already-resolved user id.
    2. The student must have *already tried* the question - that is, submitted
       at least one ``/api/check`` for this scenario recently. The intended
       training loop is investigate, answer, check, and only then consult the
       model answer. Opening the key on an untouched question is the harvesting
       case, and it is refused.
    3. Reveals are throttled per user: a ceiling per window plus a short gap
       between consecutive reveals, so a script cannot walk the whole key.
    4. A generous per-question cap backstops a script hammering one question.
       It is high enough that a student re-reading a solution after a page
       reload is never affected - the browser only fetches again when its local
       cache is gone.

What is deliberately absent
    No server-side answer storage, no analytics, no scoring. ``ATTEMPT_WINDOW``
    state is in-process memory that evaporates on restart. It exists purely to
    answer "has this student engaged with this scenario yet", and is deliberately
    not a progress record: nothing here is written to the database.

Safety properties
    * Thread-safe: one lock, held only for dict arithmetic.
    * Bounded: both the user table and the per-user scenario set are capped, so
      a script cycling usernames cannot grow memory without limit.
    * Keyed on the *resolved user id*, never on an IP or on a header such as
      ``X-Forwarded-For`` that a client can set at will.
    * Stdlib only.
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from typing import Dict, Optional, Set, Tuple

__all__ = [
    "ATTEMPT_WINDOW_SECONDS",
    "REVEAL_COOLDOWN_SECONDS",
    "REVEAL_PER_QUESTION_CAP",
    "REVEAL_RATE_LIMIT",
    "REVEAL_WINDOW_SECONDS",
    "RevealNotPermitted",
    "RevealThrottled",
    "evaluate",
    "has_attempt",
    "note_check",
    "note_reveal",
    "reset",
]


# --------------------------------------------------------------- thresholds
#
# Tuned so a human working normally never notices them, while the harvest that
# took 0.5 seconds now takes hours.

#: Reveals allowed per user per window.
REVEAL_RATE_LIMIT = 8

#: Length of that window, in seconds.
REVEAL_WINDOW_SECONDS = 60.0

#: Minimum gap between two reveals by the same user. This is the control that
#: actually stops enumeration: 46 questions at 2s each is 92 seconds of
#: throttling before the window limit even applies.
REVEAL_COOLDOWN_SECONDS = 2.0

#: Reveals of one question per user before it is refused. Set well above what a
#: student re-reading needs, and low enough to stop a single-question script.
REVEAL_PER_QUESTION_CAP = 10

#: How long a submitted check counts as "this student engaged with this
#: scenario". Long enough to finish a scenario in one sitting.
ATTEMPT_WINDOW_SECONDS = 1800.0

#: Caps that keep the in-memory tables from growing without bound.
MAX_TRACKED_USERS = 4096
MAX_SCENARIOS_PER_USER = 8
MAX_QUESTIONS_PER_USER = 64


# ------------------------------------------------------------------ errors

class RevealNotPermitted(Exception):
    """The student has not tried this scenario yet. HTTP 403."""


class RevealThrottled(Exception):
    """Too many reveals too quickly. HTTP 429, carries ``retry_after``."""

    def __init__(self, retry_after: float):
        super().__init__("too many reveals")
        self.retry_after = retry_after


# ------------------------------------------------------------------- state

_lock = threading.Lock()

#: user_id -> scenario_id -> monotonic time of the last submitted check
_attempts: "OrderedDict[int, Dict[str, float]]" = OrderedDict()

#: user_id -> (window_started_at, count, last_reveal_at)
_reveals: "OrderedDict[int, Tuple[float, int, float]]" = OrderedDict()

#: (user_id, scenario, question) -> reveal count
_per_question: "OrderedDict[Tuple[int, str, str], int]" = OrderedDict()


def _trim(table, cap):
    """Evict oldest entries until at or below ``cap``. Caller holds the lock."""
    while len(table) > cap:
        table.popitem(last=False)


def note_check(user_id: Optional[int], scenario: Optional[str]) -> None:
    """Record that ``user_id`` submitted a check for ``scenario``.

    Called as a side effect of ``/api/check`` when the caller already has a
    session. The check itself stays completely stateless and unauthenticated:
    this records nothing when the caller is anonymous and changes no response.
    """
    if user_id is None or not scenario:
        return
    now = time.monotonic()
    with _lock:
        seen = _attempts.get(user_id)
        if seen is None:
            seen = {}
            _attempts[user_id] = seen
        seen[scenario] = now
        if len(seen) > MAX_SCENARIOS_PER_USER:
            oldest = min(seen, key=seen.get)
            del seen[oldest]
        _attempts.move_to_end(user_id)
        _trim(_attempts, MAX_TRACKED_USERS)


def has_attempt(user_id: Optional[int], scenario: Optional[str]) -> bool:
    """Whether ``user_id`` has submitted a check for ``scenario`` recently."""
    if user_id is None or not scenario:
        return False
    now = time.monotonic()
    with _lock:
        seen = _attempts.get(user_id)
        if not seen:
            return False
        seen_at = seen.get(scenario)
        if seen_at is None:
            return False
        if now - seen_at > ATTEMPT_WINDOW_SECONDS:
            del seen[scenario]
            return False
        return True


def evaluate(user_id: Optional[int], scenario: Optional[str], question: Optional[str]) -> None:
    """Raise if this reveal is not allowed. Returns ``None`` when it is.

    Call this *before* touching the answer key, so a refused request never
    reaches ``answer_grader.reveal``.
    """
    if user_id is None:
        raise RevealNotPermitted("sign in to view model answers")

    key = (user_id, scenario, question)
    now = time.monotonic()
    with _lock:
        # 1. Has the student engaged with this scenario at all?
        seen = _attempts.get(user_id)
        seen_at = (seen or {}).get(scenario)
        if seen_at is None or now - seen_at > ATTEMPT_WINDOW_SECONDS:
            raise RevealNotPermitted("check your answers before viewing the model answer")

        # 2. Minimum gap between consecutive reveals.
        window_start, count, last_reveal = _reveals.get(user_id, (0.0, 0, 0.0))
        if last_reveal and now - last_reveal < REVEAL_COOLDOWN_SECONDS:
            wait = REVEAL_COOLDOWN_SECONDS - (now - last_reveal)
            raise RevealThrottled(max(1, int(wait) + 1))

        # 3. Per-question backstop.
        if _per_question.get(key, 0) >= REVEAL_PER_QUESTION_CAP:
            raise RevealNotPermitted("you have already opened this model answer")

        # 4. Reveals per window.
        if now - window_start > REVEAL_WINDOW_SECONDS:
            window_start, count = now, 0
        if count >= REVEAL_RATE_LIMIT:
            wait = (window_start + REVEAL_WINDOW_SECONDS) - now
            raise RevealThrottled(max(1, int(wait) + 1))

        # 5. Reserve the slot, so two concurrent requests cannot both pass.
        _reveals[user_id] = (window_start, count + 1, now)
        _reveals.move_to_end(user_id)
        _trim(_reveals, MAX_TRACKED_USERS)

        _per_question[key] = _per_question.get(key, 0) + 1
        _per_question.move_to_end(key)
        _trim(_per_question, MAX_TRACKED_USERS * MAX_QUESTIONS_PER_USER)


def note_reveal(user_id: Optional[int], scenario: Optional[str], question: Optional[str]) -> None:
    """Refresh the attempt window after a permitted reveal.

    A student who opens a model answer has plainly engaged with the scenario,
    so a later reveal of a sibling question is not penalised for it.
    """
    note_check(user_id, scenario)


def retry_after_seconds(user_id: Optional[int]) -> int:
    """Seconds until ``user_id`` may reveal again. Zero when not throttled."""
    if user_id is None:
        return 0
    now = time.monotonic()
    with _lock:
        window_start, count, last_reveal = _reveals.get(user_id, (0.0, 0, 0.0))
        wait = 0.0
        if last_reveal:
            wait = max(wait, REVEAL_COOLDOWN_SECONDS - (now - last_reveal))
        if count >= REVEAL_RATE_LIMIT:
            wait = max(wait, (window_start + REVEAL_WINDOW_SECONDS) - now)
        return max(0, int(wait) + 1) if wait > 0 else 0


def reset() -> None:
    """Empty every table. Intended for tests."""
    with _lock:
        _attempts.clear()
        _reveals.clear()
        _per_question.clear()
