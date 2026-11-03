"""Session and password-reset tokens.

Tokens come from the `secrets` module (the OS CSPRNG). Python's `random`
module is a Mersenne Twister: its output looks uniform, passes chi-square and
entropy checks, and can still be cloned from 624 observed 32-bit outputs.
attacks/predict_tokens.py does exactly that.

Reset tokens are stored as a SHA-256 hash, so a copy of the database doesn't
hand out working reset links. Plain SHA-256 is enough here because the token
has 256 bits of entropy; there is nothing to brute-force, unlike a password.
"""

from __future__ import annotations

import hashlib
import hmac
import math
import secrets
import time
from collections import Counter
from dataclasses import dataclass

RESET_LIFETIME_SECONDS = 15 * 60


def session_token(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


@dataclass(frozen=True)
class ResetRecord:
    """What the database stores. The token itself is only in the email."""
    token_sha256: str
    expires_at: float


def issue_reset_token(now: float | None = None) -> tuple[str, ResetRecord]:
    token = secrets.token_urlsafe(32)
    now = time.time() if now is None else now
    record = ResetRecord(hashlib.sha256(token.encode()).hexdigest(), now + RESET_LIFETIME_SECONDS)
    return token, record


def check_reset_token(token: str, record: ResetRecord, now: float | None = None) -> bool:
    now = time.time() if now is None else now
    if now > record.expires_at:
        return False
    return hmac.compare_digest(hashlib.sha256(token.encode()).hexdigest(), record.token_sha256)


def shannon_entropy(values) -> float:
    """Bits per symbol of the *output*. Says nothing about how it was generated."""
    counts, total = Counter(values), len(values)
    return -sum(c / total * math.log2(c / total) for c in counts.values()) if total else 0.0


def chi_square_uniform(values, low: int, high: int) -> float:
    expected = len(values) / (high - low + 1)
    counts = Counter(values)
    return sum((counts.get(v, 0) - expected) ** 2 / expected for v in range(low, high + 1))
