"""Rendering patient comments without XSS.

Scenario: patients leave feedback on a portal and staff read it on a
dashboard. A comment dropped into the page as-is runs in the staff browser.

What does the work:
  1. Output encoding. html.escape() on every user-controlled value, including
     the author name, turns markup into text.
  2. A scheme allowlist for links. Escaping doesn't change
     "javascript:alert(1)", so a user-supplied URL in an href needs its own check.

What doesn't: removing "dangerous" patterns from the text. The first version
did that (legacy/sanitizer_v1.py). It missed an entity-encoded javascript:
link and deleted ordinary words such as "one =" from real comments. Pattern
matching is still useful for flagging a comment for review, so flag_comment()
reports matches without changing what the patient wrote.
"""

from __future__ import annotations

import html
import re
from urllib.parse import urlsplit

MAX_COMMENT_LENGTH = 1000

_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

# For flagging only. Matched against an entity-decoded, lower-cased copy so
# "jav&#x61;script:" is reported too.
_SUSPICIOUS = {
    "script tag": re.compile(r"<\s*/?\s*script", re.I),
    "html tag with event handler": re.compile(r"<[^>]*\bon[a-z]+\s*=", re.I),
    "javascript: url": re.compile(r"javascript\s*:", re.I),
    "data:text/html url": re.compile(r"data\s*:\s*text/html", re.I),
    "embedding tag": re.compile(r"<\s*(iframe|object|embed|svg|math|base|form)\b", re.I),
}

ALLOWED_SCHEMES = {"http", "https", "mailto"}


def normalize_comment(text) -> tuple[str, list[str]]:
    """Length limit and control characters. Never rewrites the words themselves."""
    notes = []
    if not isinstance(text, str):
        return "", ["comment was not a string"]
    if len(text) > MAX_COMMENT_LENGTH:
        text = text[:MAX_COMMENT_LENGTH]
        notes.append(f"truncated to {MAX_COMMENT_LENGTH} characters")
    if _CONTROL_CHARS.search(text):
        text = _CONTROL_CHARS.sub("", text)
        notes.append("control characters removed")
    return text.strip(), notes


def flag_comment(text: str) -> list[str]:
    """Reasons a moderator might want to look at this comment. Read-only."""
    decoded = html.unescape(text)
    return [name for name, rx in _SUSPICIOUS.items() if rx.search(decoded)]


def encode(text: str) -> str:
    """Escape & < > " ' for use in HTML text or a quoted attribute."""
    return html.escape(text, quote=True)


def render_comment(author: str, comment: str) -> str:
    clean, _ = normalize_comment(comment)
    name, _ = normalize_comment(author)
    return f"<div class='comment'><b>{encode(name)}</b>: {encode(clean)}</div>"


def safe_href(url) -> str | None:
    """Return the URL if its scheme is allowed, otherwise None.

    Browsers ignore tabs and newlines inside a scheme ("java\\tscript:") and
    decode entities in attributes, so both are removed before the check.
    """
    if not isinstance(url, str):
        return None
    probe = re.sub(r"[\x00-\x20\x7f]", "", html.unescape(url))
    try:
        scheme = urlsplit(probe).scheme.lower()
    except ValueError:
        return None
    return url.strip() if scheme in ALLOWED_SCHEMES else None


def render_link(url: str, text: str) -> str:
    href = safe_href(url)
    if href is None:
        return encode(text)
    return f'<a href="{encode(href)}" rel="nofollow noopener">{encode(text)}</a>'


def render_comment_unsafe(author: str, comment: str) -> str:
    """The vulnerable version, kept for the demo and tests."""
    return "<div class='comment'><b>%s</b>: %s</div>" % (author, comment)
