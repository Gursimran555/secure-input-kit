"""Comment sanitizer, first version. Kept for comparison; see secure_input/xss.py.

It removes "dangerous" patterns from the text before storing it. Two problems:
  - an entity-encoded javascript: link (jav&#x61;script:) passes untouched, and
    <a> is not in the tag list, so the link survives;
  - the patterns also match ordinary writing: "one = 5 ml" loses "one =",
    "javascript: it's" loses "javascript:".
Output encoding (html.escape) was what actually prevented XSS.
"""

import re

MAX_COMMENT_LENGTH = 1000

_DANGEROUS_PATTERNS = [
    re.compile(r"<\s*script[^>]*>.*?<\s*/\s*script\s*>", re.IGNORECASE | re.DOTALL),
    re.compile(r"<\s*/?\s*(script|iframe|object|embed|style|link|meta|svg|img)[^>]*>", re.IGNORECASE),
    re.compile(r"\bon\w+\s*=", re.IGNORECASE),
    re.compile(r"javascript\s*:", re.IGNORECASE),
    re.compile(r"data\s*:\s*text/html", re.IGNORECASE),
]

_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def sanitize_comment(comment):
    warnings = []
    if not isinstance(comment, str):
        return "", ["comment was not a string"]
    if len(comment) > MAX_COMMENT_LENGTH:
        comment = comment[:MAX_COMMENT_LENGTH]
        warnings.append("comment truncated to %d characters" % MAX_COMMENT_LENGTH)
    if _CONTROL_CHARS.search(comment):
        comment = _CONTROL_CHARS.sub("", comment)
        warnings.append("control characters removed")
    for pattern in _DANGEROUS_PATTERNS:
        if pattern.search(comment):
            warnings.append("removed suspicious content matching: " + pattern.pattern)
            comment = pattern.sub("", comment)
    return comment.strip(), warnings
