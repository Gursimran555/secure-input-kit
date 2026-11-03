"""Email validator, first version. Kept for comparison; see secure_input/validators.py.

The regex below is fine. The problem is _SCRIPT_MARKERS: a substring blacklist
run before it, meant as extra XSS protection. "script" matches inside
prescriptions@, transcription@ and manuscripts@, and "'" rejects o'brien@.
The regex already refuses < > " ; so the blacklist added false rejections
and no protection.
"""

import re

_LOCAL_PART = r"[A-Za-z0-9](?:[A-Za-z0-9._%+-]{0,62}[A-Za-z0-9])?"
_DOMAIN_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
_TLD = r"[A-Za-z]{2,24}"

EMAIL_PATTERN = re.compile(
    r"^(?P<local>" + _LOCAL_PART + r")@"
    r"(?P<domain>(?:" + _DOMAIN_LABEL + r"\.)+" + _TLD + r")$"
)

_SCRIPT_MARKERS = ["<", ">", "script", "javascript:", "onerror", "onload", "\"", "'", ";"]

MAX_EMAIL_LENGTH = 254


def validate_email(email):
    if not isinstance(email, str):
        return False, "email must be a string"
    email = email.strip()
    if not email:
        return False, "email is empty"
    if len(email) > MAX_EMAIL_LENGTH:
        return False, "email is too long"
    lowered = email.lower()
    for marker in _SCRIPT_MARKERS:
        if marker in lowered:
            return False, "email contains script or markup characters (%r)" % marker
    if email.count("@") != 1:
        return False, "email must contain exactly one @"
    match = EMAIL_PATTERN.match(email)
    if not match:
        return False, "email does not match the expected user@domain.tld format"
    local = match.group("local")
    domain = match.group("domain")
    if ".." in local:
        return False, "local part has consecutive dots"
    if ".." in domain:
        return False, "domain has consecutive dots"
    if len(domain) > 253:
        return False, "domain is too long"
    return True, "ok"
