"""Allowlist validation for emails, filenames and file paths.

Validation here answers one question: does this value have the right *shape*?
It is not what stops injection. SQL injection is stopped by parameterised
queries (sql.py) and XSS by output encoding (xss.py). Mixing the two jobs is
how the first version of this module ended up rejecting real addresses such as
prescriptions@pharmacy.ca and o'brien@clinic.ca (see legacy/email_v1.py).

Every validator returns (ok, reason) so the caller can log why input was refused.
"""

from __future__ import annotations

import os
import re

# ---------------------------------------------------------------------------
# Email
# ---------------------------------------------------------------------------

# Local part: letters, digits and . _ % + ' -, not starting or ending with a
# symbol. The apostrophe is allowed because people are called O'Brien and
# D'Souza. Quotes, spaces, < > ; and other markup characters still don't match.
_LOCAL_PART = r"[A-Za-z0-9](?:[A-Za-z0-9._%+'-]{0,62}[A-Za-z0-9])?"
_DOMAIN_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
_TLD = r"[A-Za-z]{2,24}"

EMAIL_PATTERN = re.compile(
    r"^(?P<local>" + _LOCAL_PART + r")@"
    r"(?P<domain>(?:" + _DOMAIN_LABEL + r"\.)+" + _TLD + r")$"
)

MAX_EMAIL_LENGTH = 254


def validate_email(email) -> tuple[bool, str]:
    if not isinstance(email, str):
        return False, "email must be a string"
    email = email.strip()
    if not email:
        return False, "email is empty"
    if len(email) > MAX_EMAIL_LENGTH:
        return False, "email is too long"
    if email.count("@") != 1:
        return False, "email must contain exactly one @"
    match = EMAIL_PATTERN.fullmatch(email)
    if not match:
        return False, "email does not match user@domain.tld"
    if ".." in match.group("local") or ".." in match.group("domain"):
        return False, "consecutive dots"
    if len(match.group("domain")) > 253:
        return False, "domain is too long"
    return True, "ok"


# ---------------------------------------------------------------------------
# Filename
# ---------------------------------------------------------------------------

FILENAME_PATTERN = re.compile(r"^[A-Za-z0-9_.]+$")
MAX_FILENAME_LENGTH = 255

# Windows device names. Files may end up on a Windows share even if the
# server runs Linux.
_RESERVED_NAMES = {"con", "prn", "aux", "nul",
                   *(f"com{i}" for i in range(1, 10)), *(f"lpt{i}" for i in range(1, 10))}


def validate_filename(filename) -> tuple[bool, str]:
    """A single filename, no directories."""
    if not isinstance(filename, str):
        return False, "filename must be a string"
    if not filename:
        return False, "filename is empty"
    if len(filename) > MAX_FILENAME_LENGTH:
        return False, "filename is too long"
    if "\x00" in filename:
        return False, "filename contains a null byte"
    if ".." in filename or "/" in filename or "\\" in filename:
        return False, "path traversal characters are not allowed"
    if filename.startswith("."):
        return False, "hidden files are not allowed"
    if not FILENAME_PATTERN.match(filename):
        return False, "only letters, digits, underscore and dot are allowed"
    if filename.endswith("."):
        return False, "filename cannot end with a dot"
    if filename.split(".")[0].lower() in _RESERVED_NAMES:
        return False, "reserved device name"
    return True, "ok"


# ---------------------------------------------------------------------------
# File path inside a base directory
# ---------------------------------------------------------------------------

def resolve_safe_path(user_path, base_dir) -> tuple[str | None, str]:
    """Resolve a user-supplied relative path, or refuse it.

    Normalise first (realpath also resolves symlinks), then check the result
    is still inside base_dir, then run every component through the filename
    rules so reports/.env is refused even though it is inside the base.
    """
    if not isinstance(user_path, str):
        return None, "path must be a string"
    if not user_path.strip():
        return None, "path is empty"
    if "\x00" in user_path:
        return None, "path contains a null byte"

    cleaned = user_path.replace("\\", "/")      # catch ..\..\ on Linux too
    if os.path.isabs(cleaned) or re.match(r"^[A-Za-z]:", cleaned):
        return None, "absolute paths are not allowed"

    base_real = os.path.realpath(base_dir)
    candidate = os.path.realpath(os.path.join(base_real, cleaned))

    # commonpath, not startswith: with startswith a base of /srv/safe would
    # accept /srv/safe_backup/secret.txt.
    try:
        inside = os.path.commonpath([base_real, candidate]) == base_real
    except ValueError:                          # different drives on Windows
        inside = False
    if not inside:
        return None, "path escapes the base directory"

    relative = os.path.relpath(candidate, base_real)
    if relative != ".":
        for part in relative.split(os.sep):
            ok, reason = validate_filename(part)
            if not ok:
                return None, f"bad path component {part!r}: {reason}"
    return candidate, "ok"


def read_safe_file(user_path, base_dir) -> str:
    path, reason = resolve_safe_path(user_path, base_dir)
    if path is None:
        raise PermissionError("access denied: " + reason)
    if not os.path.isfile(path):
        raise FileNotFoundError(user_path)
    with open(path, encoding="utf-8") as fh:
        return fh.read()
