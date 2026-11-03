import os

import pytest

from legacy import email_v1
from secure_input.validators import resolve_safe_path, read_safe_file, validate_email, validate_filename

REAL_ADDRESSES = ["dr.smith@clinic.com", "x_y+z@mail.example.org", "prescriptions@pharmacy.ca",
                  "transcription@clinic.com", "manuscripts@journal.org", "o'brien@clinic.ca",
                  "d'souza.a@health.gov.ca"]

BAD_ADDRESSES = ["<script>alert(1)</script>@x.com", "user@x.com<script>", "a\"b@x.com",
                 "user@x.com;drop", "u@localhost", "u@-bad.com", "u@bad-.com", "u@a..com",
                 "u@1.2.3.4", "u@domain.c0m", "u@.com", "two@@x.com", "'quote@x.com", "", 42]


@pytest.mark.parametrize("email", REAL_ADDRESSES)
def test_real_addresses_accepted(email):
    assert validate_email(email)[0], email


@pytest.mark.parametrize("email", BAD_ADDRESSES)
def test_bad_addresses_rejected(email):
    assert not validate_email(email)[0], email


@pytest.mark.parametrize("email", ["prescriptions@pharmacy.ca", "transcription@clinic.com",
                                   "manuscripts@journal.org", "o'brien@clinic.ca"])
def test_v1_rejected_real_addresses(email):
    """The substring blacklist in v1 refused these. Kept as a regression record."""
    assert not email_v1.validate_email(email)[0]


@pytest.mark.parametrize("email", [e for e in BAD_ADDRESSES if isinstance(e, str) and e])
def test_v2_rejects_everything_v1_rejected_for_markup(email):
    """Dropping the blacklist didn't let any markup through."""
    if not email_v1.validate_email(email)[0]:
        assert not validate_email(email)[0]


def test_filenames():
    assert validate_filename("lab_results.pdf")[0]
    for f in ["../x.txt", "..", ".env", "a/b.txt", "a\\b.txt", "x.txt\x00.exe", "my file.txt",
              "a;b.txt", "<x>.html", "report.", "CON.txt", "lpt1"]:
        assert not validate_filename(f)[0], f


@pytest.fixture
def base(tmp_path):
    b = tmp_path / "safe"
    (b / "reports").mkdir(parents=True)
    (b / "reports" / "visit.txt").write_text("sample")
    (tmp_path / "safe_backup").mkdir()          # catches the startswith() bug
    (tmp_path / "secret.txt").write_text("outside")
    return str(b)


def test_paths_inside_base(base):
    assert resolve_safe_path("reports/visit.txt", base)[0]
    assert resolve_safe_path("reports/../reports/visit.txt", base)[0]
    assert read_safe_file("reports/visit.txt", base) == "sample"


@pytest.mark.parametrize("p", ["../secret.txt", "../../etc/passwd", "reports/../../secret.txt",
                               "..\\secret.txt", "../safe_backup/x.txt", "/etc/passwd",
                               "C:\\x.txt", "reports/.env", "x.txt\x00.jpg", "", "   "])
def test_paths_refused(base, p):
    assert resolve_safe_path(p, base)[0] is None, p


def test_read_outside_raises(base):
    with pytest.raises(PermissionError):
        read_safe_file("../secret.txt", base)


@pytest.mark.skipif(not hasattr(os, "symlink") or os.name == "nt", reason="symlinks")
def test_symlink_out_of_base_refused(base, tmp_path):
    os.symlink(tmp_path / "secret.txt", os.path.join(base, "reports", "link.txt"))
    assert resolve_safe_path("reports/link.txt", base)[0] is None
