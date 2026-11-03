import re

import pytest

from legacy import sanitizer_v1
from secure_input import sql, xss

ENTITY_LINK = '<a href="jav&#x61;script:alert(document.cookie)">see my results</a>'


# --- XSS -------------------------------------------------------------------

@pytest.mark.parametrize("payload", ["<script>alert('x')</script>", "<img src=x onerror=alert(1)>",
                                     "<svg/onload=alert(1)>", ENTITY_LINK, "<details open ontoggle=alert(1)>"])
def test_rendered_comment_has_no_live_markup(payload):
    out = xss.render_comment("a", payload)
    inner = out[len("<div class='comment'><b>a</b>: "):-len("</div>")]
    assert "<" not in inner and ">" not in inner and '"' not in inner


def test_author_is_encoded_too():
    assert "<b><b>" not in xss.render_comment("<b>x</b>", "hi")


def test_normal_text_is_kept_word_for_word():
    for text in ["Dose was one = 5 ml twice a day", "learning javascript: it's fun",
                 "Wait < 10 min & easy"]:
        out = xss.render_comment("p", text)
        assert xss.encode(text) in out


def test_v1_sanitizer_leaves_entity_encoded_link():
    stored, _ = sanitizer_v1.sanitize_comment(ENTITY_LINK)
    assert stored == ENTITY_LINK
    assert re.search(r"href=\"jav&#x61;script:", stored)


def test_v1_sanitizer_deletes_ordinary_words():
    assert sanitizer_v1.sanitize_comment("Dose was one = 5 ml")[0] == "Dose was  5 ml"
    assert "javascript" not in sanitizer_v1.sanitize_comment("learning javascript: fun")[0]


def test_flagging_sees_through_entities_without_changing_text():
    assert "javascript: url" in xss.flag_comment(ENTITY_LINK)
    assert xss.flag_comment("The nurse was very helpful") == []


@pytest.mark.parametrize("url", ["javascript:alert(1)", "JaVaScRiPt:alert(1)", "java\tscript:alert(1)",
                                 " javascript:alert(1)", "jav&#x61;script:alert(1)",
                                 "data:text/html,<script>alert(1)</script>", "vbscript:x", "", None])
def test_bad_link_schemes_refused(url):
    assert xss.safe_href(url) is None
    assert "<a" not in xss.render_link(url, "x")


def test_good_links_kept():
    for url in ["https://example.org/a?b=1&c=2", "http://example.org", "mailto:info@example.org"]:
        assert xss.safe_href(url) == url
    assert 'href="https://example.org/a?b=1&amp;c=2"' in xss.render_link("https://example.org/a?b=1&c=2", "x")


def test_escape_alone_does_not_fix_href():
    assert xss.encode("javascript:alert(1)") == "javascript:alert(1)"


def test_control_chars_and_length():
    text, notes = xss.normalize_comment("a\x00b" + "c" * 2000)
    assert "\x00" not in text and len(text) <= xss.MAX_COMMENT_LENGTH and len(notes) == 2


# --- SQL -------------------------------------------------------------------

@pytest.fixture
def conn():
    c = sql.create_database(iterations=1_000)
    yield c
    c.close()


def test_vulnerable_queries_are_injectable(conn):
    assert len(sql.vulnerable_find_user(conn, "' OR '1'='1")[1]) == 3
    assert sql.vulnerable_login(conn, "admin' --", "x")[1] is not None
    leaked = sql.vulnerable_patient_search(conn, "x' UNION SELECT username, password_hash FROM users --")[1]
    assert {r[0] for r in leaked} == {"admin", "dr_smith", "nurse_lee"}


def test_parameterised_queries_are_not(conn):
    assert sql.find_user(conn, "' OR '1'='1") == []
    assert sql.login(conn, "admin' --", "x") is None
    assert sql.patient_search(conn, "x' UNION SELECT username, password_hash FROM users --") == []


def test_stacked_query_does_nothing(conn):
    sql.patient_search(conn, "x'; DROP TABLE patients; --")
    assert conn.execute("SELECT COUNT(*) FROM patients").fetchone()[0] == 4


def test_login(conn):
    assert sql.login(conn, "dr_smith", "Smith$ecure99") == (2, "dr_smith", "doctor")
    assert sql.login(conn, "dr_smith", "wrong") is None
    assert sql.login(conn, "nobody", "x") is None


def test_apostrophe_is_just_data(conn):
    conn.execute("INSERT INTO patients (name, diagnosis, doctor) VALUES (?, ?, ?)",
                 ("Sean O'Brien", "Asthma", "dr_o'neill"))
    assert sql.patient_search(conn, "dr_o'neill") == [("Sean O'Brien", "Asthma")]
