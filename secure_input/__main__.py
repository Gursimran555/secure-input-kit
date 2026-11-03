"""python -m secure_input [all|v1|validation|sql|xss|format|tokens]"""

from __future__ import annotations

import os
import random
import secrets
import sys
import tempfile

from attacks import predict_tokens
from legacy import email_v1, sanitizer_v1

from . import sql, templates, tokens, validators, xss

EMAILS = ["dr.smith@clinic.com", "prescriptions@pharmacy.ca", "transcription@clinic.com",
          "o'brien@clinic.ca", "<script>alert(1)</script>@evil.com", "user@evil.com;drop",
          "patient@localhost", "user@192.168.0.1"]

COMMENTS = ["Dose was one = 5 ml twice a day",
            "My son is learning javascript: it's all he talks about",
            '<a href="jav&#x61;script:alert(document.cookie)">see my results</a>',
            "<script>alert('Hacked')</script>"]


def header(title: str) -> None:
    print("\n" + "=" * 72 + "\n" + title + "\n" + "=" * 72)


def demo_v1() -> None:
    header("WHAT THE FIRST VERSION GOT WRONG")
    print("\nEmail validator: v1 (substring blacklist + regex) vs v2 (regex only)")
    for e in EMAILS:
        v1, v2 = email_v1.validate_email(e)[0], validators.validate_email(e)[0]
        print(f"  {e!r:42} v1 {'ACCEPT' if v1 else 'reject':7} v2 {'ACCEPT' if v2 else 'reject'}")

    print("\nComment sanitizer v1: what it stored")
    for c in COMMENTS:
        out, _ = sanitizer_v1.sanitize_comment(c)
        print(f"  in : {c}\n  out: {out}")
    print("\n  Line 3 still contains a working javascript: link. Lines 1-2 lost words.")
    print("  v2 stores the text as written and encodes it when rendering:")
    print("  " + xss.render_comment("patient", COMMENTS[2]))
    print("  flagged for review: " + ", ".join(xss.flag_comment(COMMENTS[2])))


def demo_validation() -> None:
    header("FILENAMES AND PATHS")
    for f in ["lab_results.pdf", "../../etc/passwd", ".env", "report.pdf.", "invoice;rm -rf.txt",
              "file\x00.exe", "CON.txt"]:
        ok, reason = validators.validate_filename(f)
        print(f"  {'ACCEPT' if ok else 'REJECT':7} {f!r:24} {'' if ok else reason}")

    with tempfile.TemporaryDirectory() as tmp:
        base = os.path.join(tmp, "safe_files")
        os.makedirs(os.path.join(base, "reports"))
        os.makedirs(base + "_backup")
        print("\n  base directory: <tmp>/safe_files")
        for p in ["reports/visit.txt", "reports/../lab.txt", "../safe_files_backup/x.txt",
                  "../../../../etc/passwd", "..\\..\\secret.txt", "/etc/passwd",
                  "C:\\Windows\\win.ini", "reports/.env", "lab.txt\x00.jpg"]:
            path, reason = validators.resolve_safe_path(p, base)
            print(f"  {'ACCEPT' if path else 'REJECT':7} {p!r:30} {'' if path else reason}")


def demo_sql() -> None:
    header("SQL INJECTION")
    conn = sql.create_database(iterations=1_000)
    cases = [("tautology", lambda: sql.vulnerable_find_user(conn, "' OR '1'='1"),
              lambda: sql.find_user(conn, "' OR '1'='1")),
             ("login bypass", lambda: sql.vulnerable_login(conn, "admin' --", "anything"),
              lambda: sql.login(conn, "admin' --", "anything")),
             ("UNION", lambda: sql.vulnerable_patient_search(
                 conn, "x' UNION SELECT username, password_hash FROM users --"),
              lambda: sql.patient_search(conn, "x' UNION SELECT username, password_hash FROM users --"))]
    for name, bad, good in cases:
        query, result = bad()
        if isinstance(result, list):
            shown = [tuple(v[:16] + "..." if isinstance(v, str) and len(v) > 20 else v for v in r)
                     for r in result]
        else:
            shown = result
        print(f"\n  {name}\n    query      : {query}\n    vulnerable : {shown}\n    parameterised: {good()}")
    print("\n  o'brien stored and read back with parameters:",
          conn.execute("SELECT ?", ("o'brien@clinic.ca",)).fetchone()[0])
    print("  dr_smith with the right password:", sql.login(conn, "dr_smith", "Smith$ecure99"))


def demo_xss() -> None:
    header("XSS")
    for author, text in [("Maria", "The nurse was very helpful"),
                         ("attacker", "<img src=x onerror=\"alert('XSS')\">"),
                         ("<b>fake_admin</b>", "markup in the author name"),
                         ("John", "Wait time was < 10 min & parking was easy")]:
        print(f"  unsafe: {xss.render_comment_unsafe(author, text)}")
        print(f"  safe  : {xss.render_comment(author, text)}")
    print("\n  Escaping doesn't help inside href:")
    print(f"    html.escape('javascript:alert(1)') = {xss.encode('javascript:alert(1)')!r}")
    for url in ["https://example.org/results", "javascript:alert(1)", "java\tscript:alert(1)",
                "jav&#x61;script:alert(1)", "data:text/html,<script>alert(1)</script>"]:
        print(f"    {url!r:44} -> {xss.render_link(url, 'link')}")


def demo_format() -> None:
    header("FORMAT STRINGS")
    print("\n  C printf through ctypes, input 'Patient %x %x %x %x':")
    if not templates.c_printf_demo("Patient %x %x %x %x"):
        print("  (no C library found, skipped)")
    note = templates.Notification("Maria Gomez")
    attack = "{n.__init__.__globals__[CONFIG].db_password}"
    print(f"\n  Python template from the user: {attack}")
    print(f"    unsafe: {templates.unsafe_greeting(attack, note)}")
    print(f"    safe  : {templates.safe_greeting(attack, note)}")


def demo_tokens() -> None:
    header("TOKENS")
    weak = [random.randint(1, 100) for _ in range(1000)]
    strong = [secrets.randbelow(100) + 1 for _ in range(1000)]
    print("  1000 values in 1-100 (chi-square below ~123.2 = consistent with uniform)")
    for name, vals in (("random.randint   ", weak), ("secrets.randbelow", strong)):
        print(f"    {name} chi-square {tokens.chi_square_uniform(vals, 1, 100):6.1f}  "
              f"entropy {tokens.shannon_entropy(vals):.3f} bits")
    print("  Both pass. Statistics can't tell a predictable generator from a secure one.\n")
    r = predict_tokens.run(predict=10)
    print(f"  Observed {r['observed']} tokens made with random.getrandbits(128), cloned the generator:")
    print(f"    predicted next: {r['example_predicted']}")
    print(f"    actual next   : {r['example_actual']}")
    print(f"    {r['weak_correct']}/{r['predicted']} next tokens predicted exactly")
    print(f"  Same attack on secrets.token_hex(16): {r['strong_correct']}/{r['predicted']}")


SECTIONS = {"v1": demo_v1, "validation": demo_validation, "sql": demo_sql,
            "xss": demo_xss, "format": demo_format, "tokens": demo_tokens}


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    choice = argv[0] if argv else "all"
    if choice != "all" and choice not in SECTIONS:
        print(__doc__)
        return 2
    for name, fn in SECTIONS.items():
        if choice in ("all", name):
            fn()
    return 0


if __name__ == "__main__":
    sys.exit(main())
