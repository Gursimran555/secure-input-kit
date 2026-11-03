"""SQL injection: string-built queries next to parameterised ones.

An in-memory SQLite database holds staff logins (salted PBKDF2 hashes) and a
patients table. The vulnerable_* functions build SQL by concatenation and are
kept only so the attacks can be shown and tested.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import sqlite3

PBKDF2_ITERATIONS = 600_000      # OWASP's current figure for PBKDF2-HMAC-SHA256


def hash_password(password: str, salt: bytes | None = None,
                  iterations: int = PBKDF2_ITERATIONS) -> tuple[str, str]:
    salt = salt if salt is not None else secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return salt.hex(), digest.hex()


STAFF = [("admin", "Adm1n!Portal#2024", "admin"),
         ("dr_smith", "Smith$ecure99", "doctor"),
         ("nurse_lee", "LeeNurse*77", "nurse")]

PATIENTS = [("John Carter", "Type 2 Diabetes", "dr_smith"),
            ("Maria Gomez", "Hypertension", "dr_smith"),
            ("Alan Park", "Asthma", "dr_jones"),
            ("Priya Nair", "Migraine", "dr_jones")]


def create_database(iterations: int = PBKDF2_ITERATIONS) -> sqlite3.Connection:
    """Sample data only. iterations is lowered in tests to keep them fast."""
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, "
                 "salt TEXT NOT NULL, password_hash TEXT NOT NULL, iterations INTEGER NOT NULL, "
                 "role TEXT NOT NULL)")
    conn.execute("CREATE TABLE patients (id INTEGER PRIMARY KEY, name TEXT NOT NULL, "
                 "diagnosis TEXT NOT NULL, doctor TEXT NOT NULL)")
    for username, password, role in STAFF:
        salt, pw_hash = hash_password(password, iterations=iterations)
        conn.execute("INSERT INTO users (username, salt, password_hash, iterations, role) "
                     "VALUES (?, ?, ?, ?, ?)", (username, salt, pw_hash, iterations, role))
    conn.executemany("INSERT INTO patients (name, diagnosis, doctor) VALUES (?, ?, ?)", PATIENTS)
    conn.commit()
    return conn


# --- vulnerable: do not copy ------------------------------------------------

def vulnerable_find_user(conn, username):
    query = "SELECT id, username, role FROM users WHERE username = '" + username + "'"
    try:
        return query, conn.execute(query).fetchall()
    except sqlite3.Error as exc:
        return query, f"error: {exc}"


def vulnerable_login(conn, username, password):
    """Treats any returned row as a successful login."""
    query = ("SELECT id, username, role FROM users WHERE username = '" + username +
             "' AND password_hash = '" + password + "'")
    try:
        return query, conn.execute(query).fetchone()
    except sqlite3.Error as exc:
        return query, f"error: {exc}"


def vulnerable_patient_search(conn, doctor):
    query = "SELECT name, diagnosis FROM patients WHERE doctor = '" + doctor + "'"
    try:
        return query, conn.execute(query).fetchall()
    except sqlite3.Error as exc:
        return query, f"error: {exc}"


# --- parameterised ----------------------------------------------------------

def find_user(conn, username):
    return conn.execute("SELECT id, username, role FROM users WHERE username = ?",
                        (username,)).fetchall()


def login(conn, username, password):
    """Fetch the salt and hash by username, then compare in constant time."""
    row = conn.execute("SELECT id, username, role, salt, password_hash, iterations "
                       "FROM users WHERE username = ?", (username,)).fetchone()
    if row is None:
        return None
    user_id, uname, role, salt_hex, stored, iterations = row
    _, attempt = hash_password(password, bytes.fromhex(salt_hex), iterations)
    return (user_id, uname, role) if hmac.compare_digest(attempt, stored) else None


def patient_search(conn, doctor):
    return conn.execute("SELECT name, diagnosis FROM patients WHERE doctor = ?",
                        (doctor,)).fetchall()
