"""Format-string bugs, in C and in Python.

C: printf(user_input) lets the input choose the format, so "%x %x %x" reads
values off the stack and "%n" writes to memory. printf("%s", user_input) is
the fix. c/format_demo.c has the C version; c_printf_demo() calls the real
libc printf through ctypes.

Python: str.format() with a user-supplied template can walk attributes:
"{n.__init__.__globals__[CONFIG].db_password}" reads a secret from the module.
The fix is the same idea: the developer owns the template, the user only
supplies values.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import sys


class PortalConfig:
    """Stand-in for an app config object. The values are fake."""
    def __init__(self):
        self.db_password = "example-db-password"
        self.api_key = "example-api-key"


class Notification:
    def __init__(self, patient_name: str):
        self.patient_name = patient_name


CONFIG = PortalConfig()


def unsafe_greeting(template: str, notification: Notification) -> str:
    """User supplies the template. Do not copy."""
    return template.format(n=notification)


def safe_greeting(user_text: str, notification: Notification) -> str:
    return "Hello {name}, your message: {msg}".format(name=notification.patient_name, msg=user_text)


def _libc():
    try:
        if sys.platform.startswith("win"):
            return ctypes.cdll.msvcrt
        name = ctypes.util.find_library("c")
        return ctypes.CDLL(name) if name else None
    except OSError:
        return None


def c_printf_demo(user_input: str) -> bool:
    """Print user_input through libc printf, unsafe then safe. False if no libc."""
    libc = _libc()
    if libc is None:
        return False
    data = user_input.encode()
    sys.stdout.flush()
    print("  unsafe  printf(user_input)       -> ", end="", flush=True)
    libc.printf(data)                  # the bug: input is the format string
    libc.printf(b"\n")
    libc.fflush(None)
    print("  safe    printf(\"%s\", user_input) -> ", end="", flush=True)
    libc.printf(b"%s\n", data)
    libc.fflush(None)
    return True
