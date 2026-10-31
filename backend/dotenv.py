"""Minimal .env loader (no extra dependency).

BUG FIX: the backend read SARVAM_API_KEY only from os.environ, but
nothing ever loaded backend/.env or the repo-root .env. So a user who
correctly copied .env.example to backend/.env and filled in a key still
got the fallback story, and a page reload alone could never fix it --
only a backend restart after the key is actually in the environment
(or loaded here) can.

load_env_files() reads, in order, backend/.env then the repo-root .env
(the example file says either location is acceptable), parses KEY=VALUE
lines (ignoring comments and blank lines, stripping surrounding quotes),
and sets each key in os.environ only if it is not already set, and only
if the value is non-empty. Empty MITIGATA_DB= is therefore ignored, so
it does not override the default database path. No value is ever logged.
"""
import os
from pathlib import Path


def load_env_files() -> None:
    here = Path(__file__).resolve().parent
    root = here.parent
    for path in (here / ".env", root / ".env"):
        try:
            text = path.read_text(encoding="utf-8")
        except Exception:
            continue
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key, value = key.strip(), value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                value = value[1:-1]
            if key and value and key not in os.environ:
                os.environ[key] = value
