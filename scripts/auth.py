"""Password hashing and session handling for the training platform.

Standard library only. No bcrypt, no passlib, no argon2 - the platform must
stay installable with nothing but the interpreter the SIEM engine already needs.

This module is deliberately free of HTTP. It exposes small functions that
``scripts/serve_training.py`` calls, and that the tests can call directly, so
the authentication rules can be verified without starting a server.

Passwords
    Stored as scrypt with a random 16-byte salt per password::

        scrypt$<n>$<r>$<p>$<salt-b64>$<derived-key-b64>

    The parameters live *inside* the string, so the work factor can be raised
    later without invalidating existing accounts: old hashes keep verifying with
    the parameters they were created with, and new hashes use the new ones.

    Verification compares with :func:`hmac.compare_digest`, and a login for an
    unknown username still runs one scrypt against a fixed dummy hash, so the
    response time does not reveal whether an account exists.

Sessions
    The browser gets a random token in an HttpOnly cookie. Only the SHA-256 of
    that token is stored, so a leaked database file cannot be replayed as a
    live session. Sessions expire, and logout deletes the row server-side, which
    is what makes logout real rather than cosmetic.

    The raw token exists in exactly two places: the cookie the browser holds,
    and the memory of the request that created it. It is never written to the
    database, never logged, and never placed in a URL.

Storage
    Everything here goes through :mod:`labdb`. This module never opens a SQLite
    connection of its own, so the WAL / foreign-key / busy-timeout setup and the
    per-thread connection policy are defined in exactly one place.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import re
import secrets
import sqlite3
from typing import Any, Dict, Optional, Tuple

import labdb

__all__ = [
    "SESSION_TTL_SECONDS",
    "AuthenticationError",
    "DuplicateUsername",
    "InvalidCredentials",
    "authenticate",
    "create_session",
    "delete_session",
    "hash_password",
    "hash_token",
    "public_user",
    "register_user",
    "resolve_session",
    "verify_password",
]

# --------------------------------------------------------------- parameters

#: scrypt cost. n=2**14 with r=8 costs roughly 100ms and 16 MB per hash on the
#: lab hardware: slow enough to make offline cracking expensive, fast enough
#: that a student logging in does not think the server has hung.
SCRYPT_N = 2 ** 14
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_DKLEN = 32
SCRYPT_MAXMEM = 64 * 1024 * 1024

#: A session lasts one working day. Long enough for a student to walk away from
#: the machine, short enough that an unattended browser stops being a risk.
SESSION_TTL_SECONDS = 12 * 60 * 60

#: 32 random bytes -> 43 base64url characters -> 256 bits of entropy. A session
#: token is not a password and is not rate-limited by a work factor, so it must
#: simply be unguessable.
TOKEN_BYTES = 32

MIN_USERNAME_LENGTH = 3
MAX_USERNAME_LENGTH = 32
MIN_PASSWORD_LENGTH = 8
MAX_PASSWORD_LENGTH = 200

#: Letters, digits, dot, dash, underscore. Deliberately narrow: a username ends
#: up in a cookie-adjacent identity and in admin views, and there is no reason
#: for it to contain spaces, quotes or shell metacharacters.
USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9._-]+$")

_SCHEME = "scrypt"


# ------------------------------------------------------------------ errors

class AuthenticationError(Exception):
    """Base class for auth failures. Never carries the submitted password."""


class DuplicateUsername(AuthenticationError):
    """The username is already taken. Registration only."""


class InvalidCredentials(AuthenticationError):
    """Login failed. Deliberately does not say whether the username exists."""


# ------------------------------------------------------------- passwords

def _b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _b64d(text: str) -> bytes:
    # validate=True so a corrupted hash fails loudly here rather than silently
    # producing different bytes and a false "wrong password".
    return base64.b64decode(text.encode("ascii"), validate=True)


def hash_password(password: str) -> str:
    """Hash ``password`` with scrypt and a fresh random salt.

    Returns ``scrypt$n$r$p$salt$key``. The plaintext is never returned, logged
    or stored anywhere.
    """
    if not isinstance(password, str):
        raise TypeError("password must be a string")
    salt = secrets.token_bytes(16)
    derived = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        dklen=SCRYPT_DKLEN,
        maxmem=SCRYPT_MAXMEM,
    )
    return "$".join(
        (_SCHEME, str(SCRYPT_N), str(SCRYPT_R), str(SCRYPT_P), _b64e(salt), _b64e(derived))
    )


def verify_password(password: str, stored_hash: str) -> bool:
    """Check ``password`` against a stored hash. Never raises on bad input.

    A malformed, truncated, empty or wrong-scheme hash returns ``False`` rather
    than blowing up, so a corrupted row cannot turn a login into a 500.
    """
    if not isinstance(password, str) or not isinstance(stored_hash, str):
        return False
    parts = stored_hash.split("$")
    if len(parts) != 6 or parts[0] != _SCHEME:
        return False
    try:
        n, r, p = int(parts[1]), int(parts[2]), int(parts[3])
        salt = _b64d(parts[4])
        expected = _b64d(parts[5])
    except (ValueError, binascii.Error, UnicodeEncodeError):
        return False
    # Refuse absurd parameters rather than letting a corrupted row ask scrypt
    # for gigabytes of memory.
    if not (0 < n <= 2 ** 20 and 0 < r <= 32 and 0 < p <= 16) or not salt or not expected:
        return False
    try:
        derived = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=n,
            r=r,
            p=p,
            dklen=len(expected),
            maxmem=SCRYPT_MAXMEM,
        )
    except (ValueError, MemoryError):
        return False
    return hmac.compare_digest(derived, expected)


#: Verifying against this costs the same as a real verification. Used when the
#: username does not exist, so a missing account and a wrong password take the
#: same time and the endpoint cannot be used to enumerate usernames.
_DUMMY_HASH = hash_password("this value is never a real password")


def _equalise_timing(password: str) -> None:
    verify_password(password, _DUMMY_HASH)


# ---------------------------------------------------------------- tokens

def new_token() -> str:
    """A fresh, cryptographically random session token."""
    return secrets.token_urlsafe(TOKEN_BYTES)


def hash_token(token: str) -> str:
    """SHA-256 of a session token. This is the only form that is stored."""
    if not isinstance(token, str) or not token:
        raise ValueError("token must be a non-empty string")
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


# ------------------------------------------------------------- identities

def public_user(user: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Reduce a user row to what is safe to send to a browser.

    This is the single place that decides what leaves the server, so
    ``password_hash`` cannot be included by accident. The accepted fields are
    listed explicitly rather than filtered afterwards.
    """
    if user is None:
        return None
    return {
        "id": user.get("id"),
        "username": user.get("username"),
        "display_name": user.get("display_name"),
        "role": user.get("role"),
    }


# ------------------------------------------------------------ validation

def validate_username(username: Any) -> str:
    """Return a normalised username or raise :class:`AuthenticationError`."""
    if not isinstance(username, str):
        raise AuthenticationError("username is required")
    trimmed = username.strip()
    if not trimmed:
        raise AuthenticationError("username is required")
    if len(trimmed) < MIN_USERNAME_LENGTH or len(trimmed) > MAX_USERNAME_LENGTH:
        raise AuthenticationError(
            "username must be %d-%d characters" % (MIN_USERNAME_LENGTH, MAX_USERNAME_LENGTH)
        )
    if not USERNAME_PATTERN.match(trimmed):
        raise AuthenticationError("username may contain letters, digits, dot, dash and underscore only")
    return trimmed


def validate_password(password: Any) -> str:
    """Return the password unchanged or raise :class:`AuthenticationError`.

    The submitted value is never included in the message.
    """
    if not isinstance(password, str) or not password:
        raise AuthenticationError("password is required")
    if len(password) < MIN_PASSWORD_LENGTH:
        raise AuthenticationError(
            "password must be at least %d characters" % MIN_PASSWORD_LENGTH
        )
    if len(password) > MAX_PASSWORD_LENGTH:
        raise AuthenticationError("password must be at most %d characters" % MAX_PASSWORD_LENGTH)
    return password


# ------------------------------------------------------------ registration

def register_user(
    username: Any, password: Any, *, path: Optional[str] = None, created_at: Optional[str] = None
) -> Dict[str, Any]:
    """Create a student account and return its safe public form.

    There is no ``role`` parameter on purpose. Phase 2A creates students only;
    an admin must be provisioned deliberately, out of band, in a later phase.
    A request body that asks for ``role: "admin"`` is simply not read.
    """
    clean_username = validate_username(username)
    clean_password = validate_password(password)

    try:
        user_id = labdb.create_user(
            username=clean_username,
            password_hash=hash_password(clean_password),
            display_name=clean_username,
            role="student",
            path=path,
            created_at=created_at,
        )
    except sqlite3.IntegrityError as exc:
        # UNIQUE(username) is the only constraint that can realistically fire.
        if "username" in str(exc).lower():
            raise DuplicateUsername("username is already taken") from exc
        raise

    return public_user(labdb.get_user_by_id(user_id, path=path)) or {}


# ------------------------------------------------------------------ login

def authenticate(
    username: Any, password: Any, *, path: Optional[str] = None
) -> Dict[str, Any]:
    """Verify credentials and return the safe public form of the user.

    Raises :class:`InvalidCredentials` with one generic message for a missing
    username, an unknown username and a wrong password alike.
    """
    if not isinstance(username, str) or not isinstance(password, str) or not password:
        _equalise_timing(password if isinstance(password, str) else "")
        raise InvalidCredentials("invalid username or password")

    user = labdb.get_user_by_username(username.strip(), path=path)
    if user is None or not user.get("is_active"):
        # Spend the same time a real verification would, then fail identically.
        _equalise_timing(password)
        raise InvalidCredentials("invalid username or password")

    if not verify_password(password, user.get("password_hash") or ""):
        raise InvalidCredentials("invalid username or password")

    return public_user(user) or {}


# --------------------------------------------------------------- sessions

def _expiry_iso(ttl_seconds: int) -> str:
    from datetime import datetime, timedelta, timezone

    moment = datetime.now(timezone.utc).replace(microsecond=0) + timedelta(seconds=ttl_seconds)
    return moment.isoformat().replace("+00:00", "Z")


def create_session(
    user_id: int,
    *,
    path: Optional[str] = None,
    ttl_seconds: int = SESSION_TTL_SECONDS,
    ip: Optional[str] = None,
    user_agent: Optional[str] = None,
    created_at: Optional[str] = None,
) -> Tuple[str, Dict[str, Any]]:
    """Open a session and return ``(raw_token, session_row)``.

    The raw token is handed back once so the caller can put it in a cookie. Only
    its SHA-256 reaches SQLite.
    """
    token = new_token()
    session_id = labdb.create_session(
        user_id,
        hash_token(token),
        _expiry_iso(ttl_seconds),
        ip=ip,
        user_agent=user_agent,
        path=path,
        created_at=created_at,
    )
    row = labdb.get_session(hash_token(token), path=path) or {}
    row["id"] = session_id
    return token, row


def resolve_session(
    token: Optional[str], *, path: Optional[str] = None
) -> Optional[Dict[str, Any]]:
    """Turn a raw cookie token into a user, or ``None``.

    ``None`` is returned for a missing, malformed, unknown, deleted or expired
    token. An expired session is treated as absent *and* deleted, so a stale
    cookie cannot be revived and the table does not grow without bound.
    """
    if not isinstance(token, str) or not token:
        return None
    try:
        token_hash = hash_token(token)
    except ValueError:
        return None

    session = labdb.get_session(token_hash, path=path)
    if session is None:
        return None

    if _is_expired(session.get("expires_at")):
        labdb.delete_session(token_hash, path=path)
        return None

    user = labdb.get_user_by_id(session["user_id"], path=path)
    if user is None or not user.get("is_active"):
        return None
    return public_user(user)


def _is_expired(expires_at: Optional[str]) -> bool:
    """True when ``expires_at`` is missing or already in the past.

    Both timestamps are UTC ISO-8601 with second resolution, which is what
    :func:`labdb.utc_now` produces, so string comparison is a valid time
    comparison and avoids re-parsing on every request.
    """
    if not expires_at:
        return True
    return expires_at <= labdb.utc_now()


def delete_session(token: Optional[str], *, path: Optional[str] = None) -> bool:
    """Invalidate a session server-side. True when a row was removed."""
    if not isinstance(token, str) or not token:
        return False
    return labdb.delete_session(hash_token(token), path=path)


def touch_session(token: Optional[str], *, path: Optional[str] = None) -> bool:
    """Move a session's idle clock forward. Best effort."""
    if not isinstance(token, str) or not token:
        return False
    try:
        labdb.touch_session(hash_token(token), path=path)
    except Exception:
        return False
    return True
