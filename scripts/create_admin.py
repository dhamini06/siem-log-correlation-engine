"""Provision an instructor/admin account. Local, interactive, and deliberately manual.

Why a separate command instead of an endpoint
    Student accounts are self-service: ``POST /api/auth/register`` is open, and
    that is correct for a lab where students sign themselves up. An admin is
    the opposite - it must be created by someone who already has the lab on
    their own machine and who types the password deliberately. So there is no
    registration route, no admin signup page, and no flag anywhere that would
    create an administrator during startup, setup, tests or Docker.

    The only way to make an admin is to run this script, as the person who owns
    the lab.

How the password is handled
    Read with :func:`getpass.getpass`, so it is not echoed and does not end up in
    a scrollback buffer, and typed twice so a typo cannot lock an instructor out
    of the only account that exists. There is deliberately no ``--password``
    flag: a command-line argument is visible in the process list and in shell
    history, which is the opposite of what this command is for.

    The password is then handed to :func:`auth.hash_password` - the same scrypt
    implementation the login path verifies against - and only the resulting hash
    is written. The plaintext is never stored, never logged, and never echoed,
    not even on failure: error messages describe the rule that was broken, never
    the value.

What this reuses
    ``auth.validate_username`` / ``auth.validate_password`` for the rules, so a
    password an admin can set is exactly one a student can set, and
    ``auth.hash_password`` for the hashing, so there is no second copy of the
    scrypt parameters anywhere to drift out of step.

    It deliberately does *not* call ``auth.register_user``. That function has no
    role parameter at all, which is what makes the public endpoint
    student-only; going around it to ``labdb.create_user`` is the one and only
    path that can set ``role='admin'``, and it is a local script.

Usage
    python scripts/create_admin.py
    python scripts/create_admin.py --database data/training.db
"""

from __future__ import annotations

import argparse
import getpass
import os
import sqlite3
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import auth  # noqa: E402
import labdb  # noqa: E402

__all__ = [
    "DuplicateAdmin",
    "create_admin",
    "main",
    "prompt_for_admin",
]


class DuplicateAdmin(Exception):
    """The username is already taken. Refused rather than overwritten."""


def create_admin(
    username: str,
    password: str,
    *,
    path: str = None,
) -> dict:
    """Create one admin account and return its safe public form.

    The non-interactive core. Split out from the prompting so it can be tested
    directly, and so the prompt loop holds no privileged logic of its own.

    ``username`` and ``password`` are validated with the shared rules, the
    password is hashed with the shared scrypt helper, and the row is written
    through :func:`labdb.create_user`, which checks the role against
    :data:`labdb.ROLES`. Nothing but the hash is persisted.
    """
    clean_username = auth.validate_username(username)
    clean_password = auth.validate_password(password)

    # Check first for a clear message, then rely on the UNIQUE constraint as
    # the real guarantee. The pre-check is only for the error text: two admins
    # typing the same name concurrently would both pass it, and only the
    # constraint actually prevents the duplicate.
    if labdb.get_user_by_username(clean_username, path=path) is not None:
        raise DuplicateAdmin("that username is already taken")

    try:
        user_id = labdb.create_user(
            username=clean_username,
            password_hash=auth.hash_password(clean_password),
            display_name=clean_username,
            role="admin",
            path=path,
        )
    except sqlite3.IntegrityError as exc:
        if "username" in str(exc).lower():
            raise DuplicateAdmin("that username is already taken") from exc
        raise

    created = labdb.get_user_by_id(user_id, path=path) or {}
    return auth.public_user(created) or {}


def prompt_for_admin(path: str = None) -> dict:
    """Ask for the details on the terminal, then create the account.

    Refuses to run without a terminal. A pipe would put the password into
    whatever invoked the command - a script, a CI log, a shell history entry -
    which defeats the point of prompting in the first place.
    """
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        print(
            "create_admin.py needs an interactive terminal.\n"
            "Refusing to read a password from a pipe: it would end up in a "
            "script, a CI log or shell history.\n"
            "Run it directly:  python scripts/create_admin.py",
            file=sys.stderr,
        )
        raise SystemExit(2)

    print("BlueCloud Softech Solutions - SIEM training lab")
    print("Instructor account provisioning")
    print("-" * 52)

    while True:
        username = input("Username: ").strip()
        try:
            auth.validate_username(username)
            break
        except auth.AuthenticationError as exc:
            print("  %s" % exc)

    while True:
        # getpass does not echo. It falls back to a warning on a terminal that
        # cannot suppress echo, which is worth surfacing rather than hiding.
        password = getpass.getpass("Password: ")
        confirm = getpass.getpass("Confirm password: ")
        if password != confirm:
            print("  The two passwords did not match. Try again.")
            continue
        try:
            auth.validate_password(password)
            break
        except auth.AuthenticationError as exc:
            print("  %s" % exc)

    try:
        user = create_admin(username, password, path=path)
    except DuplicateAdmin as exc:
        print("\nNot created: %s" % exc, file=sys.stderr)
        return {}

    # The username is safe to echo back: it is an identifier, not a secret, and
    # the operator needs to see what they created. The password and the hash
    # are not, and are not printed anywhere on any path.
    print("-" * 52)
    print("Created instructor account: %s (role: %s)" % (user["username"], user["role"]))
    print("Sign in at http://localhost:8080/login.html")
    return user


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Create an instructor/admin account for the training lab.",
        epilog="There is no admin self-registration: this command is the only "
               "way to create one, and it must be run by hand.",
    )
    parser.add_argument(
        "--database", default=None,
        help="Path to the student database (default: data/training.db)",
    )
    # Deliberately no --password, and no --username: see the module docstring.
    args = parser.parse_args(argv)

    # Idempotent, so a fresh checkout can be provisioned without a manual
    # schema step. It creates tables, never accounts.
    path = labdb.init_db(args.database)

    user = prompt_for_admin(path=path)
    if not user:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
