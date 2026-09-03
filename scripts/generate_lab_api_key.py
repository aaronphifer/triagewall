#!/usr/bin/env python3
"""Generate one private Lab access key and its PBKDF2 configuration hash."""

from __future__ import annotations

import argparse
import os
import secrets
import stat
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from triagewall.lab.auth import hash_lab_api_key


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Generate a TriageWall Lab access key.")
    parser.add_argument("--bytes", type=int, default=32)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("triagewall-lab-credentials.txt"),
        help="new private credential file (default: %(default)s)",
    )
    args = parser.parse_args(argv)
    if not 24 <= args.bytes <= 64:
        parser.error("--bytes must be between 24 and 64")
    output_path = args.output.expanduser()
    if not output_path.parent.is_dir():
        parser.error(f"output directory does not exist: {output_path.parent}")
    plaintext = secrets.token_urlsafe(args.bytes)
    digest = hash_lab_api_key(plaintext)
    session_secret = secrets.token_urlsafe(48)
    contents = (
        "# Store TRIAGEWALL_LAB_ACCESS_KEY in a password manager, then remove "
        "this file.\n"
        "# Copy only the HASH and SESSION_SECRET values to TriageWall's .env.\n"
        f"TRIAGEWALL_LAB_ACCESS_KEY='{plaintext}'\n"
        f"TRIAGEWALL_LAB_API_KEY_HASH='{digest}'\n"
        f"TRIAGEWALL_LAB_SESSION_SECRET='{session_secret}'\n"
    )
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    if hasattr(os, "O_NOINHERIT"):
        flags |= os.O_NOINHERIT
    try:
        fd = os.open(output_path, flags, stat.S_IRUSR | stat.S_IWUSR)
    except FileExistsError:
        parser.error(f"refusing to overwrite existing credential file: {output_path}")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(contents)
        output_path.chmod(stat.S_IRUSR | stat.S_IWUSR)
    except BaseException:
        try:
            output_path.unlink(missing_ok=True)
        finally:
            raise
    print(f"Wrote private Lab credentials to {output_path}.")
    print(
        "Move the access key to your password manager, copy the two "
        "configuration values to .env, then remove the credential file."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
