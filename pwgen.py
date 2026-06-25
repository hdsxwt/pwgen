#!/usr/bin/env python3
"""
BIP85-based deterministic password generator.

Reads a BIP39 mnemonic from D:/password/key as the master seed,
then generates unique per-site passwords using BIP85 with base85 or base64.
"""

import argparse
import hashlib
import os
import sys

from bipsea import bip39, bip32, bip85

MASTER_KEY_FILE = r"D:\password\key"

# BIP85 application codes
ENCODING_CODES = {
    "base85": "707785",
    "base64": "707764",
}

# Length ranges per encoding (from bipsea.bip85.RANGES)
ENCODING_RANGES = {
    "base85": (10, 80),
    "base64": (20, 86),
}


def load_master_key():
    """Read mnemonic from MASTER_KEY_FILE and return a BIP32 master key."""
    if not os.path.exists(MASTER_KEY_FILE):
        print(f"Error: Master key file not found: {MASTER_KEY_FILE}", file=sys.stderr)
        sys.exit(1)

    with open(MASTER_KEY_FILE, encoding="utf-16") as f:
        content = f.read().strip()

    words = content.split()
    if len(words) not in (12, 15, 18, 21, 24):
        print(
            f"Error: Expected 12/15/18/21/24 mnemonic words, got {len(words)}",
            file=sys.stderr,
        )
        sys.exit(1)

    if not bip39.validate_mnemonic_words(words, "english"):
        print("Error: Invalid mnemonic phrase (checksum mismatch)", file=sys.stderr)
        sys.exit(1)

    seed = bip39.to_master_seed(words, "")
    return bip32.to_master_key(seed, mainnet=True, private=True)


def site_to_index(site: str) -> int:
    """Convert a site identifier string to a deterministic BIP32 child index."""
    h = hashlib.sha256(site.encode()).digest()
    return int.from_bytes(h[:4], "big") % 2**31


def generate_password(master_key, site: str, length: int = 12, encoding: str = "base85") -> str:
    """Generate a deterministic password for *site* using BIP85."""
    app_code = ENCODING_CODES[encoding]
    idx = site_to_index(site)
    path = f"m/83696968'/{app_code}'/{length}'/{idx}'"
    derived_key = bip85.derive(master_key, path)
    result = bip85.apply_85(derived_key, path)
    return result["application"]


def main():
    parser = argparse.ArgumentParser(
        description="BIP85 deterministic password generator",
    )
    parser.add_argument(
        "site",
        help="Site identifier string (e.g. 'github', 'google')",
    )
    parser.add_argument(
        "-l",
        "--length",
        type=int,
        default=12,
        help="Password length (default: 12; base85: 10-80, base64: 20-86)",
    )
    parser.add_argument(
        "-e",
        "--encoding",
        choices=["base85", "base64"],
        default="base85",
        help="Encoding scheme (default: base85)",
    )

    args = parser.parse_args()

    # Validate length against encoding range
    lo, hi = ENCODING_RANGES[args.encoding]
    truncate_to = None
    if args.length < lo:
        print(
            f"Note: Minimum {args.encoding} length is {lo}, "
            f"generating {lo} chars and trimming to {args.length}",
            file=sys.stderr,
        )
        truncate_to = args.length
        length = lo
    elif args.length > hi:
        print(
            f"Error: Length {args.length} exceeds {args.encoding} maximum ({hi})",
            file=sys.stderr,
        )
        sys.exit(1)
    else:
        length = args.length

    master_key = load_master_key()
    password = generate_password(master_key, args.site, length, args.encoding)
    if truncate_to is not None:
        password = password[:truncate_to]
    print(password)


if __name__ == "__main__":
    main()
