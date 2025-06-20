
"""Cipher suite configuration shared by session modules."""

import struct

# Map of cipher suite identifiers to authentication, integrity and
# confidentiality algorithm identifiers.
CIPHER_SUITE_PARAMS = {
    0: (0, 0, 0),
    1: (1, 0, 0),
    2: (1, 1, 0),
    3: (1, 1, 1),
    4: (1, 1, 2),
    5: (1, 1, 3),
    6: (2, 0, 0),
    7: (2, 2, 0),
    8: (2, 2, 1),
    9: (2, 2, 2),
    10: (2, 2, 3),
    11: (2, 3, 0),
    12: (2, 3, 1),
    13: (2, 3, 2),
    14: (2, 3, 3),
    15: (3, 0, 0),
    16: (3, 4, 0),
    17: (3, 4, 1),
}


def build_cipher_suite(auth: int, integ: int, conf: int) -> bytearray:
    """Construct the 24-byte encoding for a cipher suite."""
    return (
        bytearray(b"\x00\x00\x00\x08")
        + struct.pack("<I", auth)
        + b"\x01\x00\x00\x08"
        + struct.pack("<I", integ)
        + b"\x02\x00\x00\x08"
        + struct.pack("<I", conf)
    )
