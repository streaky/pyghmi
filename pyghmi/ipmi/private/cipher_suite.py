# Copyright 2013 IBM Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

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
