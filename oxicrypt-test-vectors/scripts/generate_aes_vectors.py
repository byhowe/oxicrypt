from dataclasses import dataclass
from enum import Enum
import os
import struct

plaintext_length = 16 * 8
vectors_len = 128


class aes(Enum):
    aes128 = 1
    aes192 = 2
    aes256 = 3

    def key_length(self) -> int:
        match self:
            case aes.aes128:
                return 16
            case aes.aes192:
                return 24
            case aes.aes256:
                return 32

    def expanded_key_length(self) -> int:
        match self:
            case aes.aes128:
                return 176
            case aes.aes192:
                return 208
            case aes.aes256:
                return 240


@dataclass
class aes_vectors:
    key: bytes
    expanded_key: bytes
    inversed_key: bytes
    plaintext: bytes
    ciphertext: bytes

    @classmethod
    def generate_random(cls, v: aes) -> "aes_vectors":
        # TODO: find algorithm to compute `expanded_key`, `inversed_key`,
        # and `ciphertext`.
        c = cls(
            key=os.urandom(v.key_length()),
            expanded_key=b"\x00" * v.expanded_key_length(),
            inversed_key=b"\x00" * v.expanded_key_length(),
            plaintext=os.urandom(plaintext_length),
            ciphertext=b"\x00" * plaintext_length,
        )
        return c

    def __bytes__(self) -> bytes:
        return (
            self.key
            + self.expanded_key
            + self.inversed_key
            + self.plaintext
            + self.ciphertext
        )


vectors128 = (aes_vectors.generate_random(aes.aes128) for _ in range(vectors_len))
vectors192 = (aes_vectors.generate_random(aes.aes192) for _ in range(vectors_len))
vectors256 = (aes_vectors.generate_random(aes.aes256) for _ in range(vectors_len))

with open("aes128_vectors.bin", "wb") as f:
    f.write(struct.pack(">I", vectors_len))
    for vectors in vectors128:
        f.write(bytes(vectors))

with open("aes192_vectors.bin", "wb") as f:
    f.write(struct.pack(">I", vectors_len))
    for vectors in vectors192:
        f.write(bytes(vectors))

with open("aes256_vectors.bin", "wb") as f:
    f.write(struct.pack(">I", vectors_len))
    for vectors in vectors256:
        f.write(bytes(vectors))
