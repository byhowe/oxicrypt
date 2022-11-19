from dataclasses import dataclass
from enum import Enum
import os

plaintext_length = 16 * 8


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
            expanded_key=bytes(),
            inversed_key=bytes(),
            plaintext=os.urandom(plaintext_length),
            ciphertext=bytes(),
        )
        return c
