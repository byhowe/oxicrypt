from dataclasses import dataclass
from typing import Callable, Literal
import oxicrypt
import struct
import sys

CompressFn = Callable[[bytearray, bytes], None]

sha1_state = struct.pack(
    "IIIII",
    0x67452301,
    0xEFCDAB89,
    0x98BADCFE,
    0x10325476,
    0xC3D2E1F0,
)

sha224_state = struct.pack(
    "IIIIIIII",
    0xC1059ED8,
    0x367CD507,
    0x3070DD17,
    0xF70E5939,
    0xFFC00B31,
    0x68581511,
    0x64F98FA7,
    0xBEFA4FA4,
)

sha256_state = struct.pack(
    "IIIIIIII",
    0x6A09E667,
    0xBB67AE85,
    0x3C6EF372,
    0xA54FF53A,
    0x510E527F,
    0x9B05688C,
    0x1F83D9AB,
    0x5BE0CD19,
)

sha384_state = struct.pack(
    "QQQQQQQQ",
    0xCBBB9D5DC1059ED8,
    0x629A292A367CD507,
    0x9159015A3070DD17,
    0x152FECD8F70E5939,
    0x67332667FFC00B31,
    0x8EB44A8768581511,
    0xDB0C2E0D64F98FA7,
    0x47B5481DBEFA4FA4,
)

sha512_state = struct.pack(
    "QQQQQQQQ",
    0x6A09E667F3BCC908,
    0xBB67AE8584CAA73B,
    0x3C6EF372FE94F82B,
    0xA54FF53A5F1D36F1,
    0x510E527FADE682D1,
    0x9B05688C2B3E6C1F,
    0x1F83D9ABFB41BD6B,
    0x5BE0CD19137E2179,
)

sha512_224_state = struct.pack(
    "QQQQQQQQ",
    0x8C3D37C819544DA2,
    0x73E1996689DCD4D6,
    0x1DFAB7AE32FF9C82,
    0x679DD514582F9FCF,
    0x0F6D2B697BD44DA8,
    0x77E36F7304C48942,
    0x3F9D85A86A1D36C8,
    0x1112E6AD91D692A1,
)

sha512_256_state = struct.pack(
    "QQQQQQQQ",
    0x22312194FC2BF72C,
    0x9F555FA3C84C64C2,
    0x2393B86B6F53B151,
    0x963877195940EABD,
    0x96283EE2A88EFFE3,
    0xBE5E1E2553863992,
    0x2B0199FC2C85B8AA,
    0x0EB72DDC81C52CA2,
)

md5_state = struct.pack("IIII", 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476)


@dataclass
class DigestMeta:
    lengthcounterw: int
    endian: Literal["big", "little"]
    blocklen: int
    statew: int
    state: bytes


sha1_meta = DigestMeta(
    lengthcounterw=8,
    endian="big",
    blocklen=64,
    statew=5,
    state=sha1_state,
)

sha224_meta = DigestMeta(
    lengthcounterw=8,
    endian="big",
    blocklen=64,
    statew=8,
    state=sha224_state,
)

sha256_meta = DigestMeta(
    lengthcounterw=8,
    endian="big",
    blocklen=64,
    statew=8,
    state=sha256_state,
)

sha384_meta = DigestMeta(
    lengthcounterw=16,
    endian="big",
    blocklen=128,
    statew=8,
    state=sha384_state,
)

sha512_meta = DigestMeta(
    lengthcounterw=16,
    endian="big",
    blocklen=128,
    statew=8,
    state=sha512_state,
)

sha512_224_meta = DigestMeta(
    lengthcounterw=16,
    endian="big",
    blocklen=128,
    statew=8,
    state=sha512_224_state,
)

sha512_256_meta = DigestMeta(
    lengthcounterw=16,
    endian="big",
    blocklen=128,
    statew=8,
    state=sha512_256_state,
)

md5_meta = DigestMeta(
    lengthcounterw=8,
    endian="little",
    blocklen=64,
    statew=4,
    state=md5_state,
)


@dataclass
class Digest:
    compress: CompressFn
    meta: DigestMeta

    state: bytearray
    block: bytearray
    curblocklen: int
    compressedlen: int

    @classmethod
    def _new(
        cls,
        compress: CompressFn,
        meta: DigestMeta,
    ) -> "Digest":
        return cls(
            compress=compress,
            meta=meta,
            state=bytearray(meta.state),
            block=bytearray(b"\x00" * meta.blocklen),
            curblocklen=0,
            compressedlen=0,
        )

    @classmethod
    def new_sha1(cls) -> "Digest":
        return cls._new(
            compress=oxicrypt.core.sha_generic_sha1_compress,
            meta=sha1_meta,
        )

    @classmethod
    def new_sha224(cls) -> "Digest":
        return cls._new(
            compress=oxicrypt.core.sha_generic_sha256_compress,
            meta=sha224_meta,
        )

    @classmethod
    def new_sha256(cls) -> "Digest":
        return cls._new(
            compress=oxicrypt.core.sha_generic_sha256_compress,
            meta=sha256_meta,
        )

    @classmethod
    def new_sha384(cls) -> "Digest":
        return cls._new(
            compress=oxicrypt.core.sha_generic_sha512_compress,
            meta=sha384_meta,
        )

    @classmethod
    def new_sha512(cls) -> "Digest":
        return cls._new(
            compress=oxicrypt.core.sha_generic_sha512_compress,
            meta=sha512_meta,
        )

    @classmethod
    def new_sha512_224(cls) -> "Digest":
        return cls._new(
            compress=oxicrypt.core.sha_generic_sha512_compress,
            meta=sha512_224_meta,
        )

    @classmethod
    def new_sha512_256(cls) -> "Digest":
        return cls._new(
            compress=oxicrypt.core.sha_generic_sha512_compress,
            meta=sha512_256_meta,
        )

    @classmethod
    def new_md5(cls) -> "Digest":
        return cls._new(
            compress=oxicrypt.core.md5_generic_md5_compress,
            meta=md5_meta,
        )

    def _compress(self):
        self.compress(self.state, bytes(self.block))

    def oneshot(self, data: bytes) -> bytes:
        self.update(data)
        self.finish()
        return bytes(self.state)

    def update(self, data: bytes):
        while len(data) > 0:
            emptyspace = self.meta.blocklen - self.curblocklen
            if emptyspace >= len(data):
                newblocklen = self.curblocklen + len(data)
                self.block[self.curblocklen : newblocklen] = data
                self.curblocklen = newblocklen
                data = data[0:0]
            else:
                self.block[self.curblocklen : self.meta.blocklen] = data[0:emptyspace]
                self.curblocklen = self.meta.blocklen
                data = data[emptyspace:]

            if self.curblocklen == self.meta.blocklen:
                self._compress()
                self.curblocklen = 0
                self.compressedlen += self.meta.blocklen

    def finish(self):
        self.block[self.curblocklen] = 0x80
        self.compressedlen += self.curblocklen
        self.curblocklen += 1

        if self.curblocklen > (self.meta.blocklen - self.meta.lengthcounterw):
            self.block[self.curblocklen :] = b"\x00" * (
                self.meta.blocklen - self.curblocklen
            )
            self._compress()
            self.curblocklen = 0

        self.block[
            self.curblocklen : (self.meta.blocklen - self.meta.lengthcounterw)
        ] = b"\x00" * (self.meta.blocklen - self.meta.lengthcounterw - self.curblocklen)
        self.compressedlen *= 8
        self.block[
            (self.meta.blocklen - self.meta.lengthcounterw) :
        ] = self.compressedlen.to_bytes(
            length=self.meta.lengthcounterw, byteorder=self.meta.endian, signed=False
        )
        self._compress()

        intlen = len(self.state) // self.meta.statew
        for i in range(self.meta.statew):
            h = int.from_bytes(
                self.state[i * intlen : (i + 1) * intlen],
                byteorder=sys.byteorder,
                signed=False,
            )
            self.state[i * intlen : (i + 1) * intlen] = h.to_bytes(
                length=intlen,
                byteorder=self.meta.endian,
                signed=False,
            )
