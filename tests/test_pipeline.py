"""
Headless tests for the RL78 decoder and decompiler pipeline.  No IDA, no ROM.

    python tests/test_pipeline.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rl78dec import decoder, decompile_image        # noqa: E402


def _img(b, size=0x100):
    a = bytearray(size)
    a[:len(b)] = bytes(b)
    return a


def test_decode_fields():
    # mov x, #0x12   (0x50 = mov X,#byte)
    ins = decoder.decode_one(_img([0x50, 0x12]), 0)
    assert ins.mnem == "mov" and ins.size == 2
    assert ins.ops[0].mode == "reg" and ins.ops[0].reg == "x"
    assert ins.ops[1].mode == "imm" and ins.ops[1].value == 0x12

    # mov a, [hl]   (0x8B)
    ins = decoder.decode_one(_img([0x8B]), 0)
    assert ins.mnem == "mov" and ins.ops[1].mode == "ind" and ins.ops[1].base_reg == "hl"

    # br !!0x0F1234  (0xEC, addr20)
    ins = decoder.decode_one(_img([0xEC, 0x34, 0x12, 0x0F]), 0)
    assert ins.mnem == "br" and ins.ops[0].mode == "far" and ins.ops[0].addr == 0x0F1234

    # bz $rel  at ea=0x10, disp=+2 -> target = 0x10 + 2 + 2 = 0x14
    ins = decoder.decode_one(_img([0] * 0x10 + [0xDD, 0x02]), 0x10)
    assert ins.mnem == "bz" and ins.ops[0].addr == 0x14

    # ES: mov a, !addr16  (0x11 prefix) -> es data at raw addr16 (no 0xF0000)
    ins = decoder.decode_one(_img([0x11, 0x8F, 0x00, 0x10]), 0)
    assert ins.es and ins.mnem == "mov"
    assert ins.ops[1].mode == "mem" and ins.ops[1].es and ins.ops[1].addr == 0x1000

    # 0x71 map: set1 cy = 71 80 ; clr1 cy = 71 88
    ins = decoder.decode_one(_img([0x71, 0x80]), 0)
    assert ins.mnem == "set1" and ins.ops[0].reg == "cy"
    ins = decoder.decode_one(_img([0x71, 0x88]), 0)
    assert ins.mnem == "clr1" and ins.ops[0].reg == "cy"
    print("ok  test_decode_fields")


def test_all_first_bytes():
    # every first byte must decode or cleanly return None, never raise
    for b in range(256):
        decoder.decode_one(_img([b, 0, 0, 0, 0]), 0)
        decoder.decode_one(_img([0x11, b, 0, 0, 0]), 0)   # with ES prefix
        for pfx in (0x31, 0x61, 0x71):
            decoder.decode_one(_img([pfx, b, 0, 0]), 0)
    print("ok  test_all_first_bytes")


def test_loop_structuring():
    # mov b,#4 ; L: dec b ; bnz L ; ret
    #   0x53 0x04 | 0x93 | 0xDF <disp> | 0xD7
    # bnz at ea=3, target L=2 -> disp = 2 - (3+2) = -3 = 0xFD
    prog = decompile_image(_img([0x53, 0x04, 0x93, 0xDF, 0xFD, 0xD7]), entries=[0])
    fn = prog.funcs[0]
    text = "\n".join(fn.lines)
    assert "do {" in text and "while (" in text and "!= 0" in text, text
    assert "b = b - 1;" in text, text
    assert text.count("{") == text.count("}"), text
    print("ok  test_loop_structuring\n")
    print(text)


if __name__ == "__main__":
    test_decode_fields()
    test_all_first_bytes()
    test_loop_structuring()
    print("\nall tests passed")
