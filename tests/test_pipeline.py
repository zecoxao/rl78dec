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

    # 0x61 map: xch a, b = 61 8B
    ins = decoder.decode_one(_img([0x61, 0x8B]), 0)
    assert ins.mnem == "xch" and ins.ops[0].reg == "a" and ins.ops[1].reg == "b"

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
    assert "v0 = v0 - 1;" in text, text
    assert text.count("{") == text.count("}"), text
    print("ok  test_loop_structuring\n")
    print(text)


def test_switch_structuring():
    raw = bytes.fromhex(
        "5c1f9170f1312d0468d3144100118a029efc11aa00410f61cb00a4d30000a4d30000"
        "4ed40000a6d300000000000000000000b8d300000000000000000000000000000000"
        "00000000000000000000cad3000000000000d70031171169c6ddf1041fde1451ff11"
        "9a00d700c331171169c6ddf1312d0425de14c2ee5a00c331171169c6ddf1312d042d"
        "de14c2ee4800f61129efdd08045cdd14c3fe3a00c2c3d1df211129efdd7553012c08"
        "de02f3655201d1dd05311791dffb110958dd617a111858dd118f54ddc2614adf0a11"
        "8f53dd5cf7119f53ddd7112907de614add1c701189614adf0360119911290dde618a"
        "08112807de618a11280dded711ca00fff1d7c331171169c6ddf10413de14c2eec6ff"
        "1138"
    )
    buf = bytearray(0x10000)
    buf[0xD34E:0xD34E + len(raw)] = raw
    prog = decompile_image(buf, entries=[0xD34E])
    fn = prog.funcs[0xD34E]
    text = "\n".join(fn.lines)
    assert "switch (" in text, text
    assert "case 0:" in text and "case 1:" in text, text
    assert "case 2:" in text and "case 3:" in text, text
    assert "case 6:" in text and "case 13:" in text, text
    assert "break;" in text, text
    assert "return;" in text, text
    print("ok  test_switch_structuring\n")
    print(text)


def test_coalesce_arithmetic():
    # Consecutive incw ax (0xA1, 0xA1, 0xD7) -> + 2
    prog = decompile_image(_img([0xA1, 0xA1, 0xD7]), entries=[0])
    text = "\n".join(prog.funcs[0].lines)
    assert "+ 2" in text, text

    # Consecutive decw bc (0xB3, 0xB3, 0xD7) -> - 2
    prog = decompile_image(_img([0xB3, 0xB3, 0xD7]), entries=[0])
    text = "\n".join(prog.funcs[0].lines)
    assert "- 2" in text, text

    print("ok  test_coalesce_arithmetic")


def test_global_memory_access():
    # Loop copying 4 bytes using 16-bit word moves with C index:
    #   MOV C, #4
    # loop:
    #   DEC C
    #   DEC C
    #   MOVW AX, [C+0xFE48]
    #   MOVW [C+0xFE4C], AX
    #   BNZ loop
    #   MOV A, !0xFFE50
    #   RET
    raw = bytes([0x52, 0x04, 0x92, 0x92, 0x69, 0x48, 0xFE, 0x68, 0x4C, 0xFE, 0xDF, 0xF6, 0x8F, 0x50, 0xFE, 0xD7])
    buf = bytearray(0x100)
    buf[:len(raw)] = raw
    prog = decompile_image(buf, entries=[0], cell_names={
        0xFFE4C: "byte_FFE4C",
        0xFFE48: "byte_FFE48",
        0xFFE50: "byte_FFE50",
    })
    text = "\n".join(prog.funcs[0].lines)
    assert "byte_FFE4C[v0] = byte_FFE48[v0];" in text, text
    assert "return byte_FFE50;" in text or "byte_FFE50" in text, text
    assert "mem16[" not in text, text

    print("ok  test_global_memory_access")


def test_named_variable_constant():
    # ADDW AX, #0x2A0E (0x04 0x0E 0x2A) ; RET (0xD7)
    raw = bytes([0x04, 0x0E, 0x2A, 0xD7])
    buf = bytearray(0x100)
    buf[:len(raw)] = raw

    # 1. Test via cell_names mapping
    prog = decompile_image(buf, entries=[0], cell_names={0x2A0E: "kermit_cmd_tableR"})
    text = "\n".join(prog.funcs[0].lines)
    assert "kermit_cmd_tableR" in text, text
    assert "0x2A0E" not in text, text
    assert hasattr(prog.funcs[0], "line_eas")
    assert prog.funcs[0].line_eas is not None

    # 2. Test via direct instruction operand name annotation
    insns, calls = decoder.decode(buf, entries=[0], base=0)
    assert 0 in insns and len(insns[0].ops) >= 2
    insns[0].ops[1].name = "kermit_cmd_tableR"
    from rl78dec import cfg, opt, structure, cgen, frame, abi, vars
    from rl78dec.names import Namer
    f = cfg.build_func(insns, 0, {0})
    frame_info = frame.analyze_frame(f)
    opt.optimize(f)
    sig = abi.analyze_calling_convention(f, frame_info)
    vars.recover_variables(f, sig, frame_info)
    tree = structure.structure(f)
    lines = cgen.generate(f, tree, Namer(), frame_info=frame_info, sig=sig)
    text2 = "\n".join(lines)
    assert "kermit_cmd_tableR" in text2, text2
    assert "0x2A0E" not in text2, text2

    print("ok  test_named_variable_constant")


def test_struct_pointer_cascading():
    from rl78dec import decoder, cfg, opt, structure, cgen, frame, abi, vars
    from rl78dec.names import Namer

    # Byte sequence:
    # 00: ADDW AX, #0x2A0E  (kermit_cmd_tableR)
    # 03: MOVW DE, AX       (DE = AX)
    # 04: MOV ES, #0
    # 06: MOVW AX, ES:[DE]  (offset 0 -> id)
    # 08: MOV A, ES:[DE+2]  (offset 2 -> auth)
    # 0B: MOV A, ES:[DE+6]  (offset 6 -> func)
    # 0E: MOVW AX, ES:[DE+4](offset 4 -> func)
    # 11: RET
    buf = bytes([
        0x04, 0x0E, 0x2A,
        0x14,
        0x41, 0x00,
        0x11, 0xA9,
        0x11, 0x8A, 0x02,
        0x11, 0x8A, 0x06,
        0x11, 0xAA, 0x04,
        0xD7
    ])

    namer = Namer(
        struct_defs={
            'kermit_cmd0': {
                'size': 8,
                'members': [
                    {'offset': 0, 'size': 2, 'name': 'id', 'type': 'int'},
                    {'offset': 2, 'size': 2, 'name': 'auth', 'type': 'int'},
                    {'offset': 4, 'size': 4, 'name': 'func', 'type': 'void (*)()'},
                ]
            }
        },
        symbol_structs={'kermit_cmd_tableR': 'kermit_cmd0', 0x2A0E: 'kermit_cmd0'}
    )

    insns, calls = decoder.decode(buf, entries=[0], base=0)
    insns[0].ops[1].name = 'kermit_cmd_tableR'
    f = cfg.build_func(insns, 0, {0})
    frame_info = frame.analyze_frame(f)
    opt.optimize(f)
    sig = abi.analyze_calling_convention(f, frame_info)
    vars.recover_variables(f, sig, frame_info)
    tree = structure.structure(f)
    lines = cgen.generate(f, tree, namer, frame_info=frame_info, sig=sig)
    text = '\n'.join(lines)

    assert "kermit_cmd0 *v1;" in text, text
    assert "v1->id" in text, text
    assert "v1->auth" in text, text
    assert "v1->func" in text, text
    assert "es_mem" not in text, text

    print("ok  test_struct_pointer_cascading")


if __name__ == "__main__":
    test_decode_fields()
    test_all_first_bytes()
    test_loop_structuring()
    test_switch_structuring()
    test_coalesce_arithmetic()
    test_global_memory_access()
    test_named_variable_constant()
    test_struct_pointer_cascading()
    print("\nall tests passed")
