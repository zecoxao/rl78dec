"""
Unit tests for interactive navigation, exact instruction EA mapping,
SSA IR rendering, and view state persistence in rl78dec.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rl78dec import decompile_image, cgen, structure, cfg, ir, db, view


def _img(b, size=0x100):
    a = bytearray(size)
    a[:len(b)] = bytes(b)
    return a


def test_exact_instruction_ea_mapping():
    # mov b,#4 ; L: dec b ; bnz L ; ret
    # 0x53 0x04 (ea=0, len=2)
    # 0x93      (ea=2, len=1: dec b)
    # 0xDF 0xFD (ea=3, len=2: bnz -3)
    # 0xD7      (ea=5, len=1: ret)
    prog = decompile_image(_img([0x53, 0x04, 0x93, 0xDF, 0xFD, 0xD7]), entries=[0])
    fn = prog.funcs[0]

    assert hasattr(fn, "line_ea"), "Function must have line_ea attribute"
    assert len(fn.line_ea) == len(fn.lines), f"line_ea length {len(fn.line_ea)} != lines length {len(fn.lines)}"

    # Check that mov b, #4 (v0 = 4;) maps to ea=0
    mov_line_idx = next(i for i, ln in enumerate(fn.lines) if "v0 = 4;" in ln)
    assert fn.line_ea[mov_line_idx] == 0, f"Expected EA 0 for mov line, got {fn.line_ea[mov_line_idx]}"

    # Check that dec b (v0 = v0 - 1;) maps to ea=2
    dec_line_idx = next(i for i, ln in enumerate(fn.lines) if "v0 = v0 - 1;" in ln)
    assert fn.line_ea[dec_line_idx] == 2, f"Expected EA 2 for dec line, got {fn.line_ea[dec_line_idx]}"

    # Check that loop header / condition maps to ea=2
    while_line_idx = next(i for i, ln in enumerate(fn.lines) if "} while (" in ln)
    assert fn.line_ea[while_line_idx] == 2, f"Expected EA 2 for while condition, got {fn.line_ea[while_line_idx]}"

    # Check that return; maps to ea=5
    ret_line_idx = next(i for i, ln in enumerate(fn.lines) if "return;" in ln)
    assert fn.line_ea[ret_line_idx] == 5, f"Expected EA 5 for ret, got {fn.line_ea[ret_line_idx]}"

    print("ok  test_exact_instruction_ea_mapping")


def test_view_ea_lookup_and_navigation():
    v = view._DecompilerView()
    v.line_ea = [0x1000, 0x1000, None, 0x1004, 0x1008, 0x100C]
    v.ea_to_line = {0x1000: 0, 0x1004: 3, 0x1008: 4, 0x100C: 5}
    v.raw_lines = [
        "void sub_1000(void)",
        "{",
        "    uint8_t v0;",
        "    v0 = 1;",
        "    v0 = v0 + 2;",
        "    return;",
    ]

    # Exact lookup
    assert v.find_line_for_ea(0x1004) == 3
    assert v.find_line_for_ea(0x100C) == 5

    # In-between / offset address lookup (closest predecessor)
    assert v.find_line_for_ea(0x1005) == 3
    assert v.find_line_for_ea(0x100A) == 4

    # Reverse lookup
    assert v.find_ea_for_line(3) == 0x1004
    assert v.find_ea_for_line(5) == 0x100C
    assert v.find_ea_for_line(2) is None

    print("ok  test_view_ea_lookup_and_navigation")


def test_ir_formatting():
    class DummyNamer:
        def code(self, ea): return f"sub_{ea:04X}"
        def label(self, ea): return f"loc_{ea:04X}"
        def cell(self, addr): return f"mem[{addr:X}]"

    namer = DummyNamer()

    # Assign
    s_assign = ir.Assign(0x100, ir.Var("v0"), ir.Const(42))
    assert view._format_ir_stmt(s_assign, namer) == "v0 = 0x2A"

    # Call
    s_call = ir.Call(0x104, target=0x2000, args=[ir.Var("v0")], dst=ir.Var("v1"))
    assert view._format_ir_stmt(s_call, namer) == "v1 = sub_2000(v0)"

    # Goto
    s_goto = ir.Goto(0x108, target=0x3000)
    assert view._format_ir_stmt(s_goto, namer) == "goto loc_3000"

    # Ret
    s_ret = ir.Ret(0x10C, val=ir.Var("v1"))
    assert view._format_ir_stmt(s_ret, namer) == "return v1"

    print("ok  test_ir_formatting")


def test_window_state_persistence():
    db.save_window_state(True, 0x1000, lineno=12, col=4, mode="ir")
    st = db.load_window_state()
    assert st["is_open"] is True
    assert st["func_ea"] == 0x1000
    assert st["lineno"] == 12
    assert st["col"] == 4
    assert st["mode"] == "ir"

    db.save_window_state(False, 0x1000, mode="c")
    st2 = db.load_window_state()
    assert st2["is_open"] is False
    assert st2["mode"] == "c"

    # Test _DecompilerView save_state and toggle_ir_mode
    v = view._DecompilerView()
    v.current_func_ea = 0x35DD
    v.save_state(is_open=True)
    st3 = db.load_window_state()
    assert st3["is_open"] is True
    assert st3["func_ea"] == 0x35DD
    assert st3["mode"] == "c"

    v.toggle_ir_mode()
    assert v.show_ir is True
    st4 = db.load_window_state()
    assert st4["mode"] == "ir"

    # Test UIHooks get_widget_config
    hooks = view._UIHooks(v)
    cfg = hooks.get_widget_config(v.GetWidget(), None)
    assert cfg["ea"] == 0x35DD
    assert cfg["mode"] == "ir"

    # Test UIHooks widget_closing marks is_open=False
    hooks.widget_closing(v.GetWidget())
    st5 = db.load_window_state()
    assert st5["is_open"] is False
    assert view._active_viewer is None

    print("ok  test_window_state_persistence")


def test_symbol_resolution_and_navigation():
    # Test resolve_symbol_ea
    assert view.resolve_symbol_ea("sub_2429") == 0x2429
    assert view.resolve_symbol_ea("loc_24F4") == 0x24F4
    assert view.resolve_symbol_ea("byte_FECA5") == 0xFECA5
    assert view.resolve_symbol_ea("word_FEC9E") == 0xFEC9E
    assert view.resolve_symbol_ea("ram_ECAA") == 0xFECAA
    assert view.resolve_symbol_ea("saddr_D5") == 0xFFFD5
    assert view.resolve_symbol_ea("RXD3") == 0xFFF16
    assert view.resolve_symbol_ea("0x24F4") == 0x24F4

    # Test navigation history push and pop
    v = view._DecompilerView()
    v.current_func_ea = 0x2429
    v._nav_history.append((0x2429, 30))
    assert len(v._nav_history) == 1
    prev_ea, prev_line = v._nav_history.pop()
    assert prev_ea == 0x2429
    assert prev_line == 30
    assert len(v._nav_history) == 0

    print("ok  test_symbol_resolution_and_navigation")


if __name__ == "__main__":
    test_exact_instruction_ea_mapping()
    test_view_ea_lookup_and_navigation()
    test_ir_formatting()
    test_window_state_persistence()
    test_symbol_resolution_and_navigation()
    print("\nALL INTERACTIVE TESTS PASS")
