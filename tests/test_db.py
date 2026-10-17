"""
Tests for IDA netnode persistence layer in rl78dec.db.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rl78dec import db, cgen, cfg, frame, abi, structure, ir


def test_db_in_memory_persistence():
    func_ea = 0x221D
    db.clear_func_data(func_ea)

    # 1. Variable renames
    db.set_var_rename(func_ea, "v0", "counter")
    db.set_var_rename(func_ea, "v1", "ptr")
    data = db.get_func_data(func_ea)
    assert data["renames"] == {"v0": "counter", "v1": "ptr"}

    # Renaming renamed variable
    db.set_var_rename(func_ea, "counter", "loop_idx")
    data = db.get_func_data(func_ea)
    assert data["renames"] == {"v0": "loop_idx", "v1": "ptr"}

    # Clearing rename
    db.set_var_rename(func_ea, "v1", "")
    data = db.get_func_data(func_ea)
    assert data["renames"] == {"v0": "loop_idx"}

    # 2. Variable type overrides
    db.set_var_type(func_ea, "v0", "uint32_t")
    db.set_var_type(func_ea, "loop_idx", "int32_t")
    data = db.get_func_data(func_ea)
    assert data["types"] == {"v0": "uint32_t", "loop_idx": "int32_t"}

    # 3. Prototype overrides
    db.set_func_proto(func_ea, "int sub_221D(uint16_t count, uint8_t flag)")
    data = db.get_func_data(func_ea)
    assert data["proto"] == "int sub_221D(uint16_t count, uint8_t flag)"

    # 4. Sync setting
    db.set_sync_enabled(False)
    assert db.get_sync_enabled() is False
    db.set_sync_enabled(True)
    assert db.get_sync_enabled() is True

    # 5. Comments
    db.set_line_comment(func_ea, 0x221D, "entry check")
    db.set_line_comment(func_ea, "line_5", "loop starts here")
    assert db.get_line_comments(func_ea) == {"8733": "entry check", "line_5": "loop starts here"}
    db.set_line_comment(func_ea, 0x221D, "")
    assert db.get_line_comments(func_ea) == {"line_5": "loop starts here"}

    # 6. Clear
    db.clear_func_data(func_ea)
    assert db.get_func_data(func_ea) == {"renames": {}, "types": {}, "proto": None, "comments": {}}

    print("ok  test_db_in_memory_persistence")


def test_db_cgen_integration():
    func_ea = 0x3000
    db.clear_func_data(func_ea)

    f = cfg.Func(func_ea)
    b = cfg.Block(func_ea)
    b.term = "ret"
    b.stmts = [
        ir.Assign(func_ea, ir.Var("v0"), ir.Const(10)),
        ir.Ret(func_ea + 2, val=ir.Var("v0")),
    ]
    f.blocks[func_ea] = b

    fi = frame.FrameInfo(f)
    fi.virtual_vars["v0"] = (ir.Var("v0"), "w")

    # Set user customizations
    db.set_var_rename(func_ea, "v0", "counter")
    db.set_var_type(func_ea, "v0", "int16_t")
    db.set_func_proto(func_ea, "int16_t sub_3000(void)")

    db_data = db.get_func_data(func_ea)
    u_renames = db_data.get("renames", {})
    u_types = db_data.get("types", {})
    u_proto = db_data.get("proto")

    sig = abi.analyze_calling_convention(f, fi, user_proto=u_proto)
    tree = structure.structure(f)

    class DummyNamer:
        def code(self, ea): return f"sub_{ea:04X}"
        def label(self, ea): return f"loc_{ea:04X}"
        def cell(self, addr): return f"mem[{addr:X}]"

    db.set_line_comment(func_ea, func_ea, "initialize to 10")
    db_data = db.get_func_data(func_ea)
    u_comments = db_data.get("comments", {})

    lines, line_eas = cgen.generate(f, tree, DummyNamer(), frame_info=fi, sig=sig,
                                    user_renames=u_renames, user_types=u_types,
                                    user_comments=u_comments, with_ea=True)
    code = "\n".join(lines)

    assert "int16_t counter;" in code
    assert "counter = 0xA;  // initialize to 10" in code
    assert "return counter;" in code
    assert len(lines) == len(line_eas)
    # verify line_eas maps counter = 0xA to func_ea
    assign_line_idx = [i for i, ln in enumerate(lines) if "counter = 0xA" in ln][0]
    assert line_eas[assign_line_idx] == func_ea

    print("ok  test_db_cgen_integration")


if __name__ == "__main__":
    test_db_in_memory_persistence()
    test_db_cgen_integration()
    print("\nall db tests passed")
