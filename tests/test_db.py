"""
Tests for IDA netnode persistence layer in rl78dec.db.
"""

import os
import sys
import types

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

    # 5. Window state persistence
    db.save_window_state(True, 0x221D, lineno=15, col=4)
    ws = db.load_window_state()
    assert ws.get("is_open") is True
    assert ws.get("func_ea") == 0x221D
    assert ws.get("lineno") == 15
    assert ws.get("col") == 4

    # 6. Clear
    db.clear_func_data(func_ea)
    assert db.get_func_data(func_ea) == {"renames": {}, "types": {}, "proto": None}

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

    lines = cgen.generate(f, tree, DummyNamer(), frame_info=fi, sig=sig,
                          user_renames=u_renames, user_types=u_types)
    code = "\n".join(lines)

    assert "int16_t counter;" in code
    assert "counter = 0xA;" in code
    assert "return counter;" in code

    print("ok  test_db_cgen_integration")


def test_decompiler_plugin_registration():
    # Stub IDA modules if not present
    for mod_name in ["ida_idaapi", "ida_idp", "ida_kernwin", "ida_funcs", "ida_lines"]:
        if mod_name not in sys.modules:
            m = types.ModuleType(mod_name)
            if mod_name == "ida_idaapi":
                m.plugin_t = object
                m.PLUGIN_PROC = 0x0008
                m.PLUGIN_KEEP = 2
                m.PLUGIN_SKIP = 0
                m.BADADDR = 0xFFFFFFFF
            elif mod_name == "ida_kernwin":
                m.action_handler_t = object
                m.action_desc_t = lambda *a, **kw: None
                m.register_action = lambda *a, **kw: True
                m.unregister_action = lambda *a, **kw: True
                m.attach_action_to_menu = lambda *a, **kw: True
                m.add_hotkey = lambda *a, **kw: None
                m.del_hotkey = lambda *a, **kw: None
                m.SETMENU_APP = 0
            elif mod_name == "ida_idp":
                m.get_idp_name = lambda: "rl78"
            sys.modules[mod_name] = m

    import rl78dec_plugin

    assert rl78dec_plugin.HOTKEY_DECOMPILE == "F5"
    assert rl78dec_plugin.ACTION_DECOMPILE == "rl78dec:decompile"

    plugin = rl78dec_plugin.PLUGIN_ENTRY()
    assert plugin.flags == sys.modules["ida_idaapi"].PLUGIN_PROC
    assert plugin.comment == "This is a decompilation plugin."
    assert plugin.wanted_hotkey == "F5"
    assert "F5" in plugin.help

    print("ok  test_decompiler_plugin_registration")


if __name__ == "__main__":
    test_db_in_memory_persistence()
    test_db_cgen_integration()
    test_decompiler_plugin_registration()
    print("\nall db tests passed")
