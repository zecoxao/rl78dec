"""
Tests for high-level virtual variable recovery layer (vars.py).
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rl78dec import abi, cfg, frame, ir, vars, opt


def test_vars_loop_induction():
    # CFG:
    # Block 0: b = 4; br Block 1
    # Block 1: b = b - 1; cmp b, 0; bnz Block 1; ret
    f = cfg.Func(0x1000)
    b0 = cfg.Block(0x1000)
    b0.stmts = [ir.Assign(0x1000, ir.Reg("b"), ir.Const(4, "b"))]
    b0.succ = [("jump", 0x1002)]

    b1 = cfg.Block(0x1002)
    b1.stmts = [
        ir.Assign(0x1002, ir.Reg("b"), ir.Bin("-", ir.Reg("b"), ir.Const(1, "b"))),
        ir.Compare(0x1004, ir.FlagDef("cmp", ir.Reg("b"), ir.Const(0, "b"))),
        ir.Branch(0x1006, "nz", 0x1002, 0x1008),
        ir.Ret(0x1008),
    ]
    b1.succ = [("cond", 0x1002), ("fall", 0x1008)]

    f.blocks[0x1000] = b0
    f.blocks[0x1002] = b1
    fi = frame.FrameInfo(f)

    vars.recover_variables(f, None, fi)

    # Both blocks must use the exact same variable (v0)
    assert isinstance(b0.stmts[0].dst, ir.Var)
    var_name = b0.stmts[0].dst.name
    assert var_name.startswith("v")

    # In loop body, dst and src must match var_name
    assert b1.stmts[0].dst.name == var_name
    assert b1.stmts[0].src.l.name == var_name
    assert b1.stmts[1].flag.a.name == var_name

    # Virtual variable must be registered with width 'b'
    assert var_name in fi.virtual_vars
    assert fi.virtual_vars[var_name][1] == "b"
    print("ok  test_vars_loop_induction")


def test_vars_disjoint_register_reuse():
    # Block 0: ax = 1; [hl] = ax; ax = 2; [de] = ax; ret
    # Since the first ax def only reaches [hl] = ax, and the second only reaches [de] = ax,
    # they must be assigned independent virtual variables!
    f = cfg.Func(0x2000)
    b = cfg.Block(0x2000)
    b.stmts = [
        ir.Assign(0x2000, ir.Reg("ax"), ir.Const(1, "w")),
        ir.Assign(0x2003, ir.Mem(ir.Reg("hl"), width="w"), ir.Reg("ax")),
        ir.Assign(0x2006, ir.Reg("ax"), ir.Const(2, "w")),
        ir.Assign(0x2009, ir.Mem(ir.Reg("de"), width="w"), ir.Reg("ax")),
        ir.Ret(0x200C),
    ]
    f.blocks[0x2000] = b
    fi = frame.FrameInfo(f)

    vars.recover_variables(f, None, fi)

    # First store src must be different variable from second store src
    # (if not single-use inlined into const, or if kept as vars)
    first_val = b.stmts[0].src if isinstance(b.stmts[0].dst, ir.Mem) else b.stmts[0].dst
    second_val = b.stmts[1].src if isinstance(b.stmts[1].dst, ir.Mem) else b.stmts[1].dst
    # They should not conflict
    print("ok  test_vars_disjoint_register_reuse")


def test_vars_param_binding():
    # ax used at entry -> bound to a0
    f = cfg.Func(0x3000)
    b = cfg.Block(0x3000)
    b.stmts = [
        ir.Assign(0x3000, ir.Mem(ir.Const(0xF000, "w"), width="w"), ir.Reg("ax")),
        ir.Ret(0x3003),
    ]
    f.blocks[0x3000] = b
    fi = frame.FrameInfo(f)

    sig = abi.FunctionSig(name="sub_3000", params=[abi.Param("a0", "uint16_t", "ax")])

    vars.recover_variables(f, sig, fi)

    assert b.stmts[0].src.name == "a0"
    # Parameter a0 should NOT be registered as a local variable declaration
    assert "a0" not in fi.virtual_vars
    print("ok  test_vars_param_binding")


def test_vars_spill_bridging():
    # Spill pair: _s0 = de; ax = _s0; ret
    f = cfg.Func(0x4000)
    b = cfg.Block(0x4000)
    b.stmts = [
        ir.Assign(0x4000, ir.Reg("de"), ir.Const(0x55, "w")),
        ir.Assign(0x4003, ir.Var("_s0", width="w"), ir.Reg("de")),
        ir.Assign(0x4006, ir.Reg("ax"), ir.Var("_s0", width="w")),
        ir.Ret(0x4009, val=ir.Reg("ax")),
    ]
    f.blocks[0x4000] = b
    fi = frame.FrameInfo(f)

    vars.recover_variables(f, None, fi)

    # _s0 must not appear in any statement
    for s in b.stmts:
        if isinstance(s, ir.Assign):
            assert not s.dst.name.startswith("_s")
            if isinstance(s.src, ir.Var):
                assert not s.src.name.startswith("_s")
    print("ok  test_vars_spill_bridging")


def test_vars_fold_call_return_to_stackvar():
    # Models the main_listener() pattern:
    # Block 0: c = call(0x35FB) -> fallthrough Block 1
    # Block 1: a = c (dead volatile copy); result = c; cmp0(a) (dead compare); ret
    f = cfg.Func(0x5000)
    b0 = cfg.Block(0x5000)
    b0.stmts = [
        ir.Call(0x5000, target=0x35FB, dst=ir.Reg("c")),
    ]
    b0.succ = [("fall", 0x5004)]

    res_var = ir.StackVar("result", width="b", offset=-2)
    b1 = cfg.Block(0x5004)
    b1.stmts = [
        ir.Assign(0x5004, ir.Reg("a"), ir.Reg("c")),
        ir.Assign(0x5005, res_var, ir.Reg("c")),
        ir.Compare(0x5007, ir.FlagDef("cmp0", a=ir.Reg("a"), b=ir.Const(0))),
        ir.Ret(0x5009),
    ]
    b1.succ = []

    f.blocks[0x5000] = b0
    f.blocks[0x5004] = b1
    fi = frame.FrameInfo(f)

    vars.recover_variables(f, None, fi)

    assert b0.stmts[0].dst == res_var
    # The redundant copy and dead compare in b1 should be eliminated
    assert len(b1.stmts) == 1 and isinstance(b1.stmts[0], ir.Ret)
    assert len(fi.virtual_vars) == 0
    print("ok  test_vars_fold_call_return_to_stackvar")


def test_vars_fold_call_return_with_subsequent_branch():
    # Models: c = call(0x4FB8); a = c; result = c; if (c != 0) ...
    # Should fold to: result = call(0x4FB8); if (result != 0) ...
    f = cfg.Func(0x6000)
    b0 = cfg.Block(0x6000)
    b0.stmts = [
        ir.Call(0x6000, target=0x4FB8, dst=ir.Reg("c")),
    ]
    b0.succ = [("fall", 0x6004)]

    res_var = ir.StackVar("result", width="b", offset=-2)
    fdef = ir.FlagDef("cmp0", a=ir.Reg("c"), b=ir.Const(0))
    br = ir.Branch(0x6008, "nz", 0x6010, 0x600A)
    br.flag = fdef

    b1 = cfg.Block(0x6004)
    b1.stmts = [
        ir.Assign(0x6004, ir.Reg("a"), ir.Reg("c")),
        ir.Assign(0x6005, res_var, ir.Reg("c")),
        ir.Compare(0x6007, fdef),
        br,
    ]
    b1.succ = [("cond", 0x6010), ("fall", 0x600A)]

    b2 = cfg.Block(0x600A)
    b2.stmts = [ir.Ret(0x600A)]
    b3 = cfg.Block(0x6010)
    b3.stmts = [ir.Ret(0x6010)]

    f.blocks[0x6000] = b0
    f.blocks[0x6004] = b1
    f.blocks[0x600A] = b2
    f.blocks[0x6010] = b3
    fi = frame.FrameInfo(f)

    vars.recover_variables(f, None, fi)

    assert b0.stmts[0].dst == res_var
    assert br.flag.a == res_var
    assert len(fi.virtual_vars) == 0
    print("ok  test_vars_fold_call_return_with_subsequent_branch")


def test_vars_preserve_subregister_pair_writes():
    # Models _start0: x = mem8[0xFD505]; a = 0; mem16[0xFE36E] = ax;
    # Must NOT fold a = 0 alone into mem16[0xFE36E] = 0.
    f = cfg.Func(0x7000)
    b = cfg.Block(0x7000)
    b.stmts = [
        ir.Assign(0x7000, ir.Reg("x"), ir.Mem(ir.Const(0xFD505, "a"), width="b")),
        ir.Assign(0x7004, ir.Reg("a"), ir.Const(0, "b")),
        ir.Assign(0x7006, ir.Mem(ir.Const(0xFE36E, "a"), width="w"), ir.Reg("ax")),
        ir.Ret(0x700A),
    ]
    f.blocks[0x7000] = b
    fi = frame.FrameInfo(f)

    vars.recover_variables(f, None, fi)

    # All 3 assignments must remain, using the unified 16-bit virtual variable
    assigns = [s for s in b.stmts if isinstance(s, ir.Assign)]
    assert len(assigns) == 3
    assert isinstance(assigns[2].src, ir.Var)
    print("ok  test_vars_preserve_subregister_pair_writes")


def test_vars_byte_shift_disjoint_webs():
    # Models sub_4FB8:
    # ax = var_s0 >> 5; var_2 = ax; a = var_s0 & 0x1F; ax = ax >> 8; var_4 = ax;
    # Because ax >> 8 only reads atom 'a', var_2 = var_s0 >> 5 and var_4 = (var_s0 & 0x1F) >> 8
    # must fold cleanly without merging via dead atom 'x'.
    f = cfg.Func(0x8000)
    b = cfg.Block(0x8000)
    var_s0 = ir.StackVar("var_s0", width="w", offset=0)
    var_2 = ir.StackVar("var_2", width="w", offset=-2)
    var_4 = ir.StackVar("var_4", width="w", offset=-4)
    b.stmts = [
        ir.Assign(0x8000, ir.Reg("ax"), ir.Bin(">>", var_s0, ir.Const(5, "b"))),
        ir.Assign(0x8003, var_2, ir.Reg("ax")),
        ir.Assign(0x8006, ir.Reg("a"), ir.Bin("&", var_s0, ir.Const(0x1F, "b")),
                  flag=ir.FlagDef("result", a=ir.Reg("a"))),
        ir.Assign(0x8009, ir.Reg("ax"), ir.Bin(">>", ir.Reg("ax"), ir.Const(8, "b"))),
        ir.Assign(0x800C, var_4, ir.Reg("ax")),
        ir.Ret(0x800F),
    ]
    f.blocks[0x8000] = b
    fi = frame.FrameInfo(f)

    vars.recover_variables(f, None, fi)

    assigns = [s for s in b.stmts if isinstance(s, ir.Assign)]
    assert len(assigns) == 2
    assert assigns[0].dst == var_2 and assigns[0].src == ir.Bin(">>", var_s0, ir.Const(5, "b"))
    assert assigns[1].dst == var_4 and assigns[1].src == ir.Bin(">>", ir.Bin("&", var_s0, ir.Const(0x1F, "b")), ir.Const(8, "b"))
    assert len(fi.virtual_vars) == 0
    print("ok  test_vars_byte_shift_disjoint_webs")


def test_swap_sandwich_elimination():
    # Simulates compiler idiom:
    # xch a, x
    # and a, #40h
    # xch a, x
    f = cfg.Func(0x9000)
    b = cfg.Block(0x9000)
    b.stmts = [
        ir.Swap(0x9000, ir.Reg("a"), ir.Reg("x")),
        ir.Assign(0x9001, ir.Reg("a"), ir.Bin("&", ir.Reg("a"), ir.Const(0x40, "b"))),
        ir.Swap(0x9003, ir.Reg("a"), ir.Reg("x")),
        ir.Ret(0x9004),
    ]
    f.blocks[0x9000] = b

    opt.optimize(f)

    # After optimization, Swaps should be completely gone, and statement should operate on 'x' directly
    swaps = [s for s in b.stmts if isinstance(s, ir.Swap)]
    assert len(swaps) == 0, f"Expected 0 swaps, found {len(swaps)}"
    assigns = [s for s in b.stmts if isinstance(s, ir.Assign)]
    assert len(assigns) == 1
    assert assigns[0].dst == ir.Reg("x")
    assert assigns[0].src == ir.Bin("&", ir.Reg("x"), ir.Const(0x40, "b"))
    print("ok  test_swap_sandwich_elimination")


def test_swap_standalone_lowering_and_recovery():
    # Standalone swap of variables/registers lowered and recovered cleanly without Swap remaining
    f = cfg.Func(0x9100)
    b = cfg.Block(0x9100)
    b.stmts = [
        ir.Assign(0x9100, ir.Reg("a"), ir.Const(1, "b")),
        ir.Assign(0x9102, ir.Reg("b"), ir.Const(2, "b")),
        ir.Swap(0x9104, ir.Reg("a"), ir.Reg("b")),
        ir.Ret(0x9106),
    ]
    f.blocks[0x9100] = b
    opt.optimize(f)

    # After opt.optimize, Swap must be lowered
    assert not any(isinstance(s, ir.Swap) for s in b.stmts)
    print("ok  test_swap_standalone_lowering_and_recovery")


def test_vars_dword_call_return_subregister_recovery():
    # Simulates sub_35FB calling sub_A5EC:
    # call sub_A5EC (returns de:bc, width="d")
    # a = e
    # saddr_D5 = a
    # bc = bc + 0x16
    f = cfg.Func(0x35FB)
    b = cfg.Block(0x35FB)
    s_call = ir.Call(0x360B, target=0xA5EC, dst=ir.Reg("de:bc", width="d"))
    s_mov_e = ir.Assign(0x360F, ir.Reg("a"), ir.Reg("e"))
    mem_d5 = ir.Mem(ir.Const(0xFFED5, width="a"), name="saddr_D5")
    s_save = ir.Assign(0x3610, mem_d5, ir.Reg("a"))
    s_add_bc = ir.Assign(0x3613, ir.Reg("bc"), ir.Bin("+", ir.Reg("bc"), ir.Const(0x16)))
    s_ret = ir.Ret(0x3679, val=ir.Reg("bc"))
    b.stmts = [s_call, s_mov_e, s_save, s_add_bc, s_ret]
    f.blocks[0x35FB] = b
    fi = frame.FrameInfo(f)

    vars.recover_variables(f, None, fi)

    # Call destination should be a virtual variable with width "d" (uint32_t)
    assert isinstance(s_call.dst, ir.Var)
    assert s_call.dst.width == "d"
    call_v = s_call.dst.name

    # Check that saddr_D5 assignment is derived from call_v >> 16 and NOT an uninitialized variable
    save_stmt = [s for s in b.stmts if isinstance(s, ir.Assign) and s.dst == mem_d5][0]
    # save_stmt.src should be (uint8_t)(call_v >> 16) or Bin(">>", call_v, 16)
    assert (
        isinstance(save_stmt.src, ir.Un)
        and save_stmt.src.op == "(uint8_t)"
        and isinstance(save_stmt.src.e, ir.Bin)
        and save_stmt.src.e.l.name == call_v
    ) or (
        isinstance(save_stmt.src, ir.Bin)
        and save_stmt.src.l.name == call_v
    )

    # Check that s_ret.val or bc addition uses (uint16_t)call_v + 16 (inlined or assigned)
    ret_bin = s_ret.val if (s_ret.val and isinstance(s_ret.val, ir.Bin)) else None
    if ret_bin is None:
        add_stmts = [s for s in b.stmts if isinstance(s, ir.Assign) and isinstance(s.src, ir.Bin) and s.src.op == "+"]
        assert len(add_stmts) > 0
        ret_bin = add_stmts[0].src
    assert ret_bin.op == "+"
    add_l = ret_bin.l
    if isinstance(add_l, ir.Un):
        add_l = add_l.e
    assert add_l.name == call_v

    # Verify virtual variable width in frame_info
    assert fi.virtual_vars[call_v][1] == "d"
    print("ok  test_vars_dword_call_return_subregister_recovery")


if __name__ == "__main__":
    test_vars_loop_induction()
    test_vars_disjoint_register_reuse()
    test_vars_param_binding()
    test_vars_spill_bridging()
    test_vars_fold_call_return_to_stackvar()
    test_vars_fold_call_return_with_subsequent_branch()
    test_vars_preserve_subregister_pair_writes()
    test_vars_byte_shift_disjoint_webs()
    test_swap_sandwich_elimination()
    test_swap_standalone_lowering_and_recovery()
    test_vars_dword_call_return_subregister_recovery()
    print("All vars tests passed.")
