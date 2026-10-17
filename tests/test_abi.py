"""
Tests for calling convention analysis, parameter inference, return type inference,
and call-site argument recovery.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rl78dec import abi, cfg, frame, ir


def test_param_inference_registers():
    # 1. 16-bit AX parameter
    f1 = cfg.Func(0x1000)
    b1 = cfg.Block(0x1000)
    b1.stmts = [
        ir.Assign(0x1000, ir.Reg("hl"), ir.Reg("ax")),
        ir.Ret(0x1002),
    ]
    f1.blocks[0x1000] = b1
    fi1 = frame.FrameInfo(f1)
    sig1 = abi.analyze_calling_convention(f1, fi1)
    assert len(sig1.params) == 1
    assert sig1.params[0].name == "a0" and sig1.params[0].type_str == "uint16_t"

    # 2. 8-bit A parameter
    f2 = cfg.Func(0x2000)
    b2 = cfg.Block(0x2000)
    b2.stmts = [
        ir.Assign(0x2000, ir.Reg("b"), ir.Reg("a")),
        ir.Ret(0x2002),
    ]
    f2.blocks[0x2000] = b2
    fi2 = frame.FrameInfo(f2)
    sig2 = abi.analyze_calling_convention(f2, fi2)
    assert len(sig2.params) == 1
    assert sig2.params[0].name == "a0" and sig2.params[0].type_str == "uint8_t"

    # 3. Two parameters: AX (16-bit) and BC (16-bit)
    f3 = cfg.Func(0x3000)
    b3 = cfg.Block(0x3000)
    b3.stmts = [
        ir.Assign(0x3000, ir.Reg("hl"), ir.Bin("+", ir.Reg("ax"), ir.Reg("bc"))),
        ir.Ret(0x3003),
    ]
    f3.blocks[0x3000] = b3
    fi3 = frame.FrameInfo(f3)
    sig3 = abi.analyze_calling_convention(f3, fi3)
    assert len(sig3.params) == 2
    assert sig3.params[0].name == "a0" and sig3.params[0].type_str == "uint16_t"
    assert sig3.params[1].name == "a1" and sig3.params[1].type_str == "uint16_t"

    # 4. Callee-saved register push should NOT be treated as incoming parameter
    f4 = cfg.Func(0x4000)
    b4 = cfg.Block(0x4000)
    push_hl = ir.Intrinsic(0x4000, "push", [ir.Reg("hl")])
    pop_hl = ir.Intrinsic(0x4002, "pop", [ir.Reg("hl")])
    b4.stmts = [
        push_hl,
        ir.Assign(0x4001, ir.Reg("a"), ir.Const(0)),
        pop_hl,
        ir.Ret(0x4003),
    ]
    f4.blocks[0x4000] = b4
    fi4 = frame.FrameInfo(f4)
    fi4.hidden_stmts.add(id(push_hl))
    fi4.hidden_stmts.add(id(pop_hl))
    sig4 = abi.analyze_calling_convention(f4, fi4)
    # HL is hidden/preserved; no parameters should be inferred
    assert len(sig4.params) == 0

    print("ok  test_param_inference_registers")


def test_param_inference_stack():
    f = cfg.Func(0x5000)
    b = cfg.Block(0x5000)
    b.stmts = [
        ir.Assign(0x5000, ir.Reg("hl"), ir.Reg("ax")),
        ir.Ret(0x5002),
    ]
    f.blocks[0x5000] = b
    fi = frame.FrameInfo(f)
    # Register stack argument arg_0
    v = ir.StackVar("arg_0", "w", 8, is_arg=True)
    fi.args["arg_0"] = (v, "w")

    sig = abi.analyze_calling_convention(f, fi)
    assert len(sig.params) == 2
    assert sig.params[0].name == "a0" and sig.params[0].type_str == "uint16_t"
    assert sig.params[1].name == "arg_0" and sig.params[1].type_str == "uint16_t"

    print("ok  test_param_inference_stack")


def test_return_inference():
    # 1. uint16_t return
    f1 = cfg.Func(0x6000)
    b1 = cfg.Block(0x6000)
    b1.stmts = [
        ir.Assign(0x6000, ir.Reg("ax"), ir.Const(0x55AA, "w")),
        ir.Ret(0x6003),
    ]
    f1.blocks[0x6000] = b1
    fi1 = frame.FrameInfo(f1)
    sig1 = abi.analyze_calling_convention(f1, fi1)
    assert sig1.ret_type == "uint16_t"
    assert isinstance(b1.stmts[-1].val, ir.Const) and b1.stmts[-1].val.value == 0x55AA

    # 2. uint8_t return
    f2 = cfg.Func(0x7000)
    b2 = cfg.Block(0x7000)
    b2.stmts = [
        ir.Assign(0x7000, ir.Reg("a"), ir.Const(1)),
        ir.Ret(0x7002),
    ]
    f2.blocks[0x7000] = b2
    fi2 = frame.FrameInfo(f2)
    sig2 = abi.analyze_calling_convention(f2, fi2)
    assert sig2.ret_type == "uint8_t"
    assert isinstance(b2.stmts[-1].val, ir.Const) and b2.stmts[-1].val.value == 1

    # 3. bool return via CY
    f3 = cfg.Func(0x8000)
    b3 = cfg.Block(0x8000)
    b3.stmts = [
        ir.Assign(0x8000, ir.Reg("cy"), ir.Const(1)),
        ir.Ret(0x8002),
    ]
    f3.blocks[0x8000] = b3
    fi3 = frame.FrameInfo(f3)
    sig3 = abi.analyze_calling_convention(f3, fi3)
    assert sig3.ret_type == "bool"
    assert isinstance(b3.stmts[-1].val, ir.Const) and b3.stmts[-1].val.value == 1

    # 4. Inconsistent return paths -> safe void fallback
    f4 = cfg.Func(0x9000)
    b4_1 = cfg.Block(0x9000)
    b4_1.stmts = [ir.Assign(0x9000, ir.Reg("ax"), ir.Const(42)), ir.Ret(0x9003)]
    b4_2 = cfg.Block(0x9010)
    b4_2.stmts = [ir.Ret(0x9011)]  # does not assign AX
    f4.blocks[0x9000] = b4_1
    f4.blocks[0x9010] = b4_2
    fi4 = frame.FrameInfo(f4)
    sig4 = abi.analyze_calling_convention(f4, fi4)
    assert sig4.ret_type == "void"
    assert b4_1.stmts[-1].val is None
    assert b4_2.stmts[-1].val is None

    print("ok  test_return_inference")


def test_call_site_recovery():
    f = cfg.Func(0xA000)
    b = cfg.Block(0xA000)

    # Setup arguments: ax = 0x12, bc = 0x34, call 0x2000, de = ax
    s_ax = ir.Assign(0xA000, ir.Reg("ax"), ir.Const(0x12))
    s_bc = ir.Assign(0xA002, ir.Reg("bc"), ir.Const(0x34))
    s_call = ir.Call(0xA004, target=0x2000)
    s_ret_assign = ir.Assign(0xA007, ir.Reg("de"), ir.Reg("ax"))
    s_ret = ir.Ret(0xA009)

    b.stmts = [s_ax, s_bc, s_call, s_ret_assign, s_ret]
    f.blocks[0xA000] = b
    fi = frame.FrameInfo(f)

    abi.analyze_calling_convention(f, fi)

    # Check that call captured arguments
    assert len(s_call.args) == 2
    assert isinstance(s_call.args[0], ir.Const) and s_call.args[0].value == 0x12
    assert isinstance(s_call.args[1], ir.Const) and s_call.args[1].value == 0x34

    # Check return assignment folded into call dst
    assert isinstance(s_call.dst, ir.Reg) and s_call.dst.name == "de"
    assert id(s_ret_assign) in fi.hidden_stmts

    print("ok  test_call_site_recovery")


def test_call_site_recovery_fallthrough_and_volatile():
    # 1. Call at end of block with fallthrough to 'a = c' (e.g. usevoltagetable)
    f1 = cfg.Func(0x3FB0)
    b1_0 = cfg.Block(0x3FB0)
    s_call1 = ir.Call(0x3FB0, target=0x36E8D)
    b1_0.stmts = [s_call1]
    b1_0.succ = [("fall", 0x3FB4)]

    b1_1 = cfg.Block(0x3FB4)
    s_assign1 = ir.Assign(0x3FB4, ir.Reg("a"), ir.Reg("c"))
    b1_1.stmts = [s_assign1, ir.Ret(0x3FB6)]
    f1.blocks[0x3FB0] = b1_0
    f1.blocks[0x3FB4] = b1_1
    fi1 = frame.FrameInfo(f1)

    abi.analyze_calling_convention(f1, fi1)
    # Return register C must be assigned as destination of call
    assert isinstance(s_call1.dst, ir.Reg) and s_call1.dst.name == "c"
    # Assignment 'a = c' must NOT be hidden since 'a' is a volatile register
    assert id(s_assign1) not in fi1.hidden_stmts

    # 2. Call followed by Compare on C (e.g. voltage_device_connected)
    f2 = cfg.Func(0x4000)
    b2_0 = cfg.Block(0x4000)
    s_call2 = ir.Call(0x4000, target=0x4BF5)
    b2_0.stmts = [s_call2]
    b2_0.succ = [("fall", 0x4004)]

    b2_1 = cfg.Block(0x4004)
    s_cmp2 = ir.Compare(0x4004, ir.FlagDef("cmp0", ir.Reg("c"), ir.Const(0)))
    b2_1.stmts = [s_cmp2, ir.Ret(0x4006)]
    f2.blocks[0x4000] = b2_0
    f2.blocks[0x4004] = b2_1
    fi2 = frame.FrameInfo(f2)

    abi.analyze_calling_convention(f2, fi2)
    assert isinstance(s_call2.dst, ir.Reg) and s_call2.dst.name == "c"
    assert id(s_cmp2) not in fi2.hidden_stmts

    # 3. Call with unused return value (all volatile registers clobbered before use)
    f3 = cfg.Func(0x5000)
    b3 = cfg.Block(0x5000)
    s_call3 = ir.Call(0x5000, target=0x6000)
    s_clrw_ax = ir.Assign(0x5004, ir.Reg("ax"), ir.Const(0))
    s_clrw_bc = ir.Assign(0x5006, ir.Reg("bc"), ir.Const(0))
    b3.stmts = [s_call3, s_clrw_ax, s_clrw_bc, ir.Ret(0x5008)]
    f3.blocks[0x5000] = b3
    fi3 = frame.FrameInfo(f3)

    abi.analyze_calling_convention(f3, fi3)
    assert s_call3.dst is None

    print("ok  test_call_site_recovery_fallthrough_and_volatile")


def test_homed_register_arguments_and_stack_offset():
    # Simulates:
    # 0x8224: push hl
    # 0x8225: push ax
    # 0x8226: movw hl, sp
    # 0x8229: movw ax, [hl]      <-- read homed a0
    # 0x822a: addw ax, [hl+8]    <-- read stack arg_0 (disp=8, arg_base = 0 + 4 + 4 = 8)
    # 0x8257: pop ax
    # 0x8258: pop hl
    # 0x8259: ret
    f = cfg.Func(0x8224)
    b = cfg.Block(0x8224)
    b.stmts = [
        ir.Intrinsic(0x8224, "push", [ir.Reg("hl")]),
        ir.Intrinsic(0x8225, "push", [ir.Reg("ax")]),
        ir.Assign(0x8226, ir.Reg("hl"), ir.Reg("sp")),
        ir.Assign(0x8229, ir.Reg("ax"), ir.Mem(ir.Reg("hl"), width="w")),
        ir.Assign(0x822A, ir.Reg("ax"), ir.Bin("+", ir.Reg("ax"), ir.Mem(ir.Bin("+", ir.Reg("hl"), ir.Const(8)), width="w"))),
        ir.Intrinsic(0x8257, "pop", [ir.Reg("ax")]),
        ir.Intrinsic(0x8258, "pop", [ir.Reg("hl")]),
        ir.Ret(0x8259),
    ]
    f.blocks[0x8224] = b

    fi = frame.analyze_frame(f)
    assert "ax" in fi.homed_args
    assert fi.homed_slot_to_arg.get(0) == "a0"
    assert fi.arg_base == 8

    # Statement 3 must have src resolved to StackVar a0
    assert isinstance(b.stmts[3].src, ir.StackVar)
    assert b.stmts[3].src.name == "a0"
    assert b.stmts[3].src.is_arg is True

    # Statement 4 must have [hl+8] resolved to StackVar arg_0
    add_r = b.stmts[4].src.r
    assert isinstance(add_r, ir.StackVar)
    assert add_r.name == "arg_0"
    assert add_r.is_arg is True

    sig = abi.analyze_calling_convention(f, fi)
    # Must have a0 in params, and arg_0 as stack parameter (no duplication of a0)
    assert len(sig.params) == 2
    assert sig.params[0].name == "a0" and sig.params[0].location == "ax"
    assert sig.params[1].name == "arg_0" and sig.params[1].location == "stack"
    print("ok  test_homed_register_arguments_and_stack_offset")


def test_caller_consensus_parameter_inference():
    f = cfg.Func(0x273D)
    b = cfg.Block(0x273D)
    b.stmts = [
        ir.Assign(0x273D, ir.Reg("c"), ir.Const(8)),
        ir.Ret(0x2740),
    ]
    f.blocks[0x273D] = b
    fi = frame.analyze_frame(f)
    consensus = {"has_ax": True}
    sig = abi.analyze_calling_convention(f, fi, caller_consensus=consensus)
    assert any(p.name == "a0" and p.location == "ax" for p in sig.params)
    print("ok  test_caller_consensus_parameter_inference")


def test_call_site_no_spurious_ax():
    # Simulates sub_35DD: caller without AX calling functions that don't take AX
    f = cfg.Func(0x35DD)
    b = cfg.Block(0x35DD)
    c1 = ir.Call(0x35DD, target=0x4B3B)
    c2 = ir.Call(0x35E1, target=0x8290)
    c3 = ir.Call(0x35E5, target=0x4D01)
    ret = ir.Ret(0x35E9)
    b.stmts = [c1, c2, c3, ret]
    f.blocks[0x35DD] = b
    fi = frame.analyze_frame(f)

    sig = abi.analyze_calling_convention(f, fi)
    assert len(sig.params) == 0
    assert len(c1.args) == 0
    assert len(c2.args) == 0
    assert len(c3.args) == 0
    print("ok  test_call_site_no_spurious_ax")


def test_dword_return_inference():
    # Test callee returning uint32_t in DE:BC (e.g. sub_4B76, sub_4BCE)
    f = cfg.Func(0x4B76)
    b = cfg.Block(0x4B76)
    b.stmts = [
        ir.Assign(0x4B88, ir.Reg("bc"), ir.Const(0xEAA4, width="w")),
        ir.Assign(0x4B8B, ir.Reg("e"), ir.Const(0x0F, width="b")),
        ir.Ret(0x4B8D),
    ]
    f.blocks[0x4B76] = b
    fi = frame.analyze_frame(f)
    sig = abi.analyze_calling_convention(f, fi)
    assert sig.ret_type == "uint32_t"
    assert isinstance(sig.ret_expr, ir.Const)
    assert sig.ret_expr.value == 0x0FEAA4
    assert sig.ret_expr.width in ("d", "dw")

    # Test callee returning 0 in DE:BC (e.g. sub_4BCE)
    f2 = cfg.Func(0x4BCE)
    b2 = cfg.Block(0x4BCE)
    b2.stmts = [
        ir.Assign(0x4BCE, ir.Reg("bc"), ir.Const(0, width="w")),
        ir.Assign(0x4BCF, ir.Reg("de"), ir.Const(0, width="w")),
        ir.Ret(0x4BD2),
    ]
    f2.blocks[0x4BCE] = b2
    fi2 = frame.analyze_frame(f2)
    sig2 = abi.analyze_calling_convention(f2, fi2)
    assert sig2.ret_type == "uint32_t"
    assert isinstance(sig2.ret_expr, ir.Const)
    assert sig2.ret_expr.value == 0
    print("ok  test_dword_return_inference")


def test_dword_call_site_recovery():
    # Test caller following a call with reads to E and BC (e.g. sub_35FB calling sub_A5EC)
    f = cfg.Func(0x35FB)
    b = cfg.Block(0x35FB)
    s_call = ir.Call(0x360B, target=0xA5EC)
    s_mov_e = ir.Assign(0x360F, ir.Reg("a"), ir.Reg("e"))
    s_save = ir.Assign(0x3610, ir.Mem(ir.Const(0xFFED5, width="a")), ir.Reg("a"))
    s_add_bc = ir.Assign(0x3613, ir.Reg("bc"), ir.Bin("+", ir.Reg("bc"), ir.Const(0x16)))
    s_ret = ir.Ret(0x3679)
    b.stmts = [s_call, s_mov_e, s_save, s_add_bc, s_ret]
    f.blocks[0x35FB] = b
    fi = frame.analyze_frame(f)

    abi.analyze_calling_convention(f, fi)
    assert isinstance(s_call.dst, ir.Reg)
    assert s_call.dst.name == "de:bc"
    assert s_call.dst.width == "d"
    print("ok  test_dword_call_site_recovery")


def test_far_pointer_param_consolidation():
    # Callee with far register pair (homed a0/a1) and far stack pair (address, segment)
    f = cfg.Func(0x48F6)
    b = cfg.Block(0x48F6)
    b.stmts = [
        ir.Assign(0x490D, ir.Reg("a"), ir.StackVar("segment", "b", 12, is_arg=True)),
        ir.Assign(0x490F, ir.Mem(ir.Const(0xFFED5, width="a")), ir.Reg("a")),
        ir.Assign(0x4911, ir.Reg("ax"), ir.StackVar("address", "w", 10, is_arg=True)),
        ir.Assign(0x4918, ir.Reg("es"), ir.Mem(ir.Const(0xFFED5, width="a"))),
        ir.Assign(0x491B, ir.Reg("a"), ir.Mem(ir.Reg("de"), width="b", es=True)),
        ir.Ret(0x4946),
    ]
    f.blocks[0x48F6] = b
    fi = frame.FrameInfo(f)
    fi.homed_args = ["ax", "bc"]
    fi.homed_slot_to_arg = {0: "a0", 2: "a1"}
    fi.args["a0"] = (ir.StackVar("a0", "w", 0, is_arg=True), "w")
    fi.args["a1"] = (ir.StackVar("a1", "b", 2, is_arg=True), "b")
    fi.args["address"] = (ir.StackVar("address", "w", 10, is_arg=True), "w")
    fi.args["segment"] = (ir.StackVar("segment", "b", 12, is_arg=True), "b")
    fi.args["msg_length"] = (ir.StackVar("msg_length", "b", 14, is_arg=True), "b")

    abi.register_callee_far_specs(0x48F6, has_far_reg=True, far_stack_indices={0})
    sig = abi.analyze_calling_convention(f, fi)
    assert len(sig.params) == 3
    assert sig.params[0].name == "a0" and sig.params[0].type_str == "uint32_t"
    assert sig.params[1].name == "address" and sig.params[1].type_str == "uint32_t"
    assert sig.params[2].name == "msg_length" and sig.params[2].type_str == "uint8_t"
    print("ok  test_far_pointer_param_consolidation")


def test_far_pointer_call_site_consolidation():
    # Caller calling trigget_TXD0_interrupt(0xDF22, 0xF, 0xDFA2, 0xF, 2)
    f = cfg.Func(0x468C)
    b = cfg.Block(0x468C)
    b.stmts = [
        ir.Intrinsic(0x46BD, "push", [ir.Const(2, width="w")]),
        ir.Assign(0x46C1, ir.Reg("c"), ir.Const(0x0F, width="b")),
        ir.Intrinsic(0x46C3, "push", [ir.Reg("bc")]),
        ir.Intrinsic(0x46C4, "push", [ir.Const(0xDFA2, width="w")]),
        ir.Assign(0x46C5, ir.Reg("ax"), ir.Const(0xDF22, width="w")),
        ir.Assign(0x46C8, ir.Reg("c"), ir.Const(0x0F, width="b")),
        ir.Assign(0x46CA, ir.Reg("b"), ir.Const(0, width="b")),
        ir.Call(0x46CB, target=0x48F6),
        ir.Assign(0x46CF, ir.Reg("sp"), ir.Bin("+", ir.Reg("sp"), ir.Const(6))),
        ir.Ret(0x46D5),
    ]
    f.blocks[0x468C] = b
    fi = frame.analyze_frame(f)

    abi.register_callee_far_specs(0x48F6, has_far_reg=True, far_stack_indices={0})
    abi.analyze_calling_convention(f, fi)

    s_call = b.stmts[7]
    assert isinstance(s_call, ir.Call)
    assert len(s_call.args) == 3
    assert isinstance(s_call.args[0], ir.Const) and s_call.args[0].value == 0xFDF22
    assert isinstance(s_call.args[1], ir.Const) and s_call.args[1].value == 0xFDFA2
    assert isinstance(s_call.args[2], ir.Const) and s_call.args[2].value == 2
    print("ok  test_far_pointer_call_site_consolidation")


if __name__ == "__main__":
    test_param_inference_registers()
    test_param_inference_stack()
    test_return_inference()
    test_call_site_recovery()
    test_call_site_recovery_fallthrough_and_volatile()
    test_homed_register_arguments_and_stack_offset()
    test_caller_consensus_parameter_inference()
    test_call_site_no_spurious_ax()
    test_dword_return_inference()
    test_dword_call_site_recovery()
    test_far_pointer_param_consolidation()
    test_far_pointer_call_site_consolidation()
    print("\nall abi tests passed")
