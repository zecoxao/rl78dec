"""
Lift decoded RL78 :class:`~rl78dec.decoder.Insn` objects into IR statements.

Semantics follow astrelsky's Ghidra SLEIGH (``RL78_sleigh``).  The common
data-movement, arithmetic, logic, compare, bit and control-flow instructions are
modelled precisely; rotates, string ops, stack and CPU-control instructions that
do not map cleanly onto C are emitted honestly as pseudo-calls.
"""

from . import ir


def op_expr(op):
    """Convert a decoder Operand into an IR expression."""
    m = op.mode
    if m == "reg":
        return ir.Reg(op.reg)
    if m == "imm":
        return ir.Const(op.value, op.width)
    if m == "mem":
        return ir.Mem(op.addr, op.width, op.es)
    if m == "ind":
        base = ir.Reg(op.base_reg)
        addr = base if op.disp == 0 else ir.Bin("+", base, ir.Const(op.disp, "b"))
        return ir.Mem(addr, op.width, op.es)
    if m == "idx16":
        addr = ir.Bin("+", ir.Const(op.disp, "a"), ir.Reg(op.base_reg))
        return ir.Mem(addr, op.width, op.es)
    if m == "hloff":
        return ir.Mem(ir.Bin("+", ir.Reg("hl"), ir.Reg(op.base_reg)), "b", op.es)
    if m == "bit":
        if op.base == "reg":
            base = ir.Reg(op.reg)
        elif op.base == "ind":
            base = ir.Mem(ir.Reg(op.base_reg), "b", op.es)
        else:
            base = ir.Mem(op.addr, "b", op.es)
        return ir.Bit(base, op.bit)
    if m in ("near", "far", "callt"):
        return ir.Const(op.addr, "a")
    return ir.Const(0)


_ALU = {"add": "+", "addc": "+", "sub": "-", "subc": "-",
        "and": "&", "or": "|", "xor": "^",
        "addw": "+", "subw": "-"}
_COND = {"bc": "cy", "bnc": "ncy", "bz": "z", "bnz": "nz", "bh": "h", "bnh": "nh"}


def _w(op):
    return "w" if op.width == "w" else "b"


def lift_insn(ins):
    ea = ins.ea
    m = ins.mnem
    ops = ins.ops

    def e(i):
        return op_expr(ops[i])

    # --- data movement -----------------------------------------------------
    if m in ("mov", "movw"):
        return [ir.Assign(ea, e(0), e(1))]
    if m in ("oneb", "onew"):
        return [ir.Assign(ea, e(0), ir.Const(1, _w(ops[0])))]
    if m in ("clrb", "clrw"):
        return [ir.Assign(ea, e(0), ir.Const(0, _w(ops[0])))]
    if m in ("xch", "xchw"):
        return [ir.Intrinsic(ea, "xch", [e(0), e(1)])]
    if m == "movs":
        return [ir.Intrinsic(ea, "movs", [e(0), e(1)], note="[hl+]=x, decw c")]

    # --- arithmetic / logic ------------------------------------------------
    if m in _ALU:
        dst, src = e(0), e(1)
        if m in ("sub", "subc", "subw"):
            flag = ir.FlagDef("sub", a=dst, b=src)
        else:
            flag = ir.FlagDef("result", a=dst)
        return [ir.Assign(ea, dst, ir.Bin(_ALU[m], dst, src), flag=flag)]
    if m in ("cmp", "cmpw", "cmps"):
        return [ir.Compare(ea, ir.FlagDef("cmp", a=e(0), b=e(1)))]
    if m == "cmp0":
        return [ir.Compare(ea, ir.FlagDef("cmp", a=e(0), b=ir.Const(0)))]
    if m in ("inc", "incw"):
        dst = e(0)
        return [ir.Assign(ea, dst, ir.Bin("+", dst, ir.Const(1, dst.width if isinstance(dst, ir.Reg) else "b")),
                          flag=ir.FlagDef("result", a=dst))]
    if m in ("dec", "decw"):
        dst = e(0)
        return [ir.Assign(ea, dst, ir.Bin("-", dst, ir.Const(1, dst.width if isinstance(dst, ir.Reg) else "b")),
                          flag=ir.FlagDef("result", a=dst))]
    if m == "mulu":
        return [ir.Assign(ea, ir.Reg("ax"), ir.IntrExpr("mulu", [ir.Reg("a"), ir.Reg("x")]))]

    # --- shifts / rotates --------------------------------------------------
    if m in ("shl", "shlw"):
        return [ir.Assign(ea, e(0), ir.Bin("<<", e(0), e(1)), flag=ir.FlagDef("result", a=e(0)))]
    if m in ("shr", "shrw"):
        return [ir.Assign(ea, e(0), ir.Bin(">>", e(0), e(1)), flag=ir.FlagDef("result", a=e(0)))]
    if m in ("sar", "sarw"):
        return [ir.Assign(ea, e(0), ir.IntrExpr("sar", [e(0), e(1)]), flag=ir.FlagDef("result", a=e(0)))]
    if m in ("ror", "rol", "rorc", "rolc", "rolwc"):
        return [ir.Assign(ea, e(0), ir.IntrExpr(m, [e(0)]))]

    # --- bit ---------------------------------------------------------------
    if m in ("set1", "clr1", "not1"):
        tgt = e(0)
        if isinstance(tgt, ir.Reg) and tgt.name == "cy":
            if m == "set1":
                return [ir.Assign(ea, tgt, ir.Const(1))]
            if m == "clr1":
                return [ir.Assign(ea, tgt, ir.Const(0))]
            return [ir.Assign(ea, tgt, ir.Un("!", tgt))]
        base, mask = tgt.base, 1 << tgt.bit          # tgt is a Bit
        op = {"set1": "|", "clr1": "&", "not1": "^"}[m]
        rhs = ir.Const((~mask) & 0xFF) if m == "clr1" else ir.Const(mask)
        return [ir.Assign(ea, base, ir.Bin(op, base, rhs))]
    if m in ("mov1", "and1", "or1", "xor1"):
        dst, src = e(0), e(1)
        if isinstance(dst, ir.Reg) and dst.name == "cy":
            rhs = src if m == "mov1" else ir.Bin({"and1": "&", "or1": "|", "xor1": "^"}[m], dst, src)
            return [ir.Assign(ea, dst, rhs)]
        # mov1 bit, cy : deposit CY into one bit
        return [ir.Intrinsic(ea, "set_bit", [dst.base, ir.Const(dst.bit), src])]

    # --- control flow ------------------------------------------------------
    if m == "br":
        tgt = ops[0]
        if tgt.mode in ("near", "far"):
            return [ir.Goto(ea, tgt.addr)]
        return [ir.Intrinsic(ea, "goto", [e(0)], note="indirect")]
    if m in _COND:
        from .decoder import target_of
        return [ir.Branch(ea, _COND[m], target_of(ins), ea + ins.size)]
    if m in ("bt", "bf", "btclr"):
        from .decoder import target_of
        sense = (m != "bf")
        br = ir.Branch(ea, None, target_of(ins), ea + ins.size, bittest=(op_expr(ops[0]), sense))
        out = [br]
        if m == "btclr":
            b = op_expr(ops[0])
            out.append(ir.Intrinsic(ea, "clr_bit", [b], note="on taken path"))
        return out
    if m == "call":
        tgt = ops[0]
        if tgt.mode in ("near", "far"):
            return [ir.Call(ea, target=tgt.addr)]
        return [ir.Call(ea, expr=e(0))]
    if m == "callt":
        return [ir.Call(ea, expr=ir.Mem(ops[0].addr, "w"))]
    if m in ("ret", "reti", "retb"):
        return [ir.Ret(ea, m)]

    # --- stack / cpu control ----------------------------------------------
    if m in ("push", "pop"):
        return [ir.Intrinsic(ea, m, [e(0)])]
    if m == "sel":
        return [ir.Intrinsic(ea, "sel", [e(0)])]
    if m in ("ei", "di", "halt", "stop", "brk", "brk1", "nop"):
        if m == "nop":
            return [ir.Nop(ea)]
        return [ir.Intrinsic(ea, m, [])]

    return [ir.Intrinsic(ea, m, [e(i) for i in range(len(ops))], note="unmodelled")]
