"""
Calling convention analysis and call-site recovery for RL78.

RL78 calling conventions (Renesas CA78K0R and CC-RL):
1. First argument passed in AX (16-bit) or A (8-bit).
2. Second argument passed in BC (16-bit) or C (8-bit).
3. Additional arguments passed on stack (pushed by caller, cleaned up with addw sp, #N).
4. Return values returned in AX or BC (16-bit), A or C (8-bit), or CY (1-bit).
5. Volatile registers: AX, BC, PSW (clobbered across calls).
6. Non-volatile (callee-saved) registers: HL, DE, BC (when preserved).

This module:
1. Reconstructs function signatures (parameters and return type).
2. Identifies live-in argument registers and stack parameters.
3. Recovers call-site arguments and return value assignments.
"""

from . import ir, regs, spill


class Param:
    __slots__ = ("name", "type_str", "location")

    def __init__(self, name, type_str="uint16_t", location="ax"):
        self.name = name
        self.type_str = type_str
        self.location = location

    def __repr__(self):
        return f"{self.type_str} {self.name}"


class FunctionSig:
    def __init__(self, name=None, ret_type="void", ret_expr=None, params=None):
        self.name = name
        self.ret_type = ret_type
        self.ret_expr = ret_expr
        self.params = list(params) if params else []

    def format_signature(self, func_name=None):
        name = func_name or self.name or "sub_unknown"
        if self.params:
            pstr = ", ".join(f"{p.type_str} {p.name}" for p in self.params)
        else:
            pstr = "void"
        return f"{self.ret_type} {name}({pstr})"


_callee_preserves_cache = {}


def get_callee_preserved_regs(callee_target):
    """Return set of registers preserved across calls to callee_target using structured IDA instruction decoding."""
    if not isinstance(callee_target, int):
        return set()
    if callee_target in _callee_preserves_cache:
        return _callee_preserves_cache[callee_target]
    res = set()
    try:
        import ida_funcs, ida_ua, ida_idp, idautils, ida_bytes, ida_idaapi
        pfn = ida_funcs.get_func(callee_target)
        if pfn:
            insn = ida_ua.insn_t()
            cur = pfn.start_ea
            pushed_at_entry = []
            for _ in range(4):
                if cur >= pfn.end_ea:
                    break
                if ida_ua.decode_insn(insn, cur) == 0:
                    break
                mnem = insn.get_canon_mnem().upper()
                if mnem == "PUSH" and insn.ops[0].type == ida_ua.o_reg:
                    rname = ida_idp.get_reg_name(insn.ops[0].reg, insn.ops[0].dtype).lower()
                    if rname in ("ax", "bc", "de", "hl"):
                        pushed_at_entry.append(rname)
                else:
                    break
                cur += insn.size

            prev_insn = ida_ua.insn_t()
            for r in set(pushed_at_entry):
                all_rets_have_pop = True
                ret_count = 0
                for ea in idautils.Heads(pfn.start_ea, pfn.end_ea):
                    if ida_ua.decode_insn(insn, ea) == 0:
                        continue
                    mnem = insn.get_canon_mnem().upper()
                    if mnem == "RET":
                        ret_count += 1
                        has_pop = False
                        prev_ea = ea
                        for _ in range(2):
                            prev_ea = ida_bytes.prev_head(prev_ea, pfn.start_ea)
                            if prev_ea == ida_idaapi.BADADDR:
                                break
                            if ida_ua.decode_insn(prev_insn, prev_ea) != 0:
                                if prev_insn.get_canon_mnem().upper() == "POP" and prev_insn.ops[0].type == ida_ua.o_reg:
                                    pop_rname = ida_idp.get_reg_name(prev_insn.ops[0].reg, prev_insn.ops[0].dtype).lower()
                                    if pop_rname == r:
                                        has_pop = True
                                        break
                        if not has_pop:
                            all_rets_have_pop = False
                            break
                if ret_count > 0 and all_rets_have_pop:
                    res.add(r)
    except Exception:
        pass
    _callee_preserves_cache[callee_target] = res
    return res


def callee_expects_ax(callee_target):
    """Return True if callee function at callee_target reads AX before defining it using structured IDA instruction decoding."""
    if not isinstance(callee_target, int):
        return None
    try:
        import ida_funcs, ida_ua, ida_idp
        pfn = ida_funcs.get_func(callee_target)
        if not pfn:
            return None
        cur = pfn.start_ea
        insn = ida_ua.insn_t()
        while cur < pfn.end_ea:
            if ida_ua.decode_insn(insn, cur) == 0:
                break
            mnem = insn.get_canon_mnem().upper()

            def is_reg(op_idx, *names):
                op = insn.ops[op_idx]
                if op.type != ida_ua.o_reg:
                    return False
                rname = ida_idp.get_reg_name(op.reg, op.dtype).upper()
                return rname in names

            if mnem in ("PUSH", "POP"):
                pass
            elif mnem in ("CLRW", "ONEW"):
                if is_reg(0, "AX"):
                    return False
            elif mnem in ("CLRB", "ONEB"):
                if is_reg(0, "A", "X"):
                    return False
            elif mnem == "MOVW":
                if is_reg(1, "AX"):
                    return True
                if is_reg(0, "AX"):
                    return False
            elif mnem == "MOV":
                if is_reg(1, "A", "X") and not is_reg(0, "A", "X"):
                    return True
                if is_reg(0, "A", "X"):
                    return False
            elif mnem in ("CMPW", "CMP"):
                if is_reg(0, "AX", "A", "X") or is_reg(1, "AX", "A", "X"):
                    return True
            elif mnem in ("ADDW", "SUBW", "ANDW", "ORW", "XORW", "SHRW", "SHLW"):
                if is_reg(0, "AX"):
                    return True
            elif mnem in ("ADD", "SUB", "AND", "OR", "XOR", "SHR", "SHL", "ROR", "ROL"):
                if is_reg(0, "A", "X"):
                    return True
            elif mnem in ("XCHW", "XCH"):
                if is_reg(0, "AX", "A", "X") or is_reg(1, "AX", "A", "X"):
                    return True
            elif mnem in ("CALL", "RET", "RETI", "BR"):
                break

            cur += insn.size
    except Exception:
        return None
    return False


_callee_returns_dword_cache = {}


def callee_returns_dword(callee_target):
    """Return True if callee at callee_target returns a 32-bit value in DE:BC using structured IDA decoding."""
    if not isinstance(callee_target, int):
        return False
    if callee_target in _callee_returns_dword_cache:
        return _callee_returns_dword_cache[callee_target]
    res = False
    try:
        import ida_funcs, ida_ua, ida_idp, ida_bytes, ida_idaapi, idautils
        pfn = ida_funcs.get_func(callee_target)
        if pfn:
            insn = ida_ua.insn_t()
            for ea in idautils.Heads(pfn.start_ea, pfn.end_ea):
                if ida_ua.decode_insn(insn, ea) == 0:
                    continue
                if insn.get_canon_mnem().upper() == "RET":
                    has_bc = False
                    has_de = False
                    prev_ea = ea
                    for _ in range(4):
                        prev_ea = ida_bytes.prev_head(prev_ea, pfn.start_ea)
                        if prev_ea == ida_idaapi.BADADDR:
                            break
                        if ida_ua.decode_insn(insn, prev_ea) != 0:
                            mnem = insn.get_canon_mnem().upper()
                            if mnem in ("MOVW", "XCHW", "CLRW", "ONEW", "MOV"):
                                for op_idx in range(2):
                                    op = insn.ops[op_idx]
                                    if op.type == ida_ua.o_reg:
                                        rname = ida_idp.get_reg_name(op.reg, op.dtype).upper()
                                        if rname in ("BC", "C", "B"):
                                            has_bc = True
                                        if rname in ("DE", "E", "D"):
                                            has_de = True
                            elif mnem in ("CALL", "RET", "RETI", "BR"):
                                break
                    if has_bc and has_de:
                        res = True
                        break
    except Exception:
        pass
    _callee_returns_dword_cache[callee_target] = res
    return res


_callee_far_specs_cache = {}


def get_callee_far_param_specs(callee_target):
    """Return far pointer parameter specifications for callee_target using structured IDA frame analysis."""
    if not isinstance(callee_target, int):
        return _callee_far_specs_cache.get(callee_target)
    if callee_target in _callee_far_specs_cache:
        return _callee_far_specs_cache[callee_target]

    res = {"has_far_reg": False, "far_stack_indices": set()}
    try:
        import ida_funcs, ida_typeinf, ida_frame
        pfn = ida_funcs.get_func(callee_target)
        if pfn:
            tif = ida_typeinf.tinfo_t()
            if ida_frame.get_func_frame(tif, pfn):
                udt = ida_typeinf.udt_type_data_t()
                if tif.get_udt_details(udt):
                    m_list = list(udt)
                    m_by_off = {m.offset // 8: m for m in m_list}
                    # 1. Check homed reg args at offset 0 and 2
                    if 0 in m_by_off and 2 in m_by_off:
                        n0 = m_by_off[0].name.lower()
                        n2 = m_by_off[2].name.lower()
                        if ("addr" in n0 or "address" in n0) and ("seg" in n2 or "segment" in n2):
                            res["has_far_reg"] = True
                        elif n2 in ("segment", "seg", "resp_segment"):
                            res["has_far_reg"] = True

                    # 2. Check stack args
                    off_args = ida_frame.frame_off_args(pfn)
                    if off_args != 0xFFFFFFFFFFFFFFFF and off_args != 0xFFFFFFFF:
                        stack_m = [m for m in m_list if (m.offset // 8) >= off_args]
                        s_idx = 0
                        j = 0
                        while j < len(stack_m) - 1:
                            sm1 = stack_m[j]
                            sm2 = stack_m[j + 1]
                            sn1 = sm1.name.lower()
                            sn2 = sm2.name.lower()
                            is_seg = False
                            if sn2 in ("segment", "seg", "resp_segment"):
                                is_seg = True
                            elif sn2 == sn1 + "_seg" or sn2 == sn1 + "_segment":
                                is_seg = True
                            elif ("addr" in sn1 or "address" in sn1 or "table" in sn1) and ("seg" in sn2 or "segment" in sn2):
                                is_seg = True

                            if is_seg:
                                res["far_stack_indices"].add(s_idx)
                                j += 2
                            else:
                                j += 1
                            s_idx += 1
    except Exception:
        pass

    if res["has_far_reg"] or res["far_stack_indices"]:
        _callee_far_specs_cache[callee_target] = res
        return res
    _callee_far_specs_cache[callee_target] = None
    return None


def register_callee_far_specs(target, has_far_reg=False, far_stack_indices=None):
    """Manually register far pointer specs for target (used for testing or explicit overrides)."""
    _callee_far_specs_cache[target] = {
        "has_far_reg": has_far_reg,
        "far_stack_indices": set(far_stack_indices or [])
    }


def _consolidate_pair(a_off, a_seg):
    """Combine a 16-bit offset and segment into a single 32-bit / 20-bit address expression."""
    off_val = a_off.value if isinstance(a_off, ir.Const) else None
    seg_val = a_seg.value if isinstance(a_seg, ir.Const) else None
    if off_val is not None and seg_val is not None:
        linear = ((seg_val & 0xFF) << 16) | (off_val & 0xFFFF)
        return ir.Const(linear, width="d")
    if seg_val is not None:
        if seg_val == 0:
            return a_off
        return ir.Bin("|", ir.Const((seg_val & 0xFF) << 16, width="d"), a_off)
    return ir.Bin("|", ir.Bin("<<", a_seg, ir.Const(16, width="b")), a_off)


def _compute_liveness(func, hidden_stmts):
    """Compute entry live-in atoms via standard backwards dataflow analysis."""
    block_gen = {}
    block_kill = {}

    for b in func.blocks.values():
        gen = set()
        kill = set()

        for s in b.stmts:
            if id(s) in hidden_stmts:
                continue

            used = set()

            def collect_uses(e):
                if isinstance(e, ir.Reg):
                    used.add(e.name)
                elif isinstance(e, ir.Bin):
                    collect_uses(e.l)
                    collect_uses(e.r)
                elif isinstance(e, ir.Un):
                    collect_uses(e.e)
                elif isinstance(e, ir.IntrExpr):
                    for a in e.args:
                        collect_uses(a)

            if isinstance(s, ir.Assign):
                collect_uses(s.src)
                if not isinstance(s.dst, ir.Reg):
                    collect_uses(s.dst)
            elif isinstance(s, ir.Compare):
                if s.flag:
                    if s.flag.a is not None:
                        collect_uses(s.flag.a)
                    if s.flag.b is not None:
                        collect_uses(s.flag.b)
            elif isinstance(s, ir.Swap):
                collect_uses(s.a)
                collect_uses(s.b)
            elif isinstance(s, ir.Call):
                # A call clobbers volatile registers AX and BC unless preserved by callee
                preserved = get_callee_preserved_regs(s.target)
                killed_regs = []
                if "ax" not in preserved:
                    killed_regs.extend(regs.atoms("ax"))
                if "bc" not in preserved:
                    killed_regs.extend(regs.atoms("bc"))
                for a in killed_regs:
                    kill.add(a)
            elif isinstance(s, ir.Intrinsic):
                if s.name != "pop":
                    for a in s.args:
                        collect_uses(a)

            # Uses not killed earlier in this block are upward exposed (gen)
            for u in used:
                for a in regs.atoms(u):
                    if a not in kill:
                        gen.add(a)

            # Defs in this block
            if isinstance(s, ir.Assign) and isinstance(s.dst, ir.Reg):
                for a in regs.atoms(s.dst.name):
                    kill.add(a)
            elif isinstance(s, ir.Intrinsic) and s.name == "pop":
                if s.args and isinstance(s.args[0], ir.Reg):
                    for a in regs.atoms(s.args[0].name):
                        kill.add(a)

        block_gen[b.start] = gen
        block_kill[b.start] = kill

    live_in = {b: set() for b in func.blocks}
    live_out = {b: set() for b in func.blocks}

    changed = True
    while changed:
        changed = False
        for b in reversed(func.ordered()):
            out = set()
            for _, succ_ea in b.succ:
                if succ_ea in live_in:
                    out.update(live_in[succ_ea])
            live_out[b.start] = out
            new_in = block_gen[b.start] | (out - block_kill[b.start])
            if new_in != live_in[b.start]:
                live_in[b.start] = new_in
                changed = True

    return live_in.get(func.entry, set())


def _infer_return(func, hidden_stmts):
    """Determine the function return type and return expression from exit blocks.

    A function has a non-void return type if and only if EVERY exit block consistently
    assigns the candidate return register (AX, BC, A, or C) as its last non-boilerplate
    statement before returning.
    """
    ret_expr = None
    ret_type = "void"

    exit_ret_info = []
    ret_block_count = 0

    for b in func.blocks.values():
        if b.stmts and isinstance(b.stmts[-1], ir.Ret):
            ret_block_count += 1
            cand_expr = None
            cand_type = "void"
            cand_reg = None

            assigned = {}
            for s in reversed(b.stmts[:-1]):
                if id(s) in hidden_stmts:
                    continue
                if isinstance(s, ir.Assign) and isinstance(s.dst, ir.Reg):
                    dname = s.dst.name
                    if dname not in assigned:
                        assigned[dname] = s.src
                elif isinstance(s, ir.Swap):
                    for r in (s.a, s.b):
                        if isinstance(r, ir.Reg) and r.name not in assigned:
                            assigned[r.name] = r
                elif isinstance(s, (ir.Call, ir.Branch, ir.Goto)):
                    break

            has_bc = "bc" in assigned or "c" in assigned
            has_de = "de" in assigned or "e" in assigned
            has_ax = "ax" in assigned or "a" in assigned
            has_cy = "cy" in assigned

            if has_bc and has_de:
                cand_type = "uint32_t"
                cand_reg = "de:bc"
                de_src = assigned.get("de", assigned.get("e"))
                bc_src = assigned.get("bc", assigned.get("c"))
                if isinstance(de_src, ir.Const) and isinstance(bc_src, ir.Const):
                    cand_expr = ir.Const(((de_src.value << 16) | bc_src.value) & 0xFFFFFFFF, width="d")
                else:
                    cand_expr = ir.Reg("de:bc", width="d")
            elif "bc" in assigned:
                cand_type = "uint16_t"
                cand_reg = "bc"
                cand_expr = assigned["bc"] if isinstance(assigned["bc"], ir.Const) else ir.Reg("bc")
            elif "ax" in assigned:
                cand_type = "uint16_t"
                cand_reg = "ax"
                cand_expr = assigned["ax"] if isinstance(assigned["ax"], ir.Const) else ir.Reg("ax")
            elif "de" in assigned:
                cand_type = "uint16_t"
                cand_reg = "de"
                cand_expr = assigned["de"] if isinstance(assigned["de"], ir.Const) else ir.Reg("de")
            elif "c" in assigned:
                cand_type = "uint8_t"
                cand_reg = "c"
                cand_expr = assigned["c"] if isinstance(assigned["c"], ir.Const) else ir.Reg("c")
            elif "a" in assigned:
                cand_type = "uint8_t"
                cand_reg = "a"
                cand_expr = assigned["a"] if isinstance(assigned["a"], ir.Const) else ir.Reg("a")
            elif "e" in assigned:
                cand_type = "uint8_t"
                cand_reg = "e"
                cand_expr = assigned["e"] if isinstance(assigned["e"], ir.Const) else ir.Reg("e")
            elif has_cy:
                cand_type = "bool"
                cand_reg = "cy"
                cand_expr = assigned["cy"] if isinstance(assigned["cy"], ir.Const) else ir.Reg("cy")

            if cand_type != "void":
                exit_ret_info.append((b, cand_type, cand_expr, cand_reg))

    # All exit blocks must agree on the return register
    if ret_block_count > 0 and len(exit_ret_info) == ret_block_count:
        first_type = exit_ret_info[0][1]
        first_reg = exit_ret_info[0][3]
        if all(info[1] == first_type and info[3] == first_reg for info in exit_ret_info):
            ret_type = first_type
            # Set each return block's Ret statement value to its specific return expression
            for b, ctype, cexpr, creg in exit_ret_info:
                if b.stmts and isinstance(b.stmts[-1], ir.Ret):
                    b.stmts[-1].val = cexpr
            ret_expr = exit_ret_info[0][2]

    # If void, make sure all Ret statements have val = None
    if ret_type == "void":
        for b in func.blocks.values():
            for s in b.stmts:
                if isinstance(s, ir.Ret):
                    s.val = None

    return ret_type, ret_expr



CALL_RETURN_ATOMS = {"x", "a", "c", "b", "e", "d"}
SCRATCH_ATOMS = {"x", "a", "c", "b"}
VOLATILE_ATOMS = {"x", "a", "c", "b", "e", "d"}


def _find_following_stmts(func, b, i, hidden_stmts):
    """Collect non-hidden statements following stmt i in block b, traversing fallthroughs."""
    res = []
    # 1. Remaining stmts in block b
    for s in b.stmts[i + 1:]:
        if id(s) not in hidden_stmts:
            res.append(s)
    # 2. Traverse fallthrough successors
    cur_b = b
    visited = {b.start}
    while len(cur_b.succ) == 1 and cur_b.succ[0][0] == "fall":
        succ_ea = cur_b.succ[0][1]
        if succ_ea in visited:
            break
        visited.add(succ_ea)
        cur_b = func.blocks.get(succ_ea)
        if not cur_b:
            break
        for s in cur_b.stmts:
            if id(s) not in hidden_stmts:
                res.append(s)
        if len(res) >= 10:
            break
    return res


def _infer_call_return(func, b, i, frame_info):
    """Determine the return register and whether the return assignment can be folded."""
    s_call = b.stmts[i]
    if getattr(s_call, "target", None) and callee_returns_dword(s_call.target):
        return ir.Reg("de:bc", width="d"), None

    stmts_after = _find_following_stmts(func, b, i, frame_info.hidden_stmts)
    killed_atoms = set()
    used_reg_names = set()
    used_volatile_atoms = set()
    first_ret_assign = None

    for s in stmts_after:
        cur_stmt_used_names = set()

        def collect_reg_names(e):
            if isinstance(e, ir.Reg):
                cur_stmt_used_names.add(e.name)
            elif isinstance(e, ir.Bin):
                collect_reg_names(e.l)
                collect_reg_names(e.r)
            elif isinstance(e, ir.Un):
                collect_reg_names(e.e)
            elif isinstance(e, ir.Bit):
                collect_reg_names(e.base)
            elif isinstance(e, ir.IntrExpr):
                for a in e.args:
                    collect_reg_names(a)
            elif isinstance(e, ir.Mem) and isinstance(e.addr, ir.Expr):
                collect_reg_names(e.addr)

        if isinstance(s, ir.Assign):
            collect_reg_names(s.src)
            if not isinstance(s.dst, ir.Reg):
                collect_reg_names(s.dst)
        elif isinstance(s, ir.Compare):
            if s.flag:
                if s.flag.a is not None:
                    collect_reg_names(s.flag.a)
                if s.flag.b is not None:
                    collect_reg_names(s.flag.b)
        elif isinstance(s, ir.Branch):
            if isinstance(s.cond, ir.Expr):
                collect_reg_names(s.cond)
            if s.flag:
                if s.flag.a is not None:
                    collect_reg_names(s.flag.a)
                if s.flag.b is not None:
                    collect_reg_names(s.flag.b)
            if s.bittest:
                collect_reg_names(s.bittest[0])
            if s.cond in ("c", "nc"):
                cur_stmt_used_names.add("cy")
        elif isinstance(s, ir.Ret) and s.val:
            collect_reg_names(s.val)
        elif isinstance(s, ir.Swap):
            collect_reg_names(s.a)
            collect_reg_names(s.b)
        elif isinstance(s, ir.Intrinsic) and s.name != "pop":
            for a in s.args:
                collect_reg_names(a)
        elif isinstance(s, ir.Switch):
            collect_reg_names(s.expr)

        stmt_has_unbilled_use = False
        for rname in cur_stmt_used_names:
            if rname == "psw":
                continue
            for a in regs.atoms(rname):
                if (a in VOLATILE_ATOMS or a == "cy") and a not in killed_atoms:
                    used_volatile_atoms.add(a)
                    used_reg_names.add(rname)
                    stmt_has_unbilled_use = True

        if stmt_has_unbilled_use and first_ret_assign is None:
            if isinstance(s, ir.Assign) and isinstance(s.src, ir.Reg):
                first_ret_assign = s

        if isinstance(s, ir.Assign) and isinstance(s.dst, ir.Reg):
            killed_atoms.update(regs.atoms(s.dst.name))
        elif isinstance(s, ir.Intrinsic) and s.name == "pop":
            if s.args and isinstance(s.args[0], ir.Reg):
                killed_atoms.update(regs.atoms(s.args[0].name))
        elif isinstance(s, ir.Call):
            killed_atoms.update(VOLATILE_ATOMS)
            killed_atoms.add("cy")

        has_used_de = ("e" in used_volatile_atoms or "d" in used_volatile_atoms)
        has_used_bc = ("b" in used_volatile_atoms or "c" in used_volatile_atoms)
        if has_used_de and has_used_bc:
            break
        if VOLATILE_ATOMS.issubset(killed_atoms):
            break

    has_used_de = ("e" in used_volatile_atoms or "d" in used_volatile_atoms)
    has_used_bc = ("b" in used_volatile_atoms or "c" in used_volatile_atoms)

    if has_used_de and has_used_bc:
        return ir.Reg("de:bc", width="d"), None
    elif ("bc" in used_reg_names and "b" not in killed_atoms and "c" not in killed_atoms) or (
        "b" in used_volatile_atoms and "c" in used_volatile_atoms
    ):
        ret_reg = "bc"
    elif "c" in used_volatile_atoms:
        ret_reg = "c"
    elif "b" in used_volatile_atoms:
        ret_reg = "bc"
    elif ("ax" in used_reg_names and "a" not in killed_atoms and "x" not in killed_atoms) or (
        "a" in used_volatile_atoms and "x" in used_volatile_atoms
    ):
        ret_reg = "ax"
    elif "a" in used_volatile_atoms:
        ret_reg = "a"
    elif "x" in used_volatile_atoms:
        ret_reg = "ax"
    elif ("de" in used_reg_names and "d" not in killed_atoms and "e" not in killed_atoms) or (
        "e" in used_volatile_atoms and "d" in used_volatile_atoms
    ):
        ret_reg = "de"
    elif "e" in used_volatile_atoms:
        ret_reg = "e"
    elif "d" in used_volatile_atoms:
        ret_reg = "de"
    elif "cy" in used_volatile_atoms:
        ret_reg = "cy"
    else:
        ret_reg = None

    if ret_reg:
        if first_ret_assign and first_ret_assign.src.name == ret_reg:
            dst_is_scratch = (
                isinstance(first_ret_assign.dst, ir.Reg) and
                any(a in SCRATCH_ATOMS for a in regs.atoms(first_ret_assign.dst.name))
            )
            if not dst_is_scratch:
                return first_ret_assign.dst, first_ret_assign
        return ir.Reg(ret_reg), None

    return None, None


def _recover_call_sites(func, frame_info, live_atoms=None, proto_params=None):
    """Recover arguments passed at each call site and fold return assignments."""
    for b in func.blocks.values():
        stmts = b.stmts
        i = 0
        while i < len(stmts):
            s = stmts[i]
            if isinstance(s, ir.Call):
                args = []
                # Look backwards for arguments setup in registers (AX, BC)
                ax_arg = None
                bc_arg = None
                caller_pushes = []
                
                j = i - 1
                while j >= 0:
                    prev = stmts[j]
                    if id(prev) in frame_info.hidden_stmts:
                        j -= 1
                        continue
                    if isinstance(prev, ir.Assign):
                        if isinstance(prev.dst, ir.Reg):
                            if prev.dst.name in ("ax", "a", "x") and ax_arg is None:
                                ax_arg = prev.src
                                frame_info.hidden_stmts.add(id(prev))
                            elif prev.dst.name in ("bc", "c", "b"):
                                if prev.dst.name in ("bc", "c") and bc_arg is None:
                                    bc_arg = prev.src
                                frame_info.hidden_stmts.add(id(prev))
                        else:
                            # Intervening write to memory or local variable: not a call argument setup
                            break
                    elif isinstance(prev, ir.Intrinsic) and prev.name == "push":
                        if prev.args and isinstance(prev.args[0], ir.Reg) and prev.args[0].name == "bc":
                            for k in range(j - 1, max(-1, j - 4), -1):
                                p_st = stmts[k]
                                if isinstance(p_st, ir.Assign) and isinstance(p_st.dst, ir.Reg) and p_st.dst.name in ("c", "bc"):
                                    if isinstance(p_st.src, ir.Const):
                                        prev.args[0] = ir.Const(p_st.src.value, width="b")
                                        frame_info.hidden_stmts.add(id(p_st))
                                        break
                                elif isinstance(p_st, ir.Intrinsic) and p_st.name == "push":
                                    break
                        caller_pushes.append(prev)
                    else:
                        break
                    j -= 1

                # Look forward for stack argument cleanup: addw sp, #N
                cleanup_bytes, cleanup_stmt = spill._find_call_cleanup(func, b, i, frame_info.hidden_stmts)
                if cleanup_stmt is not None:
                    frame_info.hidden_stmts.add(id(cleanup_stmt))

                # If ax_arg is not explicitly defined in this block, check if callee expects AX
                if ax_arg is None and s.target and callee_expects_ax(s.target):
                    caller_has_ax = False
                    if live_atoms and ("a" in live_atoms or "x" in live_atoms):
                        caller_has_ax = True
                    elif proto_params and any(getattr(p, "reg", None) == "ax" for p in proto_params):
                        caller_has_ax = True
                    else:
                        caller_has_ax = any(
                            isinstance(st, ir.Assign) and isinstance(st.dst, ir.Reg) and st.dst.name in ("ax", "a", "x")
                            for blk in func.blocks.values() for st in blk.stmts
                        )
                    if caller_has_ax:
                        ax_arg = ir.Reg("ax")

                specs = get_callee_far_param_specs(s.target) if s.target else None

                # Assemble call arguments: registers first
                if specs and specs.get("has_far_reg") and ax_arg is not None and bc_arg is not None:
                    args.append(_consolidate_pair(ax_arg, bc_arg))
                else:
                    if ax_arg is not None:
                        args.append(ax_arg)
                    if bc_arg is not None:
                        args.append(bc_arg)

                # Add caller pushed stack arguments
                stack_raw = list(s.args) if s.args else []
                if not stack_raw and cleanup_bytes > 0 and caller_pushes:
                    for push_stmt in caller_pushes:
                        frame_info.hidden_stmts.add(id(push_stmt))
                        if push_stmt.args:
                            stack_raw.append(push_stmt.args[0])

                far_stack = set(specs.get("far_stack_indices", [])) if specs else set()
                stack_idx = 0
                p_idx = 0
                while p_idx < len(stack_raw):
                    if stack_idx in far_stack and p_idx + 1 < len(stack_raw):
                        off_arg = stack_raw[p_idx]
                        seg_arg = stack_raw[p_idx + 1]
                        args.append(_consolidate_pair(off_arg, seg_arg))
                        p_idx += 2
                    else:
                        args.append(stack_raw[p_idx])
                        p_idx += 1
                    stack_idx += 1

                s.args = args

                # Look forward for return value usage if dst not already set
                if s.dst is None:
                    dst, fold_stmt = _infer_call_return(func, b, i, frame_info)
                    if dst is not None:
                        s.dst = dst
                        if fold_stmt is not None:
                            frame_info.hidden_stmts.add(id(fold_stmt))
            i += 1


def analyze_calling_convention(func, frame_info, ida_type_info=None, user_proto=None, caller_consensus=None):
    """Analyze calling convention, parameters, return types, and call sites."""
    live_atoms = _compute_liveness(func, frame_info.hidden_stmts)
    for hr in getattr(frame_info, "homed_args", []):
        live_atoms.update(regs.atoms(hr))

    if caller_consensus:
        if caller_consensus.get("has_ax") and callee_expects_ax(getattr(func, "entry", None)) is not False:
            live_atoms.update(regs.atoms("ax"))
        if caller_consensus.get("has_bc"):
            live_atoms.update(regs.atoms("bc"))

    params = []

    # 1. Register parameter 0 (AX / A)
    if user_proto:
        parsed = parse_prototype(user_proto)
        if parsed:
            u_ret, u_name, u_params = parsed
            ret_type = u_ret
            if u_name:
                func.name = u_name
            params = []
            if len(u_params) >= 1:
                params.append(Param(u_params[0][0] or "a0", u_params[0][1], "ax"))
            if len(u_params) >= 2:
                params.append(Param(u_params[1][0] or "a1", u_params[1][1], "bc"))
            sorted_args = sorted(frame_info.args.items(), key=lambda kv: kv[1][0].offset)
            for i, (name, (var, width)) in enumerate(sorted_args):
                if name in ("a0", "a1"):
                    continue
                idx = 2 + i
                if idx < len(u_params):
                    p_name, p_type = u_params[idx]
                    params.append(Param(p_name or name, p_type, "stack"))
                else:
                    tstr = "uint16_t" if width == "w" else "uint8_t"
                    params.append(Param(name, tstr, "stack"))
            _recover_call_sites(func, frame_info, live_atoms=live_atoms, proto_params=params)
            return FunctionSig(name=func.name, ret_type=ret_type, ret_expr=None, params=params)

    # 1. Register parameter 0 (AX / A) and Register parameter 1 (BC / C)
    has_ax = ("x" in live_atoms or ("a" in live_atoms and "x" in live_atoms) or "a" in live_atoms)
    has_bc = ("b" in live_atoms or ("b" in live_atoms and "c" in live_atoms) or "c" in live_atoms)

    callee_specs = get_callee_far_param_specs(getattr(func, "entry", None)) if getattr(func, "entry", None) else None
    is_far_reg = False
    if has_ax and has_bc:
        if callee_specs and callee_specs.get("has_far_reg"):
            is_far_reg = True
        elif 0 in getattr(frame_info, "homed_slot_to_arg", {}) and 2 in getattr(frame_info, "homed_slot_to_arg", {}):
            is_far_reg = True

    if is_far_reg:
        params.append(Param("a0", "uint32_t", "ax:bc"))
        if "a0" in frame_info.args:
            frame_info.args["a0"] = (frame_info.args["a0"][0], "d")
        if "a1" in frame_info.args:
            del frame_info.args["a1"]
        for b in func.blocks.values():
            for st in b.stmts:
                if isinstance(st, ir.Assign):
                    if (isinstance(st.src, ir.StackVar) and st.src.name == "a1") or \
                       (isinstance(st.src, ir.Reg) and st.src.name in ("a1", "c")):
                        frame_info.hidden_stmts.add(id(st))
                    elif isinstance(st.dst, ir.Reg) and st.dst.name == "es":
                        frame_info.hidden_stmts.add(id(st))
                    elif isinstance(st.dst, ir.Mem) and getattr(st.dst.addr, "value", None) in (0xFFED4, 0xFFED5):
                        frame_info.hidden_stmts.add(id(st))
    else:
        if "x" in live_atoms or ("a" in live_atoms and "x" in live_atoms):
            params.append(Param("a0", "uint16_t", "ax"))
        elif "a" in live_atoms:
            params.append(Param("a0", "uint8_t", "a"))

        if "b" in live_atoms or ("b" in live_atoms and "c" in live_atoms):
            params.append(Param("a1", "uint16_t", "bc"))
        elif "c" in live_atoms:
            params.append(Param("a1", "uint8_t", "c"))

    # 3. Stack parameters from frame analysis
    sorted_args = sorted([kv for kv in frame_info.args.items() if kv[0] not in ("a0", "a1")], key=lambda kv: kv[1][0].offset)
    far_stack_indices = set()
    stack_idx = 0
    idx = 0
    while idx < len(sorted_args):
        name1, (var1, width1) = sorted_args[idx]
        is_far_stack = False
        name2 = None
        if idx + 1 < len(sorted_args):
            name2, (var2, width2) = sorted_args[idx + 1]
            n1_low = name1.lower()
            n2_low = name2.lower()
            if n2_low in ("segment", "seg", "resp_segment"):
                is_far_stack = True
            elif n2_low == n1_low + "_seg" or n2_low == n1_low + "_segment":
                is_far_stack = True
            elif ("addr" in n1_low or "address" in n1_low or "table" in n1_low) and ("seg" in n2_low or "segment" in n2_low):
                is_far_stack = True

        if is_far_stack:
            params.append(Param(name1, "uint32_t", "stack"))
            far_stack_indices.add(stack_idx)
            frame_info.args[name1] = (var1, "d")
            if name2 and name2 in frame_info.args:
                del frame_info.args[name2]
            for b in func.blocks.values():
                for st in b.stmts:
                    if isinstance(st, ir.Assign):
                        if (isinstance(st.src, ir.StackVar) and st.src.name == name2) or \
                           (isinstance(st.dst, ir.StackVar) and st.dst.name == name2):
                            frame_info.hidden_stmts.add(id(st))
            idx += 2
        else:
            tstr = "uint16_t" if width1 == "w" else "uint8_t"
            params.append(Param(name1, tstr, "stack"))
            idx += 1
        stack_idx += 1

    if getattr(func, "entry", None) is not None:
        _callee_far_specs_cache[func.entry] = {
            "has_far_reg": is_far_reg,
            "far_stack_indices": far_stack_indices
        }

    # 4. Infer return type and expression
    ret_type, ret_expr = _infer_return(func, frame_info.hidden_stmts)

    # 5. Recover call-site arguments and fold return values
    _recover_call_sites(func, frame_info, live_atoms=live_atoms, proto_params=params)

    sig = FunctionSig(name=func.name, ret_type=ret_type, ret_expr=ret_expr, params=params)
    return sig


def parse_prototype(proto_str):
    """Parse a C function prototype string into (ret_type, func_name, [(param_name, param_type)])."""
    proto_str = proto_str.strip().rstrip(";")
    paren_open = proto_str.find("(")
    paren_close = proto_str.rfind(")")
    if paren_open == -1 or paren_close == -1:
        return None
    header = proto_str[:paren_open].strip()
    param_str = proto_str[paren_open + 1:paren_close].strip()

    header_parts = header.split()
    if not header_parts:
        return None
    func_name = header_parts[-1].lstrip("*")
    ret_type = " ".join(header_parts[:-1])
    if header_parts[-1].startswith("*"):
        stars = len(header_parts[-1]) - len(func_name)
        ret_type += " " + "*" * stars
    if not ret_type:
        ret_type = "void"

    params = []
    if param_str and param_str != "void":
        for part in param_str.split(","):
            part = part.strip()
            if not part:
                continue
            tokens = part.split()
            if len(tokens) == 1:
                params.append((None, tokens[0]))
            else:
                pname = tokens[-1].lstrip("*")
                ptype = " ".join(tokens[:-1])
                if tokens[-1].startswith("*"):
                    stars = len(tokens[-1]) - len(pname)
                    ptype += " " + "*" * stars
                params.append((pname, ptype))
    return ret_type, func_name, params
