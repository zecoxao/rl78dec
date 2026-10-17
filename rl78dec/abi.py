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
                # A call clobbers volatile registers AX and BC
                for a in regs.atoms("ax") + regs.atoms("bc"):
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

            for s in reversed(b.stmts[:-1]):
                if id(s) in hidden_stmts:
                    continue
                if isinstance(s, ir.Assign) and isinstance(s.dst, ir.Reg):
                    dname = s.dst.name
                    if dname in ("bc", "ax"):
                        cand_type = "uint16_t"
                        cand_expr = s.src if isinstance(s.src, ir.Const) else ir.Reg(dname)
                        cand_reg = dname
                        break
                    elif dname in ("c", "a"):
                        cand_type = "uint8_t"
                        cand_expr = s.src if isinstance(s.src, ir.Const) else ir.Reg(dname)
                        cand_reg = dname
                        break
                    elif dname == "cy":
                        cand_type = "bool"
                        cand_expr = s.src if isinstance(s.src, ir.Const) else ir.Reg("cy")
                        cand_reg = dname
                        break
                elif isinstance(s, (ir.Call, ir.Intrinsic, ir.Branch, ir.Goto)):
                    break

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



VOLATILE_ATOMS = {"x", "a", "c", "b"}


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
    stmts_after = _find_following_stmts(func, b, i, frame_info.hidden_stmts)
    killed_atoms = set()

    for s in stmts_after:
        used_reg_names = set()

        def collect_reg_names(e):
            if isinstance(e, ir.Reg):
                used_reg_names.add(e.name)
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
                used_reg_names.add("cy")
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

        used_volatile_atoms = set()
        for rname in used_reg_names:
            if rname == "psw":
                continue
            for a in regs.atoms(rname):
                if (a in VOLATILE_ATOMS or a == "cy") and a not in killed_atoms:
                    used_volatile_atoms.add(a)

        if used_volatile_atoms:
            if ("bc" in used_reg_names and "b" not in killed_atoms and "c" not in killed_atoms) or (
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
            elif "cy" in used_volatile_atoms:
                ret_reg = "cy"
            else:
                ret_reg = None

            if ret_reg:
                if isinstance(s, ir.Assign) and isinstance(s.src, ir.Reg) and s.src.name == ret_reg:
                    dst_is_volatile = (
                        isinstance(s.dst, ir.Reg) and
                        any(a in VOLATILE_ATOMS for a in regs.atoms(s.dst.name))
                    )
                    if not dst_is_volatile:
                        return s.dst, s
                    else:
                        return ir.Reg(ret_reg), None
                else:
                    return ir.Reg(ret_reg), None

        if isinstance(s, ir.Assign) and isinstance(s.dst, ir.Reg):
            killed_atoms.update(regs.atoms(s.dst.name))
        elif isinstance(s, ir.Intrinsic) and s.name == "pop":
            if s.args and isinstance(s.args[0], ir.Reg):
                killed_atoms.update(regs.atoms(s.args[0].name))
        elif isinstance(s, ir.Call):
            killed_atoms.update(VOLATILE_ATOMS)
            killed_atoms.add("cy")

        if VOLATILE_ATOMS.issubset(killed_atoms):
            break

    return None, None


def _recover_call_sites(func, frame_info):
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
                        caller_pushes.append(prev)
                    else:
                        break
                    j -= 1

                # Look forward for stack argument cleanup: addw sp, #N
                cleanup_bytes, cleanup_stmt = spill._find_call_cleanup(func, b, i, frame_info.hidden_stmts)
                if cleanup_stmt is not None:
                    frame_info.hidden_stmts.add(id(cleanup_stmt))

                # Assemble call arguments: registers first
                if ax_arg is not None:
                    args.append(ax_arg)
                if bc_arg is not None:
                    args.append(bc_arg)

                # Add caller pushed stack arguments
                if s.args:
                    args.extend(s.args)
                elif cleanup_bytes > 0 and caller_pushes:
                    for push_stmt in caller_pushes:
                        frame_info.hidden_stmts.add(id(push_stmt))
                        if push_stmt.args:
                            args.append(push_stmt.args[0])

                s.args = args

                # Look forward for return value usage if dst not already set
                if s.dst is None:
                    dst, fold_stmt = _infer_call_return(func, b, i, frame_info)
                    if dst is not None:
                        s.dst = dst
                        if fold_stmt is not None:
                            frame_info.hidden_stmts.add(id(fold_stmt))
            i += 1


def analyze_calling_convention(func, frame_info, ida_type_info=None, user_proto=None):
    """Analyze calling convention, parameters, return types, and call sites."""
    live_atoms = _compute_liveness(func, frame_info.hidden_stmts)
    for hr in getattr(frame_info, "homed_args", []):
        live_atoms.update(regs.atoms(hr))

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
                idx = 2 + i
                if idx < len(u_params):
                    p_name, p_type = u_params[idx]
                    params.append(Param(p_name or name, p_type, "stack"))
                else:
                    tstr = "uint16_t" if width == "w" else "uint8_t"
                    params.append(Param(name, tstr, "stack"))
            _recover_call_sites(func, frame_info)
            return FunctionSig(name=func.name, ret_type=ret_type, ret_expr=None, params=params)

    if "x" in live_atoms or ("a" in live_atoms and "x" in live_atoms):
        params.append(Param("a0", "uint16_t", "ax"))
    elif "a" in live_atoms:
        params.append(Param("a0", "uint8_t", "a"))

    # 2. Register parameter 1 (BC / C)
    if "b" in live_atoms or ("b" in live_atoms and "c" in live_atoms):
        params.append(Param("a1", "uint16_t", "bc"))
    elif "c" in live_atoms:
        params.append(Param("a1", "uint8_t", "c"))

    # 3. Stack parameters from frame analysis
    # Sort stack arguments by offset
    sorted_args = sorted(frame_info.args.items(), key=lambda kv: kv[1][0].offset)
    for name, (var, width) in sorted_args:
        tstr = "uint16_t" if width == "w" else "uint8_t"
        params.append(Param(name, tstr, "stack"))

    # 4. Infer return type and expression
    ret_type, ret_expr = _infer_return(func, frame_info.hidden_stmts)

    # 5. Recover call-site arguments and fold return values
    _recover_call_sites(func, frame_info)

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
