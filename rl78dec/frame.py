"""
Stack frame analysis and local variable / argument recovery for RL78.

RL78 calling conventions commonly use HL as the frame pointer (``movw hl, sp``)
after allocating local stack space via ``subw sp, #N`` (and optionally ``push ax``).
Preserved registers (callee-saved: HL, DE, BC) are pushed in the prologue and popped
in the epilogue.

This module:
1. Detects prologue/epilogue sequences and identifies callee-saved registers.
2. Identifies frame size and frame pointer register (HL or direct SP).
3. Resolves memory references ``[hl + disp]`` and ``[sp + disp]`` to named local
   variables (``var_X``) and arguments (``arg_X``), reusing IDA's frame analysis
   when available.
4. Marks prologue/epilogue boilerplate statements so the code generator can suppress them.
"""

from . import ir, regs


class FrameInfo:
    def __init__(self, func):
        self.func = func
        self.has_frame = False
        self.fp_reg = None           # "hl", "sp", or None
        self.frame_size = 0          # bytes allocated for local variables
        self.saved_regs = []         # list of callee-saved registers pushed at entry
        self.homed_args = []         # list of incoming argument registers pushed/homed at entry
        self.homed_slot_to_arg = {}  # disp -> "a0" or "a1"
        self.prologue_pushes = []    # list of registers pushed before MOVW HL, SP
        self.arg_base = 4
        self.locals = {}             # name -> (StackVar, width)
        self.args = {}               # name -> (StackVar, width)
        self.virtual_vars = {}       # name -> (Var, width)
        self.hidden_stmts = set()    # set of id(stmt) to suppress in code generation
        self.prologue_stmts = []
        self.epilogue_stmts = []

    def describe(self):
        parts = []
        if self.frame_size:
            parts.append("frame 0x%X" % self.frame_size)
        if self.saved_regs:
            parts.append("saved %s" % ", ".join(self.saved_regs))
        return "; ".join(parts) if parts else None


def _is_push_reg(s):
    return (isinstance(s, ir.Intrinsic) and s.name == "push" and
            bool(s.args) and isinstance(s.args[0], ir.Reg) and
            s.args[0].name in ("hl", "de", "bc", "ax"))


def _is_pop_reg(s):
    return (isinstance(s, ir.Intrinsic) and s.name == "pop" and
            bool(s.args) and isinstance(s.args[0], ir.Reg) and
            s.args[0].name in ("hl", "de", "bc", "ax"))


def _is_sub_sp(s):
    return (isinstance(s, ir.Assign) and isinstance(s.dst, ir.Reg) and s.dst.name == "sp" and
            isinstance(s.src, ir.Bin) and s.src.op == "-" and
            isinstance(s.src.l, ir.Reg) and s.src.l.name == "sp" and
            isinstance(s.src.r, ir.Const))


def _is_add_sp(s):
    return (isinstance(s, ir.Assign) and isinstance(s.dst, ir.Reg) and s.dst.name == "sp" and
            isinstance(s.src, ir.Bin) and s.src.op == "+" and
            isinstance(s.src.l, ir.Reg) and s.src.l.name == "sp" and
            isinstance(s.src.r, ir.Const))


def _is_mov_hl_sp(s):
    return (isinstance(s, ir.Assign) and isinstance(s.dst, ir.Reg) and s.dst.name == "hl" and
            isinstance(s.src, ir.Reg) and s.src.name == "sp")


def _scan_block_prologue(b):
    """Scan a block for a function prologue sequence."""
    saved_regs = []
    frame_size = 0
    fp_reg = None
    prologue_stmts = []

    for s in b.stmts:
        if _is_push_reg(s):
            saved_regs.append(s.args[0].name)
            prologue_stmts.append(s)
        elif _is_sub_sp(s):
            frame_size += s.src.r.value
            prologue_stmts.append(s)
        elif _is_mov_hl_sp(s):
            fp_reg = "hl"
            prologue_stmts.append(s)
            break
        else:
            break

    if not fp_reg and frame_size > 0:
        fp_reg = "sp"

    return fp_reg, frame_size, saved_regs, prologue_stmts


def _scan_epilogues(func):
    """Scan all blocks in func ending in Ret for matching epilogues."""
    epilogue_stmts = []
    for b in func.blocks.values():
        if b.stmts and isinstance(b.stmts[-1], ir.Ret):
            has_add_sp = False
            for s in reversed(b.stmts[:-1]):
                if _is_pop_reg(s):
                    epilogue_stmts.append(s)
                elif _is_add_sp(s):
                    if not has_add_sp:
                        epilogue_stmts.append(s)
                        has_add_sp = True
                    else:
                        break
                else:
                    break
    return epilogue_stmts


def _is_disp_read_before_write(func, fp_reg, target_disp):
    """Return True if stack slot [fp_reg + target_disp] is read before being written in func."""
    if not fp_reg:
        return False

    def get_mem_disp(e):
        if isinstance(e, ir.Mem) and not e.es:
            if isinstance(e.addr, ir.Reg) and e.addr.name == fp_reg:
                return 0
            if (
                isinstance(e.addr, ir.Bin)
                and e.addr.op == "+"
                and isinstance(e.addr.l, ir.Reg)
                and e.addr.l.name == fp_reg
                and isinstance(e.addr.r, ir.Const)
            ):
                return e.addr.r.value
        return None

    def expr_reads_disp(e):
        d = get_mem_disp(e)
        if d is not None and (target_disp <= d < target_disp + 2):
            return True
        if isinstance(e, ir.Bin):
            return expr_reads_disp(e.l) or expr_reads_disp(e.r)
        if isinstance(e, ir.Un):
            return expr_reads_disp(e.e)
        if isinstance(e, ir.Bit):
            return expr_reads_disp(e.base)
        if isinstance(e, ir.IntrExpr):
            return any(expr_reads_disp(a) for a in e.args)
        if isinstance(e, ir.Mem) and isinstance(e.addr, ir.Expr):
            return expr_reads_disp(e.addr)
        return False

    for b in func.ordered():
        for s in b.stmts:
            if isinstance(s, ir.Assign):
                if expr_reads_disp(s.src):
                    return True
                d = get_mem_disp(s.dst)
                if d is not None and (target_disp <= d < target_disp + 2):
                    return False
                if isinstance(s.dst, ir.Mem) and isinstance(s.dst.addr, ir.Expr):
                    if expr_reads_disp(s.dst.addr):
                        return True
            elif isinstance(s, ir.Compare):
                if s.flag:
                    if s.flag.a and expr_reads_disp(s.flag.a):
                        return True
                    if s.flag.b and expr_reads_disp(s.flag.b):
                        return True
            elif isinstance(s, ir.Call):
                if any(expr_reads_disp(a) for a in s.args):
                    return True
            elif isinstance(s, ir.Ret) and s.val:
                if expr_reads_disp(s.val):
                    return True
            elif isinstance(s, ir.Branch):
                if s.cond and isinstance(s.cond, ir.Expr) and expr_reads_disp(s.cond):
                    return True
                if s.bittest and expr_reads_disp(s.bittest[0]):
                    return True
                if s.flag:
                    if s.flag.a and expr_reads_disp(s.flag.a):
                        return True
                    if s.flag.b and expr_reads_disp(s.flag.b):
                        return True
            elif isinstance(s, ir.Switch) and s.expr:
                if expr_reads_disp(s.expr):
                    return True
            elif isinstance(s, ir.Intrinsic):
                if any(expr_reads_disp(a) for a in s.args):
                    return True
    return False


def analyze_frame(func, ida_frame_info=None):
    """Analyze the stack frame of func, resolving variables and identifying boilerplate."""
    info = FrameInfo(func)

    # 1. Detect prologue
    entry_b = func.blocks.get(func.entry)
    if entry_b:
        fp_reg, frame_size, saved_regs, prologue = _scan_block_prologue(entry_b)
        # If entry block was an initial check (e.g. cmpw ax, 0; bz ...), check fallthrough successor
        if not prologue and len(entry_b.succ) == 2:
            fall_ea = entry_b.succ[1][1] if len(entry_b.succ) > 1 else None
            if fall_ea and fall_ea in func.blocks:
                fp_reg, frame_size, saved_regs, prologue = _scan_block_prologue(func.blocks[fall_ea])
        
        if not fp_reg:
            for b in func.blocks.values():
                for i, s in enumerate(b.stmts):
                    if _is_mov_hl_sp(s):
                        fp_reg = "hl"
                        prologue.append(s)
                        if i > 0 and _is_sub_sp(b.stmts[i - 1]):
                            frame_size += b.stmts[i - 1].src.r.value
                            prologue.append(b.stmts[i - 1])
                        break
                if fp_reg:
                    break

        info.fp_reg = fp_reg
        info.frame_size = frame_size
        info.saved_regs = saved_regs
        info.prologue_stmts = prologue
        if fp_reg or frame_size > 0 or saved_regs:
            info.has_frame = True

    # 2. Detect epilogues
    info.epilogue_stmts = _scan_epilogues(func)
    popped_regs = set()
    for s in info.epilogue_stmts:
        if isinstance(s, ir.Intrinsic) and s.name == "pop" and s.args and isinstance(s.args[0], ir.Reg):
            popped_regs.add(s.args[0].name)

    # Separate true callee-saved registers from homed incoming argument registers
    # In RL78 ABI:
    # 1. HL and DE are callee-saved.
    # 2. AX is NEVER callee-saved (it is arg 0 / scratch). When pushed in the prologue,
    #    it either homes incoming argument a0 or allocates 2 bytes of local scratch.
    # 3. Pushes before MOVW HL, SP shift the frame pointer HL downwards.
    #    arg_base = frame_size + total_pushed_bytes + 4
    true_saved = []
    homed = []
    homed_slot_to_arg = {}

    total_pushed_bytes = len(info.saved_regs) * 2
    arg_base = info.frame_size + total_pushed_bytes + 4

    for i, r in enumerate(info.saved_regs):
        disp = info.frame_size + (len(info.saved_regs) - 1 - i) * 2
        if r in ("hl", "de"):
            true_saved.append(r)
        elif r == "ax":
            if _is_disp_read_before_write(func, info.fp_reg, disp):
                if "ax" not in homed:
                    homed.append("ax")
                homed_slot_to_arg[disp] = "a0"
        elif r == "bc":
            if _is_disp_read_before_write(func, info.fp_reg, disp):
                if "bc" not in homed:
                    homed.append("bc")
                homed_slot_to_arg[disp] = "a1"
            elif r in popped_regs and not homed:
                true_saved.append(r)

    info.saved_regs = true_saved
    info.homed_args = homed
    info.homed_slot_to_arg = homed_slot_to_arg
    info.arg_base = arg_base
    info.prologue_pushes = list(info.saved_regs)

    # 3. Mark boilerplate to hide
    for s in info.prologue_stmts:
        info.hidden_stmts.add(id(s))
    for s in info.epilogue_stmts:
        info.hidden_stmts.add(id(s))

    # 4. Resolve stack references
    # Unpack IDA frame info if available: (members_dict, stkvars_by_ea)
    ida_members = {}
    ida_stkvars = {}
    if ida_frame_info:
        ida_members, ida_stkvars = ida_frame_info

    frsize = info.frame_size

    def resolve_disp(disp, width):
        if disp in info.homed_slot_to_arg:
            name = info.homed_slot_to_arg[disp]
            return ir.StackVar(name, width, disp, is_arg=True)
        elif disp >= arg_base:
            name = "arg_%X" % (disp - arg_base)
            return ir.StackVar(name, width, disp, is_arg=True)
        elif disp < frsize:
            name = "var_%X" % (frsize - disp)
            return ir.StackVar(name, width, disp, is_arg=False)
        else:
            name = "var_s%X" % (disp - frsize)
            return ir.StackVar(name, width, disp, is_arg=False)

    def repl(e, ea=0):
        if isinstance(e, ir.Mem) and not e.es:
            # Check IDA frame resolution first if available
            if ea in ida_stkvars:
                # Find matching operand
                for op_idx, info_tuple in ida_stkvars[ea].items():
                    soff = info_tuple[0]
                    name = info_tuple[1]
                    size = info_tuple[2]
                    if soff in info.homed_slot_to_arg:
                        name = info.homed_slot_to_arg[soff]
                        is_arg = True
                    else:
                        is_arg = info_tuple[3] if len(info_tuple) > 3 else (name.startswith("arg_") or soff >= arg_base)
                    w = "w" if size == 2 else "b"
                    v = ir.StackVar(name, w, soff, is_arg=is_arg)
                    if is_arg:
                        prev_w = info.args.get(name, (None, None))[1]
                        w = "w" if (w == "w" or prev_w == "w") else "b"
                        info.args[name] = (v, w)
                    else:
                        prev_w = info.locals.get(name, (None, None))[1]
                        w = "w" if (w == "w" or prev_w == "w") else "b"
                        info.locals[name] = (v, w)
                    return v
                    return v

            # Standalone frame resolution
            disp = None
            if info.fp_reg == "hl":
                if isinstance(e.addr, ir.Reg) and e.addr.name == "hl":
                    disp = 0
                elif (isinstance(e.addr, ir.Bin) and e.addr.op == "+" and
                      isinstance(e.addr.l, ir.Reg) and e.addr.l.name == "hl" and
                      isinstance(e.addr.r, ir.Const)):
                    disp = e.addr.r.value
            elif info.fp_reg == "sp":
                if isinstance(e.addr, ir.Reg) and e.addr.name == "sp":
                    disp = 0
                elif (isinstance(e.addr, ir.Bin) and e.addr.op == "+" and
                      isinstance(e.addr.l, ir.Reg) and e.addr.l.name == "sp" and
                      isinstance(e.addr.r, ir.Const)):
                    disp = e.addr.r.value

            if disp is not None:
                v = resolve_disp(disp, e.width)
                if v.is_arg:
                    prev_w = info.args.get(v.name, (None, None))[1]
                    w = "w" if (e.width == "w" or prev_w == "w") else "b"
                    info.args[v.name] = (v, w)
                else:
                    prev_w = info.locals.get(v.name, (None, None))[1]
                    w = "w" if (e.width == "w" or prev_w == "w") else "b"
                    info.locals[v.name] = (v, w)
                return v

        if isinstance(e, ir.Bin):
            return ir.Bin(e.op, repl(e.l, ea), repl(e.r, ea))
        if isinstance(e, ir.Un):
            return ir.Un(e.op, repl(e.e, ea))
        if isinstance(e, ir.Bit):
            return ir.Bit(repl(e.base, ea), e.bit)
        if isinstance(e, ir.IntrExpr):
            return ir.IntrExpr(e.name, [repl(a, ea) for a in e.args])
        return e

    for b in func.blocks.values():
        for s in b.stmts:
            if isinstance(s, ir.Assign):
                s.dst = repl(s.dst, s.ea)
                s.src = repl(s.src, s.ea)
            elif isinstance(s, ir.Compare):
                if s.flag:
                    if s.flag.a is not None:
                        s.flag.a = repl(s.flag.a, s.ea)
                    if s.flag.b is not None:
                        s.flag.b = repl(s.flag.b, s.ea)
            elif isinstance(s, ir.Swap):
                s.a = repl(s.a, s.ea)
                s.b = repl(s.b, s.ea)
            elif isinstance(s, ir.Intrinsic):
                s.args = [repl(a, s.ea) for a in s.args]
            elif isinstance(s, ir.Branch):
                if s.bittest is not None:
                    base, sense = s.bittest
                    s.bittest = (repl(base, s.ea), sense)
            elif isinstance(s, ir.Switch):
                s.expr = repl(s.expr, s.ea)

    return info
