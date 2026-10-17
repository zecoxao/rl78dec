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
    true_saved = []
    homed = []
    for r in info.saved_regs:
        if r in ("hl", "de") or r in popped_regs:
            true_saved.append(r)
        else:
            homed.append(r)
    info.saved_regs = true_saved
    info.homed_args = homed

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
    saved_size = len(info.saved_regs) * 2
    arg_base = frsize + saved_size + 4  # 4 bytes far return address

    def resolve_disp(disp, width):
        if disp < frsize:
            name = "var_%X" % (frsize - disp)
            return ir.StackVar(name, width, disp, is_arg=False)
        elif disp >= arg_base:
            name = "arg_%X" % (disp - arg_base)
            return ir.StackVar(name, width, disp, is_arg=True)
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
                    is_arg = info_tuple[3] if len(info_tuple) > 3 else name.startswith("arg_")
                    w = "w" if size == 2 else "b"
                    v = ir.StackVar(name, w, soff, is_arg=is_arg)
                    if is_arg:
                        info.args[name] = (v, w)
                    else:
                        info.locals[name] = (v, w)
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
                    info.args[v.name] = (v, e.width)
                else:
                    info.locals[v.name] = (v, e.width)
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
