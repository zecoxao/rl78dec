"""
Conservative, block-local optimisation for RL78 IR.

Propagates register constants and copies into later uses within a basic block
and folds constant expressions.

Key features:
- Atom-level constant tracking: register pairs (AX, BC, DE, HL, SP) decompose into
  low and high byte atoms. Writing A updates A without clobbering X; reading AX
  composes from A and X.
- Copy propagation: copies between registers/temporaries are tracked and killed
  whenever any atom of the source or destination is overwritten.
- Register bank tracking: default RB0 at block/function entry. 'sel rbN' switches
  the active bank and clears all GPR constants/copies. Direct PSW writes or
  bank-flag modifications mark the bank unknown and clear GPRs.
- Memory-mapped GPR aliasing: stores/loads to/from addresses in the active GPR bank
  (0xFFEE0..0xFFEFF) are canonicalised as register accesses.
- Address canonicalisation: known ES constants fold into ES-prefixed addresses;
  near pointers fold to 0xF0000 | addr.
- Swap support: ir.Swap(a, b) swaps tracked constants/copies between operands
  without substituting their lvalue arguments.
- Lvalue protection: destination arguments of intrinsics (pop, set_bit, clr_bit)
  are protected from constant substitution.
- Result flags: FlagDef("result") uses the post-assignment value of the destination.
"""

from . import ir, regs

_OPS = {
    "+": lambda a, b: a + b,
    "-": lambda a, b: a - b,
    "|": lambda a, b: a | b,
    "&": lambda a, b: a & b,
    "^": lambda a, b: a ^ b,
    "<<": lambda a, b: a << (b & 31),
    ">>": lambda a, b: a >> (b & 31),
}

_LVAL_ARGS = {
    "pop": {0},
    "set_bit": {0},
    "clr_bit": {0},
}


def _fold(e):
    if isinstance(e, ir.Bin):
        l, r = _fold(e.l), _fold(e.r)
        if isinstance(l, ir.Const) and isinstance(r, ir.Const) and e.op in _OPS:
            w = "a" if "a" in (l.width, r.width) else ("w" if "w" in (l.width, r.width) else "b")
            v = _OPS[e.op](l.value, r.value)
            if v is not None:
                return ir.Const(v, w)
        if isinstance(r, ir.Const) and r.value == 0 and e.op in ("+", "-", "|", "^", "<<", ">>"):
            return l
        if isinstance(l, ir.Const) and l.value == 0 and e.op in ("+", "|", "^"):
            return r
        return ir.Bin(e.op, l, r)
    if isinstance(e, ir.Un):
        sub = _fold(e.e)
        if isinstance(sub, ir.Const):
            if e.op == "!":
                return ir.Const(0 if sub.value else 1, sub.width)
            if e.op == "~":
                return ir.Const(~sub.value, sub.width)
        return ir.Un(e.op, sub)
    if isinstance(e, ir.Mem):
        return ir.Mem(_fold(e.addr) if isinstance(e.addr, ir.Expr) else e.addr,
                      e.width, e.es, e.name)
    if isinstance(e, ir.Bit):
        base = _fold(e.base)
        if isinstance(base, ir.Const):
            return ir.Const((base.value >> e.bit) & 1)
        return ir.Bit(base, e.bit)
    if isinstance(e, ir.IntrExpr):
        return ir.IntrExpr(e.name, [_fold(a) for a in e.args])
    return e


def _mentions_any_atom(e, target_atoms):
    if isinstance(e, ir.Reg):
        return bool(set(regs.atoms(e.name)) & target_atoms)
    if isinstance(e, ir.Var):
        return False
    if isinstance(e, ir.Bin):
        return _mentions_any_atom(e.l, target_atoms) or _mentions_any_atom(e.r, target_atoms)
    if isinstance(e, ir.Un):
        return _mentions_any_atom(e.e, target_atoms)
    if isinstance(e, ir.Mem):
        return isinstance(e.addr, ir.Expr) and _mentions_any_atom(e.addr, target_atoms)
    if isinstance(e, ir.Bit):
        return _mentions_any_atom(e.base, target_atoms)
    if isinstance(e, ir.IntrExpr):
        return any(_mentions_any_atom(a, target_atoms) for a in e.args)
    return False


class Env:
    def __init__(self, bank=0):
        self.bank = bank              # active register bank (0..3 or None for unknown)
        self.atom_consts = {}         # atom (str) -> int (0..255)
        self.copies = {}              # reg_name (str) -> Expr
        self.var_consts = {}          # var_name (str) -> int
        self.var_copies = {}          # var_name (str) -> Expr

    def clear(self):
        self.atom_consts.clear()
        self.copies.clear()
        self.var_copies.clear()

    def set_var_const(self, name, val):
        self.var_copies.pop(name, None)
        self.var_consts[name] = val

    def set_var_copy(self, name, expr):
        self.var_consts.pop(name, None)
        self.var_copies[name] = expr

    def kill_var(self, name):
        self.var_consts.pop(name, None)
        self.var_copies.pop(name, None)

    def set_bank(self, bank):
        if self.bank != bank:
            self.bank = bank
            self.clear_gprs()

    def clear_gprs(self):
        for a in regs.GPR_ATOMS:
            self.atom_consts.pop(a, None)
        to_del = [k for k, v in self.copies.items()
                  if any(a in regs.GPR_ATOMS for a in regs.atoms(k)) or
                     _mentions_any_atom(v, regs.GPR_ATOMS)]
        for k in to_del:
            self.copies.pop(k, None)
        to_del_vars = [k for k, v in self.var_copies.items()
                       if _mentions_any_atom(v, regs.GPR_ATOMS)]
        for k in to_del_vars:
            self.var_copies.pop(k, None)

    def lookup_const(self, reg_name):
        if reg_name in regs.PAIRS:
            v = regs.compose(reg_name, self.atom_consts)
            if v is not None:
                return ir.Const(v, "w")
            return None
        v = self.atom_consts.get(reg_name)
        if v is not None:
            return ir.Const(v, "b")
        return None

    def kill(self, reg_name):
        target_atoms = set(regs.atoms(reg_name))
        for a in target_atoms:
            self.atom_consts.pop(a, None)
        to_del = [k for k, v in self.copies.items()
                  if bool(set(regs.atoms(k)) & target_atoms) or
                     _mentions_any_atom(v, target_atoms)]
        for k in to_del:
            self.copies.pop(k, None)
        to_del_vars = [k for k, v in self.var_copies.items()
                       if _mentions_any_atom(v, target_atoms)]
        for k in to_del_vars:
            self.var_copies.pop(k, None)

    def set_const(self, reg_name, val):
        self.kill(reg_name)
        if reg_name in regs.PAIRS:
            decomp = regs.decompose(reg_name, val)
            for a, byte_val in decomp.items():
                self.atom_consts[a] = byte_val
        else:
            self.atom_consts[reg_name] = val & 0xFF

    def set_copy(self, dst_name, src_expr):
        self.kill(dst_name)
        dst_atoms = set(regs.atoms(dst_name))
        if not _mentions_any_atom(src_expr, dst_atoms):
            self.copies[dst_name] = src_expr

    def swap(self, a_reg, b_reg):
        old_a_const = self.lookup_const(a_reg)
        old_b_const = self.lookup_const(b_reg)
        old_a_copy = self.copies.get(a_reg)
        old_b_copy = self.copies.get(b_reg)

        self.kill(a_reg)
        self.kill(b_reg)

        if old_b_const is not None:
            self.set_const(a_reg, old_b_const.value)
        elif old_b_copy is not None:
            self.set_copy(a_reg, old_b_copy)

        if old_a_const is not None:
            self.set_const(b_reg, old_a_const.value)
        elif old_a_copy is not None:
            self.set_copy(b_reg, old_a_copy)


def _subst(e, env):
    if isinstance(e, ir.Reg):
        c = env.lookup_const(e.name)
        if c is not None:
            return c
        cp = env.copies.get(e.name)
        if cp is not None:
            return cp
        return e
    if isinstance(e, (ir.Var, ir.StackVar)):
        c = env.var_consts.get(e.name)
        if c is not None:
            return ir.Const(c, e.width)
        cp = env.var_copies.get(e.name)
        if cp is not None:
            return cp
        if isinstance(e, ir.Var):
            return env.copies.get(e.name, e)
        return e
    if isinstance(e, ir.Bin):
        # pair >> 8 extracts the high byte atom of the register pair
        if e.op == ">>" and isinstance(e.r, ir.Const) and e.r.value == 8:
            if isinstance(e.l, ir.Reg) and e.l.name in regs.PAIRS:
                hi_atom = regs.PAIRS[e.l.name][1]
                return _subst(ir.Reg(hi_atom, "b"), env)
        return ir.Bin(e.op, _subst(e.l, env), _subst(e.r, env))
    if isinstance(e, ir.Un):
        return ir.Un(e.op, _subst(e.e, env))
    if isinstance(e, ir.Bit):
        return ir.Bit(_subst(e.base, env), e.bit)
    if isinstance(e, ir.IntrExpr):
        return ir.IntrExpr(e.name, [_subst(a, env) for a in e.args])
    if isinstance(e, ir.Mem):
        addr = _fold(_subst(e.addr, env)) if isinstance(e.addr, ir.Expr) else e.addr
        es = e.es
        if es:
            es_val = env.atom_consts.get("es")
            if es_val is not None:
                if isinstance(addr, ir.Const):
                    addr = ((es_val << 16) | (addr.value & 0xFFFF)) & 0xFFFFF
                    es = False
                elif isinstance(addr, int):
                    addr = ((es_val << 16) | (addr & 0xFFFF)) & 0xFFFFF
                    es = False
                elif isinstance(addr, ir.Bin) and addr.op == "+":
                    if isinstance(addr.l, ir.Const):
                        addr = ir.Bin("+", ir.Const(((es_val << 16) | (addr.l.value & 0xFFFF)) & 0xFFFFF, "a"), addr.r)
                        es = False
                    elif isinstance(addr.r, ir.Const):
                        addr = ir.Bin("+", addr.l, ir.Const(((es_val << 16) | (addr.r.value & 0xFFFF)) & 0xFFFFF, "a"))
                        es = False
        else:
            if isinstance(addr, ir.Const):
                v = addr.value
                addr = ((0xF0000 | v) & 0xFFFFF) if v < 0x10000 else v
            elif isinstance(addr, int):
                if addr < 0x10000:
                    addr = (0xF0000 | addr) & 0xFFFFF
            elif isinstance(addr, ir.Bin) and addr.op == "+":
                if isinstance(addr.l, ir.Const) and 0x8000 <= addr.l.value < 0x10000:
                    addr = ir.Bin("+", ir.Const((0xF0000 | addr.l.value) & 0xFFFFF, "a"), addr.r)
                elif isinstance(addr.r, ir.Const) and 0x8000 <= addr.r.value < 0x10000:
                    addr = ir.Bin("+", addr.l, ir.Const((0xF0000 | addr.r.value) & 0xFFFFF, "a"))

        # GPR / Special reg alias check
        if not es and isinstance(addr, int):
            gpr = regs.gpr_alias(addr, e.width, env.bank)
            if gpr is not None:
                return _subst(ir.Reg(gpr, e.width), env)
            spec = regs.special_reg(addr, e.width)
            if spec is not None:
                return _subst(ir.Reg(spec, e.width), env)

        return ir.Mem(addr, e.width, es, e.name)

    return e


def _clobber(env, s):
    if s.name == "sel":
        if s.args and isinstance(s.args[0], ir.Reg) and s.args[0].name.startswith("rb"):
            try:
                b = int(s.args[0].name[2:])
                env.set_bank(b)
            except ValueError:
                env.set_bank(None)
        else:
            env.set_bank(None)
        return
    if s.name in ("push", "ei", "di", "nop"):
        return
    if s.name == "pop" and s.args and isinstance(s.args[0], ir.Reg):
        reg_name = s.args[0].name
        if reg_name == "psw":
            env.set_bank(None)
            env.kill("psw")
        else:
            env.kill(reg_name)
        return
    env.clear()


def _same_lval(a, b):
    if isinstance(a, ir.Reg) and isinstance(b, ir.Reg):
        return a.name == b.name
    if isinstance(a, ir.Var) and isinstance(b, ir.Var):
        return a.name == b.name
    return False


def _extract_op_const(src):
    if isinstance(src, ir.Bin) and src.op in ("+", "-", "<<", ">>", "&", "|", "^"):
        if isinstance(src.r, ir.Const):
            return src.op, src.l, src.r.value, src.r.width
        if src.op in ("+", "&", "|", "^") and isinstance(src.l, ir.Const):
            return src.op, src.r, src.l.value, src.l.width
    return None


def _coalesce_stmts(stmts):
    """Peephole combine consecutive arithmetic/bitwise operations on the same register/variable."""
    changed = True
    while changed:
        changed = False
        new_stmts = []
        i = 0
        while i < len(stmts):
            if i + 1 < len(stmts):
                s1 = stmts[i]
                s2 = stmts[i + 1]
                if (isinstance(s1, ir.Assign) and isinstance(s2, ir.Assign) and
                        _same_lval(s1.dst, s2.dst)):
                    dst = s1.dst
                    is_gpr = isinstance(dst, ir.Reg) and dst.name not in ("sp", "psw", "spl", "sph")
                    is_var = isinstance(dst, ir.Var)
                    if is_gpr or is_var:
                        if not (s1.flag is not None and s2.flag is None):
                            op1_info = _extract_op_const(s1.src)
                            op2_info = _extract_op_const(s2.src)
                            if op1_info and op2_info:
                                op1, base1, c1, w1 = op1_info
                                op2, base2, c2, w2 = op2_info
                                if _same_lval(base2, dst):
                                    combined_src = None
                                    width = getattr(dst, "width", "w")
                                    if op1 == "+" and op2 == "+":
                                        combined_src = ir.Bin("+", base1, ir.Const(c1 + c2, width))
                                    elif op1 == "-" and op2 == "-":
                                        combined_src = ir.Bin("-", base1, ir.Const(c1 + c2, width))
                                    elif op1 == "+" and op2 == "-":
                                        if c1 > c2:
                                            combined_src = ir.Bin("+", base1, ir.Const(c1 - c2, width))
                                        elif c1 == c2:
                                            combined_src = base1
                                        else:
                                            combined_src = ir.Bin("-", base1, ir.Const(c2 - c1, width))
                                    elif op1 == "-" and op2 == "+":
                                        if c2 > c1:
                                            combined_src = ir.Bin("+", base1, ir.Const(c2 - c1, width))
                                        elif c2 == c1:
                                            combined_src = base1
                                        else:
                                            combined_src = ir.Bin("-", base1, ir.Const(c1 - c2, width))
                                    elif op1 == "<<" and op2 == "<<":
                                        combined_src = ir.Bin("<<", base1, ir.Const(c1 + c2, width))
                                    elif op1 == ">>" and op2 == ">>":
                                        combined_src = ir.Bin(">>", base1, ir.Const(c1 + c2, width))
                                    elif op1 == "&" and op2 == "&":
                                        combined_src = ir.Bin("&", base1, ir.Const(c1 & c2, width))
                                    elif op1 == "|" and op2 == "|":
                                        combined_src = ir.Bin("|", base1, ir.Const(c1 | c2, width))
                                    elif op1 == "^" and op2 == "^":
                                        combined_src = ir.Bin("^", base1, ir.Const(c1 ^ c2, width))

                                    if combined_src is not None:
                                        if _same_lval(dst, combined_src) and s2.flag is None:
                                            i += 2
                                            changed = True
                                            continue
                                        flag = s2.flag
                                        comb = ir.Assign(s1.ea, dst, combined_src, flag=flag)
                                        new_stmts.append(comb)
                                        i += 2
                                        changed = True
                                        continue
            new_stmts.append(stmts[i])
            i += 1
        stmts = new_stmts
    return stmts


def _coalesce_block(block):
    block.stmts = _coalesce_stmts(block.stmts)


def _subst_reg(e, old_reg, new_reg):
    if isinstance(e, ir.Reg):
        if e.name == old_reg.name:
            return ir.Reg(new_reg.name, width=e.width)
        return e
    if isinstance(e, ir.Bin):
        return ir.Bin(e.op, _subst_reg(e.l, old_reg, new_reg), _subst_reg(e.r, old_reg, new_reg))
    if isinstance(e, ir.Un):
        return ir.Un(e.op, _subst_reg(e.e, old_reg, new_reg))
    if isinstance(e, ir.IntrExpr):
        return ir.IntrExpr(e.name, [_subst_reg(a, old_reg, new_reg) for a in e.args])
    if isinstance(e, ir.Mem):
        addr = _subst_reg(e.addr, old_reg, new_reg) if isinstance(e.addr, ir.Expr) else e.addr
        return ir.Mem(addr, width=e.width, es=e.es, name=e.name)
    if isinstance(e, ir.Bit):
        return ir.Bit(_subst_reg(e.base, old_reg, new_reg), e.bit)
    return e


def _eliminate_swap_sandwiches(func):
    """
    Eliminate accumulator placeholder swap sequences:
      XCH acc, other
      <operations on acc>
      XCH acc, other
    Rewrites the middle operations to target 'other' directly and removes both XCH swaps.
    """
    for b in func.blocks.values():
        stmts = b.stmts
        i = 0
        while i < len(stmts):
            s1 = stmts[i]
            if isinstance(s1, ir.Swap) and isinstance(s1.a, ir.Reg) and isinstance(s1.b, ir.Reg):
                reg_a, reg_b = s1.a, s1.b
                j = i + 1
                match_j = None
                while j < len(stmts):
                    s2 = stmts[j]
                    if isinstance(s2, ir.Swap) and isinstance(s2.a, ir.Reg) and isinstance(s2.b, ir.Reg):
                        if {s2.a.name, s2.b.name} == {reg_a.name, reg_b.name}:
                            match_j = j
                            break
                    if isinstance(s2, (ir.Call, ir.Branch, ir.Goto, ir.Ret)):
                        break
                    j += 1
                if match_j is not None:
                    middle = stmts[i + 1 : match_j]
                    acc = reg_a if reg_a.name in ("a", "ax") else (reg_b if reg_b.name in ("a", "ax") else reg_a)
                    other = reg_b if acc == reg_a else reg_a

                    can_transform = True
                    for m_s in middle:
                        if isinstance(m_s, ir.Assign):
                            if isinstance(m_s.dst, ir.Reg) and m_s.dst.name == other.name:
                                can_transform = False
                                break
                        elif isinstance(m_s, ir.Compare):
                            pass
                        else:
                            can_transform = False
                            break

                    if can_transform:
                        new_middle = []
                        for m_s in middle:
                            if isinstance(m_s, ir.Assign):
                                new_dst = _subst_reg(m_s.dst, acc, other)
                                new_src = _subst_reg(m_s.src, acc, other)
                                new_flag = None
                                if m_s.flag:
                                    fa = _subst_reg(m_s.flag.a, acc, other) if m_s.flag.a else None
                                    fb = _subst_reg(m_s.flag.b, acc, other) if m_s.flag.b else None
                                    new_flag = ir.FlagDef(m_s.flag.kind, a=fa, b=fb)
                                new_middle.append(ir.Assign(m_s.ea, new_dst, new_src, flag=new_flag))
                            elif isinstance(m_s, ir.Compare):
                                fa = _subst_reg(m_s.flag.a, acc, other) if m_s.flag.a else None
                                fb = _subst_reg(m_s.flag.b, acc, other) if m_s.flag.b else None
                                new_middle.append(ir.Compare(m_s.ea, ir.FlagDef(m_s.flag.kind, a=fa, b=fb)))
                        stmts = stmts[:i] + new_middle + stmts[match_j + 1:]
                        b.stmts = stmts
                        continue
            i += 1


def _lower_swaps(func):
    """
    Lower any remaining standalone ir.Swap(a, b) into value assignments via a temporary variable:
      t = a
      a = b
      b = t
    This enables regular SSA dataflow, copy propagation, and dead code elimination.
    """
    temp_counter = 0
    for b in func.blocks.values():
        new_stmts = []
        for s in b.stmts:
            if isinstance(s, ir.Swap):
                w = getattr(s.a, "width", "b")
                t_var = ir.Var(f"_swap_{temp_counter}", width=w)
                temp_counter += 1
                new_stmts.append(ir.Assign(s.ea, t_var, s.a))
                new_stmts.append(ir.Assign(s.ea, s.a, s.b))
                new_stmts.append(ir.Assign(s.ea, s.b, t_var))
            else:
                new_stmts.append(s)
        b.stmts = new_stmts


def _opt_block(block, default_bank=0, initial_env=None):
    _coalesce_block(block)
    env = initial_env if initial_env is not None else Env(bank=default_bank)
    for s in block.stmts:
        if isinstance(s, ir.Assign):
            s.src = _fold(_subst(s.src, env))

            if isinstance(s.dst, ir.Mem):
                s.dst = _subst(s.dst, env)
                raw_addr = s.dst.addr if isinstance(s.dst.addr, int) else (
                    s.dst.addr.value if isinstance(s.dst.addr, ir.Const) else None
                )
                if raw_addr is not None:
                    gpr = regs.gpr_alias(raw_addr, s.dst.width, env.bank)
                    if gpr is not None:
                        s.dst = ir.Reg(gpr, s.dst.width)
                    else:
                        spec = regs.special_reg(raw_addr, s.dst.width)
                        if spec is not None:
                            s.dst = ir.Reg(spec, s.dst.width)

            if s.flag is not None:
                if s.flag.kind == "result":
                    s.flag.a = s.src if isinstance(s.src, ir.Const) else s.dst
                else:
                    if s.flag.a is not None:
                        s.flag.a = _fold(_subst(s.flag.a, env))
                    if s.flag.b is not None:
                        s.flag.b = _fold(_subst(s.flag.b, env))

            if isinstance(s.dst, ir.Reg):
                if s.dst.name == "psw":
                    env.set_bank(None)
                    env.kill("psw")
                elif isinstance(s.src, ir.Const):
                    env.set_const(s.dst.name, s.src.value)
                elif isinstance(s.src, ir.Reg) and env.lookup_const(s.src.name) is not None:
                    env.set_const(s.dst.name, env.lookup_const(s.src.name).value)
                elif isinstance(s.src, (ir.Reg, ir.Var, ir.StackVar)):
                    if isinstance(s.src, (ir.Var, ir.StackVar)) and s.src.name in env.var_consts:
                        env.set_const(s.dst.name, env.var_consts[s.src.name])
                    else:
                        env.set_copy(s.dst.name, s.src)
                else:
                    env.kill(s.dst.name)
            elif isinstance(s.dst, (ir.StackVar, ir.Var)):
                if isinstance(s.src, ir.Const):
                    env.set_var_const(s.dst.name, s.src.value)
                elif isinstance(s.src, ir.Reg):
                    c = env.lookup_const(s.src.name)
                    if c is not None:
                        env.set_var_const(s.dst.name, c.value)
                    elif not s.dst.name.startswith("_s"):
                        env.set_var_copy(s.dst.name, s.src)
                    else:
                        env.kill_var(s.dst.name)
                elif isinstance(s.src, (ir.StackVar, ir.Var)):
                    if s.src.name in env.var_consts:
                        env.set_var_const(s.dst.name, env.var_consts[s.src.name])
                    else:
                        env.set_var_copy(s.dst.name, s.src)
                else:
                    env.kill_var(s.dst.name)
            elif isinstance(s.dst, ir.Bit):
                if isinstance(s.dst.base, ir.Reg) and s.dst.base.name == "psw":
                    if s.dst.bit in (3, 5):
                        env.set_bank(None)
                    env.kill("psw")
                elif isinstance(s.dst.base, ir.Reg):
                    env.kill(s.dst.base.name)

        elif isinstance(s, ir.Swap):
            if isinstance(s.a, ir.Mem):
                s.a = _subst(s.a, env)
                raw_addr = s.a.addr if isinstance(s.a.addr, int) else (
                    s.a.addr.value if isinstance(s.a.addr, ir.Const) else None
                )
                if raw_addr is not None:
                    gpr = regs.gpr_alias(raw_addr, s.a.width, env.bank)
                    if gpr is not None:
                        s.a = ir.Reg(gpr, s.a.width)
            if isinstance(s.b, ir.Mem):
                s.b = _subst(s.b, env)
                raw_addr = s.b.addr if isinstance(s.b.addr, int) else (
                    s.b.addr.value if isinstance(s.b.addr, ir.Const) else None
                )
                if raw_addr is not None:
                    gpr = regs.gpr_alias(raw_addr, s.b.width, env.bank)
                    if gpr is not None:
                        s.b = ir.Reg(gpr, s.b.width)

            if isinstance(s.a, ir.Reg) and isinstance(s.b, ir.Reg):
                env.swap(s.a.name, s.b.name)
            else:
                if isinstance(s.a, ir.Reg):
                    env.kill(s.a.name)
                if isinstance(s.b, ir.Reg):
                    env.kill(s.b.name)

        elif isinstance(s, ir.Compare):
            if s.flag.a is not None:
                s.flag.a = _fold(_subst(s.flag.a, env))
            if s.flag.b is not None:
                s.flag.b = _fold(_subst(s.flag.b, env))

        elif isinstance(s, ir.Branch):
            if s.bittest is not None:
                base, sense = s.bittest
                s.bittest = (_fold(_subst(base, env)), sense)

        elif isinstance(s, ir.Switch):
            s.expr = _fold(_subst(s.expr, env))

        elif isinstance(s, ir.Intrinsic):
            lval_indices = _LVAL_ARGS.get(s.name, set())
            new_args = []
            for i, a in enumerate(s.args):
                if i in lval_indices:
                    if isinstance(a, ir.Mem):
                        new_args.append(_subst(a, env))
                    else:
                        new_args.append(a)
                else:
                    new_args.append(_fold(_subst(a, env)))
            s.args = new_args
            _clobber(env, s)

        elif isinstance(s, ir.Call):
            env.clear()
    _coalesce_block(block)


def optimize(func, default_bank=0):
    import copy

    # Phase 0: Eliminate accumulator placeholder swap sequences and lower remaining swaps
    _eliminate_swap_sandwiches(func)
    _lower_swaps(func)

    # Pass 1: Intra-block local optimizations
    for b in func.ordered():
        _opt_block(b, default_bank=default_bank)

    # Collect single-assigned StackVar / Var constants across func
    var_assigns = {}
    for b in func.blocks.values():
        for s in b.stmts:
            if isinstance(s, ir.Assign) and isinstance(s.dst, (ir.StackVar, ir.Var)):
                var_assigns.setdefault(s.dst.name, []).append(s.src)

    func_consts = {}
    for name, srcs in var_assigns.items():
        if len(srcs) == 1 and isinstance(srcs[0], ir.Const):
            func_consts[name] = srcs[0].value

    # Build CFG predecessor mapping
    preds = {}
    for b_start, b in func.blocks.items():
        for kind, succ_ea in b.succ:
            preds.setdefault(succ_ea, []).append(b_start)

    # Pass 2: Forward chaining across CFG along single-predecessor edges
    out_envs = {}
    for b in func.ordered():
        p_list = preds.get(b.start, [])
        if len(p_list) == 1 and p_list[0] in out_envs:
            env = copy.deepcopy(out_envs[p_list[0]])
        else:
            env = Env(bank=default_bank)

        for vname, val in func_consts.items():
            if vname not in env.var_consts:
                env.var_consts[vname] = val

        _opt_block(b, default_bank=default_bank, initial_env=env)
        out_envs[b.start] = env

    return func
