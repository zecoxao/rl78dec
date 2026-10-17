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
        self.const_names = {}         # reg_name (str) -> str

    def clear(self):
        self.atom_consts.clear()
        self.copies.clear()
        self.const_names.clear()

    def set_bank(self, bank):
        if self.bank != bank:
            self.bank = bank
            self.clear_gprs()

    def clear_gprs(self):
        for a in regs.GPR_ATOMS:
            self.atom_consts.pop(a, None)
            self.const_names.pop(a, None)
        for pair in regs.PAIRS:
            if any(a in regs.GPR_ATOMS for a in regs.atoms(pair)):
                self.const_names.pop(pair, None)
        to_del = [k for k, v in self.copies.items()
                  if any(a in regs.GPR_ATOMS for a in regs.atoms(k)) or
                     _mentions_any_atom(v, regs.GPR_ATOMS)]
        for k in to_del:
            self.copies.pop(k, None)

    def lookup_const(self, reg_name):
        name = self.const_names.get(reg_name)
        if reg_name in regs.PAIRS:
            v = regs.compose(reg_name, self.atom_consts)
            if v is not None:
                return ir.Const(v, "w", name=name)
            return None
        v = self.atom_consts.get(reg_name)
        if v is not None:
            return ir.Const(v, "b", name=name)
        return None

    def kill(self, reg_name):
        target_atoms = set(regs.atoms(reg_name))
        for a in target_atoms:
            self.atom_consts.pop(a, None)
            self.const_names.pop(a, None)
            for pair in regs.PAIRS:
                if a in regs.atoms(pair):
                    self.const_names.pop(pair, None)
        self.const_names.pop(reg_name, None)
        to_del = [k for k, v in self.copies.items()
                  if bool(set(regs.atoms(k)) & target_atoms) or
                     _mentions_any_atom(v, target_atoms)]
        for k in to_del:
            self.copies.pop(k, None)

    def set_const(self, reg_name, val, name=None):
        self.kill(reg_name)
        if reg_name in regs.PAIRS:
            decomp = regs.decompose(reg_name, val)
            for a, byte_val in decomp.items():
                self.atom_consts[a] = byte_val
        else:
            self.atom_consts[reg_name] = val & 0xFF
        if name:
            self.const_names[reg_name] = name

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
            self.set_const(a_reg, old_b_const.value, getattr(old_b_const, "name", None))
        elif old_b_copy is not None:
            self.set_copy(a_reg, old_b_copy)

        if old_a_const is not None:
            self.set_const(b_reg, old_a_const.value, getattr(old_a_const, "name", None))
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
    if isinstance(e, ir.Var):
        return env.copies.get(e.name, e)
    if isinstance(e, ir.Bin):
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


def _opt_block(block, default_bank=0):
    _coalesce_block(block)
    env = Env(bank=default_bank)
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
                    env.set_const(s.dst.name, s.src.value, getattr(s.src, "name", None))
                elif isinstance(s.src, (ir.Reg, ir.Var)):
                    env.set_copy(s.dst.name, s.src)
                else:
                    env.kill(s.dst.name)
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
    for b in func.blocks.values():
        _opt_block(b, default_bank=default_bank)
    return func
