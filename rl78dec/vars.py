"""
High-Level Virtual Variable Recovery Layer for RL78.

This module elevates the decompiler IR from machine registers to high-level C variables:
1. Reaching Definitions Analysis:
   Performs iterative dataflow analysis on general-purpose registers (AX, BC, DE, HL
   and their 8-bit halves) and stack spill slots across the entire CFG.
2. Def-Use Web Construction:
   Unifies definitions and uses that reach each other into connected live-range webs
   using Union-Find. Each web corresponds to an independent virtual variable (v0, v1, ...).
3. Parameter Binding:
   Binds live-in register reads at function entry (AX/A, BC/C) directly to parameter
   names (a0, a1).
4. Stack Spill Bridging & Elimination:
   Bridges push/pop spill slots (_s0, _s1, ...) to the underlying register values,
   eliminating the need for raw spill variables and restoring natural variable flow.
5. Copy Propagation & Dead Store Elimination:
   Eliminates redundant variable-to-variable copies and dead assignments to temporaries.
6. Single-Use Inlining:
   Inlines pure single-use temporary variables into their use sites, producing natural C expressions.
7. Variable Declarations:
   Collects all virtual variables and records their deduced types (uint16_t, uint8_t) for
   declaration at the function head.
"""

from . import ir, regs

GPR_WORD = {"ax", "bc", "de", "hl"}
GPR_BYTE = {"a", "x", "b", "c", "d", "e", "h", "l"}
ALL_GPR = GPR_WORD | GPR_BYTE

ATOM_PAIRS = {
    "ax": ("x", "a"),
    "bc": ("c", "b"),
    "de": ("e", "d"),
    "hl": ("l", "h"),
    "a": ("a",),
    "x": ("x",),
    "b": ("b",),
    "c": ("c",),
    "d": ("d",),
    "e": ("e",),
    "h": ("h",),
    "l": ("l",),
}

ALL_ATOMS = ("x", "a", "c", "b", "e", "d", "l", "h")
CALLER_SAVED_ATOMS = {"x", "a", "c", "b"}


class _UnionFind:
    def __init__(self):
        self.parent = {}

    def find(self, x):
        if x not in self.parent:
            self.parent[x] = x
            return x
        if self.parent[x] != x:
            self.parent[x] = self.find(self.parent[x])
        return self.parent[x]

    def union(self, x, y):
        rx, ry = self.find(x), self.find(y)
        if rx != ry:
            self.parent[rx] = ry


def _collect_expr_atoms(e, out):
    """Recursively collect register reads and spill variables from expression e."""
    if isinstance(e, ir.Reg) and e.name in ATOM_PAIRS:
        is_word = e.name in GPR_WORD
        out.append((e.name, ATOM_PAIRS[e.name], is_word))
    elif isinstance(e, ir.Var) and e.name.startswith("_s"):
        out.append((e.name, (e.name,), e.width == "w"))
    elif isinstance(e, ir.Bin):
        if (
            isinstance(e.l, ir.Reg)
            and e.l.name in GPR_WORD
            and isinstance(e.r, ir.Const)
        ):
            lo, hi = ATOM_PAIRS[e.l.name]
            if e.op == ">>" and e.r.value >= 8:
                out.append((e.l.name, (hi,), False))
                return
            if e.op == "<<" and e.r.value >= 8:
                out.append((e.l.name, (lo,), False))
                return
            if e.op == "&":
                if (e.r.value & 0xFF00) == 0:
                    out.append((e.l.name, (lo,), False))
                    return
                if (e.r.value & 0x00FF) == 0:
                    out.append((e.l.name, (hi,), False))
                    return
        _collect_expr_atoms(e.l, out)
        _collect_expr_atoms(e.r, out)
    elif isinstance(e, ir.Un):
        _collect_expr_atoms(e.e, out)
    elif isinstance(e, ir.Bit):
        _collect_expr_atoms(e.base, out)
    elif isinstance(e, ir.IntrExpr):
        for a in e.args:
            _collect_expr_atoms(a, out)
    elif isinstance(e, ir.Mem) and isinstance(e.addr, ir.Expr):
        _collect_expr_atoms(e.addr, out)


def _get_stmt_uses(s):
    """Return all GPR and spill variable uses in statement s."""
    uses = []
    if isinstance(s, ir.Assign):
        _collect_expr_atoms(s.src, uses)
        if isinstance(s.dst, ir.Mem) and isinstance(s.dst.addr, ir.Expr):
            _collect_expr_atoms(s.dst.addr, uses)
    elif isinstance(s, ir.Swap):
        _collect_expr_atoms(s.a, uses)
        _collect_expr_atoms(s.b, uses)
    elif isinstance(s, ir.Compare):
        if s.flag:
            if s.flag.a:
                _collect_expr_atoms(s.flag.a, uses)
            if s.flag.b:
                _collect_expr_atoms(s.flag.b, uses)
    elif isinstance(s, ir.Branch):
        if isinstance(s.cond, ir.Expr):
            _collect_expr_atoms(s.cond, uses)
        if s.flag and not (s.flag.kind == "result" and s.cond not in ("z", "nz")):
            if s.flag.a:
                _collect_expr_atoms(s.flag.a, uses)
            if s.flag.b:
                _collect_expr_atoms(s.flag.b, uses)
        if s.bittest:
            _collect_expr_atoms(s.bittest[0], uses)
    elif isinstance(s, ir.Call):
        for a in s.args:
            _collect_expr_atoms(a, uses)
        if s.expr:
            _collect_expr_atoms(s.expr, uses)
    elif isinstance(s, ir.Intrinsic):
        for a in s.args:
            _collect_expr_atoms(a, uses)
    elif isinstance(s, ir.Ret) and s.val:
        _collect_expr_atoms(s.val, uses)
    elif isinstance(s, ir.Switch):
        _collect_expr_atoms(s.expr, uses)
    return uses


def _get_stmt_defs(s):
    """Return all GPR and spill variable definitions and clobbers in statement s."""
    defs = []
    clobbers = []
    if isinstance(s, ir.Assign):
        if isinstance(s.dst, ir.Reg) and s.dst.name in ATOM_PAIRS:
            defs.append((s.dst.name, ATOM_PAIRS[s.dst.name], s.dst.name in GPR_WORD))
        elif isinstance(s.dst, ir.Var) and s.dst.name.startswith("_s"):
            defs.append((s.dst.name, (s.dst.name,), s.dst.width == "w"))
    elif isinstance(s, ir.Swap):
        if isinstance(s.a, ir.Reg) and s.a.name in ATOM_PAIRS:
            defs.append((s.a.name, ATOM_PAIRS[s.a.name], s.a.name in GPR_WORD))
        if isinstance(s.b, ir.Reg) and s.b.name in ATOM_PAIRS:
            defs.append((s.b.name, ATOM_PAIRS[s.b.name], s.b.name in GPR_WORD))
    elif isinstance(s, ir.Call):
        if isinstance(s.dst, ir.Reg) and s.dst.name in ATOM_PAIRS:
            defs.append((s.dst.name, ATOM_PAIRS[s.dst.name], s.dst.name in GPR_WORD))
        defined_atoms = set()
        for _, atoms, _ in defs:
            defined_atoms.update(atoms)
        for atom in CALLER_SAVED_ATOMS:
            if atom not in defined_atoms:
                clobbers.append(atom)
    return defs, clobbers


def _expr_uses_var(e, var_name):
    """Return True if expression e references a Var or Reg named var_name."""
    if isinstance(e, (ir.Var, ir.Reg)) and e.name == var_name:
        return True
    if isinstance(e, ir.Bin):
        return _expr_uses_var(e.l, var_name) or _expr_uses_var(e.r, var_name)
    if isinstance(e, ir.Un):
        return _expr_uses_var(e.e, var_name)
    if isinstance(e, ir.Bit):
        return _expr_uses_var(e.base, var_name)
    if isinstance(e, ir.IntrExpr):
        return any(_expr_uses_var(a, var_name) for a in e.args)
    if isinstance(e, ir.Mem) and isinstance(e.addr, ir.Expr):
        return _expr_uses_var(e.addr, var_name)
    return False


def _subst_ast(e, repl_map):
    """Substitute variables in expression e using repl_map, preserving node identity when unchanged."""
    if isinstance(e, ir.Reg) and e.name in repl_map:
        return repl_map[e.name]
    if isinstance(e, ir.Var) and e.name in repl_map:
        return repl_map[e.name]
    if isinstance(e, ir.Bin):
        nl = _subst_ast(e.l, repl_map)
        nr = _subst_ast(e.r, repl_map)
        if nl is not e.l or nr is not e.r:
            return ir.Bin(e.op, nl, nr)
        return e
    if isinstance(e, ir.Un):
        ne = _subst_ast(e.e, repl_map)
        if ne is not e.e:
            return ir.Un(e.op, ne)
        return e
    if isinstance(e, ir.Bit):
        nb = _subst_ast(e.base, repl_map)
        if nb is not e.base:
            return ir.Bit(nb, e.bit)
        return e
    if isinstance(e, ir.IntrExpr):
        new_args = [_subst_ast(a, repl_map) for a in e.args]
        if any(na is not oa for na, oa in zip(new_args, e.args)):
            return ir.IntrExpr(e.name, new_args)
        return e
    if isinstance(e, ir.Mem):
        if isinstance(e.addr, ir.Expr):
            na = _subst_ast(e.addr, repl_map)
            if na is not e.addr:
                return ir.Mem(na, e.width, e.es, e.name)
        return e
    return e


def _subst_stmt_var(s, var_name, target_expr, seen_flags=None):
    """Substitute var_name with target_expr in all read positions of statement s."""
    repl = {var_name: target_expr}
    changed = False
    if isinstance(s, ir.Assign):
        if _expr_uses_var(s.src, var_name):
            s.src = _subst_ast(s.src, repl)
            changed = True
        if isinstance(s.dst, ir.Mem) and isinstance(s.dst.addr, ir.Expr):
            if _expr_uses_var(s.dst.addr, var_name):
                s.dst.addr = _subst_ast(s.dst.addr, repl)
                changed = True
    elif isinstance(s, ir.Call):
        new_args = []
        for a in s.args:
            if _expr_uses_var(a, var_name):
                new_args.append(_subst_ast(a, repl))
                changed = True
            else:
                new_args.append(a)
        if changed:
            s.args = new_args
        if s.expr and _expr_uses_var(s.expr, var_name):
            s.expr = _subst_ast(s.expr, repl)
            changed = True
    elif isinstance(s, ir.Ret) and s.val:
        if _expr_uses_var(s.val, var_name):
            s.val = _subst_ast(s.val, repl)
            changed = True
    elif isinstance(s, ir.Compare) and s.flag:
        if seen_flags is None or id(s.flag) not in seen_flags:
            if seen_flags is not None:
                seen_flags.add(id(s.flag))
            if s.flag.a and _expr_uses_var(s.flag.a, var_name):
                s.flag.a = _subst_ast(s.flag.a, repl)
                changed = True
            if s.flag.b and _expr_uses_var(s.flag.b, var_name):
                s.flag.b = _subst_ast(s.flag.b, repl)
                changed = True
    elif isinstance(s, ir.Branch):
        if isinstance(s.cond, ir.Expr) and _expr_uses_var(s.cond, var_name):
            s.cond = _subst_ast(s.cond, repl)
            changed = True
        if s.flag and (seen_flags is None or id(s.flag) not in seen_flags):
            if seen_flags is not None:
                seen_flags.add(id(s.flag))
            if s.flag.a and _expr_uses_var(s.flag.a, var_name):
                s.flag.a = _subst_ast(s.flag.a, repl)
                changed = True
            if s.flag.b and _expr_uses_var(s.flag.b, var_name):
                s.flag.b = _subst_ast(s.flag.b, repl)
                changed = True
        if s.bittest and isinstance(s.bittest[0], ir.Expr) and _expr_uses_var(s.bittest[0], var_name):
            s.bittest = (_subst_ast(s.bittest[0], repl), s.bittest[1])
            changed = True
    elif isinstance(s, ir.Switch) and s.expr:
        if _expr_uses_var(s.expr, var_name):
            s.expr = _subst_ast(s.expr, repl)
            changed = True
    elif isinstance(s, ir.Intrinsic):
        new_args = []
        for a in s.args:
            if _expr_uses_var(a, var_name):
                new_args.append(_subst_ast(a, repl))
                changed = True
            else:
                new_args.append(a)
        if changed:
            s.args = new_args
    return changed


def _is_pure_expr(e):
    if isinstance(e, (ir.Const, ir.Reg, ir.Var)):
        return True
    if isinstance(e, ir.Bin):
        return _is_pure_expr(e.l) and _is_pure_expr(e.r)
    if isinstance(e, ir.Un):
        return _is_pure_expr(e.e)
    if isinstance(e, ir.Bit):
        return _is_pure_expr(e.base)
    if isinstance(e, ir.IntrExpr):
        return all(_is_pure_expr(a) for a in e.args)
    return False


def _eliminate_dead_compares(func, hidden):
    """Remove ir.Compare statements and clear Assign.flag whose FlagDef is never consumed by any Branch."""
    live_flags = set()
    for b in func.blocks.values():
        for s in b.stmts:
            if id(s) in hidden:
                continue
            if isinstance(s, ir.Branch) and s.flag is not None:
                if s.flag.kind == "result" and s.cond not in ("z", "nz"):
                    s.flag = None
                else:
                    live_flags.add(id(s.flag))

    changed = False
    for b in func.blocks.values():
        new_stmts = []
        stmts = b.stmts
        for idx, s in enumerate(stmts):
            if id(s) in hidden:
                new_stmts.append(s)
                continue
            if isinstance(s, ir.Compare):
                if s.flag is None or id(s.flag) not in live_flags:
                    # Also keep if a later Branch in the same block has unresolved flag=None
                    has_unresolved_branch = any(
                        id(later) not in hidden and isinstance(later, ir.Branch) and later.flag is None and later.cond is not None
                        for later in stmts[idx + 1:]
                    )
                    if not has_unresolved_branch:
                        changed = True
                        continue
            elif isinstance(s, ir.Assign) and s.flag is not None:
                if id(s.flag) not in live_flags:
                    s.flag = None
                    changed = True
            new_stmts.append(s)
        b.stmts = new_stmts
    return changed


def _compute_var_counts(func, hidden):
    """Compute use_count and def_count for all atoms and virtual variables in func."""
    use_count = {}
    def_count = {}
    seen_flags = set()

    for b in func.blocks.values():
        for s in b.stmts:
            if id(s) in hidden:
                continue
            for _, atoms, _ in _get_stmt_uses(s):
                for atom in atoms:
                    use_count[atom] = use_count.get(atom, 0) + 1

            def count_vars(e):
                if isinstance(e, ir.Var):
                    use_count[e.name] = use_count.get(e.name, 0) + 1
                elif isinstance(e, ir.Bin):
                    count_vars(e.l)
                    count_vars(e.r)
                elif isinstance(e, ir.Un):
                    count_vars(e.e)
                elif isinstance(e, ir.Bit):
                    count_vars(e.base)
                elif isinstance(e, ir.IntrExpr):
                    for a in e.args:
                        count_vars(a)
                elif isinstance(e, ir.Mem) and isinstance(e.addr, ir.Expr):
                    count_vars(e.addr)

            if isinstance(s, ir.Assign):
                count_vars(s.src)
                if isinstance(s.dst, ir.Mem) and isinstance(s.dst.addr, ir.Expr):
                    count_vars(s.dst.addr)
                if isinstance(s.dst, ir.Var):
                    def_count[s.dst.name] = def_count.get(s.dst.name, 0) + 1
            elif isinstance(s, ir.Call):
                for a in s.args:
                    count_vars(a)
                if s.expr:
                    count_vars(s.expr)
                if isinstance(s.dst, ir.Var):
                    def_count[s.dst.name] = def_count.get(s.dst.name, 0) + 1
            elif isinstance(s, ir.Ret) and s.val:
                count_vars(s.val)
            elif isinstance(s, ir.Compare) and s.flag:
                if id(s.flag) not in seen_flags:
                    seen_flags.add(id(s.flag))
                    if s.flag.a:
                        count_vars(s.flag.a)
                    if s.flag.b:
                        count_vars(s.flag.b)
            elif isinstance(s, ir.Branch):
                if s.cond and isinstance(s.cond, ir.Expr):
                    count_vars(s.cond)
                if s.flag and id(s.flag) not in seen_flags:
                    seen_flags.add(id(s.flag))
                    if s.flag.a:
                        count_vars(s.flag.a)
                    if s.flag.b:
                        count_vars(s.flag.b)
                if s.bittest and isinstance(s.bittest[0], ir.Expr):
                    count_vars(s.bittest[0])
            elif isinstance(s, ir.Switch) and s.expr:
                count_vars(s.expr)
            elif isinstance(s, ir.Intrinsic):
                for a in s.args:
                    count_vars(a)
            elif isinstance(s, ir.Swap):
                count_vars(s.a)
                count_vars(s.b)
                if isinstance(s.a, ir.Var):
                    def_count[s.a.name] = def_count.get(s.a.name, 0) + 1
                if isinstance(s.b, ir.Var):
                    def_count[s.b.name] = def_count.get(s.b.name, 0) + 1

    return use_count, def_count


def _compute_var_liveness(func, hidden):
    """Compute live_in and live_out sets of virtual variable names (v0, v1, ...) per block."""
    block_gen = {}
    block_kill = {}

    for b in func.blocks.values():
        gen = set()
        kill = set()
        seen_flags = set()
        for s in b.stmts:
            if id(s) in hidden:
                continue
            used = set()

            def collect_v(e):
                if isinstance(e, ir.Var) and e.name.startswith("v") and e.name[1:].isdigit():
                    used.add(e.name)
                elif isinstance(e, ir.Bin):
                    collect_v(e.l)
                    collect_v(e.r)
                elif isinstance(e, ir.Un):
                    collect_v(e.e)
                elif isinstance(e, ir.Bit):
                    collect_v(e.base)
                elif isinstance(e, ir.IntrExpr):
                    for a in e.args:
                        collect_v(a)
                elif isinstance(e, ir.Mem) and isinstance(e.addr, ir.Expr):
                    collect_v(e.addr)

            if isinstance(s, ir.Assign):
                collect_v(s.src)
                if isinstance(s.dst, ir.Mem) and isinstance(s.dst.addr, ir.Expr):
                    collect_v(s.dst.addr)
            elif isinstance(s, ir.Call):
                for a in s.args:
                    collect_v(a)
                if s.expr:
                    collect_v(s.expr)
            elif isinstance(s, ir.Ret) and s.val:
                collect_v(s.val)
            elif isinstance(s, ir.Compare) and s.flag:
                if id(s.flag) not in seen_flags:
                    seen_flags.add(id(s.flag))
                    if s.flag.a:
                        collect_v(s.flag.a)
                    if s.flag.b:
                        collect_v(s.flag.b)
            elif isinstance(s, ir.Branch):
                if isinstance(s.cond, ir.Expr):
                    collect_v(s.cond)
                if s.flag and id(s.flag) not in seen_flags:
                    seen_flags.add(id(s.flag))
                    if s.flag.a:
                        collect_v(s.flag.a)
                    if s.flag.b:
                        collect_v(s.flag.b)
                if s.bittest and isinstance(s.bittest[0], ir.Expr):
                    collect_v(s.bittest[0])
            elif isinstance(s, ir.Switch) and s.expr:
                collect_v(s.expr)
            elif isinstance(s, ir.Intrinsic):
                for a in s.args:
                    collect_v(a)
            elif isinstance(s, ir.Swap):
                collect_v(s.a)
                collect_v(s.b)

            for u in used:
                if u not in kill:
                    gen.add(u)

            if isinstance(s, (ir.Assign, ir.Call)) and isinstance(s.dst, ir.Var):
                if s.dst.name.startswith("v") and s.dst.name[1:].isdigit():
                    kill.add(s.dst.name)

        block_gen[b.start] = gen
        block_kill[b.start] = kill

    live_in = {b_ea: set() for b_ea in func.blocks}
    live_out = {b_ea: set() for b_ea in func.blocks}
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
    return live_in, live_out


def _stmt_uses_var_check(s, var_name, seen_flags=None):
    """Return True if statement s reads var_name."""
    if isinstance(s, ir.Assign):
        if _expr_uses_var(s.src, var_name):
            return True
        if isinstance(s.dst, ir.Mem) and isinstance(s.dst.addr, ir.Expr) and _expr_uses_var(s.dst.addr, var_name):
            return True
    elif isinstance(s, ir.Call):
        if any(_expr_uses_var(a, var_name) for a in s.args):
            return True
        if s.expr and _expr_uses_var(s.expr, var_name):
            return True
    elif isinstance(s, ir.Ret) and s.val:
        if _expr_uses_var(s.val, var_name):
            return True
    elif isinstance(s, ir.Compare) and s.flag:
        if seen_flags is None or id(s.flag) not in seen_flags:
            if seen_flags is not None:
                seen_flags.add(id(s.flag))
            if (s.flag.a and _expr_uses_var(s.flag.a, var_name)) or (s.flag.b and _expr_uses_var(s.flag.b, var_name)):
                return True
    elif isinstance(s, ir.Branch):
        if isinstance(s.cond, ir.Expr) and _expr_uses_var(s.cond, var_name):
            return True
        if s.flag and (seen_flags is None or id(s.flag) not in seen_flags):
            if seen_flags is not None:
                seen_flags.add(id(s.flag))
            if (s.flag.a and _expr_uses_var(s.flag.a, var_name)) or (s.flag.b and _expr_uses_var(s.flag.b, var_name)):
                return True
        if s.bittest and isinstance(s.bittest[0], ir.Expr) and _expr_uses_var(s.bittest[0], var_name):
            return True
    elif isinstance(s, ir.Switch) and s.expr:
        if _expr_uses_var(s.expr, var_name):
            return True
    elif isinstance(s, ir.Intrinsic):
        if any(_expr_uses_var(a, var_name) for a in s.args):
            return True
    elif isinstance(s, ir.Swap):
        if _expr_uses_var(s.a, var_name) or _expr_uses_var(s.b, var_name):
            return True
    return False


def _stmt_modifies_target(s, target):
    """Return True if statement s may overwrite or alias target."""
    if isinstance(s, (ir.Assign, ir.Call)) and s.dst is not None:
        if s.dst == target:
            return True
        if isinstance(target, ir.Mem) and isinstance(target.addr, ir.Expr):
            if isinstance(s.dst, (ir.Var, ir.Reg)) and _expr_uses_var(target.addr, s.dst.name):
                return True
        if isinstance(target, ir.Mem) and isinstance(s.dst, ir.Mem):
            return True
    if isinstance(s, ir.Call):
        if isinstance(target, ir.Mem):
            return True
        if isinstance(target, ir.Reg) and target.name in ALL_GPR:
            return True
    if isinstance(s, ir.Swap):
        if s.a == target or s.b == target:
            return True
    return False


def _fold_temp_copies(func, hidden):
    """Fold redundant temporary variable assignments directly into their destination variables.

    Handles:
    1. v = call(...); target = v;  ->  target = call(...);
    2. v = expr;      target = v;  ->  target = expr;
       (both within a basic block and across 1-to-1 fallthrough block boundaries,
       including replacing subsequent uses of v with target when safe)
    3. v = src_var; ... uses(v) ... -> ... uses(src_var) ...
    """
    preds = {b_ea: [] for b_ea in func.blocks}
    for b in func.blocks.values():
        for _, succ_ea in b.succ:
            if succ_ea in preds:
                preds[succ_ea].append(b.start)

    any_changed = False
    for _ in range(64):
        use_count, def_count = _compute_var_counts(func, hidden)
        _, live_out = _compute_var_liveness(func, hidden)

        def try_fold_pair(s_prod, b_use, copy_idx):
            v = s_prod.dst
            if not (isinstance(v, ir.Var) and v.name.startswith("v") and v.name[1:].isdigit()):
                return False
            if def_count.get(v.name, 0) != 1:
                return False
            u_cnt = use_count.get(v.name, 0)
            if isinstance(s_prod, ir.Assign):
                if _expr_uses_var(s_prod.src, v.name):
                    return False
                if s_prod.flag is not None:
                    if not (s_prod.flag.kind == "result" and s_prod.flag.a == v and u_cnt > 1):
                        return False

            s_copy = b_use.stmts[copy_idx]
            if not (isinstance(s_copy, ir.Assign) and s_copy.flag is None and s_copy.src == v):
                return False
            target = s_copy.dst
            if isinstance(target, ir.Mem) and isinstance(target.addr, ir.Expr) and _expr_uses_var(target.addr, v.name):
                return False

            if u_cnt > 1:
                if v.name in live_out.get(b_use.start, set()):
                    return False
                # Do not duplicate unnamed/SFR memory accesses across multiple uses
                if isinstance(target, ir.Mem) and not isinstance(target.addr, ir.Const):
                    return False
                seen_f = set()
                rem_uses = 0
                target_modified = False
                can_replace = True
                for st in b_use.stmts[copy_idx + 1:]:
                    if id(st) in hidden:
                        continue
                    if _stmt_uses_var_check(st, v.name, seen_f):
                        if target_modified:
                            can_replace = False
                            break
                        rem_uses += 1
                    if _stmt_modifies_target(st, target):
                        target_modified = True
                if not can_replace or (1 + rem_uses) != u_cnt:
                    return False

                seen_sub = set()
                for st in b_use.stmts[copy_idx + 1:]:
                    if id(st) in hidden:
                        continue
                    _subst_stmt_var(st, v.name, target, seen_sub)

            if isinstance(s_prod, ir.Call):
                s_prod.dst = target
                b_use.stmts.pop(copy_idx)
            else:
                s_copy.src = s_prod.src
                return "remove_prod"
            return "folded_call"

        step_changed = False
        for b in func.ordered():
            stmts = b.stmts
            i = 0
            while i < len(stmts):
                s = stmts[i]
                if id(s) in hidden:
                    i += 1
                    continue

                if isinstance(s, (ir.Call, ir.Assign)) and isinstance(s.dst, ir.Var):
                    v = s.dst
                    if v.name.startswith("v") and v.name[1:].isdigit() and def_count.get(v.name, 0) == 1:
                        # Find next non-hidden, non-Nop statement in b
                        j = i + 1
                        while j < len(stmts) and (id(stmts[j]) in hidden or isinstance(stmts[j], ir.Nop)):
                            j += 1

                        if j < len(stmts):
                            res = try_fold_pair(s, b, j)
                            if res == "remove_prod":
                                stmts.pop(i)
                                step_changed = True
                                any_changed = True
                                break
                            elif res == "folded_call":
                                step_changed = True
                                any_changed = True
                                break
                        else:
                            # s is at the end of block b; check 1-to-1 fallthrough successor
                            if len(b.succ) == 1 and b.succ[0][0] == "fall":
                                succ_ea = b.succ[0][1]
                                if len(preds.get(succ_ea, [])) == 1:
                                    succ_b = func.blocks.get(succ_ea)
                                    if succ_b is not None and succ_b is not b:
                                        k = 0
                                        while k < len(succ_b.stmts) and (
                                            id(succ_b.stmts[k]) in hidden or isinstance(succ_b.stmts[k], ir.Nop)
                                        ):
                                            k += 1
                                        if k < len(succ_b.stmts):
                                            res = try_fold_pair(s, succ_b, k)
                                            if res == "remove_prod":
                                                stmts.pop(i)
                                                step_changed = True
                                                any_changed = True
                                                break
                                            elif res == "folded_call":
                                                step_changed = True
                                                any_changed = True
                                                break

                        # Reverse copy propagation: v = src_var; ... uses(v) ...
                        if (
                            isinstance(s, ir.Assign)
                            and s.flag is None
                            and isinstance(s.src, ir.Var)
                            and v.name not in live_out.get(b.start, set())
                        ):
                            src_var = s.src
                            u_cnt = use_count.get(v.name, 0)
                            if u_cnt >= 1:
                                seen_f = set()
                                rem_uses = 0
                                src_modified = False
                                can_prop = True
                                for st in stmts[i + 1:]:
                                    if id(st) in hidden:
                                        continue
                                    if _stmt_uses_var_check(st, v.name, seen_f):
                                        if src_modified:
                                            can_prop = False
                                            break
                                        rem_uses += 1
                                    if _stmt_modifies_target(st, src_var):
                                        src_modified = True
                                if can_prop and rem_uses == u_cnt:
                                    seen_sub = set()
                                    for st in stmts[i + 1:]:
                                        if id(st) in hidden:
                                            continue
                                        _subst_stmt_var(st, v.name, src_var, seen_sub)
                                    stmts.pop(i)
                                    step_changed = True
                                    any_changed = True
                                    break

                i += 1
            if step_changed:
                break
        if not step_changed:
            break
    return any_changed


def _inline_single_use(func, hidden):
    """Inline single-use, single-def temporary assignments into their immediately following use statement."""
    use_count, def_count = _compute_var_counts(func, hidden)
    changed = False

    for b in func.blocks.values():
        new_stmts = []
        i = 0
        stmts = b.stmts
        while i < len(stmts):
            s = stmts[i]
            if id(s) in hidden:
                new_stmts.append(s)
                i += 1
                continue

            if (
                isinstance(s, ir.Assign)
                and isinstance(s.dst, ir.Var)
                and s.dst.name.startswith("v")
                and s.dst.name[1:].isdigit()
                and (s.flag is None or (s.flag.kind == "result" and s.flag.a == s.dst))
                and use_count.get(s.dst.name, 0) == 1
                and def_count.get(s.dst.name, 0) == 1
                and not _expr_uses_var(s.src, s.dst.name)
            ):
                j = i + 1
                while j < len(stmts) and (id(stmts[j]) in hidden or isinstance(stmts[j], ir.Nop)):
                    j += 1
                if j < len(stmts):
                    nxt = stmts[j]
                    if _subst_stmt_var(nxt, s.dst.name, s.src):
                        changed = True
                        i += 1
                        continue

            new_stmts.append(s)
            i += 1
        b.stmts = new_stmts
    return changed


def _eliminate_dead_assignments(func, hidden, sig=None):
    """Eliminate dead assignments to registers, unused segment registers (ES/CS), and unused virtual variables."""
    protected_atoms = set()
    if sig and sig.ret_type != "void" and sig.ret_expr:
        if isinstance(sig.ret_expr, ir.Reg):
            protected_atoms.update(ATOM_PAIRS.get(sig.ret_expr.name, (sig.ret_expr.name,)))

    any_changed = False
    changed = True
    iterations = 0
    while changed and iterations < 10:
        changed = False
        iterations += 1
        use_count, _ = _compute_var_counts(func, hidden)

        for b in func.blocks.values():
            new_stmts = []
            for s in b.stmts:
                if id(s) in hidden:
                    new_stmts.append(s)
                    continue
                if isinstance(s, ir.Assign) and s.flag is None and _is_pure_expr(s.src):
                    # Check segment registers (es, cs)
                    if isinstance(s.dst, ir.Reg) and s.dst.name in ("es", "cs"):
                        if use_count.get(s.dst.name, 0) == 0:
                            changed = True
                            any_changed = True
                            continue
                    # Check GPRs
                    elif isinstance(s.dst, ir.Reg) and s.dst.name in ALL_GPR:
                        atoms = ATOM_PAIRS.get(s.dst.name, (s.dst.name,))
                        if all(use_count.get(a, 0) == 0 for a in atoms) and not any(a in protected_atoms for a in atoms):
                            changed = True
                            any_changed = True
                            continue
                    # Check compiler-generated virtual variables (v0, v1, ...)
                    elif isinstance(s.dst, ir.Var) and s.dst.name.startswith("v") and s.dst.name[1:].isdigit():
                        if use_count.get(s.dst.name, 0) == 0:
                            changed = True
                            any_changed = True
                            continue
                elif isinstance(s, ir.Call) and s.dst and isinstance(s.dst, ir.Var) and s.dst.name.startswith("v") and s.dst.name[1:].isdigit():
                    if use_count.get(s.dst.name, 0) == 0:
                        s.dst = None
                        changed = True
                        any_changed = True

                new_stmts.append(s)
            b.stmts = new_stmts
    return any_changed


def recover_variables(func, sig, frame_info):
    """Main virtual variable recovery pass."""
    hidden = frame_info.hidden_stmts
    preds = {b_ea: [] for b_ea in func.blocks}
    for b in func.blocks.values():
        for _, succ_ea in b.succ:
            if succ_ea in preds:
                preds[succ_ea].append(b.start)

    # 1. Reaching definitions dataflow analysis
    out_defs = {}
    stmt_reaching = {}

    changed = True
    iterations = 0
    while changed and iterations < 20:
        changed = False
        iterations += 1
        for b in func.ordered():
            cur = {}
            for p_ea in preds[b.start]:
                for atom, dset in out_defs.get(p_ea, {}).items():
                    cur.setdefault(atom, set()).update(dset)

            if b.start == func.entry:
                for atom in ALL_ATOMS:
                    cur.setdefault(atom, set()).add(("entry", atom))

            for s in b.stmts:
                if id(s) in hidden:
                    continue

                uses = _get_stmt_uses(s)
                for reg_name, atoms, is_word in uses:
                    reaching_set = set()
                    for atom in atoms:
                        reaching_set.update(cur.get(atom, set()))
                    stmt_reaching[(id(s), reg_name)] = reaching_set

                defs, clobbers = _get_stmt_defs(s)
                for reg_name, atoms, is_word in defs:
                    for atom in atoms:
                        cur[atom] = {(id(s), atom)}
                for atom in clobbers:
                    cur[atom] = {("clobber", id(s), atom)}

            old_out = out_defs.get(b.start, {})
            if cur != old_out:
                out_defs[b.start] = cur
                changed = True

    # 2. Def-Use Web Construction via Union-Find
    uf = _UnionFind()
    word_nodes = set()

    for (s_id, reg_name), reaching in stmt_reaching.items():
        use_key = (s_id, reg_name, "use")
        if reg_name in GPR_WORD:
            word_nodes.add(use_key)
        for def_site in reaching:
            if def_site[0] == "clobber":
                continue
            uf.union(use_key, def_site)

    # Word subregister cohesion for definitions
    for b in func.blocks.values():
        for s in b.stmts:
            if id(s) in hidden:
                continue
            defs, _ = _get_stmt_defs(s)
            for reg_name, atoms, is_word in defs:
                def_key = (id(s), atoms[0])
                if is_word:
                    word_nodes.add(def_key)
                for atom in atoms[1:]:
                    uf.union(def_key, (id(s), atom))

    # Abstract stack spill bridging (_s0, _s1, ...)
    for b in func.blocks.values():
        for s in b.stmts:
            if id(s) in hidden:
                continue
            if isinstance(s, ir.Assign):
                if isinstance(s.dst, ir.Var) and s.dst.name.startswith("_s"):
                    # _s = reg
                    uses = _get_stmt_uses(s)
                    if uses:
                        reg_name = uses[0][0]
                        uf.union((id(s), s.dst.name), (id(s), reg_name, "use"))
                elif isinstance(s.src, ir.Var) and s.src.name.startswith("_s"):
                    # reg = _s
                    defs, _ = _get_stmt_defs(s)
                    if defs:
                        reg_name, atoms, _ = defs[0]
                        uf.union((id(s), s.src.name, "use"), (id(s), atoms[0]))

    # 3. Web assignment to parameters and virtual variables
    groups = {}
    for node in list(uf.parent.keys()):
        root = uf.find(node)
        groups.setdefault(root, set()).add(node)

    web_var = {}
    var_counter = 0

    param_map = {}
    if sig and sig.params:
        for p in sig.params:
            if p.location in ("ax", "a"):
                param_map["a0"] = ("x", "a", p.type_str == "uint16_t")
            elif p.location in ("bc", "c"):
                param_map["a1"] = ("c", "b", p.type_str == "uint16_t")

    for root, members in groups.items():
        is_word = any(m in word_nodes for m in members)
        name = None

        # Check parameter binding
        for p_name, (lo, hi, p_is_word) in param_map.items():
            if ("entry", lo) in members or ("entry", hi) in members:
                name = p_name
                is_word = p_is_word
                break

        if name is None:
            name = f"v{var_counter}"
            var_counter += 1

        width = "w" if is_word else "b"
        web_var[root] = ir.Var(name, width=width)

    # 4. Rewrite Statements using Virtual Variables
    for b in func.blocks.values():
        new_stmts = []
        for s in b.stmts:
            if id(s) in hidden:
                new_stmts.append(s)
                continue

            uses_repl = {}
            for reg_name, atoms, is_word in _get_stmt_uses(s):
                use_key = (id(s), reg_name, "use")
                root = uf.find(use_key)
                if root in web_var:
                    uses_repl[reg_name] = web_var[root]

            dst_var = None
            defs, _ = _get_stmt_defs(s)
            if defs:
                reg_name, atoms, is_word = defs[0]
                def_key = (id(s), atoms[0])
                root = uf.find(def_key)
                if root in web_var:
                    dst_var = web_var[root]

            if isinstance(s, ir.Assign):
                s.src = _subst_ast(s.src, uses_repl)
                if isinstance(s.dst, ir.Mem) and isinstance(s.dst.addr, ir.Expr):
                    s.dst.addr = _subst_ast(s.dst.addr, uses_repl)
                elif dst_var is not None:
                    if s.flag is not None and s.flag.kind == "result" and s.flag.a == s.dst:
                        s.flag.a = dst_var
                    s.dst = dst_var

                # Drop identity assignments (v = v)
                if isinstance(s.dst, ir.Var) and isinstance(s.src, ir.Var) and s.dst.name == s.src.name:
                    continue
                # Drop spill assignments (_s = v)
                if isinstance(s.dst, ir.Var) and s.dst.name.startswith("_s"):
                    continue

            elif isinstance(s, ir.Swap):
                if s.a.name in uses_repl:
                    s.a = uses_repl[s.a.name]
                if s.b.name in uses_repl:
                    s.b = uses_repl[s.b.name]
            elif isinstance(s, ir.Compare):
                if s.flag:
                    if s.flag.a:
                        s.flag.a = _subst_ast(s.flag.a, uses_repl)
                    if s.flag.b:
                        s.flag.b = _subst_ast(s.flag.b, uses_repl)
            elif isinstance(s, ir.Branch):
                if isinstance(s.cond, ir.Expr):
                    s.cond = _subst_ast(s.cond, uses_repl)
                if s.flag:
                    if s.flag.a:
                        s.flag.a = _subst_ast(s.flag.a, uses_repl)
                    if s.flag.b:
                        s.flag.b = _subst_ast(s.flag.b, uses_repl)
                if s.bittest:
                    s.bittest = (_subst_ast(s.bittest[0], uses_repl), s.bittest[1])
            elif isinstance(s, ir.Call):
                s.args = [_subst_ast(a, uses_repl) for a in s.args]
                if s.expr:
                    s.expr = _subst_ast(s.expr, uses_repl)
                if dst_var is not None:
                    s.dst = dst_var
            elif isinstance(s, ir.Intrinsic):
                s.args = [_subst_ast(a, uses_repl) for a in s.args]
            elif isinstance(s, ir.Ret) and s.val:
                s.val = _subst_ast(s.val, uses_repl)
            elif isinstance(s, ir.Switch):
                s.expr = _subst_ast(s.expr, uses_repl)

            new_stmts.append(s)
        b.stmts = new_stmts

    # 5. Optimize: Dead Code Cleanup, Temporary Copy Folding, and Single-Use Inlining
    for _ in range(10):
        c1 = _eliminate_dead_compares(func, hidden)
        c2 = _eliminate_dead_assignments(func, hidden, sig=sig)
        c3 = _fold_temp_copies(func, hidden)
        c4 = _inline_single_use(func, hidden)
        if not (c1 or c2 or c3 or c4):
            break
    _eliminate_dead_compares(func, hidden)
    _eliminate_dead_assignments(func, hidden, sig=sig)

    # 6. Collect virtual variables for function declaration
    virtual_vars = {}

    def _collect_vvar(e):
        if isinstance(e, ir.Var) and not isinstance(e, ir.StackVar) and e.name.startswith("v") and e.name[1:].isdigit():
            virtual_vars[e.name] = (e, e.width)
        elif isinstance(e, ir.Bin):
            _collect_vvar(e.l)
            _collect_vvar(e.r)
        elif isinstance(e, ir.Un):
            _collect_vvar(e.e)
        elif isinstance(e, ir.Bit):
            _collect_vvar(e.base)
        elif isinstance(e, ir.IntrExpr):
            for a in e.args:
                _collect_vvar(a)
        elif isinstance(e, ir.Mem) and isinstance(e.addr, ir.Expr):
            _collect_vvar(e.addr)

    for b in func.blocks.values():
        for s in b.stmts:
            if id(s) in hidden:
                continue
            if isinstance(s, ir.Assign):
                _collect_vvar(s.dst)
                _collect_vvar(s.src)
            elif isinstance(s, ir.Call):
                if s.dst:
                    _collect_vvar(s.dst)
                for a in s.args:
                    _collect_vvar(a)
                if s.expr:
                    _collect_vvar(s.expr)
            elif isinstance(s, ir.Compare) and s.flag:
                if s.flag.a:
                    _collect_vvar(s.flag.a)
                if s.flag.b:
                    _collect_vvar(s.flag.b)
            elif isinstance(s, ir.Branch):
                if isinstance(s.cond, ir.Expr):
                    _collect_vvar(s.cond)
                if s.flag:
                    if s.flag.a:
                        _collect_vvar(s.flag.a)
                    if s.flag.b:
                        _collect_vvar(s.flag.b)
                if s.bittest and isinstance(s.bittest[0], ir.Expr):
                    _collect_vvar(s.bittest[0])
            elif isinstance(s, ir.Ret) and s.val:
                _collect_vvar(s.val)
            elif isinstance(s, ir.Switch) and s.expr:
                _collect_vvar(s.expr)
            elif isinstance(s, ir.Intrinsic):
                for a in s.args:
                    _collect_vvar(a)
            elif isinstance(s, ir.Swap):
                _collect_vvar(s.a)
                _collect_vvar(s.b)

    frame_info.virtual_vars = virtual_vars
    return func
