"""
Conservative, block-local optimisation for RL78 IR.

Propagates register constants and copies into later uses within a basic block
and folds constant expressions.  The environment tracks *registers only*, so a
memory store never needs to invalidate it; a call, or an intrinsic that is not a
known register-preserving one (push/sel/ei/di/nop), clears it.
"""

from . import ir


def _fold(e):
    if isinstance(e, ir.Bin):
        l, r = _fold(e.l), _fold(e.r)
        if isinstance(l, ir.Const) and isinstance(r, ir.Const) and e.op in _OPS \
                and l.width != "a" and r.width != "a":
            v = _OPS[e.op](l.value, r.value)
            if v is not None:
                return ir.Const(v, "w" if "w" in (l.width, r.width) else "b")
        if isinstance(r, ir.Const) and r.value == 0 and e.op in ("+", "-", "|", "^", "<<", ">>"):
            return l
        return ir.Bin(e.op, l, r)
    if isinstance(e, ir.Un):
        return ir.Un(e.op, _fold(e.e))
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


_OPS = {
    "+": lambda a, b: a + b, "-": lambda a, b: a - b,
    "|": lambda a, b: a | b, "&": lambda a, b: a & b, "^": lambda a, b: a ^ b,
    "<<": lambda a, b: a << (b & 31), ">>": lambda a, b: a >> (b & 31),
}


def _mentions(e, name):
    if isinstance(e, ir.Reg):
        return e.name == name
    if isinstance(e, ir.Bin):
        return _mentions(e.l, name) or _mentions(e.r, name)
    if isinstance(e, ir.Un):
        return _mentions(e.e, name)
    if isinstance(e, ir.Mem):
        return isinstance(e.addr, ir.Expr) and _mentions(e.addr, name)
    if isinstance(e, ir.Bit):
        return _mentions(e.base, name)
    if isinstance(e, ir.IntrExpr):
        return any(_mentions(a, name) for a in e.args)
    return False


def _subst(e, env):
    if isinstance(e, ir.Reg):
        return env.get(e.name, e)
    if isinstance(e, ir.Bin):
        return ir.Bin(e.op, _subst(e.l, env), _subst(e.r, env))
    if isinstance(e, ir.Un):
        return ir.Un(e.op, _subst(e.e, env))
    if isinstance(e, ir.Mem):
        return ir.Mem(_subst(e.addr, env) if isinstance(e.addr, ir.Expr) else e.addr,
                      e.width, e.es, e.name)
    if isinstance(e, ir.Bit):
        return ir.Bit(_subst(e.base, env), e.bit)
    if isinstance(e, ir.IntrExpr):
        return ir.IntrExpr(e.name, [_subst(a, env) for a in e.args])
    return e


def _kill(env, name):
    for k in [k for k, v in env.items() if k == name or _mentions(v, name)]:
        del env[k]


def _opt_block(block):
    env = {}
    for s in block.stmts:
        if isinstance(s, ir.Assign):
            s.src = _fold(_subst(s.src, env))
            if s.flag is not None:
                if s.flag.a is not None:
                    s.flag.a = _fold(_subst(s.flag.a, env))
                if s.flag.b is not None:
                    s.flag.b = _fold(_subst(s.flag.b, env))
            if isinstance(s.dst, ir.Reg):
                _kill(env, s.dst.name)
                if isinstance(s.src, (ir.Const, ir.Reg)) and not _mentions(s.src, s.dst.name):
                    env[s.dst.name] = s.src
            else:
                s.dst = _fold(_subst(s.dst, env))
        elif isinstance(s, ir.Compare):
            if s.flag.a is not None:
                s.flag.a = _fold(_subst(s.flag.a, env))
            if s.flag.b is not None:
                s.flag.b = _fold(_subst(s.flag.b, env))
        elif isinstance(s, ir.Branch):
            if s.bittest is not None:
                base, sense = s.bittest
                s.bittest = (_fold(_subst(base, env)), sense)
        elif isinstance(s, ir.Intrinsic):
            s.args = [_fold(_subst(a, env)) for a in s.args]
            _clobber(env, s)
        elif isinstance(s, ir.Call):
            env.clear()


def _clobber(env, s):
    if s.name in ("push", "sel", "ei", "di", "nop"):
        return
    if s.name == "pop" and s.args and isinstance(s.args[0], ir.Reg):
        _kill(env, s.args[0].name)
        return
    if s.name == "xch":
        for a in s.args:
            if isinstance(a, ir.Reg):
                _kill(env, a.name)
        return
    env.clear()


def optimize(func):
    for b in func.blocks.values():
        _opt_block(b)
    return func
