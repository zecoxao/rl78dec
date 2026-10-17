"""
Intermediate representation for the RL78 decompiler.

The statement classes mirror those in the Kirk/Spock tool (``startrekdec``) so
the control-flow structurer and highlighter are shared unchanged; the expression
layer is a register machine: :class:`Reg`, :class:`Mem` (a memory access whose
address is itself an expression), plus the usual constants and operators.

Flags: RL78 conditional branches read Z (bz/bnz), CY (bc/bnc) and Z|CY
(bh/bnh).  A :class:`FlagDef` records what last set them so a branch renders as a
real comparison; ``cmp`` carries both operands (giving signed-free unsigned
relations), an arithmetic result carries only its value (Z against 0).
"""


class Expr:
    pass


class Const(Expr):
    __slots__ = ("value", "width", "name")

    def __init__(self, value, width="b", name=None):
        self.width = width
        self.name = name
        if width == "a":                 # an address: keep 20 bits, never mask to 8
            self.value = value & 0xFFFFF
        elif width == "w":
            self.value = value & 0xFFFF
        else:
            self.value = value & 0xFF

    def __eq__(self, o):
        return isinstance(o, Const) and o.value == self.value and o.width == self.width

    def __hash__(self):
        return hash(("const", self.value, self.width))


class Reg(Expr):
    __slots__ = ("name", "width")

    def __init__(self, name, width=None):
        self.name = name
        self.width = width or ("w" if name in ("ax", "bc", "de", "hl", "sp") else "b")

    def __eq__(self, o):
        return isinstance(o, Reg) and o.name == self.name

    def __hash__(self):
        return hash(("reg", self.name))


class Var(Expr):
    __slots__ = ("name", "width")

    def __init__(self, name, width="b"):
        self.name = name
        self.width = width

    def __eq__(self, o):
        return isinstance(o, Var) and o.name == self.name

    def __hash__(self):
        return hash(("var", self.name))


class StackVar(Var):
    """A stack frame variable or argument slot."""
    __slots__ = ("offset", "is_arg")

    def __init__(self, name, width="b", offset=0, is_arg=False):
        super().__init__(name, width)
        self.offset = offset
        self.is_arg = is_arg

    def __eq__(self, o):
        return isinstance(o, StackVar) and o.name == self.name and o.offset == self.offset

    def __hash__(self):
        return hash(("stackvar", self.name, self.offset))



class Mem(Expr):
    """A memory access at address *addr* (an Expr), width b/w.  ``es`` marks the
    ES: far-data prefix; ``name`` is an optional symbolic label (SFR/saddr)."""
    __slots__ = ("addr", "width", "es", "name")

    def __init__(self, addr, width="b", es=False, name=None):
        self.addr = addr
        self.width = width
        self.es = es
        self.name = name

    def __eq__(self, o):
        return (
            isinstance(o, Mem) and
            o.addr == self.addr and
            o.width == self.width and
            o.es == self.es and
            o.name == self.name
        )

    def __hash__(self):
        return hash(("mem", self.addr, self.width, self.es, self.name))


class Bit(Expr):
    """A single bit of a byte location (base is a Reg or Mem)."""
    __slots__ = ("base", "bit")

    def __init__(self, base, bit):
        self.base = base
        self.bit = bit

    def __eq__(self, o):
        return isinstance(o, Bit) and o.base == self.base and o.bit == self.bit

    def __hash__(self):
        return hash(("bit", self.base, self.bit))


class Bin(Expr):
    __slots__ = ("op", "l", "r")

    def __init__(self, op, l, r):
        self.op = op
        self.l = l
        self.r = r

    def __eq__(self, o):
        return isinstance(o, Bin) and o.op == self.op and o.l == self.l and o.r == self.r

    def __hash__(self):
        return hash(("bin", self.op, self.l, self.r))


class Un(Expr):
    __slots__ = ("op", "e")

    def __init__(self, op, e):
        self.op = op
        self.e = e

    def __eq__(self, o):
        return isinstance(o, Un) and o.op == self.op and o.e == self.e

    def __hash__(self):
        return hash(("un", self.op, self.e))


class IntrExpr(Expr):
    __slots__ = ("name", "args")

    def __init__(self, name, args):
        self.name = name
        self.args = args

    def __eq__(self, o):
        return isinstance(o, IntrExpr) and o.name == self.name and o.args == self.args

    def __hash__(self):
        return hash(("intrexpr", self.name, tuple(self.args)))


# ---------------------------------------------------------------------------
# flags
# ---------------------------------------------------------------------------

class FlagDef:
    """kind == 'cmp'    : Z=(a==b), CY=(a<b unsigned)   (a,b unmodified)
       kind == 'result' : Z=(res==0), CY unknown        (res written)
       kind == 'sub'    : Z=(res==0), CY=borrow          (a,b known)"""
    __slots__ = ("kind", "a", "b")

    def __init__(self, kind, a=None, b=None):
        self.kind = kind
        self.a = a
        self.b = b


# ---------------------------------------------------------------------------
# statements  (same shapes as startrekdec, so structure.py is shared)
# ---------------------------------------------------------------------------

class Assign:
    __slots__ = ("ea", "dst", "src", "flag")

    def __init__(self, ea, dst, src, flag=None):
        self.ea = ea
        self.dst = dst
        self.src = src
        self.flag = flag


class Swap:
    __slots__ = ("ea", "a", "b")

    def __init__(self, ea, a, b):
        self.ea = ea
        self.a = a
        self.b = b


class Compare:
    __slots__ = ("ea", "flag")

    def __init__(self, ea, flag):
        self.ea = ea
        self.flag = flag


class Call:
    __slots__ = ("ea", "target", "expr", "args", "dst")

    def __init__(self, ea, target=None, expr=None, args=None, dst=None):
        self.ea = ea
        self.target = target        # ea for a direct call
        self.expr = expr            # Expr for an indirect call
        self.args = list(args) if args else []
        self.dst = dst



class Intrinsic:
    __slots__ = ("ea", "name", "args", "note")

    def __init__(self, ea, name, args, note=""):
        self.ea = ea
        self.name = name
        self.args = args
        self.note = note


class Ret:
    __slots__ = ("ea", "kind", "val")

    def __init__(self, ea, kind="ret", val=None):
        self.ea = ea
        self.kind = kind
        self.val = val



class Goto:
    __slots__ = ("ea", "target")

    def __init__(self, ea, target):
        self.ea = ea
        self.target = target


class Branch:
    __slots__ = ("ea", "cond", "target", "fallthrough", "flag", "bittest")

    def __init__(self, ea, cond, target, fallthrough, bittest=None):
        self.ea = ea
        self.cond = cond            # 'z'/'nz'/'cy'/'ncy'/'h'/'nh' or None
        self.target = target
        self.fallthrough = fallthrough
        self.flag = None
        self.bittest = bittest      # (Bit, sense) for bt/bf


class Nop:
    __slots__ = ("ea",)

    def __init__(self, ea):
        self.ea = ea


class Switch:
    __slots__ = ("ea", "expr", "cases", "default", "table_ea")

    def __init__(self, ea, expr, cases, default=None, table_ea=None):
        self.ea = ea
        self.expr = expr
        self.cases = cases
        self.default = default
        self.table_ea = table_ea
