"""
RL78 register model.

The machine registers overlap: each 16-bit pair is two 8-bit registers
(``AX = A:X``, ``BC = B:C``, ``DE = D:E``, ``HL = H:L``; the first-named half is
the *high* byte), ``SP`` is ``SPH:SPL`` and ``CY`` is bit 0 of ``PSW``.  Every
register therefore decomposes into byte *atoms*; two registers alias iff their
atom sets intersect.  This module is the single source of truth for that
decomposition, and for the two ways registers also appear in data memory:

* the four general-purpose register banks are memory-mapped at
  ``0xFFEE0..0xFFEFF`` (RB0 at ``0xFFEF8``, RB1 ``0xFFEF0``, RB2 ``0xFFEE8``,
  RB3 ``0xFFEE0``; within a bank the order is ``X A C B E D L H``), and
* ``SPL/SPH/PSW/CS/ES`` sit at the top of the SFR area.
"""

from . import isa

# pair -> (low atom, high atom)
PAIRS = {
    "ax": ("x", "a"),
    "bc": ("c", "b"),
    "de": ("e", "d"),
    "hl": ("l", "h"),
    "sp": ("spl", "sph"),
}
GPR_PAIRS = frozenset(isa.R16)

_HALF = {}
for _p, (_lo, _hi) in PAIRS.items():
    _HALF[_lo] = (_p, 0)
    _HALF[_hi] = (_p, 1)

# PSW holds CY, Z, RBS, etc.
_COMPOSITE = {
    "psw": ("psw", "cy", "z", "rbs"),
    "cy": ("cy",),
    "z": ("z",),
    "rbs": ("rbs",),
}

GPR_ATOMS = frozenset(isa.R8)
ALL_ATOMS = GPR_ATOMS | frozenset(("es", "cs", "spl", "sph", "psw", "cy", "z", "rbs"))

GPR_BASE = 0xFFEE0
GPR_END = 0xFFF00


def atoms(name):
    """Byte atoms of register *name*, low byte first for pairs."""
    if name in PAIRS:
        return PAIRS[name]
    return _COMPOSITE.get(name, (name,))


def overlaps(a, b):
    return bool(set(atoms(a)) & set(atoms(b)))


def compose(name, atom_values):
    """Reconstruct register value from an atom->value mapping.

    Returns an int if all required atoms are present and numeric, else None.
    """
    if name in PAIRS:
        lo_atom, hi_atom = PAIRS[name]
        lo = atom_values.get(lo_atom)
        hi = atom_values.get(hi_atom)
        if lo is not None and hi is not None and isinstance(lo, int) and isinstance(hi, int):
            return ((hi & 0xFF) << 8) | (lo & 0xFF)
        return None
    v = atom_values.get(name)
    return v if isinstance(v, int) else None


def decompose(name, val):
    """Decompose a register value into {atom: byte_val} dict."""
    if name in PAIRS:
        lo_atom, hi_atom = PAIRS[name]
        return {lo_atom: val & 0xFF, hi_atom: (val >> 8) & 0xFF}
    return {name: val & 0xFF}


def pair_of(atom):
    """``(pair, 0 for low / 1 for high)`` for a byte register, else None."""
    return _HALF.get(atom)


def width(name):
    return "w" if name in PAIRS else "b"


def bank_base(bank):
    return 0xFFEF8 - 8 * bank


def gpr_bank_slot(addr):
    """``(bank, offset)`` of a GPR-area address, or None."""
    if not (GPR_BASE <= addr < GPR_END):
        return None
    rel = addr - GPR_BASE
    return 3 - rel // 8, rel % 8


def gpr_alias(addr, width, bank):
    """Register name that data address *addr* aliases in register bank *bank*.

    Returns None when *bank* is unknown, when the address is outside the
    active bank (an inactive bank is ordinary memory), or for a misaligned
    word access."""
    if bank is None:
        return None
    slot = gpr_bank_slot(addr)
    if slot is None or slot[0] != bank:
        return None
    off = slot[1]
    if width == "w":
        return isa.R16[off >> 1] if off % 2 == 0 else None
    return isa.R8[off]


# (address, width) -> register for the CPU registers in the SFR area
_SPECIAL = {
    (0xFFFF8, "w"): "sp",
    (0xFFFF8, "b"): "spl",
    (0xFFFF9, "b"): "sph",
    (0xFFFFA, "b"): "psw",
    (0xFFFFC, "b"): "cs",
    (0xFFFFD, "b"): "es",
}


def special_reg(addr, width):
    return _SPECIAL.get((addr, width))
