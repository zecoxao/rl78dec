"""
Address and code naming for the RL78 decompiler.

Absolute data addresses resolve to documented SFR names
(:data:`rl78dec.sfr.SFR_NAMES`), then to short saddr / RAM / far labels; code
addresses become ``sub_``/``loc_``.  Inside IDA the :class:`Namer` is fed IDA's
own names so the decompilation reuses whatever the analyst has applied.
"""

from . import sfr


class Namer:
    def __init__(self, cell_names=None, code_names=None):
        self.cell_names = dict(cell_names or {})
        self.code_names = dict(code_names or {})

    def cell(self, addr):
        n = self.cell_names.get(addr)
        if n:
            return n
        n = sfr.name_for(addr)
        if n:
            return n
        if 0xFFE20 <= addr <= 0xFFF1F:
            return "saddr_%02X" % (addr & 0xFF)
        if addr >= 0xF0000:
            return "ram_%04X" % (addr & 0xFFFF)
        return "m_%05X" % addr

    def code(self, ea):
        return self.code_names.get(ea) or ("sub_%X" % ea)

    def label(self, ea):
        return self.code_names.get(ea) or ("loc_%X" % ea)
