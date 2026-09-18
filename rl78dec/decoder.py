"""
RL78 instruction decoder.

A faithful Python port of fail0verflow's ``rl78-ida-proc`` (reg.cpp): the main
opcode map ``ana`` plus the three prefix maps (0x31/0x61/0x71) and the operand
helpers.  Decoding is byte-stream, little-endian, variable length (1-4 bytes,
plus the optional 0x11 ES prefix).

Each instruction becomes an :class:`Insn` carrying a mnemonic and a list of
:class:`Operand`.  Operand ``mode`` values:

    reg    register (``reg``)
    imm    immediate (``value``, ``width``)
    mem    absolute data address (``addr``, ``width``, ``es``)   saddr/sfr/!addr16
    bit    single bit (``base`` in reg/mem/ind, plus ``reg``/``addr``/``base_reg``, ``bit``)
    ind    [reg (+ disp)]         (``base_reg``, ``disp``, ``width``, ``es``)
    idx16  word[reg]  = mem[imm16 + reg]   (``disp``, ``base_reg``)
    hloff  [hl + reg]                      (``base_reg`` = index reg)
    near   code target within segment      (``addr``)
    far    20-bit code target              (``addr``)
    callt  vector-table entry              (``addr``)
"""

from . import isa


class Operand:
    __slots__ = ("mode", "reg", "value", "addr", "base_reg", "disp",
                 "bit", "base", "width", "es")

    def __init__(self, mode, reg=None, value=0, addr=0, base_reg=None,
                 disp=0, bit=0, base=None, width="b", es=False):
        self.mode = mode
        self.reg = reg
        self.value = value
        self.addr = addr
        self.base_reg = base_reg
        self.disp = disp
        self.bit = bit
        self.base = base
        self.width = width
        self.es = es


class Insn:
    __slots__ = ("ea", "size", "mnem", "ops", "es", "raw")

    def __init__(self, ea):
        self.ea = ea
        self.size = 0
        self.mnem = None
        self.ops = []
        self.es = False
        self.raw = b""

    def op(self, i):
        return self.ops[i] if i < len(self.ops) else None

    def __repr__(self):
        return "<Insn %05X %s>" % (self.ea, self.mnem)


class _Dec:
    def __init__(self, image, base, ea):
        self.image = image
        self.base = base
        self.start = ea - base          # file offset of the instruction
        self.pos = self.start
        self.ea = ea
        self.ins = Insn(ea)
        self.es = False

    # -- byte stream --------------------------------------------------------

    def u8(self):
        b = self.image[self.pos]
        self.pos += 1
        return b

    def u16(self):
        lo = self.u8()
        hi = self.u8()
        return lo | (hi << 8)

    @property
    def consumed(self):
        return self.pos - self.start

    def add(self, op):
        self.ins.ops.append(op)

    # -- operand builders (mirror reg.cpp operand_*) ------------------------

    def imm_val(self, v):
        self.add(Operand("imm", value=v, width="b"))

    def imm8(self):
        self.add(Operand("imm", value=self.u8(), width="b"))

    def imm16(self):
        self.add(Operand("imm", value=self.u16(), width="w"))

    def reg(self, name):
        self.add(Operand("reg", reg=name))

    def saddr(self, width="b"):
        self.add(Operand("mem", addr=isa.saddr_abs(self.u8()), width=width))

    def saddrp(self):
        self.saddr("w")

    def sfr(self, width="b"):
        addr = isa.sfr_abs(self.u8())
        self.add(self._convert(Operand("mem", addr=addr, width=width)))

    def sfrp(self):
        self.sfr("w")

    def r_bit(self, name, bit):
        self.add(Operand("bit", base="reg", reg=name, bit=bit))

    def saddr_bit(self, bit):
        self.add(Operand("bit", base="mem", addr=isa.saddr_abs(self.u8()), bit=bit))

    def sfr_bit(self, bit):
        addr = isa.sfr_abs(self.u8())
        self.add(self._convert(Operand("bit", base="mem", addr=addr, bit=bit)))

    def r_ind(self, name, width="b"):
        self.add(Operand("ind", base_reg=name, disp=0, width=width, es=self.es))

    def r_ind_bit(self, name, bit):
        self.add(Operand("bit", base="ind", base_reg=name, bit=bit, es=self.es))

    def r_off_imm8(self, name, width="b"):
        self.add(Operand("ind", base_reg=name, disp=self.u8(), width=width, es=self.es))

    def r_off_imm16(self, name, width="b"):
        self.add(Operand("idx16", base_reg=name, disp=self.u16(), width=width, es=self.es))

    def hl_off_reg(self, name):
        self.add(Operand("hloff", base_reg=name, es=self.es))

    def addr_rel(self):
        disp = self.u8()
        if disp >= 0x80:
            disp -= 0x100
        tgt = self.ea + self.consumed + disp
        self.add(Operand("near", addr=tgt & 0xFFFFF))

    def addr16_rel(self):
        disp = self.u16()
        if disp >= 0x8000:
            disp -= 0x10000
        tgt = self.ea + self.consumed + disp
        self.add(Operand("near", addr=tgt & 0xFFFFF))

    def addr16_abs(self):                 # code, segment 0
        self.add(Operand("near", addr=self.u16()))

    def addr16_abs_d(self, width="b"):    # data
        addr = self.u16()
        if not self.es:
            addr += 0xF << 16
        self.add(self._convert(Operand("mem", addr=addr, width=width, es=self.es)))

    def addr16_abs_d16(self):
        self.addr16_abs_d("w")

    def addr16_abs_bit(self, bit):
        addr = self.u16()
        if not self.es:
            addr += 0xF << 16
        self.add(self._convert(Operand("bit", base="mem", addr=addr, bit=bit, es=self.es)))

    def addr20_abs(self):
        addr = self.u16()
        addr |= self.u8() << 16
        self.add(Operand("far", addr=addr))

    def callt(self, addr):
        self.add(Operand("callt", addr=addr, width="w"))

    @staticmethod
    def _convert(op):
        """SFR/abs addresses that name SP/PSW/CS/ES become registers."""
        m = {0xFFFF8: "sp", 0xFFFFA: "psw", 0xFFFFC: "cs", 0xFFFFD: "es"}
        name = m.get(op.addr)
        if name is None:
            return op
        if op.mode == "bit":
            return Operand("bit", base="reg", reg=name, bit=op.bit)
        return Operand("reg", reg=name)

    # -- finalise -----------------------------------------------------------

    def finish(self, mnem):
        self.ins.mnem = mnem
        self.ins.es = self.es
        self.ins.size = self.consumed
        self.ins.raw = bytes(self.image[self.start:self.pos])
        return self.ins


# ---------------------------------------------------------------------------
# prefix maps
# ---------------------------------------------------------------------------

_ALU8 = ("add", "addc", "sub", "subc", "cmp", "and", "or", "xor")


def _map31(d):
    code = d.u8()
    lo, hi = code & 0xF, (code >> 4) & 0xF
    if lo <= 5:
        mnem = ("btclr", "btclr", "bt", "bt", "bf", "bf")[lo]
        bit = hi & 7
        sel = code & 0x81
        if sel == 0x00:
            d.saddr_bit(bit)
        elif sel == 0x01:
            d.r_bit("a", bit)
        elif sel == 0x80:
            d.sfr_bit(bit)
        else:
            d.r_ind_bit("hl", bit)
        d.addr_rel()
        return d.finish(mnem)
    if 7 <= lo <= 0xB and 1 <= hi <= 7:
        mnem = ("shl", "shl", "shl", "shr", "sar")[lo - 7]
        if mnem == "shl":
            d.reg(("c", "b", "a")[lo - 7])
        else:
            d.reg("a")
        d.imm_val(hi)
        return d.finish(mnem)
    if lo >= 0xC and hi >= 1:
        mnem = ("shlw", "shlw", "shrw", "sarw")[lo - 0xC]
        if mnem == "shlw":
            d.reg(("bc", "ax")[lo - 0xC])
        else:
            d.reg("ax")
        d.imm_val(hi)
        return d.finish(mnem)
    return None


def _map61(d):
    code = d.u8()
    lo, hi = code & 0xF, (code >> 4) & 0xF
    if hi <= 7 and lo <= 7:
        d.reg(isa.R8[lo]); d.reg("a")
        return d.finish(_ALU8[hi])
    if (hi <= 7 and lo == 8) or (hi <= 8 and lo >= 0xA):
        d.reg("a"); d.reg(isa.R8[lo & 7])
        return d.finish(_ALU8[hi])
    if hi >= 8 and 4 <= lo <= 7:
        addr = 0x80 | ((lo & 3) << 4) | ((hi & 7) << 1)
        d.callt(addr)
        return d.finish("callt")

    simple = {
        0x09: ("addw", lambda: (d.reg("ax"), d.r_off_imm8("hl", "w"))),
        0x29: ("subw", lambda: (d.reg("ax"), d.r_off_imm8("hl", "w"))),
        0x49: ("cmpw", lambda: (d.reg("ax"), d.r_off_imm8("hl", "w"))),
        0x59: ("inc", lambda: d.r_off_imm8("hl")),
        0x69: ("dec", lambda: d.r_off_imm8("hl")),
        0x79: ("incw", lambda: d.r_off_imm8("hl", "w")),
        0x89: ("decw", lambda: d.r_off_imm8("hl", "w")),
        0xC3: ("bh", d.addr_rel), 0xD3: ("bnh", d.addr_rel),
        0xE3: ("skh", None), 0xF3: ("sknh", None),
        0xA8: ("xch", lambda: (d.reg("a"), d.saddr())),
        0xB8: ("mov", lambda: (d.reg("es"), d.saddr())),
        0xA9: ("xch", lambda: (d.reg("a"), d.hl_off_reg("c"))),
        0xB9: ("xch", lambda: (d.reg("a"), d.hl_off_reg("b"))),
        0xAA: ("xch", lambda: (d.reg("a"), d.addr16_abs_d())),
        0xAB: ("xch", lambda: (d.reg("a"), d.sfr())),
        0xAC: ("xch", lambda: (d.reg("a"), d.r_ind("hl"))),
        0xAD: ("xch", lambda: (d.reg("a"), d.r_off_imm8("hl"))),
        0xAE: ("xch", lambda: (d.reg("a"), d.r_ind("de"))),
        0xAF: ("xch", lambda: (d.reg("a"), d.r_off_imm8("de"))),
        0xC8: ("skc", None), 0xD8: ("sknc", None),
        0xE8: ("skz", None), 0xF8: ("sknz", None),
        0xC9: ("mov", lambda: (d.reg("a"), d.hl_off_reg("b"))),
        0xD9: ("mov", lambda: (d.hl_off_reg("b"), d.reg("a"))),
        0xE9: ("mov", lambda: (d.reg("a"), d.hl_off_reg("c"))),
        0xF9: ("mov", lambda: (d.hl_off_reg("c"), d.reg("a"))),
        0xCB: ("br", lambda: d.reg("ax")),
        0xDB: ("ror", lambda: (d.reg("a"), d.imm_val(1))),
        0xEB: ("rol", lambda: (d.reg("a"), d.imm_val(1))),
        0xFB: ("rorc", lambda: (d.reg("a"), d.imm_val(1))),
        0xCC: ("brk", None),
        0xDC: ("rolc", lambda: (d.reg("a"), d.imm_val(1))),
        0xEC: ("retb", None), 0xFC: ("reti", None),
        0xCD: ("pop", lambda: d.reg("psw")),
        0xDD: ("push", lambda: d.reg("psw")),
        0xED: ("halt", None), 0xFD: ("stop", None),
        0xCE: ("movs", lambda: (d.r_off_imm8("hl"), d.reg("x"))),
        0xDE: ("cmps", lambda: (d.reg("x"), d.r_off_imm8("hl"))),
        0xEE: ("rolwc", lambda: (d.reg("ax"), d.imm_val(1))),
        0xFE: ("rolwc", lambda: (d.reg("bc"), d.imm_val(1))),
    }
    if code in simple:
        mnem, fn = simple[code]
        if fn:
            fn()
        return d.finish(mnem)
    # ALU a,[hl+b] / a,[hl+c]
    if lo == 0 and code in (0x80, 0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0):
        d.reg("a"); d.hl_off_reg("b")
        return d.finish(_ALU8[hi & 7])
    if lo == 2 and code in (0x82, 0x92, 0xA2, 0xB2, 0xC2, 0xD2, 0xE2, 0xF2):
        d.reg("a"); d.hl_off_reg("c")
        return d.finish(_ALU8[hi & 7])
    if lo == 0xA and code in (0xCA, 0xDA, 0xEA, 0xFA):
        d.reg(isa.R16[hi & 3])
        return d.finish("call")
    if lo == 0xF and code in (0xCF, 0xDF, 0xEF, 0xFF):
        d.reg(isa.RB[hi & 3])
        return d.finish("sel")
    return None


_MAP71 = ("set1", "mov1", "set1", "clr1", "mov1", "and1", "or1", "xor1",
          "clr1", "mov1", "set1", "clr1", "mov1", "and1", "or1", "xor1")


def _map71(d):
    code = d.u8()
    lo, hi = code & 0xF, (code >> 4) & 0xF
    if hi >= 8 and lo == 0:
        if hi == 8:
            d.reg("cy"); return d.finish("set1")
        if hi == 0xC:
            d.reg("cy"); return d.finish("not1")
        return None
    if hi >= 8 and lo == 8:
        if hi == 8:
            d.reg("cy"); return d.finish("clr1")
        return None

    mnem = _MAP71[lo]
    bit = hi & 7
    sel = code & 0x8F
    if sel == 0x01:
        d.saddr_bit(bit); d.reg("cy")
    elif sel == 0x81:
        d.r_ind_bit("hl", bit); d.reg("cy")
    elif sel in (0x02, 0x03):
        d.saddr_bit(bit)
    elif sel in (0x82, 0x83):
        d.r_ind_bit("hl", bit)
    elif sel in (0x04, 0x05, 0x06, 0x07):
        d.reg("cy"); d.saddr_bit(bit)
    elif sel in (0x84, 0x85, 0x86, 0x87):
        d.reg("cy"); d.r_ind_bit("hl", bit)
    elif sel in (0x00, 0x08):
        d.addr16_abs_bit(bit)
    elif sel == 0x09:
        d.sfr_bit(bit); d.reg("cy")
    elif sel == 0x89:
        d.r_bit("a", bit); d.reg("cy")
    elif sel in (0x0A, 0x0B):
        d.sfr_bit(bit)
    elif sel in (0x8A, 0x8B):
        d.r_bit("a", bit)
    elif sel in (0x0C, 0x0D, 0x0E, 0x0F):
        d.reg("cy"); d.sfr_bit(bit)
    elif sel in (0x8C, 0x8D, 0x8E, 0x8F):
        d.reg("cy"); d.r_bit("a", bit)
    else:
        return None
    return d.finish(mnem)


# ---------------------------------------------------------------------------
# main opcode map (ana)
# ---------------------------------------------------------------------------

def _main(d, code):
    lo, hi = code & 0xF, (code >> 4) & 0xF

    # ALU low-nibble group: add/addc/sub/subc/cmp/and/or/xor
    if lo >= 0xA and hi <= 7:
        mnem = _ALU8[hi]
        if lo == 0xA:
            d.saddr()
        else:
            d.reg("a")
        if lo in (0xA, 0xC):
            d.imm8()
        elif lo == 0xB:
            d.saddr()
        elif lo == 0xD:
            d.r_ind("hl")
        elif lo == 0xE:
            d.r_off_imm8("hl")
        elif lo == 0xF:
            d.addr16_abs_d()
        return d.finish(mnem)

    if code == 0x31:
        return _map31(d)
    if code == 0x61:
        return _map61(d)
    if code == 0x71:
        return _map71(d)

    # register-index ranges
    if code in (0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57):
        d.reg(isa.R8[lo]); d.imm8(); return d.finish("mov")
    if code in (0x60, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67):
        d.reg("a"); d.reg(isa.R8[lo]); return d.finish("mov")
    if code in (0x70, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77):
        d.reg(isa.R8[lo]); d.reg("a"); return d.finish("mov")
    if code in (0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87):
        d.reg(isa.R8[lo]); return d.finish("inc")
    if code in (0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97):
        d.reg(isa.R8[lo]); return d.finish("dec")
    if code in (0xD0, 0xD1, 0xD2, 0xD3):
        d.reg(isa.R8[lo]); return d.finish("cmp0")
    if code in (0xE0, 0xE1, 0xE2, 0xE3):
        d.reg(isa.R8[lo]); return d.finish("oneb")
    if code in (0xF0, 0xF1, 0xF2, 0xF3):
        d.reg(isa.R8[lo]); return d.finish("clrb")
    if code in (0xC0, 0xC2, 0xC4, 0xC6):
        d.reg(isa.R16[lo >> 1]); return d.finish("pop")
    if code in (0xC1, 0xC3, 0xC5, 0xC7):
        d.reg(isa.R16[lo >> 1]); return d.finish("push")
    if code in (0xE6, 0xE7):
        d.reg(isa.R16[lo & 1]); return d.finish("onew")
    if code in (0xF6, 0xF7):
        d.reg(isa.R16[lo & 1]); return d.finish("clrw")

    m = _MAIN.get(code)
    if m is None:
        return None
    mnem, fn = m
    if fn:
        fn(d)
    return d.finish(mnem)


# one-off encodings: code -> (mnem, builder)
_MAIN = {
    0x00: ("nop", None),
    0x01: ("addw", lambda d: (d.reg("ax"), d.reg("ax"))),
    0x02: ("addw", lambda d: (d.reg("ax"), d.addr16_abs_d16())),
    0x03: ("addw", lambda d: (d.reg("ax"), d.reg("bc"))),
    0x04: ("addw", lambda d: (d.reg("ax"), d.imm16())),
    0x05: ("addw", lambda d: (d.reg("ax"), d.reg("de"))),
    0x06: ("addw", lambda d: (d.reg("ax"), d.saddrp())),
    0x07: ("addw", lambda d: (d.reg("ax"), d.reg("hl"))),
    0x08: ("xch", lambda d: (d.reg("a"), d.reg("x"))),
    0x09: ("mov", lambda d: (d.reg("a"), d.r_off_imm16("b"))),
    0x10: ("addw", lambda d: (d.reg("sp"), d.imm8())),
    0x12: ("movw", lambda d: (d.reg("bc"), d.reg("ax"))),
    0x13: ("movw", lambda d: (d.reg("ax"), d.reg("bc"))),
    0x14: ("movw", lambda d: (d.reg("de"), d.reg("ax"))),
    0x15: ("movw", lambda d: (d.reg("ax"), d.reg("de"))),
    0x16: ("movw", lambda d: (d.reg("hl"), d.reg("ax"))),
    0x17: ("movw", lambda d: (d.reg("ax"), d.reg("hl"))),
    0x18: ("mov", lambda d: (d.r_off_imm16("b"), d.reg("a"))),
    0x19: ("mov", lambda d: (d.r_off_imm16("b"), d.imm8())),
    0x20: ("subw", lambda d: (d.reg("sp"), d.imm8())),
    0x22: ("subw", lambda d: (d.reg("ax"), d.addr16_abs_d16())),
    0x23: ("subw", lambda d: (d.reg("ax"), d.reg("bc"))),
    0x24: ("subw", lambda d: (d.reg("ax"), d.imm16())),
    0x25: ("subw", lambda d: (d.reg("ax"), d.reg("de"))),
    0x26: ("subw", lambda d: (d.reg("ax"), d.saddrp())),
    0x27: ("subw", lambda d: (d.reg("ax"), d.reg("hl"))),
    0x28: ("mov", lambda d: (d.r_off_imm16("c"), d.reg("a"))),
    0x29: ("mov", lambda d: (d.reg("a"), d.r_off_imm16("c"))),
    0x30: ("movw", lambda d: (d.reg("ax"), d.imm16())),
    0x32: ("movw", lambda d: (d.reg("bc"), d.imm16())),
    0x33: ("xchw", lambda d: (d.reg("ax"), d.reg("bc"))),
    0x34: ("movw", lambda d: (d.reg("de"), d.imm16())),
    0x35: ("xchw", lambda d: (d.reg("ax"), d.reg("de"))),
    0x36: ("movw", lambda d: (d.reg("hl"), d.imm16())),
    0x37: ("xchw", lambda d: (d.reg("ax"), d.reg("hl"))),
    0x38: ("mov", lambda d: (d.r_off_imm16("c"), d.imm8())),
    0x39: ("mov", lambda d: (d.r_off_imm16("bc"), d.imm8())),
    0x40: ("cmp", lambda d: (d.addr16_abs_d(), d.imm8())),
    0x41: ("mov", lambda d: (d.reg("es"), d.imm8())),
    0x42: ("cmpw", lambda d: (d.reg("ax"), d.addr16_abs_d16())),
    0x43: ("cmpw", lambda d: (d.reg("ax"), d.reg("bc"))),
    0x44: ("cmpw", lambda d: (d.reg("ax"), d.imm16())),
    0x45: ("cmpw", lambda d: (d.reg("ax"), d.reg("de"))),
    0x46: ("cmpw", lambda d: (d.reg("ax"), d.saddrp())),
    0x47: ("cmpw", lambda d: (d.reg("ax"), d.reg("hl"))),
    0x48: ("mov", lambda d: (d.r_off_imm16("bc"), d.reg("a"))),
    0x49: ("mov", lambda d: (d.reg("a"), d.r_off_imm16("bc"))),
    0x58: ("movw", lambda d: (d.r_off_imm16("b", "w"), d.reg("ax"))),
    0x59: ("movw", lambda d: (d.reg("ax"), d.r_off_imm16("b", "w"))),
    0x68: ("movw", lambda d: (d.r_off_imm16("c", "w"), d.reg("ax"))),
    0x69: ("movw", lambda d: (d.reg("ax"), d.r_off_imm16("c", "w"))),
    0x78: ("movw", lambda d: (d.r_off_imm16("bc", "w"), d.reg("ax"))),
    0x79: ("movw", lambda d: (d.reg("ax"), d.r_off_imm16("bc", "w"))),
    0x88: ("mov", lambda d: (d.reg("a"), d.r_off_imm8("sp"))),
    0x89: ("mov", lambda d: (d.reg("a"), d.r_ind("de"))),
    0x8A: ("mov", lambda d: (d.reg("a"), d.r_off_imm8("de"))),
    0x8B: ("mov", lambda d: (d.reg("a"), d.r_ind("hl"))),
    0x8C: ("mov", lambda d: (d.reg("a"), d.r_off_imm8("hl"))),
    0x8D: ("mov", lambda d: (d.reg("a"), d.saddr())),
    0x8E: ("mov", lambda d: (d.reg("a"), d.sfr())),
    0x8F: ("mov", lambda d: (d.reg("a"), d.addr16_abs_d())),
    0x98: ("mov", lambda d: (d.r_off_imm8("sp"), d.reg("a"))),
    0x99: ("mov", lambda d: (d.r_ind("de"), d.reg("a"))),
    0x9A: ("mov", lambda d: (d.r_off_imm8("de"), d.reg("a"))),
    0x9B: ("mov", lambda d: (d.r_ind("hl"), d.reg("a"))),
    0x9C: ("mov", lambda d: (d.r_off_imm8("hl"), d.reg("a"))),
    0x9D: ("mov", lambda d: (d.saddr(), d.reg("a"))),
    0x9E: ("mov", lambda d: (d.sfr(), d.reg("a"))),
    0x9F: ("mov", lambda d: (d.addr16_abs_d(), d.reg("a"))),
    0xA0: ("inc", lambda d: d.addr16_abs_d()),
    0xB0: ("dec", lambda d: d.addr16_abs_d()),
    0xA1: ("incw", lambda d: d.reg("ax")),
    0xB1: ("decw", lambda d: d.reg("ax")),
    0xA2: ("incw", lambda d: d.addr16_abs_d16()),
    0xB2: ("decw", lambda d: d.addr16_abs_d16()),
    0xA3: ("incw", lambda d: d.reg("bc")),
    0xB3: ("decw", lambda d: d.reg("bc")),
    0xA4: ("inc", lambda d: d.saddr()),
    0xB4: ("dec", lambda d: d.saddr()),
    0xA5: ("incw", lambda d: d.reg("de")),
    0xB5: ("decw", lambda d: d.reg("de")),
    0xA6: ("incw", lambda d: d.saddrp()),
    0xB6: ("decw", lambda d: d.saddrp()),
    0xA7: ("incw", lambda d: d.reg("hl")),
    0xB7: ("decw", lambda d: d.reg("hl")),
    0xA8: ("movw", lambda d: (d.reg("ax"), d.r_off_imm8("sp", "w"))),
    0xB8: ("movw", lambda d: (d.r_off_imm8("sp", "w"), d.reg("ax"))),
    0xA9: ("movw", lambda d: (d.reg("ax"), d.r_ind("de", "w"))),
    0xB9: ("movw", lambda d: (d.r_ind("de", "w"), d.reg("ax"))),
    0xAA: ("movw", lambda d: (d.reg("ax"), d.r_off_imm8("de", "w"))),
    0xBA: ("movw", lambda d: (d.r_off_imm8("de", "w"), d.reg("ax"))),
    0xAB: ("movw", lambda d: (d.reg("ax"), d.r_ind("hl", "w"))),
    0xBB: ("movw", lambda d: (d.r_ind("hl", "w"), d.reg("ax"))),
    0xAC: ("movw", lambda d: (d.reg("ax"), d.r_off_imm8("hl", "w"))),
    0xBC: ("movw", lambda d: (d.r_off_imm8("hl", "w"), d.reg("ax"))),
    0xAD: ("movw", lambda d: (d.reg("ax"), d.saddrp())),
    0xBD: ("movw", lambda d: (d.saddrp(), d.reg("ax"))),
    0xAE: ("movw", lambda d: (d.reg("ax"), d.sfrp())),
    0xBE: ("movw", lambda d: (d.sfrp(), d.reg("ax"))),
    0xAF: ("movw", lambda d: (d.reg("ax"), d.addr16_abs_d16())),
    0xBF: ("movw", lambda d: (d.addr16_abs_d16(), d.reg("ax"))),
    0xC8: ("mov", lambda d: (d.r_off_imm8("sp"), d.imm8())),
    0xC9: ("movw", lambda d: (d.saddrp(), d.imm16())),
    0xCA: ("mov", lambda d: (d.r_off_imm8("de"), d.imm8())),
    0xCB: ("movw", lambda d: (d.sfrp(), d.imm16())),
    0xCC: ("mov", lambda d: (d.r_off_imm8("hl"), d.imm8())),
    0xCD: ("mov", lambda d: (d.saddr(), d.imm8())),
    0xCE: ("mov", lambda d: (d.sfr(), d.imm8())),
    0xCF: ("mov", lambda d: (d.addr16_abs_d(), d.imm8())),
    0xD4: ("cmp0", lambda d: d.saddr()),
    0xD5: ("cmp0", lambda d: d.addr16_abs_d()),
    0xD6: ("mulu", lambda d: d.reg("x")),
    0xD7: ("ret", None),
    0xD8: ("mov", lambda d: (d.reg("x"), d.saddr())),
    0xE8: ("mov", lambda d: (d.reg("b"), d.saddr())),
    0xF8: ("mov", lambda d: (d.reg("c"), d.saddr())),
    0xD9: ("mov", lambda d: (d.reg("x"), d.addr16_abs_d())),
    0xE9: ("mov", lambda d: (d.reg("b"), d.addr16_abs_d())),
    0xF9: ("mov", lambda d: (d.reg("c"), d.addr16_abs_d())),
    0xDA: ("movw", lambda d: (d.reg("bc"), d.saddrp())),
    0xEA: ("movw", lambda d: (d.reg("de"), d.saddrp())),
    0xFA: ("movw", lambda d: (d.reg("hl"), d.saddrp())),
    0xDB: ("movw", lambda d: (d.reg("bc"), d.addr16_abs_d16())),
    0xEB: ("movw", lambda d: (d.reg("de"), d.addr16_abs_d16())),
    0xFB: ("movw", lambda d: (d.reg("hl"), d.addr16_abs_d16())),
    0xDC: ("bc", lambda d: d.addr_rel()),
    0xDD: ("bz", lambda d: d.addr_rel()),
    0xDE: ("bnc", lambda d: d.addr_rel()),
    0xDF: ("bnz", lambda d: d.addr_rel()),
    0xEC: ("br", lambda d: d.addr20_abs()),
    0xED: ("br", lambda d: d.addr16_abs()),
    0xEE: ("br", lambda d: d.addr16_rel()),
    0xEF: ("br", lambda d: d.addr_rel()),
    0xE4: ("oneb", lambda d: d.saddr()),
    0xE5: ("oneb", lambda d: d.addr16_abs_d()),
    0xF4: ("clrb", lambda d: d.saddr()),
    0xF5: ("clrb", lambda d: d.addr16_abs_d()),
    0xFC: ("call", lambda d: d.addr20_abs()),
    0xFD: ("call", lambda d: d.addr16_abs()),
    0xFE: ("call", lambda d: d.addr16_rel()),
    0xFF: ("brk1", None),
}


# ---------------------------------------------------------------------------
# public API
# ---------------------------------------------------------------------------

def decode_one(image, ea, base=0):
    """Decode one instruction at *ea*; return an :class:`Insn` or ``None``."""
    off = ea - base
    if off < 0 or off >= len(image):
        return None
    d = _Dec(image, base, ea)
    try:
        code = d.u8()
        if code == 0x11:                 # ES: prefix
            d.es = True
            code = d.u8()
        ins = _main(d, code)
    except IndexError:
        return None
    return ins


def target_of(ins):
    """Static code target of a branch/call, or None."""
    if not ins.ops:
        return None
    op = ins.ops[-1] if ins.mnem in ("bt", "bf", "btclr") else ins.ops[0]
    if op.mode in ("near", "far"):
        return op.addr
    return None


def _succ(ins):
    m = ins.mnem
    out = []
    tgt = target_of(ins)
    if m == "br":
        if tgt is not None:
            out.append(("jump", tgt))
    elif m in isa.RET or m in ("brk", "stop"):
        pass
    elif m in isa.COND_BRANCH or m in isa.BIT_BRANCH:
        if tgt is not None:
            out.append(("jump", tgt))
        out.append(("fall", ins.ea + ins.size))
    elif m == "call":
        if tgt is not None:
            out.append(("call", tgt))
        out.append(("fall", ins.ea + ins.size))
    else:
        out.append(("fall", ins.ea + ins.size))
    return out


def decode(image, entries, base=0):
    """Recursive-descent decode from *entries*.  Returns (insns, calls)."""
    insns = {}
    calls = set()
    seen = set()
    work = [e for e in entries if base <= e < base + len(image)]
    while work:
        ea = work.pop()
        if ea in seen or not (base <= ea < base + len(image)):
            continue
        seen.add(ea)
        ins = decode_one(image, ea, base)
        if ins is None or ins.size == 0:
            continue
        insns[ea] = ins
        for how, tgt in _succ(ins):
            if tgt is None:
                continue
            if how == "call":
                calls.add(tgt)
            work.append(tgt)
    return insns, calls
