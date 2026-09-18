"""
IDA integration for rl78dec.

Run inside IDA on a database opened with fail0verflow's RL78 processor module
(``rl78-ida-proc``).  The bridge reads the flash bytes out of the database,
uses IDA's function boundaries as entry points, and wraps the naming layer so
the decompilation reuses whatever labels the analyst has applied.

IDA is imported lazily so importing :mod:`rl78dec` outside IDA stays clean.
"""

from . import decoder, cfg, opt, structure, cgen
from .names import Namer
from . import Program, Function, BANNER  # noqa: F401


class IdaNamer(Namer):
    def __init__(self):
        super().__init__()
        import ida_name
        self._ida_name = ida_name

    def _lookup(self, ea):
        return self._ida_name.get_name(ea) or None

    def cell(self, addr):
        return self._lookup(addr) or super().cell(addr)

    def code(self, ea):
        return self._lookup(ea) or super().code(ea)

    def label(self, ea):
        return self._lookup(ea) or super().label(ea)


def _read_image():
    import ida_bytes, ida_segment
    hi = 0
    seg = ida_segment.get_first_seg()
    while seg is not None:
        if seg.start_ea < 0x80000:
            hi = max(hi, seg.end_ea)
        seg = ida_segment.get_next_seg(seg.start_ea)
    hi = min(hi, 0x80000)
    data = bytearray(hi)
    got = ida_bytes.get_bytes(0, hi)
    if got:
        data[:len(got)] = got
    return data


def _entries():
    import idautils
    return sorted(idautils.Functions(0, 0x80000))


def decompile_program():
    image = _read_image()
    entries = _entries() or [0]
    insns, calls = decoder.decode(image, entries=entries, base=0)
    funcs = cfg.build_functions(insns, calls, extra_entries=entries)
    namer = IdaNamer()
    out = {}
    for entry, f in funcs.items():
        opt.optimize(f)
        tree = structure.structure(f)
        out[entry] = Function(entry, namer.code(entry), f, tree,
                              cgen.generate(f, tree, namer))
    return Program(image, insns, out, namer)


def decompile_one(ea):
    import ida_funcs
    f = ida_funcs.get_func(ea)
    entry = f.start_ea if f is not None else ea
    image = _read_image()
    entset = set(_entries()) | {entry}
    insns, _ = decoder.decode(image, entries=[entry] + _entries(), base=0)
    func = cfg.build_func(insns, entry, entset)
    if func is None:
        raise RuntimeError("rl78dec: nothing decoded at 0x%X" % entry)
    namer = IdaNamer()
    opt.optimize(func)
    tree = structure.structure(func)
    return Function(entry, namer.code(entry), func, tree,
                    cgen.generate(func, tree, namer, banner=BANNER))
