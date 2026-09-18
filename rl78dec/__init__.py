"""
rl78dec -- a decompiler for the Renesas RL78, targeting the PlayStation 4/5
"syscon" system-controller firmware.

IDA's (fail0verflow) RL78 processor module is used purely as a decoder in the
IDA front end; the standalone package re-implements that decoder so the whole
pipeline runs headless on a raw flash dump.  Design mirrors zecoxao's ``spudec``
and the Kirk/Spock ``startrekdec``:

    decoder -> lifter -> cfg -> opt -> structure -> cgen
"""

from . import decoder, cfg, opt, structure, cgen, loader
from .names import Namer

__version__ = "0.1.0"

BANNER = [
    "/*",
    " * Decompiled by rl78dec -- Renesas RL78 (PS4/PS5 syscon).",
    " * Registers a/x/ax/bc/de/hl etc. are the machine registers; mem8/mem16",
    " * index data memory (SFRs and saddr cells shown by name).  CY/HF compares",
    " * are unsigned.  Unmodelled opcodes are printed as pseudo-calls.",
    " */",
    "",
]


class Function:
    def __init__(self, entry, name, func, tree, lines):
        self.entry = entry
        self.name = name
        self.cfg = func
        self.tree = tree
        self.lines = lines


class Program:
    def __init__(self, image, insns, funcs, namer):
        self.image = image
        self.insns = insns
        self.funcs = funcs
        self.namer = namer

    def listing(self, banner=True):
        out = list(BANNER) if banner else []
        for entry in sorted(self.funcs):
            out.extend(self.funcs[entry].lines)
            out.append("")
        return "\n".join(out)


def decompile_image(image, entries, base=0, cell_names=None, code_names=None):
    insns, calls = decoder.decode(image, entries=entries, base=base)
    funcs = cfg.build_functions(insns, calls, extra_entries=entries)
    namer = Namer(cell_names=cell_names, code_names=code_names)
    out = {}
    for entry, f in funcs.items():
        opt.optimize(f)
        tree = structure.structure(f)
        lines = cgen.generate(f, tree, namer)
        out[entry] = Function(entry, namer.code(entry), f, tree, lines)
    return Program(image, insns, out, namer)


def decompile_file(path, extra_entries=(), **kw):
    image = loader.load(path)
    entries = list(loader.vector_entries(image)) + list(extra_entries)
    return decompile_image(image, entries=entries, **kw)
