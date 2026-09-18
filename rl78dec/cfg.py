"""
Control-flow graph for RL78.

Carves the decoded stream into functions and basic blocks and lifts each block.
RL78 specifics handled here: ``call`` falls through, ``ret``/``reti``/``retb`` and
an unconditional ``br`` end a block, and the *skip* idiom
(``skz``/``skc``/``skh`` and negations) is lowered to a conditional branch that
jumps over exactly the next instruction.
"""

from . import ir, isa
from .lifter import lift_insn
from .decoder import target_of


class Block:
    __slots__ = ("start", "insns", "stmts", "succ", "term")

    def __init__(self, start):
        self.start = start
        self.insns = []
        self.stmts = []
        self.succ = []
        self.term = None


class Func:
    __slots__ = ("entry", "blocks", "calls", "name")

    def __init__(self, entry):
        self.entry = entry
        self.blocks = {}
        self.calls = set()
        self.name = None

    def ordered(self):
        return [self.blocks[k] for k in sorted(self.blocks)]


def _skip_target(insns, ea):
    """Address after the instruction that a skip at *ea* would skip."""
    n1 = ea + insns[ea].size
    nxt = insns.get(n1)
    return n1 + nxt.size if nxt else n1


def _succ(insns, ins):
    m = ins.mnem
    ea = ins.ea
    nxt = ea + ins.size
    if m in isa.SKIP:
        return [("cond", _skip_target(insns, ea)), ("fall", nxt)]
    if m == "br":
        t = target_of(ins)
        return [("jump", t)] if t is not None else []
    if m in isa.RET or m == "stop":
        return []
    if m in isa.COND_BRANCH or m in isa.BIT_BRANCH:
        t = target_of(ins)
        s = [("cond", t)] if t is not None else []
        s.append(("fall", nxt))
        return s
    return [("fall", nxt)]


def _collect_body(insns, entry, entry_set):
    body = set()
    work = [entry]
    while work:
        ea = work.pop()
        if ea in body or ea not in insns:
            continue
        body.add(ea)
        for how, tgt in _succ(insns, insns[ea]):
            if tgt in insns and (tgt == entry or tgt not in entry_set):
                work.append(tgt)
    return body


def _leaders(insns, body):
    leaders = set()
    for ea in body:
        ins = insns[ea]
        for how, tgt in _succ(insns, ins):
            if how in ("cond", "jump") and tgt in body:
                leaders.add(tgt)
        # instruction after any control transfer starts a block
        if ins.mnem in isa.COND_BRANCH or ins.mnem in isa.BIT_BRANCH \
                or ins.mnem in isa.SKIP or ins.mnem == "call" or ins.mnem == "callt" \
                or ins.mnem in isa.STOP or ins.mnem in isa.RET:
            nxt = ea + ins.size
            if nxt in body:
                leaders.add(nxt)
    return leaders


def _skip_branch(insns, ins):
    flag, sense = isa.SKIP[ins.mnem]
    cond = {("cy", True): "cy", ("cy", False): "ncy",
            ("z", True): "z", ("z", False): "nz",
            ("h", True): "h", ("h", False): "nh"}[(flag, sense)]
    return ir.Branch(ins.ea, cond, _skip_target(insns, ins.ea), ins.ea + ins.size)


def build_func(insns, entry, entry_set):
    body = _collect_body(insns, entry, entry_set)
    if not body:
        return None
    leaders = _leaders(insns, body)
    leaders.add(entry)

    f = Func(entry)
    cur = None
    for ea in sorted(body):
        ins = insns[ea]
        if ea in leaders or cur is None:
            cur = Block(ea)
            f.blocks[ea] = cur
        cur.insns.append(ins)

        succ = _succ(insns, ins)
        nxt = ea + ins.size
        term = None
        if ins.mnem == "br" and target_of(ins) is not None:
            term = ("goto", succ)
        elif ins.mnem == "br":
            term = ("ret", [])                       # indirect br: ends block
        elif ins.mnem in isa.RET or ins.mnem == "stop":
            term = ("ret", [])
        elif ins.mnem in isa.SKIP or ins.mnem in isa.COND_BRANCH or ins.mnem in isa.BIT_BRANCH:
            term = ("branch", succ)
        elif nxt in leaders or nxt not in body:
            term = ("fall", [("fall", nxt)] if nxt in body else [])
        if term is not None:
            cur.term, cur.succ = term
            cur = None

    for b in f.blocks.values():
        for ins in b.insns:
            if ins.mnem == "call" and target_of(ins) is not None:
                f.calls.add(target_of(ins))
            if ins.mnem in isa.SKIP:
                b.stmts.append(_skip_branch(insns, ins))
            else:
                b.stmts.extend(lift_insn(ins))

    _resolve_flags(f)
    return f


def _resolve_flags(f):
    flag_out = {}
    preds = {}
    for b in f.blocks.values():
        for _, tgt in b.succ:
            preds.setdefault(tgt, []).append(b.start)

    def scan(block, incoming):
        cur = incoming
        for s in block.stmts:
            if isinstance(s, ir.Compare):
                cur = s.flag
            elif isinstance(s, ir.Assign) and s.flag is not None:
                cur = s.flag
            elif isinstance(s, ir.Branch) and s.cond is not None:
                s.flag = cur
            elif isinstance(s, (ir.Call, ir.Intrinsic)):
                cur = None                    # a call clobbers flags
        return cur

    for _ in range(4):
        changed = False
        for b in f.ordered():
            pl = preds.get(b.start, [])
            incoming = flag_out.get(pl[0]) if len(pl) == 1 else None
            out = scan(b, incoming)
            if flag_out.get(b.start) is not out:
                flag_out[b.start] = out
                changed = True
        if not changed:
            break


def build_functions(insns, calls, extra_entries=()):
    entry_set = {e for e in (set(calls) | set(extra_entries)) if e in insns}
    funcs = {}
    for entry in sorted(entry_set):
        fn = build_func(insns, entry, entry_set)
        if fn is not None:
            funcs[entry] = fn
    return funcs
