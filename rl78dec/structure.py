"""
Control-flow structuring (shared design with startrekdec).

A recursive address-range structurer recovers ``if`` / ``while`` / ``do-while``
and always leaves a correct ``goto`` + label fallback.  Only the condition
rendering differs from the Kirk tool: RL78 branches read Z/CY (unsigned) and the
bit-test branches (bt/bf) render the tested bit directly.
"""

from . import ir


class SStmt:
    def __init__(self, stmt): self.stmt = stmt
class SLabel:
    def __init__(self, ea): self.ea = ea
class SGoto:
    def __init__(self, ea): self.ea = ea
class SRet:
    def __init__(self, val=None): self.val = val
class SIf:
    def __init__(self, cond, then, els): self.cond = cond; self.then = then; self.els = els
class SIfGoto:
    def __init__(self, cond, ea): self.cond = cond; self.ea = ea
class SWhile:
    def __init__(self, body, cond=None, dowhile=False):
        self.body = body; self.cond = cond; self.dowhile = dowhile
class SSwitch:
    def __init__(self, expr, cases, default=None):
        self.expr = expr
        self.cases = cases          # [(list_of_vals, body_nodes)]
        self.default = default      # body_nodes or None
class SBreak:
    pass
class SContinue:
    def __init__(self, cond=None): self.cond = cond
class SBreakIf:
    def __init__(self, cond): self.cond = cond


# --- condition rendering (RL78: Z, CY unsigned, bit tests) ------------------

_REL = {"z": "==", "nz": "!=", "cy": "<", "ncy": ">=", "h": ">", "nh": "<="}
_NEG = {"==": "!=", "!=": "==", ">": "<=", "<": ">=", ">=": "<", "<=": ">"}
_FLAG = {"z": "ZF", "nz": "!ZF", "cy": "CY", "ncy": "!CY", "h": "HF", "nh": "!HF"}


def cond_expr(branch):
    if branch.bittest is not None:
        base, sense = branch.bittest
        return base if sense else ir.Un("!", base)
    flag, c = branch.flag, branch.cond
    if flag is None:
        return ir.IntrExpr(_FLAG[c], [])
    if flag.kind in ("cmp", "sub", "cmp0"):
        return ir.Bin(_REL[c], flag.a, flag.b)
    if flag.kind == "result":
        if c in ("z", "nz"):
            return ir.Bin(_REL[c], flag.a, ir.Const(0))
        return ir.IntrExpr(_FLAG[c], [])       # CY/HF not derivable from a result
    return ir.IntrExpr(_FLAG[c], [])


def negate(e):
    if isinstance(e, ir.Un) and e.op == "!":
        return e.e
    if isinstance(e, ir.Bin) and e.op in _NEG:
        return ir.Bin(_NEG[e.op], e.l, e.r)
    if isinstance(e, ir.IntrExpr) and not e.args:
        return ir.IntrExpr(e.name[1:] if e.name.startswith("!") else "!" + e.name, [])
    if isinstance(e, ir.Const):
        return ir.Const(0 if e.value else 1)
    return ir.Un("!", e)


# --- structurer -------------------------------------------------------------

class _Structurer:
    def __init__(self, func):
        self.f = func
        self.order = func.ordered()
        self.idx = {b.start: i for i, b in enumerate(self.order)}
        self.blocks = self.order
        self._open = set()
        self._handled = set()

    def run(self):
        return self._emit(0, len(self.blocks), loop=None)

    def _in_range(self, ea, lo, hi):
        i = self.idx.get(ea)
        return i is not None and lo <= i < hi

    def _find_latch(self, header_idx, hi):
        h = self.blocks[header_idx].start
        latch = None
        for j in range(header_idx, hi):
            for _, tgt in self.blocks[j].succ:
                if tgt == h and j >= header_idx:   # >= : also catch self-loops
                    latch = j
        return latch

    def _ret_val(self, block):
        for s in reversed(block.stmts):
            if isinstance(s, ir.Ret):
                return s.val
        return None

    def _body_stmts(self, block):
        out = []
        for s in block.stmts:
            if isinstance(s, (ir.Goto, ir.Branch, ir.Ret, ir.Nop, ir.Compare, ir.Switch)):
                continue
            out.append(SStmt(s))
        return out


    def _emit_switch(self, b, lo, hi, loop):
        sw = next((s for s in b.stmts if isinstance(s, ir.Switch)), None)
        if sw is None:
            return None, None

        target_to_vals = {}
        for val, tgt in sorted(sw.cases.items()):
            if tgt and tgt != 0 and tgt != sw.default:
                target_to_vals.setdefault(tgt, []).append(val)

        case_succs = set()
        for tgt in target_to_vals.keys():
            ti = self.idx.get(tgt)
            if ti is not None:
                tb = self.blocks[ti]
                for _, s_tgt in tb.succ:
                    if s_tgt not in target_to_vals:
                        case_succs.add(s_tgt)

        follow_ea = None
        if len(case_succs) == 1:
            cand = next(iter(case_succs))
            if self._in_range(cand, lo, hi):
                follow_ea = cand

        cases = []
        for tgt, vals in target_to_vals.items():
            ti = self.idx.get(tgt)
            if ti is not None:
                c_body = []
                c_body.extend(self._body_stmts(self.blocks[ti]))
                t_term = self.blocks[ti].term
                if t_term == "ret":
                    c_body.append(SRet(self._ret_val(self.blocks[ti])))
                elif self.blocks[ti].succ:
                    s_tgt = self.blocks[ti].succ[0][1]
                    if s_tgt == follow_ea:
                        c_body.append(SBreak())
                    else:
                        self._emit_edge(c_body, s_tgt, lo, hi, loop, fall_i=None)
                cases.append((vals, c_body))
                self._handled.add(ti)
            else:
                cases.append((vals, [SGoto(tgt)]))

        default_body = None
        if sw.default and sw.default in self.idx:
            di = self.idx[sw.default]
            default_body = self._body_stmts(self.blocks[di])
            t_term = self.blocks[di].term
            if t_term == "ret":
                default_body.append(SRet(self._ret_val(self.blocks[di])))
            elif self.blocks[di].succ:
                s_tgt = self.blocks[di].succ[0][1]
                if s_tgt == follow_ea:
                    default_body.append(SBreak())
                else:
                    self._emit_edge(default_body, s_tgt, lo, hi, loop, fall_i=None)
            self._handled.add(di)

        node = SSwitch(sw.expr, cases, default=default_body)
        nxt = self.idx.get(follow_ea) if follow_ea is not None else None
        return node, nxt

    def _emit(self, lo, hi, loop):
        out = []
        i = lo
        while i < hi:
            if i in self._handled:
                i += 1
                continue
            b = self.blocks[i]
            out.append(SLabel(b.start))

            latch = None if i in self._open else self._find_latch(i, hi)
            if latch is not None:
                node, nxt = self._emit_loop(i, latch, hi)
                out.append(node)
                i = nxt
                continue

            out.extend(self._body_stmts(b))
            term = b.term
            if term == "switch":
                node, nxt = self._emit_switch(b, lo, hi, loop)
                if node is not None:
                    node.ea = b.stmts[-1].ea if b.stmts else b.start
                    out.append(node)
                    if nxt is not None and nxt > i:
                        i = nxt
                    else:
                        i += 1
                    continue
            if term == "ret":
                ret_node = SRet(self._ret_val(b))
                ret_node.ea = b.stmts[-1].ea if b.stmts else b.start
                out.append(ret_node)
                i += 1
                continue

            if term == "goto":
                tgt = b.succ[0][1]
                self._emit_edge(out, tgt, lo, hi, loop, fall_i=i + 1)
                i += 1
                continue
            if term == "branch":
                cond = cond_expr(self._branch_of(b))
                taken = b.succ[0][1]
                fall = b.succ[1][1] if len(b.succ) > 1 else None
                b_ea = b.stmts[-1].ea if b.stmts else b.start
                if loop is not None and taken in (loop[0], loop[1]):
                    c_node = SContinue(cond) if taken == loop[0] else SBreakIf(cond)
                    c_node.ea = b_ea
                    out.append(c_node)
                    self._fall_after(out, fall, lo, hi, loop, i)
                    i += 1
                    continue
                ti = self.idx.get(taken)
                if ti is not None and i + 1 <= ti < hi and taken != b.start \
                        and (loop is None or taken not in (loop[0], loop[1])):
                    then = self._emit(i + 1, ti, loop)
                    if_node = SIf(negate(cond), then, None)
                    if_node.ea = b_ea
                    out.append(if_node)
                    i = ti
                    continue
                if_goto = SIfGoto(cond, taken)
                if_goto.insn_ea = b_ea
                out.append(if_goto)
                self._fall_after(out, fall, lo, hi, loop, i)
                i += 1
                continue
            if b.succ:
                tgt = b.succ[0][1]
                if self.idx.get(tgt) != i + 1:
                    self._emit_edge(out, tgt, lo, hi, loop, fall_i=i + 1)
            i += 1
        return out

    def _emit_loop(self, hidx, latch, hi):
        loop_lo, loop_hi = hidx, latch + 1
        header = self.blocks[hidx].start
        follow_ea = None
        for k, tgt in self.blocks[latch].succ:
            if not self._in_range(tgt, loop_lo, loop_hi):
                follow_ea = tgt
                break
        loop_ctx = (header, follow_ea)
        self._open.add(hidx)
        body = self._emit(loop_lo, loop_hi, loop_ctx)
        self._open.discard(hidx)
        node = SWhile(body, cond=None, dowhile=False)
        node.ea = header
        nxt = latch + 1
        if follow_ea is not None and self.idx.get(follow_ea) is not None:
            nxt = self.idx[follow_ea]
        return node, nxt

    def _branch_of(self, block):
        for s in block.stmts:
            if isinstance(s, ir.Branch):
                return s
        return None

    def _fall_after(self, out, fall, lo, hi, loop, i):
        if fall is None or self.idx.get(fall) == i + 1:
            return
        if loop is not None:
            if fall == loop[0]:
                out.append(SContinue()); return
            if fall == loop[1]:
                out.append(SBreak()); return
        out.append(SGoto(fall))

    def _emit_edge(self, out, tgt, lo, hi, loop, fall_i):
        if loop is not None:
            if tgt == loop[0]:
                out.append(SContinue()); return
            if tgt == loop[1]:
                out.append(SBreak()); return
        if self.idx.get(tgt) == fall_i:
            return
        out.append(SGoto(tgt))


def structure(func):
    return _Structurer(func).run()
