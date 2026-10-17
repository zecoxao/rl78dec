"""
Abstract stack tracking and spill/reload elimination for RL78.

On register-constrained microcontrollers like RL78 (which has only 4 16-bit register
pairs: AX, BC, DE, HL), compilers routinely push registers to temporary stack slots and
pop them back later to:
1. Preserve a register while using it for an inner calculation.
2. Transfer a value from one register to another.
3. Pass arguments to a function call.

This module simulates the evaluation stack across the CFG to:
- Match push/pop spill pairs and convert them into virtual variable assignments
  (v = r; ... r' = v;), completely eliminating raw push(...) and pop(...) intrinsics.
- Mark caller-pushed arguments before calls with stack cleanup (addw sp, #N),
  folding them into call arguments and hiding the push and stack cleanup statements.
"""

from . import ir


def _find_call_cleanup(func, b, i, hidden):
    """Find stack cleanup addw sp, #N after a call, checking current block and fallthrough successor."""
    stmts = b.stmts
    k = i + 1
    while k < len(stmts):
        nxt = stmts[k]
        if (isinstance(nxt, ir.Assign) and isinstance(nxt.dst, ir.Reg) and
                nxt.dst.name == "sp" and isinstance(nxt.src, ir.Bin) and
                nxt.src.op == "+" and isinstance(nxt.src.l, ir.Reg) and nxt.src.l.name == "sp" and
                isinstance(nxt.src.r, ir.Const)):
            return nxt.src.r.value, nxt
        elif isinstance(nxt, (ir.Call, ir.Ret, ir.Branch, ir.Goto)):
            return 0, None
        k += 1

    # Check fallthrough successor block if call was at or near the end of block
    if len(b.succ) == 1 and b.succ[0][0] == "fall":
        succ_ea = b.succ[0][1]
        succ_b = func.blocks.get(succ_ea)
        if succ_b:
            for nxt in succ_b.stmts:
                if (isinstance(nxt, ir.Assign) and isinstance(nxt.dst, ir.Reg) and
                        nxt.dst.name == "sp" and isinstance(nxt.src, ir.Bin) and
                        nxt.src.op == "+" and isinstance(nxt.src.l, ir.Reg) and nxt.src.l.name == "sp" and
                        isinstance(nxt.src.r, ir.Const)):
                    return nxt.src.r.value, nxt
                elif isinstance(nxt, (ir.Call, ir.Ret, ir.Branch, ir.Goto)):
                    return 0, None
    return 0, None


def _find_def_before(stmts, idx, reg_name):
    """Search backwards from idx - 1 for assignment setting up reg_name before a push."""
    j = idx - 1
    low_half = {"ax": "x", "bc": "c", "de": "e", "hl": "l"}.get(reg_name)
    high_half = {"ax": "a", "bc": "b", "de": "d", "hl": "h"}.get(reg_name)

    low_src, low_stmt = None, None
    high_src, high_stmt = None, None

    while j >= 0:
        s = stmts[j]
        if isinstance(s, ir.Assign) and isinstance(s.dst, ir.Reg):
            if s.dst.name == reg_name:
                if low_src is None and high_src is None:
                    return s.src, [s]
                elif low_src is not None and high_src is None:
                    if isinstance(s.src, ir.Const):
                        high_src = ir.Const((s.src.value >> 8) & 0xFF, "b")
                        high_stmt = s
                        break
                elif high_src is not None and low_src is None:
                    if isinstance(s.src, ir.Const):
                        low_src = ir.Const(s.src.value & 0xFF, "b")
                        low_stmt = s
                        break
            if low_half and s.dst.name == low_half and low_src is None:
                low_src, low_stmt = s.src, s
            if high_half and s.dst.name == high_half and high_src is None:
                high_src, high_stmt = s.src, s
            if low_src is not None and (high_src is not None or high_half is None):
                break
        elif isinstance(s, (ir.Call, ir.Ret, ir.Branch, ir.Goto)):
            break
        j -= 1

    if low_src is not None and high_src is not None:
        stmts_found = [s for s in (low_stmt, high_stmt) if s]
        if isinstance(low_src, ir.Const) and isinstance(high_src, ir.Const):
            combined = (high_src.value << 8) | low_src.value
            return ir.Const(combined, "w"), stmts_found
        return low_src, stmts_found
    elif low_src is not None:
        return low_src, [low_stmt]
    elif high_src is not None:
        return high_src, [high_stmt]

    return None, []


def eliminate_spills(func, frame_info):
    """Simulate abstract stack to eliminate register spills and recover stack arguments."""
    hidden = frame_info.hidden_stmts
    in_stack = {func.entry: ()}
    spill_cnt = 0

    # First pass: identify call argument pushes associated with addw sp, #N cleanups
    for b in func.blocks.values():
        stmts = b.stmts
        for i, s in enumerate(stmts):
            if isinstance(s, ir.Call):
                cleanup_bytes, cleanup_stmt = _find_call_cleanup(func, b, i, hidden)
                if cleanup_bytes > 0:
                    hidden.add(id(cleanup_stmt))
                    expected_pushes = cleanup_bytes // 2
                    found_pushes = []
                    j = i - 1
                    # Scan backwards for pushes that set up these call arguments
                    while j >= 0 and len(found_pushes) < expected_pushes:
                        prev = stmts[j]
                        if id(prev) in hidden:
                            j -= 1
                            continue
                        if isinstance(prev, ir.Intrinsic) and prev.name == "push" and prev.args:
                            arg_val = prev.args[0]
                            if isinstance(arg_val, ir.Reg):
                                def_src, def_stmts = _find_def_before(stmts, j, arg_val.name)
                                if def_src is not None:
                                    arg_val = def_src
                                    for ds in def_stmts:
                                        hidden.add(id(ds))
                            found_pushes.append(arg_val)
                            hidden.add(id(prev))
                        elif isinstance(prev, (ir.Call, ir.Ret, ir.Branch, ir.Goto)):
                            break
                        j -= 1

                    # Backward scan encounters arguments in left-to-right parameter order
                    # (the push immediately before call is at [SP], which is the first stack parameter)
                    for push_val in found_pushes:
                        s.args.append(push_val)

    # Second pass: simulate remaining pushes/pops as register spills and reloads
    order = func.ordered()
    visited = set()
    worklist = [order[0].start] if order else []

    while worklist:
        b_ea = worklist.pop(0)
        if b_ea not in func.blocks:
            continue
        b = func.blocks[b_ea]
        visited.add(b_ea)

        stk = list(in_stack.get(b.start, ()))
        new_stmts = []

        for s in b.stmts:
            if id(s) in hidden:
                new_stmts.append(s)
                continue

            if isinstance(s, ir.Intrinsic) and s.name == "push" and s.args:
                arg = s.args[0]
                var = ir.Var(f"_s{spill_cnt}", width=getattr(arg, "width", "w"))
                spill_cnt += 1
                stk.append(var)
                # Replace push with assignment to spill variable
                new_stmts.append(ir.Assign(s.ea, var, arg))

            elif isinstance(s, ir.Intrinsic) and s.name == "pop" and s.args:
                dst = s.args[0]
                if stk:
                    var = stk.pop()
                    # Replace pop with restore from spill variable
                    new_stmts.append(ir.Assign(s.ea, dst, var))
                else:
                    new_stmts.append(s)

            elif (isinstance(s, ir.Assign) and isinstance(s.dst, ir.Reg) and
                  s.dst.name == "sp" and isinstance(s.src, ir.Bin) and
                  s.src.op == "+" and isinstance(s.src.r, ir.Const)):
                # SP adjustment: pop items from abstract stack
                cleanup_words = s.src.r.value // 2
                for _ in range(cleanup_words):
                    if stk:
                        stk.pop()
                new_stmts.append(s)

            else:
                new_stmts.append(s)

        b.stmts = new_stmts
        out_tuple = tuple(stk)

        for _, succ_ea in b.succ:
            if succ_ea in func.blocks:
                if succ_ea not in in_stack:
                    in_stack[succ_ea] = out_tuple
                    if succ_ea not in visited and succ_ea not in worklist:
                        worklist.append(succ_ea)
                elif in_stack[succ_ea] != out_tuple:
                    # In case of stack divergence, keep shorter stack
                    if len(out_tuple) < len(in_stack[succ_ea]):
                        in_stack[succ_ea] = out_tuple

    return func
