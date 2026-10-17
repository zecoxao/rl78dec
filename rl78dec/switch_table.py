"""
Switch statement and jump table detection for RL78.

RL78 switch tables appear as:
1. Far 32-bit pointer table (4 bytes per entry, [word, cs_byte, pad]):
   shlw ax, 2
   addw ax, #table_addr
   movw de, ax
   mov es, #0
   mov a, es:[de+2]
   mov cs, a
   movw ax, es:[de+0]
   br ax
2. Near 16-bit pointer table (2 bytes per entry, [word]):
   shlw ax, 1
   addw ax, #table_addr
   movw ax, [ax]
   br ax
   or:
   shlw bc, 1
   movw ax, table_addr[bc]
   br ax
3. Split CS / AX tables:
   mov a, cs_table[reg]
   shlw reg, 1
   mov cs, a
   movw ax, ax_table[reg]
   br ax
4. IDA Pro switch_info_t (if available).
"""

import struct
from . import ir


class SwitchInfo:
    __slots__ = ("ea", "table_ea", "scale", "cases", "targets", "default_ea", "expr", "dispatch_eas")

    def __init__(self, ea, table_ea, scale, cases, default_ea=None, expr=None, dispatch_eas=None):
        self.ea = ea                      # Address of indirect branch (br ax)
        self.table_ea = table_ea          # Base address of jump table
        self.scale = scale                # 2 or 4 bytes per entry
        self.cases = cases                # dict: case_val (int) -> target_ea (int) or None
        self.default_ea = default_ea      # Default target EA (or None)
        self.expr = expr if expr is not None else ir.Reg("a")
        self.targets = sorted(set(t for t in cases.values() if t and t != 0))
        self.dispatch_eas = set(dispatch_eas) if dispatch_eas else set()


def parse_table(image, table_ea, scale=4, base=0, max_cases=64):
    """Read pointers from jump table in image until reaching code or invalid pointer."""
    cases = {}
    min_target = base + len(image)
    for i in range(max_cases):
        off = table_ea - base + i * scale
        if off >= min_target or off + scale > len(image):
            break
        if scale == 4:
            raw = struct.unpack("<I", image[off:off+4])[0]
            tgt = (raw & 0xFFFF) | (((raw >> 16) & 0xFF) << 16)
        else:
            tgt = struct.unpack("<H", image[off:off+2])[0]

        if tgt == 0:
            cases[i] = None
        elif base <= tgt < base + len(image):
            min_target = min(min_target, tgt)
            cases[i] = tgt
        else:
            break
    return cases


def detect_switch(image, insns, br_ins, base=0):
    """Detect if br_ins (br ax) is an indirect jump implementing a switch statement."""
    if br_ins.mnem != "br" or not br_ins.ops or br_ins.ops[0].mode != "reg" or br_ins.ops[0].reg != "ax":
        return None

    # Check IDA switch_info_t if running in IDA
    try:
        import ida_nalt
        si = ida_nalt.get_switch_info(br_ins.ea)
        if si and si.jumps:
            table_ea = si.jumps
            cases_dict = {}
            results = ida_nalt.calc_switch_cases(br_ins.ea, si)
            if results:
                for idx in range(len(results.cases)):
                    val = results.values[idx] if idx < len(results.values) else idx
                    cases_dict[val] = results.cases[idx]
            if cases_dict:
                return SwitchInfo(br_ins.ea, table_ea, 4, cases_dict, default_ea=si.defjump or None)
    except Exception:
        pass

    # Heuristic pattern matching in preceding instructions
    cur = br_ins.ea
    window = []
    for _ in range(16):
        prev = [ea for ea, it in insns.items() if ea + it.size == cur]
        if not prev:
            break
        cur = prev[0]
        window.insert(0, insns[cur])

    if not window:
        return None

    table_ea = None
    scale = 2
    idx_reg = "a"
    shlw_ins = None

    for it in window:
        if it.mnem == "shlw" and it.ops and len(it.ops) > 1 and it.ops[1].mode == "imm":
            shlw_ins = it
            scale = 1 << it.ops[1].value
            if it.ops[0].mode == "reg" and it.ops[0].reg in ("bc", "c"):
                idx_reg = "c"
        if it.mnem in ("addw", "movw") and it.ops and len(it.ops) > 1 and it.ops[1].mode == "imm":
            val = it.ops[1].value
            if base <= val < base + len(image):
                table_ea = val

    if not table_ea:
        return None

    cases = parse_table(image, table_ea, scale=scale, base=base)
    if not any(cases.values()):
        return None

    # Identify dispatch sequence instructions and index register
    dispatch_eas = {br_ins.ea}
    if shlw_ins is not None:
        shlw_idx = window.index(shlw_ins)
        for it in window[shlw_idx:]:
            dispatch_eas.add(it.ea)
        if idx_reg == "a":
            for it in reversed(window[:shlw_idx]):
                if it.mnem == "clrb":
                    dispatch_eas.add(it.ea)
                elif it.mnem == "mov" and it.ops and len(it.ops) > 1 and it.ops[0].mode == "reg":
                    if it.ops[0].reg in ("x", "a") and it.ops[1].mode == "reg":
                        idx_reg = it.ops[1].reg
                        dispatch_eas.add(it.ea)
                        break
                    else:
                        break
                else:
                    break

    return SwitchInfo(br_ins.ea, table_ea, scale, cases, expr=ir.Reg(idx_reg), dispatch_eas=dispatch_eas)
