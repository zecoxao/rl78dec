"""
IDA integration for rl78dec.

Run inside IDA on a database opened with fail0verflow's RL78 processor module
(``rl78-ida-proc``).  The bridge reads the flash bytes out of the database,
uses IDA's function boundaries as entry points, and wraps the naming layer so
the decompilation reuses whatever labels the analyst has applied.

IDA is imported lazily so importing :mod:`rl78dec` outside IDA stays clean.
"""

from . import decoder, cfg, opt, structure, cgen, frame, abi, spill, vars, db
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


def _ida_frame_info(ea):
    try:
        import ida_funcs, ida_frame, ida_typeinf, ida_ua
        from ida_idaapi import BADADDR
        pfn = ida_funcs.get_func(ea)
        if not pfn:
            return None
        tif = ida_typeinf.tinfo_t()
        members = {}
        if ida_frame.get_func_frame(tif, pfn):
            udt = ida_typeinf.udt_type_data_t()
            if tif.get_udt_details(udt):
                for m in udt:
                    members[m.offset // 8] = (m.name, m.size // 8, m.type.dstr())

        off_args = ida_frame.frame_off_args(pfn)
        stkvars_by_ea = {}
        hl_disp_to_stkvar = {}
        cur = pfn.start_ea
        while cur < pfn.end_ea:
            insn = ida_ua.insn_t()
            if ida_ua.decode_insn(insn, cur) > 0:
                for n in range(8):
                    op = insn.ops[n]
                    if op.type == ida_ua.o_void:
                        break
                    if op.type == ida_ua.o_displ and op.reg in (11, 12):
                        if op.reg == 11 and op.addr in hl_disp_to_stkvar:
                            stkvars_by_ea.setdefault(cur, {})[n] = hl_disp_to_stkvar[op.addr]
                        else:
                            soff = ida_frame.calc_stkvar_struc_offset(pfn, insn, n)
                            if soff != BADADDR:
                                if soff >= (1 << 63):
                                    soff -= (1 << 64)
                                m = members.get(soff)
                                name = m[0] if m else ida_frame.build_stkvar_name(pfn, soff)
                                size = m[1] if m else (2 if getattr(op, 'dtype', 0) == 1 else 1)
                                if soff < 0:
                                    is_arg = False
                                    if name.startswith("arg_"):
                                        name = "var_%X" % abs(soff)
                                else:
                                    is_arg = (soff >= off_args) if off_args != BADADDR else name.startswith("arg_")
                                entry_info = (soff, name, size, is_arg)
                                stkvars_by_ea.setdefault(cur, {})[n] = entry_info
                                if op.reg == 11 and op.addr not in hl_disp_to_stkvar:
                                    hl_disp_to_stkvar[op.addr] = entry_info
            cur += insn.size if insn.size > 0 else 1
        return (members, stkvars_by_ea)
    except Exception:
        return None


def _get_ida_func_proto(ea):
    """Retrieve C prototype string from IDA's type system if present."""
    try:
        import ida_nalt, ida_typeinf
        tif = ida_typeinf.tinfo_t()
        if ida_nalt.get_tinfo(tif, ea) and tif.is_func():
            return tif.dstr()
    except Exception:
        pass
    return None


def _get_caller_consensus(entry):
    """Infer whether callers set AX / BC registers before calling entry using structured IDA instruction decoding."""
    try:
        import idautils, ida_ua, ida_idp, ida_bytes, ida_idaapi
        caller_eas = list(idautils.CodeRefsTo(entry, 0))
        if not caller_eas:
            return None
        ax_count = 0
        bc_count = 0
        valid = 0
        insn = ida_ua.insn_t()
        for c in caller_eas:
            cur = ida_bytes.prev_head(c, 0)
            found_ax = False
            found_bc = False
            count = 0
            while cur != ida_idaapi.BADADDR and cur >= c - 16 and count < 4:
                if ida_ua.decode_insn(insn, cur) == 0:
                    break
                mnem = insn.get_canon_mnem().upper()
                count += 1
                # Check destination operand if it writes to AX/A/X or BC/B/C
                if insn.ops[0].type == ida_ua.o_reg:
                    rname = ida_idp.get_reg_name(insn.ops[0].reg, insn.ops[0].dtype).upper()
                    if not found_ax and rname in ("AX", "A", "X"):
                        found_ax = True
                    if not found_bc and rname in ("BC", "B", "C"):
                        found_bc = True
                if mnem in ("CALL", "RET", "RETI", "BR"):
                    break
                cur = ida_bytes.prev_head(cur, 0)
            valid += 1
            if found_ax:
                ax_count += 1
            if found_bc:
                bc_count += 1
        if valid == 0:
            return None
        return {
            "has_ax": (ax_count / valid) >= 0.75,
            "has_bc": (bc_count / valid) >= 0.75,
        }
    except Exception:
        return None


def decompile_program():
    image = _read_image()
    entries = _entries() or [0]
    insns, calls = decoder.decode(image, entries=entries, base=0)
    funcs = cfg.build_functions(insns, calls, extra_entries=entries)
    namer = IdaNamer()
    out = {}
    for entry, f in funcs.items():
        db_data = db.get_func_data(entry)
        u_renames = db_data.get("renames", {})
        u_types = db_data.get("types", {})
        u_proto = db_data.get("proto") or _get_ida_func_proto(entry)

        ida_info = _ida_frame_info(entry)
        frame_info = frame.analyze_frame(f, ida_frame_info=ida_info)
        frame_info.user_renames = u_renames
        frame_info.user_types = u_types

        spill.eliminate_spills(f, frame_info)
        opt.optimize(f)
        consensus = _get_caller_consensus(entry)
        sig = abi.analyze_calling_convention(f, frame_info, user_proto=u_proto, caller_consensus=consensus)
        vars.recover_variables(f, sig, frame_info)
        tree = structure.structure(f)
        lines, line_ea = cgen.generate(f, tree, namer, frame_info=frame_info, sig=sig,
                                       user_renames=u_renames, user_types=u_types, with_ea=True)
        out[entry] = Function(entry, namer.code(entry), f, tree, lines, line_ea=line_ea)
    return Program(image, insns, out, namer)


def decompile_one(ea):
    import ida_funcs
    f = ida_funcs.get_func(ea)
    entry = f.start_ea if f is not None else ea
    image = _read_image()
    entset = set(_entries()) | {entry}
    insns, _ = decoder.decode(image, entries=[entry] + _entries(), base=0)

    # If the user invoked on an internal switch case fragment, find its parent function
    for ins in insns.values():
        if getattr(ins, "switch", None) is not None and entry in ins.switch.targets:
            parent_f = ida_funcs.get_func(ins.ea)
            if parent_f and parent_f.start_ea != entry:
                entry = parent_f.start_ea
                break

    func = cfg.build_func(insns, entry, entset)
    if func is None:
        raise RuntimeError("rl78dec: nothing decoded at 0x%X" % entry)
    namer = IdaNamer()

    db_data = db.get_func_data(entry)
    u_renames = db_data.get("renames", {})
    u_types = db_data.get("types", {})
    u_comments = db_data.get("comments", {})
    u_proto = db_data.get("proto") or _get_ida_func_proto(entry)

    ida_info = _ida_frame_info(entry)
    frame_info = frame.analyze_frame(func, ida_frame_info=ida_info)
    frame_info.user_renames = u_renames
    frame_info.user_types = u_types

    spill.eliminate_spills(func, frame_info)
    opt.optimize(func)
    consensus = _get_caller_consensus(entry)
    sig = abi.analyze_calling_convention(func, frame_info, user_proto=u_proto, caller_consensus=consensus)
    vars.recover_variables(func, sig, frame_info)
    tree = structure.structure(func)
    lines, line_ea = cgen.generate(func, tree, namer, frame_info=frame_info, sig=sig, banner=BANNER,
                                  user_renames=u_renames, user_types=u_types, user_comments=u_comments,
                                  with_ea=True)
    return Function(entry, namer.code(entry), func, tree, lines, line_ea=line_ea)

