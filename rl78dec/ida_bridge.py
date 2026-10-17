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


_CACHED_STRUCT_INFO = None


def _load_struct_info():
    try:
        import ida_typeinf, ida_bytes, ida_name, idautils, ida_nalt
        struct_defs = {}
        symbol_structs = {}

        ti = ida_typeinf.get_idati()
        sname = ida_typeinf.first_named_type(ti, ida_typeinf.NTF_TYPE)
        while sname:
            tif = ida_typeinf.tinfo_t()
            if tif.get_named_type(ti, sname) and tif.is_udt():
                udt = ida_typeinf.udt_type_data_t()
                if tif.get_udt_details(udt):
                    members = []
                    for m in udt:
                        members.append({
                            "offset": m.offset // 8,
                            "size": m.size // 8,
                            "name": m.name,
                            "type": m.type.dstr()
                        })
                    struct_defs[sname] = {
                        "size": tif.get_size(),
                        "members": sorted(members, key=lambda x: x["offset"])
                    }
            sname = ida_typeinf.next_named_type(ti, sname, ida_typeinf.NTF_TYPE)

        buf = ida_nalt.opinfo_t()
        for ea in idautils.Heads(0, 0x80000):
            flags = ida_bytes.get_flags(ea)
            if ida_bytes.is_struct(flags):
                if ida_bytes.get_opinfo(buf, ea, 0, flags):
                    st_name = ida_typeinf.get_tid_name(buf.tid)
                    if st_name and st_name in struct_defs:
                        symbol_structs[ea] = st_name
                        sym_name = ida_name.get_name(ea)
                        if sym_name:
                            symbol_structs[sym_name] = st_name

        return struct_defs, symbol_structs
    except Exception:
        return {}, {}


def _get_struct_info():
    global _CACHED_STRUCT_INFO
    if _CACHED_STRUCT_INFO is None:
        _CACHED_STRUCT_INFO = _load_struct_info()
    return _CACHED_STRUCT_INFO


class IdaNamer(Namer):
    def __init__(self):
        struct_defs, symbol_structs = _get_struct_info()
        super().__init__(struct_defs=struct_defs, symbol_structs=symbol_structs)
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
        cur = pfn.start_ea
        while cur < pfn.end_ea:
            insn = ida_ua.insn_t()
            if ida_ua.decode_insn(insn, cur) > 0:
                for n in range(8):
                    op = insn.ops[n]
                    if op.type == ida_ua.o_void:
                        break
                    if op.type == ida_ua.o_displ and op.reg in (11, 12):
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
                            stkvars_by_ea.setdefault(cur, {})[n] = (soff, name, size, is_arg)
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


def _resolve_op_name(ea, n, op=None):
    try:
        import ida_bytes, ida_name, ida_idaapi, idc, idautils, re
        flags = ida_bytes.get_flags(ea)
        is_off = ida_bytes.is_off(flags, n)
        op_text = idc.print_operand(ea, n)

        # 1. Direct symbol in immediate operand: e.g. #kermit_cmd_tableR
        if op_text.startswith("#"):
            clean = op_text[1:].split(";")[0].strip()
            if clean.isidentifier():
                target_ea = ida_name.get_name_ea(ida_idaapi.BADADDR, clean)
                if target_ea != ida_idaapi.BADADDR:
                    return clean

            # Handle parentheses around expression, e.g. #(copy_hwversion - word_F0000)
            if clean.startswith("(") and clean.endswith(")"):
                inner = clean[1:-1].strip()
                parts = re.split(r"\s*[-+]\s*", inner)
                if parts:
                    first_sym = parts[0].strip()
                    target_ea = ida_name.get_name_ea(ida_idaapi.BADADDR, first_sym)
                    if target_ea != ida_idaapi.BADADDR and not first_sym.startswith(("word_F0000", "unk_F0000", "byte_F0000", "unk_60000")):
                        return first_sym

            # If immediate value is a numeric address pointing to a known symbol
            if op and getattr(op, "val", None) is not None:
                val = op.val
                if 0x800 <= val < 0x80000:
                    val_name = ida_name.get_name(val)
                    if val_name and not val_name.startswith(("byte_", "word_", "dword_", "unk_", "loc_", "sub_")):
                        return val_name

        # 2. If marked as offset or has data xrefs, check data xrefs from this instruction
        if is_off:
            for x in idautils.XrefsFrom(ea):
                if not x.iscode:
                    xname = ida_name.get_name(x.to)
                    if xname and not xname.startswith(("word_F0000", "unk_F0000", "byte_F0000", "unk_60000")):
                        return xname

        # 3. Direct identifier matching a known symbol
        clean_text = op_text.split(";")[0].strip()
        if clean_text.isidentifier():
            target_ea = ida_name.get_name_ea(ida_idaapi.BADADDR, clean_text)
            if target_ea != ida_idaapi.BADADDR:
                return clean_text

        # 4. Check op.val directly if it's an address pointing to a named symbol
        if op and getattr(op, "val", None) is not None:
            val = op.val
            if 0x800 <= val < 0x80000:
                val_name = ida_name.get_name(val)
                if val_name and not val_name.startswith(("byte_", "word_", "dword_", "unk_", "loc_", "sub_")):
                    return val_name
    except Exception:
        pass
    return None


def _annotate_operand_names(insns):
    for ins in insns.values():
        for n, op in enumerate(ins.ops):
            if op.mode in ("imm", "mem", "idx16"):
                sym = _resolve_op_name(ins.ea, n, op)
                if sym:
                    op.name = sym


def decompile_program():
    image = _read_image()
    entries = _entries() or [0]
    insns, calls = decoder.decode(image, entries=entries, base=0)
    _annotate_operand_names(insns)
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
        sig = abi.analyze_calling_convention(f, frame_info, user_proto=u_proto)
        vars.recover_variables(f, sig, frame_info)
        tree = structure.structure(f)
        out[entry] = Function(entry, namer.code(entry), f, tree,
                              cgen.generate(f, tree, namer, frame_info=frame_info, sig=sig,
                                            user_renames=u_renames, user_types=u_types))
    return Program(image, insns, out, namer)


def decompile_one(ea):
    import ida_funcs
    f = ida_funcs.get_func(ea)
    entry = f.start_ea if f is not None else ea
    image = _read_image()
    entset = set(_entries()) | {entry}
    insns, _ = decoder.decode(image, entries=[entry] + _entries(), base=0)
    _annotate_operand_names(insns)

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
    u_proto = db_data.get("proto") or _get_ida_func_proto(entry)

    ida_info = _ida_frame_info(entry)
    frame_info = frame.analyze_frame(func, ida_frame_info=ida_info)
    frame_info.user_renames = u_renames
    frame_info.user_types = u_types

    spill.eliminate_spills(func, frame_info)
    opt.optimize(func)
    sig = abi.analyze_calling_convention(func, frame_info, user_proto=u_proto)
    vars.recover_variables(func, sig, frame_info)
    tree = structure.structure(func)
    return Function(entry, namer.code(entry), func, tree,
                    cgen.generate(func, tree, namer, frame_info=frame_info, sig=sig, banner=BANNER,
                                  user_renames=u_renames, user_types=u_types))

