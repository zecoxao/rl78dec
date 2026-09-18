"""
IDA plugin entry point for rl78dec, the RL78 (PS4/PS5 syscon) decompiler.

Install by copying this file *and* the ``rl78dec`` package directory together
into IDA's user plugin directory:

    %APPDATA%\\Hex-Rays\\IDA Pro\\plugins\\

It runs on a database opened with fail0verflow's RL78 processor module
(https://github.com/fail0verflow/rl78-ida-proc):

    Ctrl-Shift-S   decompile the function under the cursor
    Ctrl-F5        decompile every function in the database
"""

import os
import sys
import time
import traceback

import ida_idaapi
import ida_idp
import ida_kernwin
import ida_funcs

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

HOTKEY_ONE = "Ctrl-Shift-S"
HOTKEY_ALL = "Ctrl-F5"

_views = []
_hotkeys = []


def _is_rl78():
    try:
        return ida_idp.get_idp_name().lower().startswith("rl78")
    except Exception:
        return False


def _run_one():
    from rl78dec import ida_bridge, view
    if not _is_rl78():
        ida_kernwin.warning("rl78dec: this database is not RL78.\n"
                            "Open it with fail0verflow's RL78 processor module first.")
        return
    ea = ida_kernwin.get_screen_ea()
    if ida_funcs.get_func(ea) is None:
        ida_kernwin.warning("rl78dec: no function at 0x%X. Press 'P' to create one." % ea)
        return
    try:
        fn = ida_bridge.decompile_one(ea)
    except Exception:
        ida_kernwin.warning("rl78dec failed:\n\n%s" % traceback.format_exc())
        return
    v = view.show(fn)
    if v is not None:
        _views.append(v)
    print("rl78dec: %s -> %d blocks" % (fn.name, len(fn.cfg.blocks)))


def _run_all():
    from rl78dec import ida_bridge, view
    import ida_nalt
    if not _is_rl78():
        ida_kernwin.warning("rl78dec: this database is not RL78.")
        return
    ida_kernwin.show_wait_box("rl78dec: decompiling all functions...")
    t0 = time.time()
    try:
        prog = ida_bridge.decompile_program()
    except Exception:
        ida_kernwin.hide_wait_box()
        ida_kernwin.warning("rl78dec: decompile all failed:\n\n%s" % traceback.format_exc())
        return
    finally:
        try:
            ida_kernwin.hide_wait_box()
        except Exception:
            pass
    lines = prog.listing().splitlines()
    print("rl78dec: %d functions in %.1fs" % (len(prog.funcs), time.time() - t0))

    default = os.path.splitext(ida_nalt.get_input_file_path() or "syscon")[0] + ".c"
    path = ida_kernwin.ask_file(True, default, "Save the decompiled listing")
    if path:
        try:
            with open(path, "w", encoding="utf-8") as fp:
                fp.write("\n".join(lines) + "\n")
            print("rl78dec: wrote %d lines to %s" % (len(lines), path))
        except Exception as exc:
            ida_kernwin.warning("rl78dec: could not write %s:\n%s" % (path, exc))
    v = view.show_listing("rl78dec - all functions", lines)
    if v is not None:
        _views.append(v)


class Rl78DecPlugin(ida_idaapi.plugin_t):
    flags = 0
    comment = "RL78 (PS4/PS5 syscon) decompiler: lifter + structuring + pseudo-C"
    help = "%s decompiles the current function, %s decompiles everything." % (HOTKEY_ONE, HOTKEY_ALL)
    wanted_name = "RL78 decompiler (rl78dec)"
    wanted_hotkey = HOTKEY_ONE

    def init(self):
        if not _is_rl78():
            return ida_idaapi.PLUGIN_SKIP
        ctx = ida_kernwin.add_hotkey(HOTKEY_ALL, _run_all)
        if ctx is not None:
            _hotkeys.append(ctx)
        print("rl78dec: loaded -- %s = this function, %s = decompile all"
              % (HOTKEY_ONE, HOTKEY_ALL))
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        _run_one()

    def term(self):
        for ctx in _hotkeys:
            try:
                ida_kernwin.del_hotkey(ctx)
            except Exception:
                pass
        del _hotkeys[:]
        del _views[:]


def PLUGIN_ENTRY():
    return Rl78DecPlugin()
