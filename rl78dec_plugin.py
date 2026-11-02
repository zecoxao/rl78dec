"""
IDA plugin entry point for rl78dec, the RL78 (PS4/Vita syscon) decompiler.

Install by copying this file *and* the ``rl78dec`` package directory together
into IDA's user plugin directory:

    %APPDATA%\\Hex-Rays\\IDA Pro\\plugins\\

It runs on a database opened with fail0verflow's RL78 processor module
(https://github.com/fail0verflow/rl78-ida-proc):

    F5             decompile the function under the cursor (or refresh)
    Ctrl-Shift-S   legacy decompile shortcut
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

HOTKEY_DECOMPILE = "F5"
HOTKEY_LEGACY = "Ctrl-Shift-S"
HOTKEY_ALL = "Ctrl-F5"

ACTION_DECOMPILE = "rl78dec:decompile"
MENU_PSEUDOCODE_PATH = "View/Open subviews/Generate pseudocode"
MENU_PLUGIN_PATH = "Edit/Plugins/RL78 decompiler (rl78dec)"

_views = []
_hotkeys = []


def _is_rl78():
    try:
        return ida_idp.get_idp_name().lower().startswith("rl78")
    except Exception:
        return False


class _DecompileActionHandler(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        _run_one()
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


def _run_one():
    from rl78dec import ida_bridge, view
    if not _is_rl78():
        ida_kernwin.warning("rl78dec: this database is not RL78.\n"
                            "Open it with fail0verflow's RL78 processor module first.")
        return
    ea = ida_kernwin.get_screen_ea()
    f = ida_funcs.get_func(ea) if (ea is not None and ea != ida_idaapi.BADADDR) else None

    # If the pseudocode viewer is active and focused, get_screen_ea() can be BADADDR
    if f is None and getattr(view, "_active_viewer", None) is not None and view._active_viewer.current_func_ea is not None:
        start_ea = view._active_viewer.current_func_ea
    elif f is not None:
        start_ea = f.start_ea
    else:
        ida_kernwin.warning("rl78dec: no function at 0x%X. Press 'P' to create one." % (ea if ea is not None else 0))
        return

    try:
        fn = ida_bridge.decompile_one(start_ea)
    except Exception:
        ida_kernwin.warning("rl78dec failed:\n\n%s" % traceback.format_exc())
        return
    v = view.show(fn)
    if v is not None and v not in _views:
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
    if v is not None and v not in _views:
        _views.append(v)


def _register_actions():
    ida_kernwin.unregister_action(ACTION_DECOMPILE)
    desc = ida_kernwin.action_desc_t(
        ACTION_DECOMPILE,
        "RL78 Pseudocode",
        _DecompileActionHandler(),
        HOTKEY_DECOMPILE,
        "Decompile current RL78 function to pseudocode (F5)",
        -1
    )
    if ida_kernwin.register_action(desc):
        ida_kernwin.attach_action_to_menu(MENU_PSEUDOCODE_PATH, ACTION_DECOMPILE, ida_kernwin.SETMENU_APP)
        ida_kernwin.attach_action_to_menu(MENU_PLUGIN_PATH, ACTION_DECOMPILE, ida_kernwin.SETMENU_APP)


def _unregister_actions():
    try:
        ida_kernwin.detach_action_from_menu(MENU_PSEUDOCODE_PATH, ACTION_DECOMPILE)
    except Exception:
        pass
    try:
        ida_kernwin.detach_action_from_menu(MENU_PLUGIN_PATH, ACTION_DECOMPILE)
    except Exception:
        pass
    try:
        ida_kernwin.unregister_action(ACTION_DECOMPILE)
    except Exception:
        pass


class Rl78DecPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_PROC
    comment = "This is a decompilation plugin."
    help = "%s decompiles the current function, %s decompiles everything." % (HOTKEY_DECOMPILE, HOTKEY_ALL)
    wanted_name = "RL78 decompiler (rl78dec)"
    wanted_hotkey = HOTKEY_DECOMPILE

    def init(self):
        if not _is_rl78():
            return ida_idaapi.PLUGIN_SKIP

        _register_actions()

        for hk, fn in [(HOTKEY_DECOMPILE, _run_one),
                       (HOTKEY_LEGACY, _run_one),
                       (HOTKEY_ALL, _run_all)]:
            ctx = ida_kernwin.add_hotkey(hk, fn)
            if ctx is not None:
                _hotkeys.append(ctx)

        print("rl78dec: loaded -- %s = this function, %s = decompile all"
              % (HOTKEY_DECOMPILE, HOTKEY_ALL))
        try:
            from rl78dec import view
            view.init_hooks()
        except Exception:
            pass
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        _run_one()

    def term(self):
        _unregister_actions()
        for ctx in _hotkeys:
            try:
                ida_kernwin.del_hotkey(ctx)
            except Exception:
                pass
        del _hotkeys[:]
        del _views[:]
        try:
            from rl78dec import view
            view.cleanup()
        except Exception:
            pass


def PLUGIN_ENTRY():
    return Rl78DecPlugin()
