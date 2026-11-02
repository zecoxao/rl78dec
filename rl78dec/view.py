"""
Interactive IDA custom viewer for rl78dec pseudocode.

Provides:
- Right-click context menu and hotkeys for:
  - Renaming variables and functions ('N') with IDB netnode persistence.
  - Setting variable and function types ('Y') with IDA type system integration.
  - Linking / synchronizing with IDA's disassembly view (follows cursor across functions).
  - Jumping to disassembly ('Enter' / 'Space' / double-click).
  - Refreshing decompilation ('F5').
- Caret token occurrence highlighting using SCOLOR_EXTRA.
- Navigation history stack (forward navigation on symbol click, back with 'Esc').
- Decompiler window state persistence across IDA sessions via netnodes.
- Automatic docking beside IDA View-A.
"""

import re
import ida_kernwin
import ida_funcs
import ida_lines
import ida_typeinf
import idaapi

from . import highlight, ida_bridge, db

_EA = re.compile(r"\b(?:loc_|sub_)([0-9A-Fa-f]+)\b")
_ADDR_HEX = re.compile(r"\b0x([0-9A-Fa-f]{4,6})\b")
_VIEW_TITLE = "rl78dec - Pseudocode"

ACTION_DECOMPILE = "rl78dec:decompile"
ACTION_RENAME = "rl78dec:rename_var"
ACTION_SET_TYPE = "rl78dec:set_type"
ACTION_TOGGLE_SYNC = "rl78dec:toggle_sync"
ACTION_JUMP_DISASM = "rl78dec:jump_disasm"
ACTION_REFRESH = "rl78dec:refresh"

_active_viewer = None
_ui_hooks = None


def _line_ea(line):
    """Extract code linear address from loc_XXXXX or sub_XXXXX in line."""
    clean = ida_lines.tag_remove(line) if hasattr(ida_lines, "tag_remove") else line
    m = _EA.search(clean)
    if m:
        try:
            return int(m.group(1), 16)
        except ValueError:
            pass
    m = _ADDR_HEX.search(clean)
    if m:
        try:
            return int(m.group(1), 16)
        except ValueError:
            pass
    return None


class _ActionHandler(ida_kernwin.action_handler_t):
    def __init__(self, view, callback):
        super().__init__()
        self.view = view
        self.callback = callback

    def activate(self, ctx):
        self.callback()
        return 1

    def update(self, ctx):
        if not self.view:
            return ida_kernwin.AST_DISABLE_FOR_WIDGET
        widget = self.view.GetWidget()
        if widget and ctx.widget == widget:
            return ida_kernwin.AST_ENABLE_FOR_WIDGET
        return ida_kernwin.AST_DISABLE_FOR_WIDGET


class _DecompilerView(ida_kernwin.simplecustviewer_t):
    def __init__(self):
        super().__init__()
        self.current_func_ea = None
        self.current_func_name = None
        self.line_ea = []
        self.raw_lines = []
        self.sync_with_disasm = db.get_sync_enabled()
        self._nav_history = []
        self._last_token = None
        self._highlighted_token_lines = set()

    def build_or_refresh(self, fn):
        """Populate or update lines with decompiled Function fn."""
        self.current_func_ea = fn.entry
        self.current_func_name = fn.name
        self.line_ea = []
        self.raw_lines = list(fn.lines)
        self._last_token = None
        self._highlighted_token_lines.clear()

        self.ClearLines()
        fn_line_eas = getattr(fn, "line_eas", None) or getattr(fn.lines, "line_eas", None)
        for i, ln in enumerate(fn.lines):
            self.AddLine(highlight.colorize(ln))
            ea = fn_line_eas[i] if (fn_line_eas and i < len(fn_line_eas)) else None
            self.line_ea.append(ea if ea is not None else _line_ea(ln))
        self.Refresh()

    def show_func(self, ea):
        """Decompile function at ea and refresh view."""
        pfn = ida_funcs.get_func(ea)
        entry = pfn.start_ea if pfn else ea
        try:
            fn = ida_bridge.decompile_one(entry)
            self.build_or_refresh(fn)
            return True
        except Exception as exc:
            print("rl78dec: decompilation failed for 0x%X: %s" % (entry, exc))
            return False

    def get_word_under_cursor(self):
        """Return the identifier under cursor and the line number."""
        pos = self.GetPos()
        if not pos:
            word = self.GetCurrentWord()
            return word or "", 0
        lineno, col = pos[0], pos[1]
        if lineno < 0 or lineno >= len(self.raw_lines):
            return "", lineno
        line = self.raw_lines[lineno]
        if not line:
            return "", lineno
        if col < 0:
            col = 0
        elif col >= len(line):
            col = len(line) - 1

        # Check identifier character boundary
        if not (line[col].isalnum() or line[col] == "_"):
            if col > 0 and (line[col - 1].isalnum() or line[col - 1] == "_"):
                col -= 1
            elif col + 1 < len(line) and (line[col + 1].isalnum() or line[col + 1] == "_"):
                col += 1
            else:
                return "", lineno

        start = col
        while start > 0 and (line[start - 1].isalnum() or line[start - 1] == "_"):
            start -= 1
        end = col
        while end < len(line) and (line[end].isalnum() or line[end] == "_"):
            end += 1
        return line[start:end], lineno

    def _update_token_highlight(self):
        """Highlight all occurrences of the identifier under caret across the view."""
        if not self.raw_lines:
            return
        word, lineno = self.get_word_under_cursor()
        active_token = None
        if word and (word[0].isalpha() or word[0] == "_"):
            if word not in highlight.C_KEYWORDS and word not in highlight.C_TYPES:
                active_token = word

        if active_token == self._last_token:
            return

        self._last_token = active_token

        to_restore = set(self._highlighted_token_lines)
        self._highlighted_token_lines.clear()

        new_matching = set()
        if active_token:
            pat = re.compile(r"\b" + re.escape(active_token) + r"\b")
            for idx, raw in enumerate(self.raw_lines):
                if pat.search(raw):
                    new_matching.add(idx)

        affected = to_restore.union(new_matching)
        for idx in affected:
            if 0 <= idx < len(self.raw_lines):
                try:
                    colored = highlight.colorize(self.raw_lines[idx], highlight_ident=active_token)
                    self.EditLine(idx, colored)
                    if idx in new_matching:
                        self._highlighted_token_lines.add(idx)
                except Exception:
                    pass
        if affected:
            try:
                self.RefreshCurrent()
            except Exception:
                pass

    def OnCursorPosChanged(self):
        self._update_token_highlight()

    def OnClick(self, shift):
        self._update_token_highlight()

    def on_rename(self):
        """Rename variable or function under cursor and persist in IDB netnode."""
        if self.current_func_ea is None:
            return
        word, lineno = self.get_word_under_cursor()
        if not word:
            word = ida_kernwin.ask_str("", 0, "Enter variable name to rename")
            if not word:
                return

        new_name = ida_kernwin.ask_str(word, 0, f"Rename '{word}' in {self.current_func_name or 'function'}")
        if new_name is None:
            return
        new_name = new_name.strip()

        # If renaming the function itself
        if word == self.current_func_name or (lineno == 0 and ("(" in self.raw_lines[0])):
            import ida_name
            if new_name:
                ida_name.set_name(self.current_func_ea, new_name)
                self.current_func_name = new_name
            self.show_func(self.current_func_ea)
            return

        # Save variable rename to persistent IDB netnode
        db.set_var_rename(self.current_func_ea, word, new_name)

        # If word is a global symbol in IDA, also rename in IDA's name table
        try:
            import ida_name, ida_idaapi
            ea = ida_name.get_name_ea(ida_idaapi.BADADDR, word)
            if ea != ida_idaapi.BADADDR and new_name:
                ida_name.set_name(ea, new_name)
        except Exception:
            pass

        # If it's a stack frame variable, also rename in IDA's frame struct
        self._rename_frame_member(word, new_name)

        # Refresh decompile
        self.show_func(self.current_func_ea)

    def _rename_frame_member(self, old_name, new_name):
        """Rename stack variable member in IDA's frame structure if present."""
        try:
            import ida_frame
            pfn = ida_funcs.get_func(self.current_func_ea)
            if not pfn:
                return
            tif = ida_typeinf.tinfo_t()
            if ida_frame.get_func_frame(tif, pfn):
                udt = ida_typeinf.udt_type_data_t()
                if tif.get_udt_details(udt):
                    for m in udt:
                        if m.name == old_name:
                            m.name = new_name
                            tif.create_udt(udt, ida_typeinf.BTF_STRUCT)
                            break
        except Exception:
            pass

    def on_set_type(self):
        """Set variable type or function prototype and persist in IDB netnode."""
        if self.current_func_ea is None:
            return
        word, lineno = self.get_word_under_cursor()
        is_sig_line = (lineno == 0) or ("(" in self.raw_lines[lineno] and ")" in self.raw_lines[lineno] and not self.raw_lines[lineno].strip().endswith(";"))

        if is_sig_line or word == self.current_func_name:
            # Edit function prototype
            data = db.get_func_data(self.current_func_ea)
            curr_proto = data.get("proto") or (self.raw_lines[0] if self.raw_lines else "")
            new_proto = ida_kernwin.ask_str(curr_proto, 0, f"Set Function Prototype for {self.current_func_name}")
            if new_proto is None:
                return
            new_proto = new_proto.strip()
            db.set_func_proto(self.current_func_ea, new_proto)

            # Apply to IDA type system
            if new_proto:
                try:
                    ida_typeinf.apply_cdecl(None, self.current_func_ea, new_proto)
                except Exception:
                    pass

            self.show_func(self.current_func_ea)
            return

        if not word:
            return

        # Edit variable type
        data = db.get_func_data(self.current_func_ea)
        curr_type = data.get("types", {}).get(word, "uint16_t")
        new_type = ida_kernwin.ask_str(curr_type, 0, f"Set Type for variable '{word}'")
        if new_type is None:
            return
        new_type = new_type.strip()
        db.set_var_type(self.current_func_ea, word, new_type)

        self.show_func(self.current_func_ea)

    def toggle_sync(self):
        """Toggle synchronization with IDA disassembly view."""
        self.sync_with_disasm = not self.sync_with_disasm
        db.set_sync_enabled(self.sync_with_disasm)
        state_str = "ENABLED" if self.sync_with_disasm else "DISABLED"
        print(f"rl78dec: Sync with Disassembly {state_str}")
        if self.sync_with_disasm:
            ea = ida_kernwin.get_screen_ea()
            pfn = ida_funcs.get_func(ea)
            if pfn and pfn.start_ea != self.current_func_ea:
                self.show_func(pfn.start_ea)

    def jump_disasm(self):
        """Jump to the linear address corresponding to current line or token."""
        word, lineno = self.get_word_under_cursor()
        if word:
            # Check if word is a named symbol in IDA (variable, function, label, SFR)
            try:
                import ida_name, ida_idaapi
                target_ea = ida_name.get_name_ea(ida_idaapi.BADADDR, word)
                if target_ea != ida_idaapi.BADADDR:
                    pfn = ida_funcs.get_func(target_ea)
                    if pfn and pfn.start_ea == target_ea:
                        idaapi.jumpto(target_ea)
                        if target_ea != self.current_func_ea:
                            pos = self.GetPos()
                            self._nav_history.append((self.current_func_ea, pos[0] if pos else 0, pos[1] if pos else 0))
                            self.show_func(target_ea)
                        return True
                    else:
                        idaapi.jumpto(target_ea)
                        return True
            except Exception:
                pass

            # If word is a function or label address
            m = _EA.search(word) or _ADDR_HEX.search(word)
            if m:
                try:
                    target_ea = int(m.group(1), 16)
                    pfn = ida_funcs.get_func(target_ea)
                    if pfn and pfn.start_ea == target_ea:
                        idaapi.jumpto(target_ea)
                        if target_ea != self.current_func_ea:
                            pos = self.GetPos()
                            self._nav_history.append((self.current_func_ea, pos[0] if pos else 0, pos[1] if pos else 0))
                            self.show_func(target_ea)
                        return True
                    else:
                        idaapi.jumpto(target_ea)
                        return True
                except ValueError:
                    pass

        if lineno is not None and lineno < len(self.line_ea):
            ea = self.line_ea[lineno]
            if ea is not None:
                idaapi.jumpto(ea)
                return True
        return False

    def OnDblClick(self, shift):
        return self.jump_disasm()

    def OnKeydown(self, vkey, shift):
        if vkey in (ord('N'), ord('n')):
            self.on_rename()
            return True
        if vkey in (ord('Y'), ord('y')):
            self.on_set_type()
            return True
        if vkey == 116:  # F5
            if self.current_func_ea is not None:
                self.show_func(self.current_func_ea)
            return True
        if vkey in (13, 32):  # Enter or Space
            return self.jump_disasm()
        if vkey == 9:  # Tab
            self.toggle_sync()
            return True
        if vkey == 27:  # Esc
            if self._nav_history:
                prev_ea, prev_line, prev_col = self._nav_history.pop()
                self.show_func(prev_ea)
                try:
                    self.Jump(prev_line, prev_col)
                except Exception:
                    pass
                return True
            global _active_viewer
            _active_viewer = None
            if self.current_func_ea is not None:
                db.save_window_state(False, self.current_func_ea)
            self.Close()
            return True
        return False


class _ViewHooks(ida_kernwin.UI_Hooks):
    def __init__(self, view):
        super().__init__()
        self.view = view

    def create_desktop_widget(self, title, cfg):
        if title == _VIEW_TITLE:
            global _active_viewer
            if _active_viewer is None or _active_viewer.GetWidget() is None:
                v = _DecompilerView()
                if v.Create(_VIEW_TITLE):
                    _active_viewer = v
                    _register_actions(_active_viewer)
                    self.view = _active_viewer
                    return _active_viewer.GetWidget()
            else:
                return _active_viewer.GetWidget()
        return None

    def desktop_applied(self, name, from_idb, type):
        self._restore_from_state()

    def database_inited(self, is_new_database):
        self._restore_from_state()

    def saving(self):
        self._record_current_state()

    def saved(self):
        self._record_current_state()

    def _record_current_state(self):
        global _active_viewer
        if _active_viewer is not None and _active_viewer.GetWidget() is not None:
            pos = _active_viewer.GetPos() or (0, 0)
            if _active_viewer.current_func_ea is not None:
                db.save_window_state(True, _active_viewer.current_func_ea,
                                     lineno=pos[0], col=pos[1])

    def _restore_from_state(self):
        global _active_viewer
        state = db.load_window_state()
        if not state.get("is_open") or not state.get("func_ea"):
            return
        func_ea = state["func_ea"]
        lineno = state.get("lineno", 0)
        col = state.get("col", 0)
        if _active_viewer is not None and _active_viewer.GetWidget() is not None:
            if _active_viewer.current_func_ea != func_ea or not _active_viewer.raw_lines:
                _active_viewer.show_func(func_ea)
            if lineno:
                try:
                    _active_viewer.Jump(lineno, col)
                except Exception:
                    pass

    def screen_ea_changed(self, ea, prev_ea):
        """Automatically follow current function in disassembly when sync is active."""
        if not self.view or not self.view.sync_with_disasm:
            return
        if _active_viewer is not self.view:
            return
        pfn = ida_funcs.get_func(ea)
        if pfn is None:
            return
        if pfn.start_ea != self.view.current_func_ea:
            self.view.show_func(pfn.start_ea)

    def widget_invisible(self, widget):
        """Reset active viewer when the decompiler window is closed."""
        if self.view and widget == self.view.GetWidget():
            global _active_viewer
            if self.view.current_func_ea is not None:
                db.save_window_state(False, self.view.current_func_ea)
            _active_viewer = None

    def finish_populating_widget_popup(self, widget, popup_handle):
        """Attach decompiler context actions to the right-click popup menu."""
        wtype = ida_kernwin.get_widget_type(widget)
        if wtype == ida_kernwin.BWN_DISASM:
            ida_kernwin.attach_action_to_popup(widget, popup_handle, ACTION_DECOMPILE)
            return

        if not self.view:
            return
        view_widget = self.view.GetWidget()
        if widget != view_widget:
            return

        # Attach custom decompiler actions
        ida_kernwin.attach_action_to_popup(widget, popup_handle, ACTION_RENAME)
        ida_kernwin.attach_action_to_popup(widget, popup_handle, ACTION_SET_TYPE)
        ida_kernwin.attach_action_to_popup(widget, popup_handle, ACTION_TOGGLE_SYNC)
        ida_kernwin.attach_action_to_popup(widget, popup_handle, ACTION_JUMP_DISASM)
        ida_kernwin.attach_action_to_popup(widget, popup_handle, ACTION_REFRESH)


def _register_actions(view):
    """Register IDA actions for popup menu (without global shortcuts that interfere with other windows)."""
    actions = [
        (ACTION_RENAME, "Rename variable/symbol... (N)", view.on_rename),
        (ACTION_SET_TYPE, "Set variable/function type... (Y)", view.on_set_type),
        (ACTION_TOGGLE_SYNC, "Sync with Disassembly (Tab)", view.toggle_sync),
        (ACTION_JUMP_DISASM, "Jump to Disassembly (Enter)", view.jump_disasm),
        (ACTION_REFRESH, "Refresh Decompilation (F5)", lambda: view.show_func(view.current_func_ea)),
    ]
    for action_id, label, callback in actions:
        ida_kernwin.unregister_action(action_id)
        desc = ida_kernwin.action_desc_t(
            action_id,
            label,
            _ActionHandler(view, callback),
            None,
            label
        )
        ida_kernwin.register_action(desc)


def show(function):
    """Open or refresh the dockable decompiler view for the specified function."""
    global _active_viewer, _ui_hooks
    first_create = False
    if _active_viewer is None or _active_viewer.GetWidget() is None:
        v = _DecompilerView()
        if not v.Create(_VIEW_TITLE):
            return None
        _active_viewer = v
        _register_actions(_active_viewer)
        first_create = True

        if _ui_hooks is None:
            _ui_hooks = _ViewHooks(_active_viewer)
            _ui_hooks.hook()
        else:
            _ui_hooks.view = _active_viewer

    _active_viewer.build_or_refresh(function)
    _active_viewer.Show()

    if first_create:
        try:
            ida_kernwin.set_dock_pos(_VIEW_TITLE, "IDA View-A", ida_kernwin.DP_RIGHT)
        except Exception:
            pass

    if _active_viewer.current_func_ea is not None:
        pos = _active_viewer.GetPos() or (0, 0)
        db.save_window_state(True, _active_viewer.current_func_ea, lineno=pos[0], col=pos[1])

    return _active_viewer


def init_hooks():
    """Initialize UI hooks early (at plugin load) to support desktop/docking persistence."""
    global _ui_hooks
    if _ui_hooks is None:
        _ui_hooks = _ViewHooks(None)
        _ui_hooks.hook()


def show_listing(title, lines):
    """Fallback simple viewer for whole-program export listing."""
    v = ida_kernwin.simplecustviewer_t()
    if v.Create(title):
        for ln in lines:
            v.AddLine(highlight.colorize(ln))
        v.Show()
        return v
    return None


def cleanup():
    """Unregister hooks and actions on plugin unload."""
    global _active_viewer, _ui_hooks
    if _ui_hooks is not None:
        try:
            _ui_hooks.unhook()
        except Exception:
            pass
        _ui_hooks = None
    for action_id in [ACTION_DECOMPILE, ACTION_RENAME, ACTION_SET_TYPE, ACTION_TOGGLE_SYNC, ACTION_JUMP_DISASM, ACTION_REFRESH]:
        try:
            ida_kernwin.unregister_action(action_id)
        except Exception:
            pass
    _active_viewer = None
