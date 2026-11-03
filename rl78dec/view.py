"""
Interactive IDA custom viewer for rl78dec pseudocode.

Provides:
- Right-click context menu and hotkeys for:
  - Renaming variables and functions ('N') with IDB netnode persistence.
  - Setting variable and function types ('Y') with IDA type system integration.
  - Bidirectional synchronization with IDA's disassembly view (follows cursor across instructions and functions).
  - Jumping to symbols and disassembly ('Enter' / 'Space' / double-click).
  - Call navigation history with 'Esc' back-stepping.
  - Refreshing decompilation ('F5').
  - Hex-Rays standard 'Tab' switching between disassembly and pseudocode.
- Reusable dockable window that updates in place during navigation.
"""

import re
try:
    import ida_kernwin
    import ida_funcs
    import ida_lines
    import ida_typeinf
    import ida_idaapi
    import ida_name
    import idaapi
except ImportError:
    ida_kernwin = None
    ida_funcs = None
    ida_lines = None
    ida_typeinf = None
    ida_idaapi = None
    ida_name = None
    idaapi = None

_action_handler_base = getattr(ida_kernwin, "action_handler_t", object) if ida_kernwin else object
_simplecustviewer_base = getattr(ida_kernwin, "simplecustviewer_t", None) if ida_kernwin else None
if _simplecustviewer_base is None:
    class _MockCustViewer:
        def __init__(self):
            self._widget = id(self)
        def Create(self, title):
            return True
        def GetPos(self):
            return (0, 0)
        def GetLineNo(self):
            return 0
        def GetCurrentWord(self):
            return ""
        def GetWidget(self):
            return self._widget
        def ClearLines(self):
            pass
        def AddLine(self, line):
            pass
        def Refresh(self):
            pass
        def Jump(self, line, col):
            pass
        def Close(self):
            pass
        def Show(self):
            return True
    _simplecustviewer_base = _MockCustViewer

_ui_hooks_base = getattr(ida_kernwin, "UI_Hooks", object) if ida_kernwin else object
_view_hooks_base = getattr(ida_kernwin, "View_Hooks", object) if ida_kernwin else object

from . import highlight, ida_bridge, db

_EA = re.compile(r"\b(?:loc_|sub_)([0-9A-Fa-f]+)\b")
_ADDR_HEX = re.compile(r"\b0x([0-9A-Fa-f]{4,6})\b")
_VIEW_TITLE = "rl78dec - Pseudocode"

ACTION_RENAME = "rl78dec:rename_var"
ACTION_SET_TYPE = "rl78dec:set_type"
ACTION_TOGGLE_SYNC = "rl78dec:toggle_sync"
ACTION_TOGGLE_IR = "rl78dec:toggle_ir"
ACTION_JUMP_DISASM = "rl78dec:jump_disasm"
ACTION_REFRESH = "rl78dec:refresh"

_active_viewer = None
_ui_hooks = None
_view_hooks = None


def resolve_symbol_ea(word, current_func_ea=None):
    """
    Resolve identifier string to linear address in IDA:
    - Global symbols & functions in IDA name table
    - Local labels in function name table
    - Synthesized identifiers (sub_XXXX, loc_XXXX, byte_XXXX, word_XXXX, ram_XXXX, saddr_XX)
    - Hardware SFR names (RXD3, P2, etc.)
    - Hex constants (0xXXXX)
    """
    if not word:
        return None

    if ida_name and ida_idaapi:
        try:
            ea = ida_name.get_name_ea(ida_idaapi.BADADDR, word)
            if ea != ida_idaapi.BADADDR:
                return ea
            if current_func_ea is not None:
                ea = ida_name.get_name_ea(current_func_ea, word)
                if ea != ida_idaapi.BADADDR:
                    return ea
        except Exception:
            pass

    m = re.match(r"^(?:sub_|loc_|byte_|word_|dword_|m_)([0-9A-Fa-f]+)$", word)
    if m:
        try:
            return int(m.group(1), 16)
        except ValueError:
            pass

    m = re.match(r"^ram_([0-9A-Fa-f]{4})$", word, re.IGNORECASE)
    if m:
        try:
            return 0xF0000 | int(m.group(1), 16)
        except ValueError:
            pass

    m = re.match(r"^saddr_([0-9A-Fa-f]{2})$", word, re.IGNORECASE)
    if m:
        try:
            val = int(m.group(1), 16)
            return (0xFFF00 | val) if val >= 0x20 else (0xFFE00 | val)
        except ValueError:
            pass

    try:
        from . import sfr
        sfr_addrs = getattr(sfr, "SFR_ADDRS", None)
        if sfr_addrs is None:
            sfr.SFR_ADDRS = {n: addr for addr, n in sfr.SFR_NAMES.items()}
            sfr_addrs = sfr.SFR_ADDRS
        if word in sfr_addrs:
            return sfr_addrs[word]
    except Exception:
        pass

    m = re.match(r"^0x([0-9A-Fa-f]+)$", word)
    if m:
        try:
            return int(m.group(1), 16)
        except ValueError:
            pass

    return None


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


class _ActionHandler(_action_handler_base):
    def __init__(self, view, callback):
        super().__init__()
        self.view = view
        self.callback = callback

    def activate(self, ctx):
        self.callback()
        return 1

    def update(self, ctx):
        if not self.view:
            return ida_kernwin.AST_DISABLE_FOR_WIDGET if ida_kernwin else 0
        widget = self.view.GetWidget()
        if widget and ctx.widget == widget:
            return ida_kernwin.AST_ENABLE_FOR_WIDGET
        return ida_kernwin.AST_DISABLE_FOR_WIDGET


class _DecompilerView(_simplecustviewer_base):
    def __init__(self):
        super().__init__()
        self.current_func_ea = None
        self.current_func_name = None
        self.line_ea = []
        self.raw_lines = []
        self.ea_to_line = {}
        self.sync_with_disasm = db.get_sync_enabled()
        self.show_ir = False
        self._is_syncing = False
        self._nav_history = []

    def save_state(self, is_open=True):
        """Save active window state into the persistent database netnode."""
        if self.current_func_ea is None:
            return
        pos = self.GetPos()
        lineno = max(0, pos[0]) if (pos and pos[0] >= 0) else 0
        col = max(0, pos[1]) if (pos and pos[1] >= 0) else 0
        mode = "ir" if getattr(self, "show_ir", False) else "c"
        db.save_window_state(is_open=is_open, func_ea=self.current_func_ea, lineno=lineno, col=col, mode=mode)

    def _build_ir_lines(self, func, namer):
        """Format SSA IR lines for the current function."""
        lines = []
        line_ea = []
        lines.append(f"// Lifted SSA IR for {self.current_func_name or 'function'}")
        line_ea.append(self.current_func_ea)
        for bid in sorted(func.blocks.keys()):
            b = func.blocks[bid]
            lines.append(f"block_{bid:X}:")
            b_ea = getattr(b, "start", bid)
            line_ea.append(b_ea)
            for s in b.stmts:
                s_str = _format_ir_stmt(s, namer)
                lines.append(f"    {s_str}")
                line_ea.append(getattr(s, "ea", b_ea))
        return lines, line_ea

    def toggle_ir_mode(self):
        """Toggle between C pseudocode and lifted SSA IR view."""
        self.show_ir = not getattr(self, "show_ir", False)
        if self.current_func_ea is not None:
            self.show_func(self.current_func_ea)
        self.save_state(is_open=True)

    def find_line_for_ea(self, ea):
        """Find the matching line index for instruction linear address ea."""
        if not hasattr(self, "ea_to_line") or not self.ea_to_line:
            return None
        if ea in self.ea_to_line:
            return self.ea_to_line[ea]
        # Return line for closest preceding instruction EA
        prev_eas = [e for e in self.ea_to_line if e <= ea]
        if prev_eas:
            return self.ea_to_line[max(prev_eas)]
        return None

    def find_ea_for_line(self, line_idx):
        """Find instruction linear address for given line index."""
        if hasattr(self, "line_ea") and 0 <= line_idx < len(self.line_ea):
            return self.line_ea[line_idx]
        return None

    def build_or_refresh(self, fn):
        """Populate or update lines with decompiled Function fn."""
        self.current_func_ea = fn.entry
        self.current_func_name = fn.name
        self.line_ea = list(getattr(fn, "line_ea", []))
        self.raw_lines = list(fn.lines)
        self.ea_to_line = {}

        self.ClearLines()
        for idx, ln in enumerate(fn.lines):
            self.AddLine(highlight.colorize(ln))
            ea = self.line_ea[idx] if idx < len(self.line_ea) else _line_ea(ln)
            if idx >= len(self.line_ea):
                self.line_ea.append(ea)
            if ea is not None and ea not in self.ea_to_line:
                self.ea_to_line[ea] = idx

        self.Refresh()
        self.save_state(is_open=True)

    def show_func(self, ea):
        """Decompile function at ea and refresh view."""
        pfn = ida_funcs.get_func(ea) if ida_funcs else None
        entry = pfn.start_ea if pfn else ea
        try:
            fn = ida_bridge.decompile_one(entry)
            if getattr(self, "show_ir", False):
                lines, line_ea = self._build_ir_lines(getattr(fn, "cfg", getattr(fn, "func", None)), ida_bridge.IdaNamer())
                self.current_func_ea = entry
                self.current_func_name = fn.name
                self.line_ea = line_ea
                self.raw_lines = lines
                self.ea_to_line = {}
                self.ClearLines()
                for idx, ln in enumerate(lines):
                    self.AddLine(highlight.colorize(ln))
                    lea = line_ea[idx] if idx < len(line_ea) else None
                    if lea is not None and lea not in self.ea_to_line:
                        self.ea_to_line[lea] = idx
                self.Refresh()
            else:
                self.build_or_refresh(fn)
            self.save_state(is_open=True)
            return True
        except Exception as exc:
            print("rl78dec: decompilation failed for 0x%X: %s" % (entry, exc))
            return False

    def get_word_under_cursor(self):
        """Return the identifier under cursor and the line number."""
        pos = self.GetPos()
        if not pos:
            word = self.GetCurrentWord()
            lineno = self.GetLineNo() if hasattr(self, "GetLineNo") else 0
            return (word or "").strip(), (lineno or 0)
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
            if new_name and ida_name:
                ida_name.set_name(self.current_func_ea, new_name)
                self.current_func_name = new_name
            self.show_func(self.current_func_ea)
            return

        # Save variable rename to persistent IDB netnode
        db.set_var_rename(self.current_func_ea, word, new_name)

        # If word is a global symbol in IDA, also rename in IDA's name table
        try:
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
        if self.sync_with_disasm and ida_kernwin and ida_funcs:
            ea = ida_kernwin.get_screen_ea()
            pfn = ida_funcs.get_func(ea)
            if pfn and pfn.start_ea != self.current_func_ea:
                self.show_func(pfn.start_ea)
            line = self.find_line_for_ea(ea)
            if line is not None:
                self.Jump(line, 0)

    def jump_symbol_or_disasm(self):
        """
        Navigate to symbol under cursor matching IDA assembly view behavior:
        - If function call: navigate to that function in decompiler (push history).
        - If label within current function: jump caret to label in decompiler.
        - If global variable / SFR / data address: jump disassembly to that data address.
        - Fallback: jump disassembly to the originating instruction address of the current line.
        """
        word, lineno = self.get_word_under_cursor()
        target_ea = resolve_symbol_ea(word, self.current_func_ea)

        bad_addr = getattr(ida_idaapi, "BADADDR", 0xFFFFFFFFFFFFFFFF)
        if target_ea is not None and target_ea != bad_addr:
            pfn = ida_funcs.get_func(target_ea) if ida_funcs else None

            # 1. Target is a different function -> decompile and navigate into it
            if pfn is not None and pfn.start_ea != self.current_func_ea:
                self._nav_history.append((self.current_func_ea, lineno))
                self.show_func(pfn.start_ea)
                if self.sync_with_disasm and idaapi:
                    try:
                        self._is_syncing = True
                        idaapi.jumpto(target_ea)
                    finally:
                        self._is_syncing = False
                return True

            # 2. Target is a label within the current function -> jump caret to line
            if pfn is not None and pfn.start_ea == self.current_func_ea and target_ea != self.current_func_ea:
                line = self.find_line_for_ea(target_ea)
                if line is not None:
                    self.Jump(line, 0)
                    if self.sync_with_disasm and idaapi:
                        try:
                            self._is_syncing = True
                            idaapi.jumpto(target_ea)
                            my_w = self.GetWidget()
                            if my_w and ida_kernwin:
                                ida_kernwin.activate_widget(my_w, True)
                        finally:
                            self._is_syncing = False
                    return True

            # 3. Target is a global variable, SFR, data address, or current func start
            if idaapi:
                idaapi.jumpto(target_ea)
                return True

        # 4. Fallback: Jump disassembly to line's instruction address
        if lineno is not None and lineno < len(self.line_ea):
            ea = self.line_ea[lineno]
            if ea is not None and idaapi:
                idaapi.jumpto(ea)
                return True

        return False

    def OnDblClick(self, shift):
        return self.jump_symbol_or_disasm()

    def OnKeydown(self, vkey, shift):
        if vkey in (ord('N'), ord('n')):
            self.on_rename()
            return True
        if vkey in (ord('Y'), ord('y')):
            self.on_set_type()
            return True
        if vkey == 116: # F5
            if self.current_func_ea is not None:
                self.show_func(self.current_func_ea)
            return True
        if vkey in (13, 32): # Enter or Space
            return self.jump_symbol_or_disasm()
        if vkey == 9: # Tab
            # Hex-Rays behavior: Tab switches focus to Disassembly at current instruction
            pos = self.GetPos()
            lineno = pos[0] if pos else self.GetLineNo()
            ea = self.find_ea_for_line(lineno) or self.current_func_ea
            if ea is not None and idaapi:
                idaapi.jumpto(ea)
            return True
        if vkey in (ord('I'), ord('i')):
            self.toggle_ir_mode()
            return True
        if vkey == 27: # Esc
            if self._nav_history:
                prev_ea, prev_line = self._nav_history.pop()
                self.show_func(prev_ea)
                if prev_line is not None:
                    self.Jump(prev_line, 0)
                if self.sync_with_disasm and idaapi:
                    target_disasm = self.find_ea_for_line(prev_line) or prev_ea
                    try:
                        self._is_syncing = True
                        idaapi.jumpto(target_disasm)
                    finally:
                        self._is_syncing = False
                return True
            global _active_viewer
            self.save_state(is_open=False)
            _active_viewer = None
            self.Close()
            return True
        return False


class _ViewHooks(_view_hooks_base):
    def __init__(self, view):
        super().__init__()
        self.view = view

    def _sync_to_disasm(self, widget):
        """Synchronize cursor position from decompiler to disassembly view."""
        if not self.view or not self.view.sync_with_disasm:
            return
        if getattr(self.view, "_is_syncing", False):
            return
        if _active_viewer is not self.view:
            return
        my_widget = self.view.GetWidget()
        if my_widget is None or widget != my_widget:
            return

        # Token occurrence highlighting
        word, lineno = self.view.get_word_under_cursor()
        if word and ida_kernwin:
            try:
                ida_kernwin.set_highlight(my_widget, word, ida_kernwin.HIF_IDENTIFIER)
            except Exception:
                pass

        ea = self.view.find_ea_for_line(lineno)
        # Update saved cursor position in database netnode
        self.view.save_state(is_open=True)
        bad_addr = getattr(ida_idaapi, "BADADDR", 0xFFFFFFFFFFFFFFFF)
        if ea is not None and ea != bad_addr and ida_kernwin and idaapi:
            curr_screen_ea = ida_kernwin.get_screen_ea()
            if curr_screen_ea != ea:
                try:
                    self.view._is_syncing = True
                    idaapi.jumpto(ea)
                    # Restore focus to decompiler so caret navigation is seamless
                    if my_widget:
                        ida_kernwin.activate_widget(my_widget, True)
                finally:
                    self.view._is_syncing = False

    def view_curpos(self, widget):
        self._sync_to_disasm(widget)

    def view_click(self, widget, event):
        self._sync_to_disasm(widget)


class _UIHooks(_ui_hooks_base):
    def __init__(self, view):
        super().__init__()
        self.view = view

    def screen_ea_changed(self, ea, prev_ea):
        """Automatically follow disassembly cursor in the decompiler view."""
        if not self.view or not self.view.sync_with_disasm:
            return
        if getattr(self.view, "_is_syncing", False):
            return
        if _active_viewer is not self.view:
            return
        bad_addr = getattr(ida_idaapi, "BADADDR", 0xFFFFFFFFFFFFFFFF)
        if ea is None or ea == bad_addr:
            return

        pfn = ida_funcs.get_func(ea) if ida_funcs else None
        if pfn is None:
            return

        try:
            self.view._is_syncing = True

            # If function changed, switch function
            if pfn.start_ea != self.view.current_func_ea:
                self.view.show_func(pfn.start_ea)

            # Find matching line for ea and scroll/jump caret
            line = self.view.find_line_for_ea(ea)
            if line is not None:
                self.view.Jump(line, 0)
                # Keep user focus on disassembly view
                if ida_kernwin:
                    curr_w = ida_kernwin.get_current_widget()
                    if curr_w and curr_w != self.view.GetWidget():
                        ida_kernwin.activate_widget(curr_w, True)
        finally:
            self.view._is_syncing = False

    def widget_closing(self, widget):
        """Save closed window state when decompiler tab is closed."""
        if self.view and widget == self.view.GetWidget():
            self.view.save_state(is_open=False)
            global _active_viewer
            _active_viewer = None

    def widget_invisible(self, widget):
        """Reset active viewer and mark window closed when widget becomes invisible."""
        if self.view and widget == self.view.GetWidget():
            self.view.save_state(is_open=False)
            global _active_viewer
            _active_viewer = None

    def get_widget_config(self, widget, cfg):
        """Called by IDA when saving desktop configuration."""
        if not self.view:
            return None
        my_w = self.view.GetWidget()
        if widget != my_w:
            return None
        pos = self.view.GetPos()
        lineno = pos[0] if pos else 0
        col = pos[1] if pos else 0
        mode = "ir" if getattr(self.view, "show_ir", False) else "c"
        return {
            "ea": self.view.current_func_ea,
            "lineno": lineno,
            "col": col,
            "mode": mode,
            "sync": getattr(self.view, "sync_with_disasm", True),
        }

    def set_widget_config(self, widget, cfg):
        """Called by IDA when applying desktop configuration."""
        if not self.view:
            return
        my_w = self.view.GetWidget()
        if widget != my_w:
            return
        config = {}
        if cfg and hasattr(cfg, "get_dict"):
            try:
                config = cfg.get_dict() or {}
            except Exception:
                pass
        lineno = max(0, config.get("lineno", 0))
        col = max(0, config.get("col", 0))
        mode = config.get("mode", "c")
        if mode == "ir" and not getattr(self.view, "show_ir", False):
            self.view.toggle_ir_mode()
        if lineno > 0:
            self.view.Jump(lineno, col)

    def create_desktop_widget(self, title, cfg):
        """Called by IDA when restoring desktop layout widgets."""
        if title != _VIEW_TITLE:
            return None
        config = {}
        if cfg and hasattr(cfg, "get_dict"):
            try:
                config = cfg.get_dict() or {}
            except Exception:
                pass
        ea = config.get("ea")
        if ea is None:
            st = db.load_window_state()
            if st.get("is_open"):
                ea = st.get("func_ea")
                config.update(st)
        if ea is None:
            return None

        v = restore_view(ea, config=config, display=False)
        return v.GetWidget() if v else None

    def ready_to_run(self):
        """Called when IDA UI elements are fully initialized."""
        self._check_and_restore_saved_view()

    def database_inited(self, is_new_database, idc_script):
        """Called after database initialization."""
        self._check_and_restore_saved_view()

    def _check_and_restore_saved_view(self):
        """Restore decompiler view from database netnode if not already opened by desktop manager."""
        if not ida_kernwin or (hasattr(ida_kernwin, "is_idaq") and not ida_kernwin.is_idaq()):
            return
        existing = ida_kernwin.find_widget(_VIEW_TITLE)
        if existing is not None:
            return
        st = db.load_window_state()
        if st and st.get("is_open") and st.get("func_ea") is not None:
            restore_view(st["func_ea"], config=st, display=True)

    def finish_populating_widget_popup(self, widget, popup_handle):
        """Attach decompiler context actions to the right-click popup menu."""
        if not self.view:
            return
        view_widget = self.view.GetWidget()
        if widget != view_widget:
            return

        # Attach custom decompiler actions
        ida_kernwin.attach_action_to_popup(widget, popup_handle, ACTION_RENAME)
        ida_kernwin.attach_action_to_popup(widget, popup_handle, ACTION_SET_TYPE)
        ida_kernwin.attach_action_to_popup(widget, popup_handle, ACTION_TOGGLE_SYNC)
        ida_kernwin.attach_action_to_popup(widget, popup_handle, ACTION_TOGGLE_IR)
        ida_kernwin.attach_action_to_popup(widget, popup_handle, ACTION_JUMP_DISASM)
        ida_kernwin.attach_action_to_popup(widget, popup_handle, ACTION_REFRESH)


def _format_ir_expr(e, namer):
    from . import ir
    if isinstance(e, ir.Const):
        return f"0x{e.value:X}" if e.value >= 10 else str(e.value)
    if isinstance(e, (ir.Reg, ir.Var, ir.StackVar)):
        return e.name
    if isinstance(e, ir.Bin):
        return f"{_format_ir_expr(e.l, namer)} {e.op} {_format_ir_expr(e.r, namer)}"
    if isinstance(e, ir.Un):
        return f"{e.op}{_format_ir_expr(e.e, namer)}"
    if isinstance(e, ir.Mem):
        return f"mem[{_format_ir_expr(e.addr, namer)}]" if isinstance(e.addr, ir.Expr) else f"mem[{e.addr:X}]"
    if isinstance(e, ir.IntrExpr):
        return f"{e.name}({', '.join(_format_ir_expr(a, namer) for a in e.args)})"
    return str(e)


def _format_ir_stmt(s, namer):
    from . import ir
    if isinstance(s, ir.Assign):
        return f"{_format_ir_expr(s.dst, namer)} = {_format_ir_expr(s.src, namer)}"
    if isinstance(s, ir.Call):
        args_str = ", ".join(_format_ir_expr(a, namer) for a in s.args)
        t_str = namer.code(s.target) if s.target is not None else _format_ir_expr(s.expr, namer)
        call_str = f"{t_str}({args_str})"
        if s.dst is not None:
            return f"{_format_ir_expr(s.dst, namer)} = {call_str}"
        return call_str
    if isinstance(s, ir.Goto):
        return f"goto {namer.label(s.target)}"
    if isinstance(s, ir.Ret):
        if getattr(s, "val", None) is not None:
            return f"return {_format_ir_expr(s.val, namer)}"
        return "return"
    return str(s)


def _register_actions(view):
    """Register IDA actions for popup menu (scoped to widget to avoid chooser interference)."""
    if not ida_kernwin:
        return
    actions = [
        (ACTION_RENAME, "Rename variable/symbol... (N)", view.on_rename),
        (ACTION_SET_TYPE, "Set variable/function type... (Y)", view.on_set_type),
        (ACTION_TOGGLE_SYNC, "Sync with Disassembly (Tab)", view.toggle_sync),
        (ACTION_TOGGLE_IR, "Toggle C / SSA IR View (I)", view.toggle_ir_mode),
        (ACTION_JUMP_DISASM, "Jump to Symbol/Disassembly (Enter)", view.jump_symbol_or_disasm),
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


def show(function, dock=True):
    """Open or refresh the dockable decompiler view for the specified function."""
    global _active_viewer, _ui_hooks, _view_hooks
    if _active_viewer is None or _active_viewer.GetWidget() is None:
        v = _DecompilerView()
        if not v.Create(_VIEW_TITLE):
            return None
        _active_viewer = v
        _register_actions(_active_viewer)

        if _ui_hooks is None and ida_kernwin:
            _ui_hooks = _UIHooks(_active_viewer)
            _ui_hooks.hook()
        elif _ui_hooks is not None:
            _ui_hooks.view = _active_viewer

        if _view_hooks is None and ida_kernwin:
            _view_hooks = _ViewHooks(_active_viewer)
            _view_hooks.hook()
        elif _view_hooks is not None:
            _view_hooks.view = _active_viewer
    else:
        if _ui_hooks is not None:
            _ui_hooks.view = _active_viewer
        if _view_hooks is not None:
            _view_hooks.view = _active_viewer

    _active_viewer.build_or_refresh(function)
    _active_viewer.Show()

    # Dock beside IDA View-A if in GUI mode
    if dock and ida_kernwin and hasattr(ida_kernwin, "is_idaq") and ida_kernwin.is_idaq():
        try:
            disasm_w = ida_kernwin.find_widget("IDA View-A")
            my_w = _active_viewer.GetWidget()
            if disasm_w and my_w:
                ida_kernwin.display_widget(
                    my_w,
                    ida_kernwin.WOPN_DP_TAB | ida_kernwin.WOPN_RESTORE,
                    disasm_w
                )
        except Exception:
            pass

    _active_viewer.save_state(is_open=True)
    return _active_viewer


def restore_view(ea, config=None, display=True):
    """Restore decompiler view for function at ea with persistent settings."""
    global _active_viewer, _ui_hooks, _view_hooks
    try:
        fn = ida_bridge.decompile_one(ea)
    except Exception as exc:
        print("rl78dec: restore failed for 0x%X: %s" % (ea, exc))
        return None

    if _active_viewer is None or _active_viewer.GetWidget() is None:
        v = _DecompilerView()
        if not v.Create(_VIEW_TITLE):
            return None
        _active_viewer = v
        _register_actions(_active_viewer)

        if _ui_hooks is None and ida_kernwin:
            _ui_hooks = _UIHooks(_active_viewer)
            _ui_hooks.hook()
        elif _ui_hooks is not None:
            _ui_hooks.view = _active_viewer

        if _view_hooks is None and ida_kernwin:
            _view_hooks = _ViewHooks(_active_viewer)
            _view_hooks.hook()
        elif _view_hooks is not None:
            _view_hooks.view = _active_viewer
    else:
        v = _active_viewer
        if _ui_hooks is not None:
            _ui_hooks.view = v
        if _view_hooks is not None:
            _view_hooks.view = v

    cfg = config or {}
    v.sync_with_disasm = cfg.get("sync", db.get_sync_enabled())
    mode = cfg.get("mode", "c")
    v.show_ir = (mode == "ir")

    if v.show_ir:
        lines, line_ea = v._build_ir_lines(getattr(fn, "cfg", getattr(fn, "func", None)), ida_bridge.IdaNamer())
        v.current_func_ea = fn.entry
        v.current_func_name = fn.name
        v.line_ea = line_ea
        v.raw_lines = lines
        v.ea_to_line = {}
        v.ClearLines()
        for idx, ln in enumerate(lines):
            v.AddLine(highlight.colorize(ln))
            lea = line_ea[idx] if idx < len(line_ea) else None
            if lea is not None and lea not in v.ea_to_line:
                v.ea_to_line[lea] = idx
        v.Refresh()
    else:
        v.build_or_refresh(fn)

    lineno = max(0, cfg.get("lineno", 0))
    col = max(0, cfg.get("col", 0))
    if lineno > 0:
        v.Jump(lineno, col)

    if display:
        v.Show()
        if ida_kernwin and hasattr(ida_kernwin, "is_idaq") and ida_kernwin.is_idaq():
            try:
                disasm_w = ida_kernwin.find_widget("IDA View-A")
                my_w = v.GetWidget()
                if disasm_w and my_w:
                    ida_kernwin.display_widget(
                        my_w,
                        ida_kernwin.WOPN_DP_TAB | ida_kernwin.WOPN_RESTORE,
                        disasm_w
                    )
            except Exception:
                pass

    v.save_state(is_open=True)
    return v


def check_and_restore_saved_view():
    """Restore decompiler view from database netnode if it was open when saved."""
    if not ida_kernwin or (hasattr(ida_kernwin, "is_idaq") and not ida_kernwin.is_idaq()):
        return None
    existing = ida_kernwin.find_widget(_VIEW_TITLE)
    if existing is not None:
        return None
    st = db.load_window_state()
    if st and st.get("is_open") and st.get("func_ea") is not None:
        return restore_view(st["func_ea"], config=st, display=True)
    return None


def init_hooks():
    """Early hook registration for UI and View events."""
    global _ui_hooks, _view_hooks
    if _ui_hooks is None and ida_kernwin:
        _ui_hooks = _UIHooks(None)
        _ui_hooks.hook()
    if _view_hooks is None and ida_kernwin:
        _view_hooks = _ViewHooks(None)
        _view_hooks.hook()


def show_listing(title, lines):
    """Fallback simple viewer for whole-program export listing."""
    if not ida_kernwin:
        return None
    v = ida_kernwin.simplecustviewer_t()
    if v.Create(title):
        for ln in lines:
            v.AddLine(highlight.colorize(ln))
        v.Show()
        return v
    return None


def cleanup():
    """Unregister hooks and actions on plugin unload."""
    global _active_viewer, _ui_hooks, _view_hooks
    if _ui_hooks is not None:
        try:
            _ui_hooks.unhook()
        except Exception:
            pass
        _ui_hooks = None
    if _view_hooks is not None:
        try:
            _view_hooks.unhook()
        except Exception:
            pass
        _view_hooks = None
    for action_id in [ACTION_RENAME, ACTION_SET_TYPE, ACTION_TOGGLE_SYNC, ACTION_TOGGLE_IR, ACTION_JUMP_DISASM, ACTION_REFRESH]:
        try:
            if ida_kernwin:
                ida_kernwin.unregister_action(action_id)
        except Exception:
            pass
    _active_viewer = None
