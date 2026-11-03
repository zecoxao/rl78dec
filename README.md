# rl78dec — a Renesas RL78 Decompiler for IDA Pro

`rl78dec` is a high-fidelity decompiler for **Renesas RL78** (and 78K0R) microcontroller firmware, specifically targeting the PlayStation 4 and PlayStation Vita **syscon** (system controller) MCUs, automotive control modules, and industrial embedded systems. It functions both as an interactive **Hex-Rays-style plugin for IDA Pro 9.x / 8.x** and as a **standalone headless lifter**.

The IDA processor module is leveraged strictly for instruction decoding (`insn_t`), while lifting, static single assignment (SSA) optimization, stack frame analysis, variable recovery, calling convention synthesis, control-flow restructuring, and C generation are entirely native:

```mermaid
flowchart LR
    Decoder["1. Decoder (insn_t)"] --> Lifter["2. IR Lifter"]
    Lifter --> CFG["3. CFG Builder"]
    CFG --> Frame["4. Frame Analysis"]
    Frame --> Spill["5. Spill Elimination"]
    Spill --> Opt["6. Canonical Opt"]
    Opt --> ABI["7. ABI & Far Ptr"]
    ABI --> Vars["8. Def-Use Webs"]
    Vars --> Struct["9. Structurer"]
    Struct --> CGen["10. C Emitter"]
```

---

## What It Produces

```c
/*
 * Decompiled by rl78dec -- Renesas RL78 (PS4/Vita syscon).
 */

void trigget_TXD0_interrupt(uint32_t a0, uint32_t address, uint8_t msg_length)
{
    uint16_t v11;

    if (msg_length == 0) {
        return;
    }
    while (1) {
        msg_length = msg_length - 1;
        if ((msg_length + 1) == 0) break;
        address = address + 1;
        TXD0 = *((uint8_t *)address - 1);
        do {
        } while ((SSR00 & 0x40) != 0);
        a0 = a0 + 1;
        v11 = a0 - 1;
        *v11 = TXD0;
        continue;
    }
}

uint16_t sub_35FB(void)
{
    uint32_t v0;
    uint16_t v2;

    if (isFirstInit != 0) {
        current_state = 0;
        sub_7A2E();
        v0 = sub_A5EC();
        saddr_D5 = (uint8_t)(v0 >> 16);
        v2 = (uint16_t)v0 + 0x16;
        tmp_seg = saddr_D5;
        sub_3A836(v2, tmp_seg);
        ...
        trigget_TXD0_interrupt(0xFDF22, 0xFDFA2, 1 + 1);
        ...
    }
    return 0;
}
```

---

## Key Capabilities & Architectural Enhancements

### 1. 20-Bit Far Pointer & Segment Consolidation
The RL78 architecture pairs 16-bit registers with a 20-bit address space (up to 1 MB across 16 segments/banks `0x0`–`0x0F`). In Renesas C compilers (CA78K0R, CC-RL, and IAR), far pointer arguments (`void __far *` or `uint32_t`) are split into an offset and segment:
* **Register Parameters**: 16-bit offset passed in `AX`, 4-bit segment in `BC` (or `C`).
* **Stack Parameters**: 16-bit offset at `[SP+0]`, 16-bit segment at `[SP+2]` (pushed via `PUSH BC; PUSH DE`).

`rl78dec` automatically consolidates these fragmented pairs into single 20-bit C pointer arguments:
* **Callee Consolidation**: Inspects stack frame member pairings (`(address, segment)`, `(resp_address, resp_segment)`, `(table, table_seg)`) and dataflow dereferences through `ES`. Consolidates the pair into a single `uint32_t` parameter (`uint32_t address`, `uint32_t a0`), suppressing internal `tmp_seg = segment; es = tmp_seg;` boilerplate.
* **Call-Site Synthesis**: Analyzes `PUSH BC` sequences preceded by `MOV C, #imm` (`0x0F`), folds adjacent push pairs, and combines them with offset registers/constants into unified 20-bit linear addresses:
  ```c
  // Before:
  trigget_TXD0_interrupt(0xDF22, 0xF, 0xDFA2, 0xF, 1 + 1);
  // After segment consolidation:
  trigget_TXD0_interrupt(0xFDF22, 0xFDFA2, 1 + 1);
  ```
* **Linear Symbol Matching**: Consolidated constants resolve directly to named global symbols (`word_FDF22`, `byte_FDFA2`, `cmd_result`).

### 2. Multi-Register (`DE:BC`) 32-Bit Return Conventions
Functions returning 32-bit values or far pointers return them across register pair **`DE:BC`** (`DE` = high 16-bit segment/bank, `BC` = low 16-bit offset):
* **Return Inference**: Callee exit basic blocks leading to `RET` are analyzed for definitions of `DE`/`E` and `BC`/`C`, inferring `uint32_t` return types and folding 32-bit constant return expressions.
* **Call-Site Recovery**: Call sites identify calls to multi-register callees and allocate 32-bit destination registers (`ir.Reg("de:bc", width="d")`).
* **Subregister Extraction**: Union-Find variable webs allocate `uint32_t vN` variables and synthesize clean subregister extraction expressions:
  * Reads of `E`: `(uint8_t)(v0 >> 16)`
  * Reads of `DE`: `(uint16_t)(v0 >> 16)`
  * Reads of `BC`: `(uint16_t)v0`
  * Reads of `C`: `(uint8_t)v0`
* Eliminates uninitialized function entry variable bugs (e.g. spurious `saddr_D5 = v0;`).

### 3. Hex-Rays Parity Interactive UX Engine
The interactive decompiler window (`simplecustviewer_t`) provides a first-class, Hex-Rays-style experience inside IDA Pro:
* **Exact Instruction EA Anchoring**: Every C statement maps to its originating instruction address (`ea_t`). Zero regex or string-heuristic line mapping.
* **Hex-Rays Standard `Tab` Switching**:
  * Pressing `Tab` (or `F5`) in Disassembly opens Pseudocode at the matching statement and focuses the decompiler.
  * Pressing `Tab` in Pseudocode jumps Disassembly directly to the originating instruction address and focuses `IDA View-A`.
* **Bidirectional Cursor Synchronization**:
  * Caret navigation in Pseudocode updates the Disassembly cursor in real-time without stealing window focus.
  * Moving the cursor in `IDA View-A` scrolls and positions the Pseudocode cursor without stealing Disassembly focus.
  * Built-in re-entrancy flags (`_is_syncing`) prevent recursive event loops.
* **Native Qt Token Occurrence Highlighting**: Placing the caret on any variable or symbol automatically highlights all occurrences across the function via `ida_kernwin.set_highlight(..., HIF_IDENTIFIER)`.
* **Context-Aware Click-Through Navigation & History Stack**:
  * Double-clicking or pressing `Enter` on a function call navigates to that function, pushing the caller's position `(func_ea, lineno)` to a navigation history stack.
  * Pressing `Esc` pops the history stack and returns directly to the caller.
  * Double-clicking global variables, SFRs, labels, and memory addresses navigates IDA to that linear address.
* **Dual-Mode SSA IR Inspection (`I` Hotkey)**: Toggles in-place between high-level Pseudo-C and 3-address SSA IR with explicit basic block control-flow edges (predecessors/successors) and instruction addresses.
* **Line Comments (`/` or `;`) & Cross-References (`X`)**: Attach persistent line comments directly to decompiled statements and inspect cross-references.
* **Chooser Safety**: Keyboard actions are scoped strictly using `AST_ENABLE_FOR_WIDGET` to the custom viewer and `BWN_DISASM`, ensuring no interference with IDA's Functions window or modal choosers.

### 4. Resilient Netnode & Desktop Layout Persistence
* **Two-Tier Persistence**:
  * **Database Netnode (`$ rl78dec`)**: User renames, type overrides, function prototypes, line comments, and active window state (`is_open`, `func_ea`, `lineno`, `col`, `mode`) are serialized into the `.idb` / `.i64` database.
  * **Desktop Layout Manager**: Implements `get_widget_config`, `set_widget_config`, and `create_desktop_widget` hooks so decompiler tabs, splitters, and docking positions survive closing and reopening IDA databases.

### 5. Native C Lowering & Idiom Elimination
* **Machine `SWAP` / `xchg` Elimination**: Renesas compilers frequently emit `xch a, reg` instructions as temporary placeholders due to instruction set asymmetries. `rl78dec` traces register dataflow, eliminating synthetic `SWAP(a, b)` intrinsics in favor of direct variable assignments.
* **Zero-Extension Idiom (`pair >> 8`)**: Eliminates the 8-bit right-shift truncation bug by folding `(pair >> 8)` into the direct zero-extended high atom.
* **Native Pointer Dereferencing**: Recognizes pointer offsets (`*(ptr - 1)` or `ptr[offset]`) and direct pointer dereferences (`*ptr`, `*(uint16_t *)ptr`), eliminating synthetic `es_mem8[...]` arrays.
* **Hardware Intrinsic Lowering**: Lowers `mulu` to `(uint16_t)a * x`, signed shifts to arithmetic casts (`(int8_t)x >> n`), and rotations to C bitwise expressions.

### 6. Structured IDA Instruction Decoding & Caller Consensus
* Decodes canonical instructions and typed operand structures (`op_t`) directly via `ida_ua.decode_insn` and `ida_idp.get_reg_name`, replacing fragile string parsing.
* Statistical caller consensus scans call sites across the database to determine register parameters (`AX`, `BC`), correctly distinguishing homed arguments (`PUSH BC; PUSH AX; MOVW HL, SP`) from callee-saved registers.

### 7. Virtual Variable Recovery & Spill Elimination
* Grouping def-use chains via Union-Find isolates disjoint reuses of register pairs into independent virtual variables (`v0`, `v1`, ...).
* Eliminates function body register spills (`push de ... pop ax`) and removes dead temporary variables.
* Recovers loop induction variables and binds entry registers cleanly to parameter names.

### 8. Switch Statement & Jump Table Recovery
* Recovers in-flash 16-bit near and 32-bit far jump tables (`br ax`).
* Pulls detached switch fragment basic blocks back into the parent function's CFG.
* Recovers clean C `switch (...) { case ...: ... }` blocks with `break` and `return`.

---

## Interactive Hotkeys & Shortcuts

When running as an IDA Pro plugin:

| Hotkey | Action | Description |
| :--- | :--- | :--- |
| **`F5`** | Decompile / Refresh | Decompiles the function under cursor or refreshes active view |
| **`Tab`** | Switch View | Disassembly $\leftrightarrow$ Pseudocode at exact matching instruction EA |
| **`Enter`** | Navigate Symbol | Jumps to callee function, label, or global data address |
| **`Esc`** | History Back | Steps backward through the navigation history stack |
| **`I`** | Toggle SSA IR | Switches between high-level Pseudo-C and 3-address SSA IR |
| **`N`** | Rename Identifier | Renames variable, parameter, or function (saved to IDB netnode) |
| **`Y`** | Set Type / Prototype | Modifies variable type or function prototype (IDA type system) |
| **`/`** or **`;`** | Line Comment | Adds or edits a persistent comment on the current statement |
| **`X`** | Cross-References | Opens IDA's cross-references window for the symbol under cursor |
| **`Ctrl-F5`** | Decompile Database | Decompiles all functions in database and exports to `.c` file |

---

## How to Run

### As an IDA Pro Plugin
1. Install fail0verflow's [RL78 processor module](https://github.com/fail0verflow/rl78-ida-proc).
2. Copy `rl78dec_plugin.py` and the `rl78dec/` directory into your IDA Pro plugins directory:
   ```cmd
   copy rl78dec_plugin.py "%APPDATA%\Hex-Rays\IDA Pro\plugins\"
   xcopy /E /I rl78dec "%APPDATA%\Hex-Rays\IDA Pro\plugins\rl78dec"
   ```
3. Open any RL78 database (`.idb` / `.i64`) and press **`F5`** or **`Tab`** on any instruction.

### Headless (Command-Line)
Decompile raw binary dumps or Sony FUPD containers without IDA:

```bash
# Decompile entire firmware to C listing
python -m rl78dec syscon.bin -o syscon.c

# Decompile a single function by address
python -m rl78dec syscon.bin --func 0x35FB

# Specify custom entry points
python -m rl78dec syscon.bin --entry 0x2000 --entry 0x48F6
```

---

## Test Suite

The test suite runs headlessly without requiring an IDA installation or binary dumps:

```bash
python -m unittest tests/test_abi.py
python -m unittest tests/test_vars.py
python -m unittest tests/test_frame.py
python -m unittest tests/test_spill.py
python -m unittest tests/test_pipeline.py
python -m unittest tests/test_interactive.py
python -m unittest tests/test_db.py
python -m unittest tests/test_highlight.py
python -m unittest tests/test_regs.py
```

All 35 unit tests across 9 test suites verify:
* Far pointer parameter consolidation and call-site argument synthesis.
* Multi-register (`DE:BC`) dword returns and subregister extraction.
* Abstract stack simulation, spill elimination, and loop induction recovery.
* Exact instruction EA mapping and bidirectional line navigation.
* In-memory and netnode state persistence.
* Token syntax highlighting and chooser isolation.

---

## Architecture Blueprint

Detailed reverse-engineering notes on commercial decompiler engines (e.g. Hex-Rays `hexx64.dll`), common decompiler design pitfalls, and implementation blueprints are maintained in the project's [Decompiler Plugin Agent Architecture Plan](file:///C:/Users/Proxima/.gemini/antigravity/brain/73f40ee3-7112-4366-b1cc-d89b5949daf6/decompiler_plugin_agent_architecture_plan.md).

---

## Credits & License

* Built on the RL78 reverse-engineering work of **fail0verflow** (RL78 processor module, syscon loader) and **astrelsky/hedgeberg** (Ghidra SLEIGH).
* Decompiler architecture inspired by zecoxao's **`spudec`**.
* MIT License. No proprietary firmware is included.
