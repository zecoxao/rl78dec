# rl78dec — a Renesas RL78 decompiler

`rl78dec` decompiles Renesas **RL78** firmware to readable pseudo-C, aimed at the
PlayStation 4 **syscon** (system controller) whose MCU is an RL78. It is the
RL78 analogue of [`spudec`](https://github.com/zecoxao/spudec) and the Kirk/Spock
[`startrekdec`](https://github.com/zecoxao/startrekdec): the IDA processor module
is used purely as a *decoder*, and lifting, control-flow recovery and code
generation are ours.

```
decoder → lifter → cfg → opt → structure → cgen
```

## What it produces

```c
void sub_7EB1(void)
{
    WDTE = 0xAC;                                  // kick the watchdog
    ax = 1;
    es = 0xF;
    if (1 == es_mem16[0xB502]) {
        es = 0xF;
        es_mem16[0xB4FE] = es_mem16[0xB4FE] + 1;  // 32-bit counter
        ax = 0;
        if (0 != es_mem16[0xB4FE]) goto loc_191CD;
        es_mem16[0xB500] = es_mem16[0xB500] + 1;
    }
loc_191CD:
    return;
}
```

Registers print as themselves (`a`, `ax`, `hl`, …); `mem8`/`mem16` index data
memory, with documented SFRs and saddr cells shown by name (`WDTE`, `P4`,
`MK0L`, …). `cmp`/`cmp0` fold into relational `if`s (CY/HF compares are
unsigned), the RL78 *skip* idiom (`skz`/`skc`/…) becomes a one-instruction `if`,
loops are recovered as `while`/`do-while`, and cross-function tail jumps render
as `JUMPOUT(addr)`.

## Two ways to run it

**Headless (no IDA)** — a raw flash dump or a Sony FUPD container:

```
python -m rl78dec syscon.bin -o syscon.c
python -m rl78dec syscon.bin --func 0x7EB1        # one function
python -m rl78dec syscon.bin --entry 0x1234       # extra entry point
```

Entry points are taken from the interrupt/reset vector table; the decoder then
follows direct calls. PS4 syscon dumps can be found in the community (e.g. the
darthsternie firmware archive); they are **not** included here.

**As an IDA plugin** — open the dump with fail0verflow's
[RL78 processor module](https://github.com/fail0verflow/rl78-ida-proc), then drop
`rl78dec_plugin.py` **and** the `rl78dec/` package into
`%APPDATA%\Hex-Rays\IDA Pro\plugins\`:

| Hotkey | Action |
| --- | --- |
| `Ctrl-Shift-S` | decompile the function under the cursor |
| `Ctrl-F5` | decompile the whole database (and offer to save it) |

The viewer is syntax-highlighted with IDA's theme colours and double-click jumps
to the address of a `loc_`/`sub_` line. Inside IDA the output reuses whatever
names you have applied.

## The instruction set

RL78 (S1/S2 core): little-endian, variable length (1–4 bytes, plus the optional
`0x11` **ES:** far-data prefix), with three secondary opcode maps (`0x31`,
`0x61`, `0x71`). Registers `X A C B E D L H` (and pairs `AX BC DE HL`), SFRs at
`0xFFF00+`, saddr at `0xFFE20+`.

`rl78dec/decoder.py` is a faithful port of fail0verflow's
[`rl78-ida-proc`](https://github.com/fail0verflow/rl78-ida-proc) (`reg.cpp`,
based on Renesas R01US0015EJ0220); the lifter follows astrelsky's Ghidra SLEIGH
semantics ([`RL78_sleigh`](https://github.com/astrelsky/RL78_sleigh)), from which
the SFR names are also taken. Rotates, string ops, stack and CPU-control
instructions that do not map cleanly onto C are printed honestly as pseudo-calls
rather than guessed.

## Limitations

* Only the S1/S2 instruction set the fail0verflow module covers (no S3
  multiply/divide/MAC).
* Entry discovery follows direct calls only; indirect calls (`call ax`, jump
  tables) need seeding with `--entry`.
* No stack-frame / calling-convention reconstruction yet: `push`/`pop` are shown
  as intrinsics.

## Tests

```
python tests/test_pipeline.py
python tests/test_highlight.py
```

Hand-assembled, so they need neither IDA nor a firmware dump: they check decoder
field extraction, that every opcode decodes without raising, that a loop is
recovered as a `do/while`, and the token highlighter.

## Credits

Built on the RL78 reverse-engineering of fail0verflow (processor module, syscon
loader) and astrelsky/hedgeberg (Ghidra SLEIGH). Decompiler design mirrors
zecoxao's `spudec`. MIT licensed. No firmware is included.
