"""
Headless command-line front end:

    python -m rl78dec syscon.bin
    python -m rl78dec syscon.bin -o syscon.c
    python -m rl78dec syscon.bin --func 0x7EB1        # one function
    python -m rl78dec syscon.bin --entry 0x1000       # extra entry point

No IDA required.  Accepts a raw flash dump or a Sony FUPD container.
"""

import argparse
import sys

from . import decompile_file


def _int(s):
    return int(s, 0)


def main(argv=None):
    argv = argv if argv is not None else sys.argv[1:]
    ap = argparse.ArgumentParser(prog="rl78dec",
                                 description="Decompile RL78 (PS4/PS5 syscon) firmware to pseudo-C.")
    ap.add_argument("rom", help="raw RL78 flash dump or FUPD container")
    ap.add_argument("-o", "--out", help="write listing to this file (default: stdout)")
    ap.add_argument("--entry", type=_int, action="append", default=None,
                    help="extra entry point (repeatable)")
    ap.add_argument("--func", type=_int, default=None,
                    help="only emit the function at this address")
    ap.add_argument("--no-banner", action="store_true")
    args = ap.parse_args(argv)

    extra = tuple(args.entry) if args.entry else ()
    prog = decompile_file(args.rom, extra_entries=extra)

    if args.func is not None:
        f = prog.funcs.get(args.func)
        if f is None:
            ap.error("no function decoded at 0x%X (try --entry 0x%X)" % (args.func, args.func))
        text = "\n".join(f.lines)
    else:
        text = prog.listing(banner=not args.no_banner)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as fp:
            fp.write(text + "\n")
        print("rl78dec: wrote %d functions to %s" % (len(prog.funcs), args.out), file=sys.stderr)
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
