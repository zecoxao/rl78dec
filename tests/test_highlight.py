"""Headless test for the highlighter (stubs ida_lines).  python tests/test_highlight.py"""

import os
import sys
import types

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _stub():
    il = types.ModuleType("ida_lines")
    il.COLSTR = lambda t, c: "<%s>%s</%s>" % (c, t, c)
    for name in ("AUTOCMT", "STRING", "NUMBER", "KEYWORD", "TYPE",
                 "CREFTAIL", "CNAME", "REG", "SYMBOL"):
        setattr(il, "SCOLOR_" + name, name.lower())
    sys.modules["ida_lines"] = il


def test_highlight():
    _stub()
    from rl78dec import highlight as H
    assert "<keyword>if</keyword>" in H.colorize("    if (a < 4) goto loc_10;")
    assert "<keyword>do</keyword>" in H.colorize("    do {")
    assert "<creftail>loc_10</creftail>" in H.colorize("    goto loc_10;")
    assert "<number>0xFFF00</number>" in H.colorize("x = 0xFFF00;")
    assert "<cname>push</cname>" in H.colorize("    push(ax);")
    assert "<reg>ax</reg>" in H.colorize("    ax = 0;")
    assert H.colorize("loc_10:").startswith("<creftail>")
    assert H.colorize(" * banner").startswith("<autocmt>")
    assert len(H.colorize_all(["void f(void)", "{", "}"])) == 3
    print("ok  test_highlight")


if __name__ == "__main__":
    test_highlight()
    print("\nall tests passed")
