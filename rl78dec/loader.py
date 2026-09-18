"""
Image loading and entry-point discovery for RL78 firmware.

Handles a raw flash dump (the common PS4-syscon case) and, when present, a Sony
"FUPD" update container (parsed the way fail0verflow's ``ps4syscon.py`` does).
Entry points come from the interrupt/reset vector table at the bottom of code
flash; the decoder then follows direct calls to discover the rest.
"""

import struct

VECTOR_TABLE_SIZE = 0x80          # 64 vectors x 2 bytes at the base of cflash
CODE_LIMIT = 0x80000

_FUPD_MAGICS = (b"PTCH", b"BLNK", b"BASE", b"SYST")


def load_raw(path):
    with open(path, "rb") as fp:
        return bytearray(fp.read())


def is_fupd(data):
    return len(data) >= 0x14 and data[0x10:0x14] in _FUPD_MAGICS


def load_fupd(data):
    """Reconstruct a flat image from a FUPD container.  Returns a bytearray of
    size 0x60000 with each block placed at its flash address."""
    magic = data[0x10:0x14]
    is_patch = magic == b"PTCH"
    n_blocks = data[0x15]
    image = bytearray(0x60000)
    for i in range(n_blocks):
        off, size, flash = struct.unpack_from("<HHH", data, 0x20 + 8 * i)
        off = (off << 8) + (0x400 if is_patch else 0x110)
        size <<= 8
        flash <<= 8
        if is_patch and flash == 0:
            flash = 0x1000
        blk = data[off:off + size]
        if flash + len(blk) <= len(image):
            image[flash:flash + len(blk)] = blk
    return image


def load(path):
    data = load_raw(path)
    if is_fupd(data):
        return load_fupd(data)
    return data


def vector_entries(image):
    """Reset vector (offset 0) plus interrupt vectors, de-duplicated."""
    entries = []
    seen = set()
    for off in range(0, min(VECTOR_TABLE_SIZE, len(image) - 1), 2):
        v = struct.unpack_from("<H", image, off)[0]
        if 0 < v < CODE_LIMIT and v != 0xFFFF and v not in seen:
            seen.add(v)
            entries.append(v)
    return entries
