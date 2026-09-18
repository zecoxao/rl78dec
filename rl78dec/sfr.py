"""
RL78 special-function-register names (from astrelsky's RL78_sleigh
``rl78_sfr.sinc``).  Byte SFRs occupy 0xFFF00..0xFFFFF; index i maps to name
``_SFR_BYTES[i]``.  Generic placeholders (``SFRnn`` / ``_``) are dropped so only
documented registers get symbolic names in the output.
"""

_SFR_BYTES = (
    "P0", "P1", "P2", "P3", "P4", "P5", "P6", "P7",
    "P8", "P9", "P10", "P11", "P12", "P13", "P14", "P15",
    "TXD0", None, "RXD0", None, "TXD3", None, "RXD3", None,
    None, None, "TDR01L", "TDR01H", None, None, None, "ADCRH",
    "PM0", "PM1", "PM2", "PM3", "PM4", "PM5", "PM6", "PM7",
    "PM8", "PM9", "PM10", "PM11", "PM12", None, "PM14", "PM15",
    "ADM0", "ADS", "ADM1", None, None, None, None, "KRM",
    "EGP0", "EGN0", "EGP1", "EGN1", None, None, None, None,
    None, None, None, None, "TXD1", None, "RXD1", None,
    "TXD2", None, "RXD2", None, None, None, None, None,
    "IICA0", "IICS0", "IICF0", None, "IICA1", "IICS1", "IICF1", None,
    None, None, None, None, None, None, None, None,
    None, None, None, None, None, None, "TDR03L", "TDR03H",
    None, None, None, None, None, None, None, None,
    None, None, "TDR11L", "TDR11H", None, None, "TDR13L", "TDR13H",
    None, None, None, None, None, None, None, None,
    None, None, None, None, None, None, None, None,
    None, None, None, None, None, None, None, None,
    None, None, "SEC", "MIN", "HOUR", "WEEK", "DAY", "MONTH",
    "YEAR", "SUBCUD", "ALARMWM", "ALARMWH", "ALARMWW", "RTCC0", "RTCC1", None,
    "CMC", "CSC", "OSTC", "OSTS", "CKC", "CKS0", "CKS1", None,
    "RESF", "LVIM", "LVIS", "WDTE", "CRCIN", "TOOL0", None, None,
    "DSA0", "DSA1", "DRA0L", "DRA0H", "DRA1L", "DRA1H", "DBC0L", "DBC0H",
    "DMC0", "DMC1", "DRC0", "DRC1", None, None, None, None,
    None, None, None, None, None, None, None, None,
    None, None, None, None, None, None, None, None,
    "IF2L", "IF2H", "IF3L", None, "MK2L", "MK2H", "MK3L", None,
    "PR02L", "PR02H", "PR03L", None, "PR12L", "PR12H", "PR13L", None,
    "IF0L", "IF0H", "IF1L", "IF1H", "MK0L", "MK0H", "MK1L", "MK1H",
    "PR00L", "PR00H", "PR01L", "PR01H", "PR10L", "PR10H", "PR11L", "PR11H",
    None, None, None, None, None, None, None, None,
    None, None, None, "RESERVE", None, None, "PMC", "MEM",
)

SFR_NAMES = {0xFFF00 + i: n for i, n in enumerate(_SFR_BYTES) if n}


def name_for(addr):
    return SFR_NAMES.get(addr)
