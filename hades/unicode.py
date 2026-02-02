"""Unicode utilities"""

TAG_BASE = 0xE0000
TAG_SPACE = 0xE0020
TAG_BEGIN = 0xE0001
TAG_END = 0xE007F

WORD_JOINER = 0x2060
INVISIBLE_TIMES = 0x2062
INVISIBLE_SEPARATOR = 0x2063
INVISIBLE_PLUS = 0x2064

PREFIX = chr(INVISIBLE_SEPARATOR) + chr(INVISIBLE_TIMES)


def decode_tags(text: str) -> str:
    """
    Convert Unicode tag characters (U+E0020-U+E007E) to ASCII.
    """
    if not text.startswith(PREFIX):
        raise ValueError("Text is not encoded with tags")

    text = text[len(PREFIX):]

    out: list[str] = []

    for ch in text:
        cp = ord(ch)

        if TAG_SPACE <= cp <= TAG_SPACE + 0x5E:  # 0x20-0x7E
            out.append(chr(cp - TAG_SPACE + 0x20))
        elif cp == WORD_JOINER:
            break
        else:
            out.append(ch)

    return "".join(out)


def encode_tags(text: str) -> str:
    """
    Convert ASCII characters (U+0020-U+007E) to Unicode tag characters.
    """
    out: list[str] = [PREFIX]

    for ch in text:
        cp = ord(ch)

        if 0x20 <= cp <= 0x7E:
            out.append(chr(TAG_SPACE + cp - 0x20))
        else:
            out.append(ch)

    out.append(chr(WORD_JOINER))

    return "".join(out)
