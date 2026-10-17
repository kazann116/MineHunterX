"""Convert non-ASCII characters inside quoted DFM strings to Delphi #NNNN escapes.

Usage: python tools/dfm_escape.py <file.dfm> [...]
The file is rewritten in place as pure ASCII with CRLF line endings.
"""
import re
import sys


def escape_literal(match):
    body = match.group(1)
    out, buf = [], ''
    for ch in body.replace("''", "\0"):
        if ch == "\0":
            buf += "''"
        elif ord(ch) < 128:
            buf += ch
        else:
            if buf:
                out.append("'" + buf + "'")
                buf = ''
            out.append('#%d' % ord(ch))
    if buf or not out:
        out.append("'" + buf + "'")
    return ''.join(out)


def convert(path):
    with open(path, encoding='utf-8-sig') as f:
        text = f.read()
    text = re.sub(r"'((?:[^']|'')*)'", escape_literal, text)
    with open(path, 'w', encoding='ascii', newline='\r\n') as f:
        f.write(text.replace('\r\n', '\n'))


if __name__ == '__main__':
    for p in sys.argv[1:]:
        convert(p)
