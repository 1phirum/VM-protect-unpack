import mmap
import sys

path = sys.argv[1]
with open(path, "rb") as f:
    data = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)

markers = [
    b".pas", b".dpr", b".dfm", b".dproj",
    b".cpp", b".hpp", b".cxx", b".cbproj",
    b"__fastcall", b"System::", b"Vcl::", b"std::", b"boost::",
    b"Delphi", b"Embarcadero", b"Borland", b"C++Builder", b"bcc32", b"dcc32",
    b".?AV", b".?AU", b".?AW", b"type_info", b"bad_alloc",
    b"TFormLogin", b"Vcl.Forms", b"System.SysUtils", b"Project1",
]

print("size", len(data))


def count(marker):
    n = 0
    start = 0
    while True:
        i = data.find(marker, start)
        if i < 0:
            return n
        n += 1
        start = i + len(marker)


for m in markers:
    print("%-20s %d" % (m.decode("latin1"), count(m)))


def samples(marker, limit=20, width=180):
    out = []
    start = 0
    while len(out) < limit:
        i = data.find(marker, start)
        if i < 0:
            break
        a = max(0, i - 60)
        b = min(len(data), i + width)
        chunk = data[a:b]
        text = "".join(chr(c) if 32 <= c < 127 else "." for c in chunk)
        out.append("0x%X %s" % (i, text))
        start = i + len(marker)
    return out


for marker in (b".pas", b".cpp", b".hpp", b".dpr", b".cbproj", b"C++Builder", b"bcc32", b"dcc32", b".?AV"):
    print("\n=== %s ===" % marker.decode("latin1"))
    for line in samples(marker):
        print(line)

data.close()
