import pefile
import sys

path = sys.argv[1]
p = pefile.PE(path)


def entries(node):
    return getattr(node, "entries", []) or []


print("=== resource dir ===")
rd = getattr(p, "DIRECTORY_ENTRY_RESOURCE", None)
for entry in entries(rd):
    print("type", entry.id, getattr(entry, "name", None))
    for name in entries(getattr(entry, "directory", None)):
        print("  name", name.id, getattr(name, "name", None))
        for lang in entries(getattr(name, "directory", None)):
            print("    lang", lang.id, getattr(lang, "name", None))
            data = getattr(lang, "data", None)
            if data is not None:
                s = getattr(data, "struct", None)
                size = getattr(s, "Size", None)
                off = getattr(s, "OffsetToData", None)
                print("      rva=0x%X size=0x%X" % (off or 0, size or 0))
                if entry.id == 16 and size:
                    raw = p.get_data(off, size)
                    print(raw.decode("utf-16le", "replace"))

print("=== FileInfo raw ===")
print(repr(getattr(p, "FileInfo", None)))

p.close()
