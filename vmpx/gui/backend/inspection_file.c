#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <math.h>
#include "inspection.h"
#include "pe/hdr.h"
#include "util/bin.h"

static int fail(vp_error* e, const wchar_t* msg)
{
    if (e)
    {
        e->code = GetLastError();
        swprintf(e->message, 512, L"%ls (error %lu)", msg, e->code);
    }
    return -1;
}
static void value(wchar_t* out, uint64_t v)
{
    swprintf(out, 64, L"0x%08llX", (unsigned long long)v);
}
static void ansi(const uint8_t* source, size_t n, wchar_t* out, size_t cap)
{
    size_t i;
    for (i = 0; i < n && i + 1 < cap && source[i]; i++)
    {
        out[i] = (wchar_t)source[i];
    }
    out[i] = 0;
}
static double entropy(const uint8_t* data, size_t size)
{
    size_t counts[256] = {0}, i;
    double e = 0;
    for (i = 0; i < size; i++)
    {
        counts[data[i]]++;
    }
    for (i = 0; i < 256; i++)
    {
        if (counts[i])
        {
            double p = (double)counts[i] / (double)size;
            e -= p * log(p) / log(2.0);
        }
    }
    return e;
}
static const uint8_t* mapped(const pehdr_t* h, uint32_t rva, size_t len)
{
    uint32_t off;
    uint16_t i;
    if (rva >= h->headers_size)
    {
        int valid = 0;
        for (i = 0; i < h->sections; i++)
        {
            const uint8_t* s = pehdr_section(h, i);
            uint32_t base = bin_rd32(s + 12), raw = bin_rd32(s + 16);
            if (rva >= base && (uint64_t)(rva - base) + len <= raw)
            {
                valid = 1;
                break;
            }
        }
        if (!valid)
        {
            return NULL;
        }
    }
    if (pehdr_rva_to_off(h, rva, &off) != 0 || (uint64_t)off + len > h->size)
    {
        return NULL;
    }
    return h->data + off;
}
static void emit_sections(const pehdr_t* h, const uint8_t* data, vp_row_fn sections, void* context)
{
    uint16_t i;
    for (i = 0; i < h->sections; i++)
    {
        const uint8_t* s = pehdr_section(h, i);
        wchar_t cells[8][64];
        const wchar_t* ptrs[8];
        uint32_t raw = bin_rd32(s + 16), off = bin_rd32(s + 20), flags = bin_rd32(s + 36);
        size_t n = raw > (8u << 20) ? (8u << 20) : raw;
        size_t j;
        swprintf(cells[0], 64, L"%u", (unsigned)i + 1);
        ansi(s, 8, cells[1], 64);
        value(cells[2], bin_rd32(s + 12));
        value(cells[3], bin_rd32(s + 8));
        value(cells[4], off);
        value(cells[5], raw);
        swprintf(cells[6], 64, L"%ls%ls%ls", flags & 0x40000000 ? L"R" : L"",
                 flags & 0x80000000 ? L"W" : L"", flags & 0x20000000 ? L"X" : L"");
        swprintf(cells[7], 64, L"%.3f",
                 n && off && (uint64_t)off + n <= h->size ? entropy(data + off, n) : 0);
        for (j = 0; j < 8; j++)
        {
            ptrs[j] = cells[j];
        }
        if (sections)
        {
            sections(context, ptrs, 8);
        }
    }
}

static int emit_imports(const pehdr_t* h, vp_row_fn imports, void* context, vp_error* error)
{
    if (imports)
    {
        uint32_t rva = pehdr_dir_rva(h, PEHDR_DIR_IMPORT);
        size_t d, total = 0, step = h->magic == 0x20B ? 8 : 4;
        for (d = 0; rva && d < 512; d++)
        {
            const uint8_t* desc = mapped(h, rva + (uint32_t)d * 20, 20);
            uint32_t nameRva, thunkRva, iat;
            wchar_t module[256];
            size_t j;
            if (!desc)
            {
                SetLastError(ERROR_BAD_EXE_FORMAT);
                fail(error, L"Truncated import directory");
                return -1;
            }
            nameRva = bin_rd32(desc + 12);
            if (!nameRva)
            {
                break;
            }
            const uint8_t* name = mapped(h, nameRva, 1);
            if (!name)
            {
                fail(error, L"Invalid import module name");
                return -1;
            }
            ansi(name,
                 (size_t)(h->data + h->size - name) > 255 ? 255
                                                          : (size_t)(h->data + h->size - name),
                 module, 256);
            thunkRva = bin_rd32(desc);
            if (!thunkRva)
            {
                thunkRva = bin_rd32(desc + 16);
            }
            iat = bin_rd32(desc + 16);
            for (j = 0; j < 65536 && total < 65536; j++)
            {
                const uint8_t* tp = mapped(h, thunkRva + (uint32_t)(j * step), step);
                uint64_t thunk, mask = step == 8 ? 0x8000000000000000ull : 0x80000000ull;
                wchar_t fn[256], slot[64];
                const wchar_t* row[4];
                if (!tp)
                {
                    break;
                }
                thunk = step == 8 ? bin_rd64(tp) : bin_rd32(tp);
                if (!thunk)
                {
                    break;
                }
                if (thunk & mask)
                {
                    swprintf(fn, 256, L"Ordinal %u", (unsigned)(thunk & 0xffff));
                }
                else
                {
                    const uint8_t* p = thunk <= UINT32_MAX ? mapped(h, (uint32_t)thunk, 3) : NULL;
                    if (!p)
                    {
                        swprintf(fn, 256, L"Unmapped import name");
                    }
                    else
                    {
                        ansi(p + 2,
                             (size_t)(h->data + h->size - p - 2) > 255
                                 ? 255
                                 : (size_t)(h->data + h->size - p - 2),
                             fn, 256);
                    }
                }
                value(slot, iat + j * step);
                row[0] = module;
                row[1] = fn;
                row[2] = slot;
                row[3] = thunk & mask ? L"Ordinal" : L"Named";
                imports(context, row, 4);
                total++;
            }
        }
    }
    return 0;
}

static int complete_optional_header(const uint8_t* data, uint64_t size)
{
    if (size < 64)
    {
        return 0;
    }
    const uint64_t offset = bin_rd32(data + 0x3c);
    if (offset + 26 > size)
    {
        return 0;
    }
    const uint16_t optional_size = bin_rd16(data + offset + 20);
    const uint16_t magic = bin_rd16(data + offset + 24);
    const unsigned required = magic == 0x20b ? 112 : magic == 0x10b ? 96 : 0;
    return required && optional_size >= required && offset + 24 + optional_size <= size;
}

int vp_inspect_file(const wchar_t* path, vp_file_info* info, vp_row_fn sections, vp_row_fn imports,
                    void* context, vp_error* error)
{
    if (!path || !info)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return fail(error, L"Invalid file query");
    }
    HANDLE file = INVALID_HANDLE_VALUE, map = NULL;
    const uint8_t* data = NULL;
    LARGE_INTEGER size;
    pehdr_t h;
    int rc = -1;
    file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                       FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE)
    {
        return fail(error, L"Cannot open executable");
    }
    if (!GetFileSizeEx(file, &size) || size.QuadPart < 64)
    {
        fail(error, L"File is too small");
        goto done;
    }
    map = CreateFileMappingW(file, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!map)
    {
        fail(error, L"Cannot map file");
        goto done;
    }
    data = (const uint8_t*)MapViewOfFile(map, FILE_MAP_READ, 0, 0, 0);
    if (!data)
    {
        fail(error, L"Cannot read mapping");
        goto done;
    }
    if (!complete_optional_header(data, (uint64_t)size.QuadPart) ||
        pehdr_parse(data, (uint64_t)size.QuadPart, &h) != 0 ||
        h.opt_size < (h.magic == 0x20B ? 112 : 96) ||
        h.num_dirs > (h.opt_size - (h.magic == 0x20B ? 112 : 96)) / 8)
    {
        SetLastError(ERROR_BAD_EXE_FORMAT);
        fail(error, L"Invalid or truncated PE headers");
        goto done;
    }
    info->file_size = h.size;
    info->image_base = h.image_base;
    info->image_size = h.size_image;
    info->entry = h.entry;
    info->machine = h.machine;
    info->sections = h.sections;
    info->magic = h.magic;
    emit_sections(&h, data, sections, context);
    if (emit_imports(&h, imports, context, error) != 0)
    {
        goto done;
    }
    rc = 0;
done:
    if (data)
    {
        UnmapViewOfFile(data);
    }
    if (map)
    {
        CloseHandle(map);
    }
    CloseHandle(file);
    return rc;
}
