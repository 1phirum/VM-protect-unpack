/* agent_embed.c - the dynamic agent ships inside vmpx.exe
 *
 * A release build has no vmpxagent.dll beside the executable. The DLL is stored
 * as an RCDATA resource and written to a content-addressed path under %TEMP% the
 * first time an injection needs it, because the injection path calls
 * LoadLibraryW inside the target and the loader needs a real file to open.
 * A development build keeps vmpxagent.dll next to the executable and that copy
 * is used instead, so the agent stays debuggable while it is being changed.
 */
#include "vmpx.h"
#include "util/agent_embed.h"

#define VMPX_AGENT_RCDATA_ID   101
#define VMPX_AGENT_RCDATA_TYPE MAKEINTRESOURCEW(10)   /* RT_RCDATA */

static wchar_t g_extracted[MAX_PATH * 2];
static int g_extracted_valid = 0;
static int g_extracted_owned = 0;   /* this process created the file */

static int side_by_side(wchar_t* out, size_t cap) {
    if (!GetModuleFileNameW(NULL, out, (DWORD)cap)) return -1;
    wchar_t* slash = wcsrchr(out, L'\\');
    if (!slash) return -1;
    slash[1] = 0;
    if (wcslen(out) + wcslen(L"vmpxagent.dll") + 1 >= cap) return -1;
    wcscat_s(out, cap, L"vmpxagent.dll");
    return GetFileAttributesW(out) == INVALID_FILE_ATTRIBUTES ? -1 : 0;
}

static int extract_embedded(wchar_t* out, size_t cap) {
    HRSRC res = FindResourceW(NULL, MAKEINTRESOURCEW(VMPX_AGENT_RCDATA_ID),
                              VMPX_AGENT_RCDATA_TYPE);
    if (!res) return -1;
    DWORD size = SizeofResource(NULL, res);
    if (!size) return -1;
    HGLOBAL glob = LoadResource(NULL, res);
    if (!glob) return -1;
    const uint8_t* data = (const uint8_t*)LockResource(glob);
    if (!data) return -1;

    /* Content-addressed name: two builds never share a temp file, and a stale
     * file from an older build is never injected by accident. */
    uint32_t h = 2166136261u;
    for (DWORD i = 0; i < size; i++) {
        h ^= data[i];
        h *= 16777619u;
    }

    wchar_t temp[MAX_PATH] = { 0 };
    DWORD n = GetTempPathW(MAX_PATH, temp);
    if (!n || n >= MAX_PATH) return -1;
    if (swprintf_s(out, cap, L"%svmpxagent-%08X.dll", temp, h) < 0) return -1;

    WIN32_FILE_ATTRIBUTE_DATA fa;
    if (GetFileAttributesExW(out, GetFileExInfoStandard, &fa) &&
        fa.nFileSizeHigh == 0 && fa.nFileSizeLow == size) {
        g_extracted_valid = 1;
        wcscpy_s(g_extracted, _countof(g_extracted), out);
        return 0;
    }

    wchar_t part[MAX_PATH * 2];
    if (swprintf_s(part, _countof(part), L"%s.part%u", out,
                   GetCurrentProcessId()) < 0)
        return -1;

    HANDLE f = CreateFileW(part, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) return -1;
    DWORD wrote = 0;
    BOOL ok = WriteFile(f, data, size, &wrote, NULL);
    if (ok) FlushFileBuffers(f);
    CloseHandle(f);
    if (!ok || wrote != size) {
        DeleteFileW(part);
        return -1;
    }
    if (!MoveFileExW(part, out,
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        DeleteFileW(part);
        return -1;
    }

    g_extracted_valid = 1;
    g_extracted_owned = 1;
    wcscpy_s(g_extracted, _countof(g_extracted), out);
    return 0;
}

int agent_materialize(const char* override, wchar_t* out, size_t cap) {
    if (override && *override) {
        return MultiByteToWideChar(CP_UTF8, 0, override, -1, out, (int)cap)
                   ? 0 : -1;
    }
    if (side_by_side(out, cap) == 0) return 0;
    return extract_embedded(out, cap);
}

void agent_release(void) {
    if (!g_extracted_valid) return;
    g_extracted_valid = 0;
    if (g_extracted_owned) {
        /* A target that still has the agent mapped keeps the image section
         * open, so the delete can fail while that process lives. The file is
         * content-addressed and identical for this build, so a leftover is
         * inert; queue it for removal at the next boot rather than leaving it
         * with no expiry at all. */
        if (!DeleteFileW(g_extracted))
            (void)MoveFileExW(g_extracted, NULL, MOVEFILE_DELAY_UNTIL_REBOOT);
    }
    g_extracted_owned = 0;
    g_extracted[0] = 0;
}
