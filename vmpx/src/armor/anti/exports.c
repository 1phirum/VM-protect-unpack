/* exports.c - loader-free ntdll and export lookup used under the loader lock (L1) */
#include "armor/anti/anti.h"

typedef struct {
    uint16_t Length;
    uint16_t MaximumLength;
    wchar_t* Buffer;
} ustr_t;

typedef struct {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    void*      DllBase;
    void*      EntryPoint;
    uint32_t   SizeOfImage;
    ustr_t     FullDllName;
    ustr_t     BaseDllName;
} ldr_entry_t;

typedef struct {
    uint32_t   Length;
    uint8_t    Initialized;
    uint8_t    pad[3];
    void*      SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} peb_ldr_t;

static int name_is(const ustr_t* s, const wchar_t* lit) {
    size_t n = wcslen(lit);
    if (!s || !s->Buffer || s->Length != n * sizeof(wchar_t)) return 0;
    return _wcsnicmp(s->Buffer, lit, n) == 0;
}

uint8_t* anti_find_ntdll(void) {
    uint8_t* peb = (uint8_t*)__readfsdword(0x30);
    if (!peb) return NULL;
    peb_ldr_t* ldr = *(peb_ldr_t**)(peb + 0x0C);
    if (!ldr) return NULL;
    LIST_ENTRY* head = &ldr->InLoadOrderModuleList;
    for (LIST_ENTRY* it = head->Flink; it != head; it = it->Flink) {
        ldr_entry_t* e = (ldr_entry_t*)it;
        if (name_is(&e->BaseDllName, L"ntdll.dll")) return (uint8_t*)e->DllBase;
    }
    return NULL;
}

void* anti_export_by_name(uint8_t* base, const char* name) {
    if (!base || !name) return NULL;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    IMAGE_NT_HEADERS32* nt = (IMAGE_NT_HEADERS32*)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;
    IMAGE_DATA_DIRECTORY* dir =
        &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!dir->VirtualAddress || !dir->Size) return NULL;

    IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)(base + dir->VirtualAddress);
    uint32_t* names = (uint32_t*)(base + exp->AddressOfNames);
    uint16_t* ords = (uint16_t*)(base + exp->AddressOfNameOrdinals);
    uint32_t* funcs = (uint32_t*)(base + exp->AddressOfFunctions);

    for (uint32_t i = 0; i < exp->NumberOfNames; i++) {
        const char* n = (const char*)(base + names[i]);
        if (strcmp(n, name) == 0) return base + funcs[ords[i]];
    }
    return NULL;
}
