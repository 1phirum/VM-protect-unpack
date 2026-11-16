#pragma once
#include <stddef.h>
#include <stdint.h>
#include <wchar.h>
#ifdef __cplusplus
extern "C"
{
#endif
    typedef void (*vp_row_fn)(void* context, const wchar_t* const* cells, size_t count);
    typedef struct
    {
        uint64_t file_size, image_base;
        uint32_t image_size, entry;
        uint16_t machine, sections, magic;
    } vp_file_info;
    typedef struct
    {
        unsigned long code;
        wchar_t message[512];
    } vp_error;
    int vp_inspect_file(const wchar_t* path, vp_file_info* info, vp_row_fn sections,
                        vp_row_fn imports, void* context, vp_error* error);
    int vp_processes(vp_row_fn rows, void* context, vp_error* error);
    int vp_process_inspect(uint32_t pid, int view, vp_row_fn rows, void* context, vp_error* error);
    int vp_read(uint32_t pid, uint64_t address, void* bytes, size_t size, size_t* got,
                vp_error* error);
    int vp_stop_watch(uint32_t pid, vp_error* error);
/* 1 modules, 2 memory regions, 3 windows, 4 agent status */
#ifdef __cplusplus
}
#endif
