/* armor/parent.h - parent-process spoof and agent hint mapping */
#pragma once

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif

#include <windows.h>
#include <stdint.h>

typedef struct {
    HANDLE map;
    void*  view;
} armor_hint_t;

/* Spawn suspended.  If explorer.exe can be opened with PROCESS_CREATE_PROCESS,
 * PROC_THREAD_ATTRIBUTE_PARENT_PROCESS makes it the target's parent.  Returns
 * the spoofed parent pid through parent_pid (0 when the fallback ran). */
int  armor_spawn_parented(const wchar_t* exe, const wchar_t* dir,
                          PROCESS_INFORMATION* pi, uint32_t* parent_pid);

/* Publish Local\VMPX_PARENT_<target_pid> {magic, parent, tool} while the agent
 * DLL attaches.  The mapping must stay alive until injection returns. */
int  armor_hint_open(uint32_t target_pid, uint32_t parent_pid, uint32_t tool_pid,
                     armor_hint_t* hint);
void armor_hint_close(armor_hint_t* hint);
