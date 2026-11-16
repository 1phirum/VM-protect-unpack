/* armor/stealth/handlers.h - internal handler declarations (L1) */
#pragma once

#include "armor/stealth/stealth.h"

/* process information */
LONG NTAPI stealth_h_qip(HANDLE proc, ULONG cls, PVOID info, ULONG len, PULONG ret);
LONG NTAPI stealth_h_qsi(ULONG cls, PVOID info, ULONG len, PULONG ret);
LONG NTAPI stealth_h_qit(HANDLE thread, ULONG cls, PVOID info, ULONG len, PULONG ret);
LONG NTAPI stealth_h_sit(HANDLE thread, ULONG cls, PVOID info, ULONG len);
LONG NTAPI stealth_h_gct(HANDLE thread, PCONTEXT ctx);
LONG NTAPI stealth_h_sct(HANDLE thread, PCONTEXT ctx);
LONG NTAPI stealth_h_qvm(HANDLE proc, PVOID addr, ULONG cls, PVOID info,
                         SIZE_T len, PSIZE_T ret);
LONG NTAPI stealth_h_qpc(PLARGE_INTEGER counter, PLARGE_INTEGER freq);
LONG NTAPI stealth_h_qst(PLARGE_INTEGER now);
LONG NTAPI stealth_h_ctex(PHANDLE th, ACCESS_MASK access, POBJECT_ATTRIBUTES oa,
                          HANDLE proc, PVOID start, PVOID arg, ULONG flags,
                          SIZE_T zero, SIZE_T stack, SIZE_T max_stack, PVOID attr);
LONG NTAPI stealth_h_sdc(ULONG cmd, PVOID in, ULONG in_len, PVOID out,
                         ULONG out_len, PULONG ret);

/* Win32 probes */
BOOL WINAPI stealth_h_isdbg(void);
BOOL WINAPI stealth_h_crdbg(HANDLE proc, PBOOL present);
void WINAPI stealth_h_odsw(LPCWSTR text);
void WINAPI stealth_h_odsa(LPCSTR text);
DWORD WINAPI stealth_h_tick(void);
ULONGLONG WINAPI stealth_h_tick64(void);
void WINAPI stealth_h_gstaft(LPFILETIME out);
void WINAPI stealth_h_gstpft(LPFILETIME out);

/* window discovery */
BOOL WINAPI stealth_h_enumw(WNDENUMPROC proc, LPARAM lparam);
HWND WINAPI stealth_h_findw(LPCWSTR cls, LPCWSTR title);
HWND WINAPI stealth_h_findexw(HWND parent, HWND after, LPCWSTR cls, LPCWSTR title);
HWND WINAPI stealth_h_finda(LPCSTR cls, LPCSTR title);
HWND WINAPI stealth_h_findexa(HWND parent, HWND after, LPCSTR cls, LPCSTR title);

/* memory */
LONG NTAPI stealth_h_rvm(HANDLE proc, PVOID addr, PVOID buf, SIZE_T len, PSIZE_T ret);
LONG NTAPI stealth_h_pvm(HANDLE proc, PVOID* addr, PSIZE_T size, ULONG prot, PULONG old);
LONG NTAPI stealth_h_wvm(HANDLE proc, PVOID addr, PVOID buf, SIZE_T len, PSIZE_T ret);
