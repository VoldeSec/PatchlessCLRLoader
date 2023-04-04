#pragma once
#include <windows.h>
#define TH32CS_SNAPTHREAD   0x00000004

typedef void (WINAPI* exception_callback)(PEXCEPTION_POINTERS);

typedef struct tagTHREADENTRY32
{
    DWORD   dwSize;
    DWORD   cntUsage;
    DWORD   th32ThreadID;       // this thread
    DWORD   th32OwnerProcessID; // Process this thread is associated with
    LONG    tpBasePri;
    LONG    tpDeltaPri;
    DWORD   dwFlags;
} THREADENTRY32;

typedef THREADENTRY32 * LPTHREADENTRY32;


typedef BOOL(WINAPI* _GetThreadContext) (HANDLE hThread, LPCONTEXT lpContext);
typedef BOOL(WINAPI* _SetThreadContext) (HANDLE hThread, const CONTEXT* lpContext);
typedef DWORD(WINAPI* _GetCurrentThreadId) (void);
typedef DWORD(WINAPI* _GetCurrentProcessId) (void);
typedef HANDLE(WINAPI* _GetCurrentThread) (void);
typedef HANDLE(WINAPI* _OpenThread) (DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwThreadId);
typedef HANDLE(WINAPI* _CreateToolhelp32Snapshot) (DWORD dwFlags, DWORD th32ProcessID);
typedef PVOID(WINAPI* _AddVectoredExceptionHandler) (ULONG First, PVECTORED_EXCEPTION_HANDLER Handler);
typedef BOOL(WINAPI* _Thread32First) (HANDLE hSnapshot, LPTHREADENTRY32 lpte);
typedef BOOL(WINAPI* _Thread32Next) (HANDLE hSnapshot, LPTHREADENTRY32 lpte);
typedef BOOL(WINAPI* _CloseHandle) (HANDLE hObject);


void rip_ret_patch(const PEXCEPTION_POINTERS ExceptionInfo);
uintptr_t find_gadget(const uintptr_t function, const BYTE* stub, const UINT size, const size_t dist);
void hardware_engine_stop(PVOID handler);
PVOID hardware_engine_init(void);
LONG WINAPI exception_handler(PEXCEPTION_POINTERS ExceptionInfo);
void delete_descriptor_entry(const uintptr_t adr, const DWORD tid);
void insert_descriptor_entry(const uintptr_t adr, const unsigned pos, exception_callback fun, const DWORD tid);
void set_hardware_breakpoints(const uintptr_t address, const UINT pos, const BOOL init, const DWORD tid);
void set_hardware_breakpoint(const DWORD tid, const uintptr_t address, const UINT pos, const BOOL init);
