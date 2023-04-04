#include <Windows.h>
#include "breakpoint.h"
#define TOKENIZE(x) L#x
#define MALLOC( size ) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size)
#define FREE( adr ) HeapFree(GetProcessHeap(), 0, adr)
/*All callback functions must match this prototype.*/

struct descriptor_entry
{
    /* Data */
    uintptr_t adr;
    unsigned pos;
    DWORD tid;
    exception_callback fun;


    struct descriptor_entry* next, * prev;
};



/*Global*/
CRITICAL_SECTION g_critical_section;
struct descriptor_entry* head = NULL;
char k32mod[] = { 'k', 'e', 'r', 'n', 'e', 'l', '3','2','.', 'd', 'l', 'l', 0 };

void set_hardware_breakpoint(const DWORD tid, const uintptr_t address, const UINT pos, const BOOL init)
{
    CONTEXT context = { .ContextFlags = CONTEXT_DEBUG_REGISTERS };
    HANDLE thd;

    char fgcti[] = { 'G', 'e', 't', 'C', 'u', 'r', 'r', 'e', 'n', 't', 'T', 'h', 'r','e', 'a', 'd', 'I', 'd', 0};
    _GetCurrentThreadId fGetCurrentThreadId = (_GetCurrentThreadId)GetProcAddress(GetModuleHandleA(k32mod), fgcti);

    if (tid == fGetCurrentThreadId())
    {
        char fgct[] = { 'G', 'e', 't', 'C', 'u', 'r', 'r', 'e', 'n', 't', 'T', 'h', 'r','e', 'a', 'd', 0 };
        _GetCurrentThread GetCurrentThread = (_GetCurrentThread)GetProcAddress(GetModuleHandleA(k32mod), fgct);
        thd = GetCurrentThread();
    }
    else
    {
        char fop[] = { 'O', 'p', 'e', 'n', 'T', 'h', 'r','e', 'a', 'd', 0 };
        _OpenThread OpenThread = (_OpenThread)GetProcAddress(GetModuleHandleA(k32mod), fop);
        thd = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);
    }
    char fgtc[] = { 'G', 'e', 't', 'T', 'h', 'r', 'e', 'a', 'd', 'C', 'o', 'n', 't','e', 'x', 't', 0 };
    _GetThreadContext GetThreadContext = (_GetThreadContext)GetProcAddress(GetModuleHandleA(k32mod), fgtc);
    GetThreadContext(thd, &context);

    if (init)
    {
        (&context.Dr0)[pos] = address;
        context.Dr7 &= ~(3ull << (16 + 4 * pos));
        context.Dr7 &= ~(3ull << (18 + 4 * pos));
        context.Dr7 |= 1ull << (2 * pos);
    }
    else
    {
        if ((&context.Dr0)[pos] == address)
        {
            context.Dr7 &= ~(1ull << (2 * pos));
            (&context.Dr0)[pos] = 0ull;
        }
    }
    char fstc[] = { 'S', 'e', 't', 'T', 'h', 'r', 'e', 'a', 'd', 'C', 'o', 'n', 't','e', 'x', 't', 0 };
    _SetThreadContext SetThreadContext = (_SetThreadContext)GetProcAddress(GetModuleHandleA(k32mod), fstc);
    SetThreadContext(thd, &context);

    if (thd != INVALID_HANDLE_VALUE) CloseHandle(thd);
}


void set_hardware_breakpoints(const uintptr_t address, const UINT pos, const BOOL init, const DWORD tid)
{
    char fgcpi[] = { 'G', 'e', 't', 'C', 'u', 'r', 'r', 'e', 'n', 't', 'P', 'r', 'o', 'c','e', 's', 's', 'I', 'd', 0 };
    _GetCurrentProcessId GetCurrentProcessId = (_GetCurrentProcessId)GetProcAddress(GetModuleHandleA(k32mod), fgcpi);
    const DWORD pid = GetCurrentProcessId();
    char fcths[] = { 'C', 'r', 'e', 'a', 't', 'e', 'T', 'o', 'o', 'l', 'h', 'e', 'l', 'p','3', '2', 'S', 'n', 'a', 'p', 's', 'h', 'o', 't', 0};
    _CreateToolhelp32Snapshot CreateToolhelp32Snapshot = (_CreateToolhelp32Snapshot)GetProcAddress(GetModuleHandleA(k32mod), fcths);
    const HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

    if (h != INVALID_HANDLE_VALUE) {
        THREADENTRY32 te = { .dwSize = sizeof(THREADENTRY32) };
        char ft32f[] = { 'T', 'h', 'r', 'e', 'a', 'd', '3', '2', 'F', 'i', 'r', 's', 't', 0 };
        _Thread32First Thread32First = (_Thread32First)GetProcAddress(GetModuleHandleA(k32mod), ft32f);
        char ft32n[] = { 'T', 'h', 'r', 'e', 'a', 'd', '3', '2', 'N', 'e', 'x', 't', 0 };

        _Thread32Next Thread32Next = (_Thread32Next)GetProcAddress(GetModuleHandleA(k32mod), ft32n);

        if (Thread32First(h, &te)) {
            do {
                if ((te.dwSize >= FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) +
                    sizeof(te.th32OwnerProcessID)) && te.th32OwnerProcessID == pid) {
                    if (tid != 0 && tid != te.th32ThreadID) {
                        continue;
                    }
                    set_hardware_breakpoint(
                        te.th32ThreadID,
                        address,
                        pos,
                        init
                    );

                }
                te.dwSize = sizeof(te);
            } while (Thread32Next(h, &te));
        }
        char fch[] = { 'C', 'l', 'o', 's', 'e', 'H', 'a', 'n', 'd', 'l', 'e', 0 };
        _CloseHandle CloseHandle = (_CloseHandle)GetProcAddress(GetModuleHandleA(k32mod), fch);
        CloseHandle(h);
    }
}

void insert_descriptor_entry(const uintptr_t adr, const unsigned pos, const exception_callback fun, const DWORD tid)
{
    struct descriptor_entry* new = MALLOC(sizeof(struct descriptor_entry));
    const unsigned idx = pos % 4;

    EnterCriticalSection(&g_critical_section);

    new->adr = adr;
    new->pos = idx;
    new->tid = tid;
    new->fun = fun;

    new->next = head;

    new->prev = NULL;

    if (head != NULL)
        head->prev = new;

    head = new;

    LeaveCriticalSection(&g_critical_section);

    set_hardware_breakpoints(
        adr,
        idx,
        TRUE,
        tid
    );
}

void delete_descriptor_entry(const uintptr_t adr, const DWORD tid)
{
    struct descriptor_entry* temp;
    unsigned pos = 0;
    BOOL found = FALSE;

    EnterCriticalSection(&g_critical_section);

    temp = head;

    while (temp != NULL)
    {
        if (temp->adr == adr &&
            temp->tid == tid)
        {
            found = TRUE;

            pos = temp->pos;
            if (head == temp)
                head = temp->next;

            if (temp->next != NULL)
                temp->next->prev = temp->prev;

            if (temp->prev != NULL)
                temp->prev->next = temp->next;

            FREE(temp);
        }

        temp = temp->next;
    }

    LeaveCriticalSection(&g_critical_section);

    if (found)
    {
        set_hardware_breakpoints(
            adr,
            pos,
            FALSE,
            tid
        );
    }

}

LONG WINAPI exception_handler(PEXCEPTION_POINTERS ExceptionInfo)
{
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP)
    {
        struct descriptor_entry* temp;
        BOOL resolved = FALSE;

        EnterCriticalSection(&g_critical_section);
        temp = head;
        while (temp != NULL)
        {
            if (temp->adr == ExceptionInfo->ContextRecord->Rip)
            {
                char fgcti[] = { 'G', 'e', 't', 'C', 'u', 'r', 'r', 'e', 'n', 't', 'T', 'h', 'r', 'e','a', 'd', 'I', 'd', 0 };
                _GetCurrentThreadId fGetCurrentThreadId = (_GetCurrentThreadId)GetProcAddress(GetModuleHandleA(k32mod), fgcti);
                if (temp->tid != 0 && temp->tid != fGetCurrentThreadId())
                    continue;

                temp->fun(ExceptionInfo);
                resolved = TRUE;
            }

            temp = temp->next;
        }
        LeaveCriticalSection(&g_critical_section);

        if (resolved)
        {
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}


PVOID hardware_engine_init(void)
{
    char faveh[] = { 'A', 'd', 'd', 'V', 'e', 'c', 't', 'o', 'r', 'e', 'd', 'E', 'x', 'c','e', 'p', 't', 'i', 'o', 'n', 'H', 'a', 'n', 'd', 'l', 'e', 'r', 0};
    _AddVectoredExceptionHandler fAddVectoredExceptionHandler = (_AddVectoredExceptionHandler)GetProcAddress(GetModuleHandleA(k32mod), faveh);
    const PVOID handler = fAddVectoredExceptionHandler(1, exception_handler);
    InitializeCriticalSection(&g_critical_section);

    return handler;
}

void hardware_engine_stop(PVOID handler)
{
    struct descriptor_entry* temp;

    EnterCriticalSection(&g_critical_section);

    temp = head;
    while (temp != NULL)
    {
        delete_descriptor_entry(temp->adr, temp->tid);
        temp = temp->next;
    }

    LeaveCriticalSection(&g_critical_section);

    if (handler != NULL) RemoveVectoredExceptionHandler(handler);

    DeleteCriticalSection(&g_critical_section);
}


uintptr_t find_gadget(const uintptr_t function, const BYTE* stub, const UINT size, const size_t dist)
{
    for (size_t i = 0; i < dist; i++)
    {
        if (memcmp((LPVOID)(function + i), stub, size) == 0) {
            return (function + i);
        }
    }
    return 0ull;
}

void rip_ret_patch(const PEXCEPTION_POINTERS ExceptionInfo)
{
    ExceptionInfo->ContextRecord->Rip = find_gadget(
        ExceptionInfo->ContextRecord->Rip,
        "\xc3", 1, 500);
    ExceptionInfo->ContextRecord->EFlags |= (1 << 16); // Set Resume Flag
}
