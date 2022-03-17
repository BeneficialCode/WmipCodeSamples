// MemColls.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include "MemColls.h"

int wmain(int argc,wchar_t *argv[]){
    if (!XtractParams(argc, argv))
        return GetLastError();
    g_pMem = PrvAlloc(g_size, g_initialProt);
    if (g_pMem == nullptr)
        return GetLastError();
    if (!ProcessCommandLoop())
        return GetLastError();
    return ERROR_SUCCESS;
}

//++
// Function: AccessMemory
//
// Memory access function.
//
// Before returning, frees the parameters instance.
//--
DWORD WINAPI AccessMemory(void* param) {
    DWORD tid = GetCurrentThreadId();
    MemAccess* pAccess = (MemAccess*)param;
    PBYTE pPage;

    PBYTE pEnd = (PBYTE)pAccess->Start + pAccess->Size;
    if (pAccess->AccessCode == ACC_READ) {
        wprintf(L"\nThread %d - Reading memory from %#p to %#p...",
            tid, pAccess->Start, pEnd);
    }
    else {
        wprintf(L"\nThread %d - Writing memory from %#p to %#p...",
            tid, pAccess->Start, pEnd);
    }
    if (g_bBrk) {
        DebugBreak();
    }
    for (pPage = (PBYTE)pAccess->Start; pPage < pEnd; pPage += 0x1000) {
        if (pAccess->AccessCode == ACC_READ) {
            g_dummyByte = *pPage;
        }
        else {
            *((DWORDLONG*)pPage) = (DWORDLONG)pPage;
        }
    }
    ::HeapFree(pAccess->hHeap, 0, pAccess);
    wprintf(L"\nThread %d - Finished accessing memory", tid);

    return ERROR_SUCCESS;
}

//++
// Function: ChangeProtection
//
// Changes the region protection
//
// 
//--
DWORD WINAPI ChangeProtection(void* param) {
    DWORD error;
    DWORD oldProtect;
    DWORD tid = GetCurrentThreadId();

    MemPChange* pChange = (MemPChange*)param;
    PBYTE pEnd = (PBYTE)pChange->Start + pChange->Size;
    wprintf(L"\nThread %d - Setting protection to 0x%x from %#p to \
        %#p...", tid, pChange->NewProt, pChange->Start, pEnd);
    if (g_bBrk) {
        DebugBreak();
    }
    if (!::VirtualProtectEx(GetCurrentProcess(),
        pChange->Start,
        pChange->Size,
        pChange->NewProt,
        &oldProtect)) {
        error = GetLastError();
        wprintf(L"\nThread %d - VirtualProtectEx() failed with GetLastError()\
        = %d", tid, error);
        return error;
    }
    wprintf(L"\nThread %d - Memory protection set to %d", tid, pChange->NewProt);
    return ERROR_SUCCESS;
}

//++
// Function: CreateThrWr
//
// Wrapper for CreateThread
//
// 
//--
BOOL CreateThrWr(LPTHREAD_START_ROUTINE startAddress, LPVOID param) {
    DWORD error;
    HANDLE hThread;

    hThread = ::CreateThread(nullptr, 0, startAddress, param, 0, nullptr);
    if (hThread == nullptr) {
        error = GetLastError();
        wprintf(L"\nCreateThread failed with GetLastError() = %d", error);
        SetLastError(error);
        return false;
    }

    ::CloseHandle(hThread);
    return TRUE;
}

//++
// Function: DecommitMemory
//
// Memory decommit function.
//
// Before returning, frees the parameters instance.
//--
DWORD WINAPI DecommitMemroy(void* param) {
    DWORD error;
    DWORD tid = GetCurrentThreadId();
    MemDecommit* pDecommit = (MemDecommit*)param;
    PBYTE pEnd = (PBYTE)pDecommit->Start + pDecommit->Size;
    wprintf(L"\nThread %d - Decommiting memory from %#p to %#p...",
        tid, pDecommit->Start, pEnd);
    if (g_bBrk) {
        DebugBreak();
    }
    if (!::VirtualFreeEx(GetCurrentProcess(),
        pDecommit->Start,
        pDecommit->Size,
        MEM_DECOMMIT)) {
        error = GetLastError();
        wprintf(L"\nThread %d - VirtualFreeEx failed with GetLastError() = %d",
            tid, error);
    }
    HeapFree(pDecommit->hHeap, 0, pDecommit);
    wprintf(L"\nThread %d - Finished decommitting memory", tid);
    return ERROR_SUCCESS;
}

//++
// Function: FreeMemory
//
// Frees the memory region.
//--
DWORD WINAPI FreeMemory(void* param) {
    DWORD error = ERROR_SUCCESS;
    DWORD tid = GetCurrentThreadId();

    if (g_bBrk)
        DebugBreak();

    if (!::VirtualFreeEx(GetCurrentProcess(),
        param,
        0,
        MEM_RELEASE)) {
        error = GetLastError();
        wprintf(L"\n Thread %d - VirtualFreeEx failed with GetLastError() = \
        %d", tid, error);
        return error;
    }
    wprintf(L"\n Thread %d - Memory freed", tid);
    return ERROR_SUCCESS;
}

void PrintCmdList() {
    wprintf(L"\n\n");
    wprintf(L"\n%c - Read entire region", CMD_READ);
    wprintf(L"\n%c - Write entire region", CMD_WRITE);
    wprintf(L"\n%c - Access subrange", CMD_ACCESS_RANGE);
    wprintf(L"\n%c - Change subrange protection", CMD_CHANGE_RANGE_PROT);
    wprintf(L"\n%c - Free memory", CMD_FREE);
    wprintf(L"\n%c - Decommit memory", CMD_DECOMMIT);
    wprintf(L"\n%c - Synchronous free memory", CMD_FREE_SYNC);
    wprintf(L"\n%c - Shrink working set", CMD_SHRINK);
    wprintf(L"\n%c - Reallocate memory", CMD_REALLOC);
    wprintf(L"\n%c - Activate breaking mode", CMD_SET_BRK);
    wprintf(L"\n%c - Deactivate breaking mode", CMD_CLEAR_BRK);
    wprintf(L"\n%c - Quit", CMD_QUIT);
    wprintf(L"\n\n");
    wprintf(L"\nRegion   : 0x%16p - 0x%16p", g_pMem, ((PBYTE)g_pMem) + g_size);
    wprintf(L"\nSize     : 0x%I64x (%I64d)", g_size, g_size);
    wprintf(L"\nBreaking : %s", g_bBrk ? L"active" : L"not active");
    wprintf(L"\n\n");

    return;
}

void PrintHelp() {
    wprintf(L"\n\n");
    wprintf(L"Usage:");
    wprintf(L"\n\n");
    wprintf(L"    " PGM_NAME L" alloc_size alloc_protection");
    wprintf(L"\n\n");
    wprintf(L"    alloc_size       : allocation size in bytes");
    wprintf(L"\n\n");
    wprintf(L"    alloc_protection : protection, e.g.:");
    wprintf(L"\n");
    wprintf(L"        PAGE_READWRITE = 0x%x", PAGE_READWRITE);
    wprintf(L"\n");
    wprintf(L"        PAGE_READONLY  = 0x%x", PAGE_READONLY);
    wprintf(L"\n");
    wprintf(L"        See also flProtect of VirtualAllocEx()");
    wprintf(L"\n");
    return;
}

//++
// Function: ProcessCommand
//
// Executes a command.
//
// Sets *pbEndLoop if the command causes the command loop to end.
//
// Returns FALSE on errors.
//
// 
//--
bool ProcessCommandLoop() {
    BOOL bEndLoop = false;
    do
    {
        PrintCmdList();
        WCHAR cmd = getwchar();
        if (!ProcessCommand(cmd, &bEndLoop)) {
            return false;
        }
    } while (!bEndLoop);
    return true;
}

//++
// Function: ProcessCommand
//
// Executes the loop which reads the command character from
// the keyboard and executes it in a separate thread.
//--
bool ProcessCommand(WCHAR cmd, PBOOL pbEndLoop) {
    switch (cmd) {
    case CMD_READ:
        return StartAccess(ACC_READ, g_pMem, g_size);
        break;
    case CMD_ACCESS_RANGE:
        return StartRangeAccess();
        break;
    case CMD_WRITE:
        return StartAccess(ACC_WRITE, g_pMem, g_size);
        break;
    case CMD_CHANGE_RANGE_PROT:
        return StartRangePchange();
        break;
    case CMD_FREE:
        return StartFree();
        break;
    case CMD_DECOMMIT:
        return StartRangeDecommit();
        break;
    case CMD_FREE_SYNC:
        FreeMemory(g_pMem);

        // Let the command loop go on regadless of any errors
        return TRUE;
    case CMD_SHRINK:
        return StartShrink();
        break;
    case CMD_REALLOC:
        g_pMem = PrvAlloc(g_size, g_initialProt);
        if (g_pMem == NULL) return FALSE;
        break;
    case CMD_SET_BRK:
        g_bBrk = TRUE;
        break;
    case CMD_CLEAR_BRK:
        g_bBrk = FALSE;
        break;
    case CMD_QUIT:
        *pbEndLoop = TRUE;
        break;
    default:
        wprintf(L"\nInvalid command: %c", cmd);
    }
    return TRUE;
}

//++
// Function: PrvAlloc
//
// Reserves and commits the memory range.
//--
PVOID PrvAlloc(DWORD64 size, DWORD protection) {
    DWORD error;
    wprintf(L"\nAllocating 0x%I64x (%I64d) bytes with protection\
        0x%x...",size,size,protection);

    PBYTE pRegion = (PBYTE)::VirtualAllocEx(GetCurrentProcess(),
        nullptr, size, MEM_COMMIT | MEM_RESERVE,
        protection);
    if (pRegion == nullptr) {
        error = GetLastError();
        wprintf(L"\nVirtualAlloc() failed with GetLastError() = %d",
            error);
        SetLastError(error);
        return nullptr;
    }
    PBYTE pEnd = pRegion + size;
    wprintf(L"\nAllocated region: 0x%16p 0x%16p", pRegion, pEnd);
    return pRegion;
}

//++
// Function: ShrinkWs
//
// Shrinks the working set
// 
//--
DWORD WINAPI ShrinkWs(void* param) {
    UNREFERENCED_PARAMETER(param);
    DWORD error;
    DWORD tid = GetCurrentThreadId();

    if (!::SetProcessWorkingSetSizeEx(GetCurrentProcess(),
        -1, -1, 0)) {
        error = GetLastError();
        wprintf(L"\nThread %d - SetProcessWorkingSetSizeEx() failed with GetLastError() = %d",
            tid, error);
        return error;
    }
    wprintf(L"\nThread %d - Working set shrinked", tid);
    return ERROR_SUCCESS;
}

//++
// Function: StartAccess
//
// Starts a thread executing a loop which touches the pages of the memory region,
// reading or writing, according to AccessCode.
// 
//--
bool StartAccess(int accessCode, PVOID pStart, SIZE_T size) {
    DWORD error;
    HANDLE hHeap = GetProcessHeap();
    if (hHeap == nullptr) {
        error = GetLastError();
        wprintf(L"\nGetProcessHeap failed with GetLastError() = %d", error);
        SetLastError(error);
        return false;
    }
    MemAccess* pAccess = (MemAccess*)HeapAlloc(hHeap, 0, sizeof MemAccess);
    if (pAccess == nullptr) {
        error = GetLastError();
        wprintf(L"\nHeapAlloc failed with GetLastError() = %d", error);
        SetLastError(error);
        return false;
    }
    pAccess->hHeap = hHeap;
    pAccess->AccessCode = accessCode;
    pAccess->Start = pStart;
    pAccess->Size = size;
    bool bRet;
    do
    {
        if (!CreateThrWr(AccessMemory, pAccess)) {
            error = GetLastError();
            wprintf(L"\nFailed to start thread for memory with AccessCode = %d", accessCode);
            if (pAccess != nullptr)
                ::HeapFree(hHeap, 0, pAccess);
            bRet = false;
            SetLastError(error);
            break;
        }
        bRet = true;
    } while (false);
    return bRet;
}

//++
// Function: StartDecommit
//
// Starts a thread wich decommits the memory region specified
// by the input parameters
// 
//--
bool StartDecommit(PVOID pStart, SIZE_T length) {
    DWORD error;
    HANDLE hHeap = GetProcessHeap();
    if (hHeap == nullptr) {
        error = GetLastError();
        wprintf(L"\nGetProcessHeap failed with GetLastError() = %d", error);
        SetLastError(error);
        return false;
    }
    MemDecommit* pDecommit = (MemDecommit*)::HeapAlloc(hHeap, 0, sizeof MemDecommit);
    if (pDecommit == nullptr) {
        error = GetLastError();
        wprintf(L"\nHeapAlloc failed with GetLastError() = %d", error);
        SetLastError(error);
        return false;
    }
    bool bRet;
    if (!CreateThrWr(DecommitMemroy, pDecommit)) {
        error = GetLastError();
        wprintf(L"\nFailed to start thread for memory decommit");
        if (pDecommit != nullptr)
            ::HeapFree(hHeap, 0, pDecommit);
        bRet = false;
        SetLastError(error);
        return false;
    }
    return true;
}

//++
// Function: StartFree
//
// Starts a thread wich frees the memory region
// 
//--
bool StartFree() {
    DWORD error;
    if (!CreateThrWr(FreeMemory, g_pMem)) {
        error = GetLastError();
        wprintf(L"\nFailed to start thread for memory freeing");
        SetLastError(error);
        return false;
    }
    return true;
}

//++
// Function: StartPchange
//
// Starts a thread wich changes the protection of a memory region
// as specified by the input params.
// 
//--
bool StartPchange(PVOID pStart, SIZE_T length, DWORD newProt) {
    DWORD error;
    HANDLE hHeap = GetProcessHeap();
    if (hHeap == nullptr) {
        error = GetLastError();
        wprintf(L"\nGetProcessHeap failed with GetLastError() = %d", error);
        SetLastError(error);
        return false;
    }
    MemPChange* pChange = (MemPChange*)HeapAlloc(hHeap, 0, sizeof MemPChange);
    if (pChange == nullptr) {
        error = GetLastError();
        wprintf(L"\nHeapAlloc failed with GetLastError() = %d", error);
        SetLastError(error);
        return false;
    }
    pChange->hHeap = hHeap;
    pChange->Start = pStart;
    pChange->Size = length;
    pChange->NewProt = newProt;
    if (!CreateThrWr(ChangeProtection, pChange)) {
        error = GetLastError();
        wprintf(L"\nFailed to start thread for memory protection change");
        if (pChange != nullptr)
            HeapFree(hHeap, 0, pChange);
        SetLastError(error);
        return false;
    }
    return true;
}

//++
// Function: StartRangeAccess
//
// Starts a thread which accesses a range of the memory region.
// 
//--
bool StartRangeAccess() {
    int accessCode;
    PVOID pStart;
    SIZE_T length;

    wprintf(L"\n");
    wprintf(L"\nstart address: ");
    if (!wscanf_s(L"%I64i", (PLONGLONG)&pStart)) {
        pStart = nullptr;
        // drain stdin
        while(getwc(stdin)!=L'\n'){}
    }
    if (!pStart) {
        wprintf(L"\ninvalid address");
        // return TRUE because we don't want to end the cmd loop
        return true;
    }
    wprintf(L"\nLength: ");
    if (!wscanf_s(L"%I64i", &length)) {
        length = 0;
        // drain stdin
        while(getwc(stdin)!=L'\n'){}
    }

    if (!length) {
        wprintf(L"invalid legnth");
        return TRUE;
    }
    wprintf(L"\naccess type (%d = read, %d = write):",
        ACC_READ, ACC_WRITE);
    if (!wscanf_s(L"%i", &accessCode)) {
        accessCode = 0;
        // drain stdin
        while (getwc(stdin) != L'\n') {}
    }
    if (!accessCode) {
        wprintf(L"\ninvalid access code");
        return true;
    }
    return StartAccess(accessCode, pStart, length);
}

//++
// Function: StartRangeDecommit
//
// Prompts for the parameters to decommit a memory range and
// starts a thread wich performs the operation.
// 
//--
bool StartRangeDecommit() {
    SIZE_T length;
    PVOID pStart;

    wprintf(L"\n");
    wprintf(L"\nstart address: ");
    if (!wscanf_s(L"%I64i", (PLONGLONG)&pStart)) {
        pStart = nullptr;
        // drain stdin
        while (getwc(stdin) != L'\n') {}
    }
    if (!pStart) {
        wprintf(L"\ninvalid address");
        return true;
    }
    wprintf(L"\nlength: ");
    if (!wscanf_s(L"%I64i", &length)) {
        length = 0;

        // drain stdin
        while (getwc(stdin) != L'\n') {}
    }
    if (!length) {
        wprintf(L"\ninvalid length");
        return true;
    }
    return StartDecommit(pStart, length);
}

//++
// Function: StartRangePchange
//
// Prompts for parameters to change protection of a memory
// range and starts a thread which performs the change.
// 
//--
bool StartRangePchange() {
    DWORD prot;
    SIZE_T length;
    PVOID pStart;

    wprintf(L"\n");
    wprintf(L"\nstart address: ");
    if (!wscanf_s(L"%I64i", (PLONGLONG)&pStart)) {
        pStart = nullptr;
        // drain stdin
        while (getwc(stdin) != L'\n') {}
    }
    if (!pStart) {
        wprintf(L"\ninvalid address");
        return true;
    }
    wprintf(L"\nlength: ");
    if (!wscanf_s(L"%I64i", &length)) {
        length = 0;

        // drain stdin
        while (getwc(stdin) != L'\n') {}
    }
    if (!length) {
        wprintf(L"\ninvalid length");
        return true;
    }
    wprintf(L"\npretection: ");
    if (!wscanf_s(L"%i", &prot)) {
        while(getwc(stdin)!=L'\n'){}
        wprintf(L"invalid protection");
        return true;
    }
    return StartPchange(pStart, length, prot);
}

//++
// Function: StartShrink
//
// Starts a thread which shrinks the workingset
// 
//--
bool StartShrink() {
    DWORD error;
    if (!CreateThrWr(ShrinkWs, nullptr)) {
        error = GetLastError();
        wprintf(L"\nFailed to start thread for working set shrinking");
        SetLastError(error);
        return false;
    }
    return true;
}

bool XtractParams(int argc, LPWSTR argv[]) {
    int converted;
    if (argc < 2) {
        PrintHelp();
        SetLastError(ERROR_INVALID_PARAMETER);
        return false;
    }
    if (*argv[1] == L'?') {
        PrintHelp();
        SetLastError(ERROR_SUCCESS);
        return false;
    }
    if (wcslen(argv[1]) == 2) {
        if (*(argv[1] + 1) == L'?') {
            PrintHelp();
            SetLastError(ERROR_SUCCESS);
            return false;
        }
    }
    if (argc < 3) {
        wprintf(L"\n\nError,too few parameters. " PGM_NAME L"/? for help.\n\n");
        SetLastError(ERROR_INVALID_PARAMETER);
        return false;
    }
    converted = swscanf_s(argv[1], L"%I64i", &g_size);
    if (!converted || !g_size) {
        wprintf(L"\n\nError, invalid size: %s." PGM_NAME L"/? for help.\n\n",
            argv[1]);
        SetLastError(ERROR_INVALID_PARAMETER);
        return false;
    }
    converted = swscanf_s(argv[2], L"%i", &g_initialProt);
    if (!converted) {
        wprintf(L"\n\nError, invalid protection: %s." PGM_NAME L"/? for help.\n\n",
            argv[2]);
        SetLastError(ERROR_INVALID_PARAMETER);
        return false;
    }
    return true;
}