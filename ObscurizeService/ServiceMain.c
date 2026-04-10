#include "ServiceMain.h"
#include "AgentInjector.h"
#include "ProcessListener.h"
#include "ControlPipeListener.h"
#include "ArtefactManager.h"
#include "../ObscurizeShared/ObscurizeDef.h"

// r77api utilities
#include "../r77-rootkit/r77-rootkit-master/r77api/r77mindef.h"
#include "../r77-rootkit/r77-rootkit-master/r77api/r77win.h"
#include "../r77-rootkit/r77-rootkit-master/r77api/r77header.h"
#include "../r77-rootkit/r77-rootkit-master/r77api/r77process.h"

#include <sddl.h>
#include <strsafe.h>

// ============================================================
//  ObscurizeService – ServiceMain.c
//
//  Windows Service entry point and lifecycle management.
//
//  Architecture (standalone EXE, simpler than r77's winlogon
//  injection approach):
//
//    main()
//      └─ StartServiceCtrlDispatcher
//           └─ ObsServiceMain  (called by SCM)
//                └─ InitializeObscurizeService
//                     ├─ Load Agent DLLs from PE resources
//                     ├─ Create/configure HKLM\ObscurizeConfig
//                     ├─ Apply mode artefacts (Defensive or Trap)
//                     ├─ Inject Agent into all running processes
//                     ├─ NewProcessListenerThread   (100 ms poll)
//                     └─ ControlPipeListenerThread  (GUI commands)
// ============================================================

// --------------------------------------------------------
//  Globals
// --------------------------------------------------------

LPBYTE          g_AgentDll32     = NULL;
DWORD           g_AgentDll32Size = 0;
LPBYTE          g_AgentDll64     = NULL;
DWORD           g_AgentDll64Size = 0;
volatile BOOL   g_InjectionPaused = FALSE;

static SERVICE_STATUS_HANDLE s_statusHandle = NULL;
static SERVICE_STATUS        s_serviceStatus = { 0 };
static HANDLE                s_stopEvent     = NULL;

static HANDLE s_newProcessThread  = NULL;
static HANDLE s_controlPipeThread = NULL;

// --------------------------------------------------------
//  Config registry setup
// --------------------------------------------------------

/// Create HKLM\SOFTWARE\ObscurizeConfig and set DACL so that
/// the GUI running as an admin user can write mode/enable values.
static BOOL EnsureConfigKey(VOID)
{
    HKEY  key         = NULL;
    DWORD disposition = 0;
    LONG result = RegCreateKeyExW(
        HKEY_LOCAL_MACHINE, OBS_CONFIG_KEY, 0, NULL,
        REG_OPTION_NON_VOLATILE,
        KEY_ALL_ACCESS | KEY_WOW64_64KEY,
        NULL, &key, &disposition);

    if (result != ERROR_SUCCESS) return FALSE;

    // SDDL: BUILTIN\Administrators (BA) full control only.
    // Standard users query status via the control pipe, not by reading
    // the registry directly.  Giving AU write access would let any
    // unprivileged process tamper with config or overwrite the cached
    // Agent DLL blobs.
    PSECURITY_DESCRIPTOR sd = NULL;
    ULONG sdSize = 0;
    if (ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:(A;OICI;GA;;;SY)(A;OICI;GA;;;BA)",
            SDDL_REVISION_1, &sd, &sdSize))
    {
        RegSetKeySecurity(key, DACL_SECURITY_INFORMATION, sd);
        LocalFree(sd);
    }

    // Write defaults only on first-ever creation.  On subsequent service
    // starts the existing values are preserved so the admin's last-set
    // state (mode, enabled, domain toggle) survives reboots.
    if (disposition == REG_CREATED_NEW_KEY)
    {
        DWORD defaultEnabled = 0;               // off until admin enables it
        DWORD defaultMode    = OBS_MODE_DEFENSIVE;
        DWORD defaultDomain  = 0;               // domain spoof off by default
        RegSetValueExW(key, OBS_CONFIG_VALUE_ENABLED, 0, REG_DWORD,
                       (LPBYTE)&defaultEnabled, sizeof(DWORD));
        RegSetValueExW(key, OBS_CONFIG_VALUE_MODE, 0, REG_DWORD,
                       (LPBYTE)&defaultMode, sizeof(DWORD));
        RegSetValueExW(key, OBS_CONFIG_VALUE_DOMAIN_ENABLED, 0, REG_DWORD,
                       (LPBYTE)&defaultDomain, sizeof(DWORD));
    }

    RegCloseKey(key);
    return TRUE;
}

/// Cache Agent DLL bytes in the registry so an in-process hook
/// (if added later) can retrieve them without filesystem access.
static VOID CacheAgentDllsInRegistry(VOID)
{
    HKEY key = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, OBS_CONFIG_KEY, 0,
                      KEY_SET_VALUE | KEY_WOW64_64KEY, &key) != ERROR_SUCCESS)
        return;

    if (g_AgentDll32 && g_AgentDll32Size)
        RegSetValueExW(key, OBS_REG_AGENT32_VALUE, 0, REG_BINARY,
                       g_AgentDll32, g_AgentDll32Size);
    if (g_AgentDll64 && g_AgentDll64Size)
        RegSetValueExW(key, OBS_REG_AGENT64_VALUE, 0, REG_BINARY,
                       g_AgentDll64, g_AgentDll64Size);

    RegCloseKey(key);
}

/// Remove cached DLL bytes from registry (called on uninstall/shutdown).
static VOID RemoveCachedAgentDlls(VOID)
{
    HKEY key = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, OBS_CONFIG_KEY, 0,
                      KEY_SET_VALUE | KEY_WOW64_64KEY, &key) != ERROR_SUCCESS)
        return;

    RegDeleteValueW(key, OBS_REG_AGENT32_VALUE);
    RegDeleteValueW(key, OBS_REG_AGENT64_VALUE);
    RegCloseKey(key);
}

// --------------------------------------------------------
//  Current mode helper
// --------------------------------------------------------

static DWORD ReadCurrentMode(VOID)
{
    DWORD mode = OBS_MODE_DEFENSIVE;
    HKEY  key  = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, OBS_CONFIG_KEY, 0,
                      KEY_QUERY_VALUE | KEY_WOW64_64KEY, &key) == ERROR_SUCCESS)
    {
        DWORD type, size = sizeof(DWORD), value;
        if (RegQueryValueExW(key, OBS_CONFIG_VALUE_MODE, NULL, &type,
                             (LPBYTE)&value, &size) == ERROR_SUCCESS && type == REG_DWORD)
        {
            if (value == OBS_MODE_DEFENSIVE || value == OBS_MODE_TRAP)
                mode = value;
        }
        RegCloseKey(key);
    }
    return mode;
}

// --------------------------------------------------------
//  SCM status helper
// --------------------------------------------------------

static VOID ReportServiceStatus(DWORD currentState, DWORD exitCode, DWORD waitHint)
{
    static DWORD s_checkPoint = 1;

    s_serviceStatus.dwServiceType             = SERVICE_WIN32_OWN_PROCESS;
    s_serviceStatus.dwCurrentState            = currentState;
    s_serviceStatus.dwControlsAccepted        =
        (currentState == SERVICE_START_PENDING) ? 0
        : (SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_PAUSE_CONTINUE);
    s_serviceStatus.dwWin32ExitCode           = exitCode;
    s_serviceStatus.dwServiceSpecificExitCode = 0;
    s_serviceStatus.dwCheckPoint              =
        (currentState == SERVICE_RUNNING || currentState == SERVICE_STOPPED)
        ? 0 : s_checkPoint++;
    s_serviceStatus.dwWaitHint                = waitHint;

    SetServiceStatus(s_statusHandle, &s_serviceStatus);
}

// --------------------------------------------------------
//  Callbacks forwarded from listener threads
// --------------------------------------------------------

VOID NewProcessCallback(DWORD processId)
{
    if (!g_InjectionPaused)
        InjectAgentIntoProcess(processId);
}

// ControlPipeListener invokes this when a command arrives.
VOID ObsControlCallback(DWORD controlCode, HANDLE pipe)
{
    switch (controlCode)
    {
        // ---- Enable / Disable ----
        case OBS_CTRL_ENABLE:
        {
            HKEY key;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, OBS_CONFIG_KEY, 0,
                              KEY_SET_VALUE | KEY_WOW64_64KEY, &key) == ERROR_SUCCESS)
            {
                DWORD val = 1;
                RegSetValueExW(key, OBS_CONFIG_VALUE_ENABLED, 0, REG_DWORD,
                               (LPBYTE)&val, sizeof(DWORD));
                RegCloseKey(key);
            }
            break;
        }
        case OBS_CTRL_DISABLE:
        {
            HKEY key;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, OBS_CONFIG_KEY, 0,
                              KEY_SET_VALUE | KEY_WOW64_64KEY, &key) == ERROR_SUCCESS)
            {
                DWORD val = 0;
                RegSetValueExW(key, OBS_CONFIG_VALUE_ENABLED, 0, REG_DWORD,
                               (LPBYTE)&val, sizeof(DWORD));
                RegCloseKey(key);
            }
            break;
        }

        // ---- Mode switch ----
        case OBS_CTRL_SET_MODE_DEFENSIVE:
        case OBS_CTRL_SET_MODE_TRAP:
        {
            DWORD newMode = (controlCode == OBS_CTRL_SET_MODE_DEFENSIVE)
                            ? OBS_MODE_DEFENSIVE : OBS_MODE_TRAP;

            // Update registry first so the Agent's config thread picks it up.
            HKEY key;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, OBS_CONFIG_KEY, 0,
                              KEY_SET_VALUE | KEY_WOW64_64KEY, &key) == ERROR_SUCCESS)
            {
                RegSetValueExW(key, OBS_CONFIG_VALUE_MODE, 0, REG_DWORD,
                               (LPBYTE)&newMode, sizeof(DWORD));
                RegCloseKey(key);
            }

            // Swap registry artefacts to match the new mode.
            ApplyModeArtefacts(newMode);
            break;
        }

        // ---- Status query ----
        case OBS_CTRL_QUERY_STATUS:
        {
            DWORD mode    = ReadCurrentMode();
            DWORD enabled = 0;

            HKEY key;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, OBS_CONFIG_KEY, 0,
                              KEY_QUERY_VALUE | KEY_WOW64_64KEY, &key) == ERROR_SUCCESS)
            {
                DWORD type, size = sizeof(DWORD);
                RegQueryValueExW(key, OBS_CONFIG_VALUE_ENABLED, NULL, &type,
                                 (LPBYTE)&enabled, &size);
                RegCloseKey(key);
            }

            DWORD status;
            if (!enabled)
                status = OBS_STATUS_DISABLED;
            else
                status = (mode == OBS_MODE_DEFENSIVE)
                         ? OBS_STATUS_MODE_DEFENSIVE
                         : OBS_STATUS_MODE_TRAP;

            DWORD written;
            WriteFile(pipe, &status, sizeof(DWORD), &written, NULL);
            break;
        }

        // ---- Domain spoofing toggle ----
        case OBS_CTRL_DOMAIN_ENABLE:
        case OBS_CTRL_DOMAIN_DISABLE:
        {
            DWORD val = (controlCode == OBS_CTRL_DOMAIN_ENABLE) ? 1 : 0;
            HKEY key;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, OBS_CONFIG_KEY, 0,
                              KEY_SET_VALUE | KEY_WOW64_64KEY, &key) == ERROR_SUCCESS)
            {
                RegSetValueExW(key, OBS_CONFIG_VALUE_DOMAIN_ENABLED, 0, REG_DWORD,
                               (LPBYTE)&val, sizeof(DWORD));
                RegCloseKey(key);
            }
            break;
        }

        // ---- Injection control ----
        case OBS_CTRL_INJECT_ALL:
        {
            InjectAgentIntoAllProcesses();
            break;
        }
        case OBS_CTRL_DETACH_ALL:
        {
            DetachAllAgents();
            break;
        }

    }
}

// --------------------------------------------------------
//  SCM control handler
// --------------------------------------------------------

VOID WINAPI ObsServiceCtrlHandler(DWORD control)
{
    switch (control)
    {
        case SERVICE_CONTROL_STOP:
        {
            ReportServiceStatus(SERVICE_STOP_PENDING, NO_ERROR, 5000);
            SetEvent(s_stopEvent);
            break;
        }
        case SERVICE_CONTROL_PAUSE:
        {
            g_InjectionPaused = TRUE;
            ReportServiceStatus(SERVICE_PAUSED, NO_ERROR, 0);
            break;
        }
        case SERVICE_CONTROL_CONTINUE:
        {
            g_InjectionPaused = FALSE;
            ReportServiceStatus(SERVICE_RUNNING, NO_ERROR, 0);
            break;
        }
        case SERVICE_CONTROL_INTERROGATE:
        {
            // SCM queries current status – just re-report.
            SetServiceStatus(s_statusHandle, &s_serviceStatus);
            break;
        }
    }
}

// --------------------------------------------------------
//  Core initialisation
// --------------------------------------------------------

BOOL InitializeObscurizeService(VOID)
{
    // Obtain SeDebugPrivilege so we can open and inject into
    // any process regardless of its owner.
    EnabledDebugPrivilege();

    // Load Agent DLLs from embedded PE resources.
    if (!LoadAgentDllsFromResources(&g_AgentDll32, &g_AgentDll32Size,
                                    &g_AgentDll64, &g_AgentDll64Size))
    {
        // DLLs not yet embedded (development build) – non-fatal.
        // Injection will simply be skipped.
        OutputDebugStringW(L"[Obscurize] Agent DLLs not found in resources – injection disabled.\n");
    }

    // Ensure config registry key exists and is writable by admins.
    if (!EnsureConfigKey()) return FALSE;

    // Store Agent DLL bytes in registry for potential future in-process use.
    CacheAgentDllsInRegistry();

    // Apply artefacts for the current configured mode.
    ApplyModeArtefacts(ReadCurrentMode());

    // Inject Agent into every currently-running process.
    InjectAgentIntoAllProcesses();

    // Start the new-process watcher (100 ms polling).
    s_newProcessThread = StartNewProcessListener(NewProcessCallback);
    if (!s_newProcessThread) return FALSE;

    // Start the GUI control pipe listener.
    s_controlPipeThread = StartControlPipeListener(ObsControlCallback);
    if (!s_controlPipeThread) return FALSE;

    return TRUE;
}

// --------------------------------------------------------
//  Graceful shutdown
// --------------------------------------------------------

VOID UninitializeObscurizeService(VOID)
{
    // Pause injection so no new processes get the agent while we clean up.
    g_InjectionPaused = TRUE;

    // Stop listener threads.
    if (s_newProcessThread)
    {
        TerminateThread(s_newProcessThread, 0);
        CloseHandle(s_newProcessThread);
        s_newProcessThread = NULL;
    }

    // Detach Agent from all injected processes.
    DetachAllAgents();

    // Remove mode artefacts if in Defensive mode.
    RemoveModeArtefacts();

    // Remove cached DLL bytes from registry.
    RemoveCachedAgentDlls();

    // Free DLL byte buffers.
    if (g_AgentDll32) { HeapFree(GetProcessHeap(), 0, g_AgentDll32); g_AgentDll32 = NULL; }
    if (g_AgentDll64) { HeapFree(GetProcessHeap(), 0, g_AgentDll64); g_AgentDll64 = NULL; }

    // Stop the control pipe thread LAST – if this was triggered from
    // the pipe thread itself, the thread terminates naturally after this.
    if (s_controlPipeThread)
    {
        TerminateThread(s_controlPipeThread, 0);
        CloseHandle(s_controlPipeThread);
        s_controlPipeThread = NULL;
    }
}

// --------------------------------------------------------
//  ObsServiceMain – called by SCM
// --------------------------------------------------------

VOID WINAPI ObsServiceMain(DWORD argc, LPWSTR *argv)
{
    (VOID)argc;
    (VOID)argv;

    s_statusHandle = RegisterServiceCtrlHandlerW(OBS_SERVICE_NAME, ObsServiceCtrlHandler);
    if (!s_statusHandle) return;

    s_stopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!s_stopEvent)
    {
        ReportServiceStatus(SERVICE_STOPPED, GetLastError(), 0);
        return;
    }

    ReportServiceStatus(SERVICE_START_PENDING, NO_ERROR, 3000);

    if (!InitializeObscurizeService())
    {
        ReportServiceStatus(SERVICE_STOPPED, ERROR_FUNCTION_FAILED, 0);
        CloseHandle(s_stopEvent);
        return;
    }

    ReportServiceStatus(SERVICE_RUNNING, NO_ERROR, 0);

    // Block until SCM sends a stop signal.
    WaitForSingleObject(s_stopEvent, INFINITE);

    ReportServiceStatus(SERVICE_STOP_PENDING, NO_ERROR, 5000);
    UninitializeObscurizeService();
    ReportServiceStatus(SERVICE_STOPPED, NO_ERROR, 0);

    CloseHandle(s_stopEvent);
}

// --------------------------------------------------------
//  Entry point
// --------------------------------------------------------

int wmain(int argc, WCHAR *argv[])
{
    (VOID)argc;
    (VOID)argv;

    SERVICE_TABLE_ENTRYW serviceTable[] =
    {
        { OBS_SERVICE_NAME, ObsServiceMain },
        { NULL, NULL }
    };

    // If StartServiceCtrlDispatcher fails we were launched interactively.
    if (!StartServiceCtrlDispatcherW(serviceTable))
    {
        DWORD err = GetLastError();
        if (err == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT)
        {
            // Running from the command line for testing.
            // Run a minimal interactive loop for development.
            wprintf(L"[Obscurize] Running interactively (not as a service).\n");
            wprintf(L"[Obscurize] Starting service logic...\n");

            if (InitializeObscurizeService())
            {
                wprintf(L"[Obscurize] Initialized. Press Enter to stop.\n");
                getwchar();
                UninitializeObscurizeService();
            }
            else
            {
                wprintf(L"[Obscurize] InitializeObscurizeService failed.\n");
                return 1;
            }
        }
    }

    return 0;
}
