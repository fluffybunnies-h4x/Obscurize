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

// --------------------------------------------------------
//  Trap-mode session identity
//
//  When entering Trap mode the service generates one consistent
//  username (firstname.lastname) and computer name (XXX-XXXXXX)
//  and writes them to the registry as UserSID / HostBinding.
//  All injected processes read these values, so every process
//  reports the same identity regardless of injection order or
//  timing — preventing a C2 operator from seeing inconsistency.
//
//  If the operator has already set UserSID / HostBinding
//  manually (deliberate persona), those values are left alone.
//  When switching back to Defensive mode the auto-generated
//  values are deleted so per-process randomness resumes.
// --------------------------------------------------------

// Character sets must stay in sync with Config.c / GenerateRandomIdentities()
static const LPCWSTR s_FirstNames[] = {
    L"james", L"john", L"robert", L"michael", L"william",
    L"david", L"richard", L"joseph", L"thomas", L"charles",
    L"mary", L"patricia", L"jennifer", L"linda", L"barbara",
    L"sarah", L"jessica", L"karen", L"lisa", L"nancy", NULL
};
static const LPCWSTR s_LastNames[] = {
    L"smith", L"jones", L"williams", L"brown", L"taylor",
    L"davies", L"evans", L"thomas", L"roberts", L"johnson",
    L"wilson", L"walker", L"wright", L"thompson", L"white", NULL
};
// Uppercase consonants only – no vowels (prevents accidental words)
static const WCHAR s_Alpha[]    = L"ABCDEFGHJKLMNPQRSTVWXYZ";
// Consonant-heavy alphanumeric for the 6-char suffix
static const WCHAR s_ConsAlnum[] = L"BCDFGHJKLMNPQRSTVWXZ2345679";

static DWORD s_sessionRng = 0;

static DWORD SessionRand(VOID)
{
    if (s_sessionRng == 0)
        s_sessionRng = GetCurrentProcessId() ^ GetTickCount();
    s_sessionRng ^= s_sessionRng << 13;
    s_sessionRng ^= s_sessionRng >> 17;
    s_sessionRng ^= s_sessionRng << 5;
    return s_sessionRng;
}

// Write a consistent Trap-mode identity to the registry.
// Skips each value individually if it is already manually set.
static VOID WriteSessionIdentity(VOID)
{
    HKEY key = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, OBS_CONFIG_KEY, 0,
                      KEY_QUERY_VALUE | KEY_SET_VALUE | KEY_WOW64_64KEY,
                      &key) != ERROR_SUCCESS)
        return;

    DWORD type, size;

    // Username – generate only if not already set
    size = 0;
    BOOL hasUser = (RegQueryValueExW(key, OBS_CONFIG_VALUE_USERNAME, NULL,
                                     &type, NULL, &size) == ERROR_SUCCESS
                    && type == REG_SZ && size > sizeof(WCHAR));
    if (!hasUser)
    {
        DWORD nFirst = 0, nLast = 0;
        while (s_FirstNames[nFirst]) nFirst++;
        while (s_LastNames[nLast])  nLast++;

        WCHAR username[64] = { 0 };
        StringCchPrintfW(username, 64, L"%s.%s",
                         s_FirstNames[SessionRand() % nFirst],
                         s_LastNames [SessionRand() % nLast]);
        DWORD len = (DWORD)((wcslen(username) + 1) * sizeof(WCHAR));
        RegSetValueExW(key, OBS_CONFIG_VALUE_USERNAME, 0, REG_SZ,
                       (LPBYTE)username, len);
    }

    // Computer name – generate only if not already set
    size = 0;
    BOOL hasComp = (RegQueryValueExW(key, OBS_CONFIG_VALUE_COMPNAME, NULL,
                                     &type, NULL, &size) == ERROR_SUCCESS
                    && type == REG_SZ && size > sizeof(WCHAR));
    if (!hasComp)
    {
        DWORD alphaLen    = (DWORD)(ARRAYSIZE(s_Alpha)    - 1);
        DWORD consAlnumLen = (DWORD)(ARRAYSIZE(s_ConsAlnum) - 1);

        WCHAR compname[16] = { 0 };
        compname[0] = s_Alpha[SessionRand() % alphaLen];
        compname[1] = s_Alpha[SessionRand() % alphaLen];
        compname[2] = s_Alpha[SessionRand() % alphaLen];
        compname[3] = L'-';
        for (int i = 0; i < 6; i++)
            compname[4 + i] = s_ConsAlnum[SessionRand() % consAlnumLen];
        compname[10] = L'\0';

        DWORD len = (DWORD)((wcslen(compname) + 1) * sizeof(WCHAR));
        RegSetValueExW(key, OBS_CONFIG_VALUE_COMPNAME, 0, REG_SZ,
                       (LPBYTE)compname, len);
    }

    RegCloseKey(key);
}

// Remove auto-generated session identity so Defensive mode uses
// per-process random values again.  Manual overrides are also
// cleared – the operator must re-enter them when switching back.
static VOID ClearSessionIdentity(VOID)
{
    HKEY key = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, OBS_CONFIG_KEY, 0,
                      KEY_SET_VALUE | KEY_WOW64_64KEY, &key) != ERROR_SUCCESS)
        return;

    RegDeleteValueW(key, OBS_CONFIG_VALUE_USERNAME);
    RegDeleteValueW(key, OBS_CONFIG_VALUE_COMPNAME);
    RegCloseKey(key);
}

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

    // SDDL:
    //   SY – SYSTEM           : full control (service reads + writes config)
    //   BA – Administrators   : full control (GUI writes mode/enabled/etc.)
    //   WD – Everyone         : read-only  (agent DLL runs in any process at
    //                           any integrity level and must read Enabled/Mode;
    //                           medium-integrity processes have the BA group
    //                           as deny-only via UAC token filtering, so they
    //                           fail KEY_QUERY_VALUE without this ACE)
    // Write access (KEY_SET_VALUE) remains restricted to SY/BA only, so no
    // unprivileged process can tamper with config or overwrite the Agent DLLs.
    PSECURITY_DESCRIPTOR sd = NULL;
    ULONG sdSize = 0;
    if (ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:(A;OICI;GA;;;SY)(A;OICI;GA;;;BA)(A;OICI;GR;;;WD)",
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
        RegSetValueExW(key, OBS_CONFIG_VALUE_DOMAIN_MODE, 0, REG_DWORD,
                       (LPBYTE)&defaultDomain, sizeof(DWORD));
    }

    RegCloseKey(key);
    return TRUE;
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

            // Maintain a consistent session identity in Trap mode so every
            // injected process reports the same username and computer name.
            if (newMode == OBS_MODE_TRAP)
                WriteSessionIdentity();
            else
                ClearSessionIdentity();
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

        // ---- Domain mode ----
        case OBS_CTRL_DOMAIN_OFF:
        case OBS_CTRL_DOMAIN_WORKGROUP:
        case OBS_CTRL_DOMAIN_JOINED:
        {
            DWORD val = (controlCode == OBS_CTRL_DOMAIN_JOINED)   ? OBS_DOMAIN_MODE_JOINED
                      : (controlCode == OBS_CTRL_DOMAIN_WORKGROUP) ? OBS_DOMAIN_MODE_WORKGROUP
                      :                                              OBS_DOMAIN_MODE_OFF;
            HKEY key;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, OBS_CONFIG_KEY, 0,
                              KEY_SET_VALUE | KEY_WOW64_64KEY, &key) == ERROR_SUCCESS)
            {
                RegSetValueExW(key, OBS_CONFIG_VALUE_DOMAIN_MODE, 0, REG_DWORD,
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

        // ---- Synchronous per-PID injection (sent by HookedCreateProcessW/A) ----
        // The agent creates wmic.exe suspended, sends this code + the PID, and waits
        // for our OBS_STATUS_OK reply before calling ResumeThread.  Because InjectDll
        // is synchronous, the agent DLL is fully installed before we reply.
        case OBS_CTRL_INJECT_PID:
        {
            DWORD pid = 0, bytesRead = 0;
            if (ReadFile(pipe, &pid, sizeof(DWORD), &bytesRead, NULL)
                && bytesRead == sizeof(DWORD)
                && pid != 0)
            {
                InjectAgentIntoProcess(pid);
            }
            DWORD status = OBS_STATUS_OK, written = 0;
            WriteFile(pipe, &status, sizeof(DWORD), &written, NULL);
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

    // In Trap mode, pin a consistent session identity so all injected
    // processes report the same username / computer name.
    DWORD startupMode = ReadCurrentMode();
    if (startupMode == OBS_MODE_TRAP)
        WriteSessionIdentity();

    // Apply artefacts for the current configured mode.
    ApplyModeArtefacts(startupMode);

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
