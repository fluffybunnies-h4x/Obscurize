#include "Config.h"
#include "../ObscurizeShared/ObscurizeDef.h"
#include <Shlwapi.h>
#include <strsafe.h>

// ============================================================
//  ObscurizeAgent – Config.c
//  Reads HKLM\SOFTWARE\ObscurizeConfig every second and keeps
//  an atomically-swapped snapshot for the hooks to read.
// ============================================================

static HANDLE  s_configThread  = NULL;
static POBS_CONFIG volatile s_config = NULL;
static CRITICAL_SECTION s_configLock;

// ------------------------------------------------------------
//  Internal helpers
// ------------------------------------------------------------

static POBS_CONFIG ReadConfigFromRegistry(VOID)
{
    POBS_CONFIG cfg = (POBS_CONFIG)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(OBS_CONFIG));
    if (!cfg) return NULL;

    // Safe defaults – disabled, Defensive mode
    cfg->Enabled = FALSE;
    cfg->Mode    = OBS_MODE_DEFENSIVE;
    StringCchCopyW(cfg->SpoofUsername,     64,                          OBS_TRAP_USERNAME_DEFAULT);
    StringCchCopyW(cfg->SpoofComputerName, MAX_COMPUTERNAME_LENGTH + 1, OBS_TRAP_COMPNAME_DEFAULT);
    static const BYTE trapOUI[] = OBS_TRAP_MAC_OUI;
    CopyMemory(cfg->SpoofMacOUI, trapOUI, 3);
    cfg->CustomMacOUI = FALSE;
    cfg->DomainEnabled = FALSE;
    StringCchCopyW(cfg->SpoofDomainName, 256, OBS_SPOOF_DOMAIN_ACTIVE);

    HKEY key = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, OBS_CONFIG_KEY, 0,
                      KEY_QUERY_VALUE | KEY_WOW64_64KEY, &key) != ERROR_SUCCESS)
    {
        return cfg;  // Return defaults if key doesn't exist yet
    }

    // Enabled
    DWORD type, size, value;
    size = sizeof(DWORD);
    if (RegQueryValueExW(key, OBS_CONFIG_VALUE_ENABLED, NULL, &type,
                         (LPBYTE)&value, &size) == ERROR_SUCCESS && type == REG_DWORD)
    {
        cfg->Enabled = (value != 0);
    }

    // Mode
    size = sizeof(DWORD);
    if (RegQueryValueExW(key, OBS_CONFIG_VALUE_MODE, NULL, &type,
                         (LPBYTE)&value, &size) == ERROR_SUCCESS && type == REG_DWORD)
    {
        if (value == OBS_MODE_DEFENSIVE || value == OBS_MODE_TRAP)
            cfg->Mode = value;
    }

    // Trap-mode username override
    size = sizeof(cfg->SpoofUsername) - sizeof(WCHAR);
    RegQueryValueExW(key, OBS_CONFIG_VALUE_USERNAME, NULL, &type,
                     (LPBYTE)cfg->SpoofUsername, &size);

    // Trap-mode computer name override
    size = sizeof(cfg->SpoofComputerName) - sizeof(WCHAR);
    RegQueryValueExW(key, OBS_CONFIG_VALUE_COMPNAME, NULL, &type,
                     (LPBYTE)cfg->SpoofComputerName, &size);

    // Trap-mode MAC OUI override (3 bytes stored as REG_BINARY)
    BYTE ouiBuf[3];
    size = 3;
    if (RegQueryValueExW(key, OBS_CONFIG_VALUE_MACVENDOR, NULL, &type,
                         ouiBuf, &size) == ERROR_SUCCESS && type == REG_BINARY && size == 3)
    {
        CopyMemory(cfg->SpoofMacOUI, ouiBuf, 3);
        cfg->CustomMacOUI = TRUE;
    }

    // DomainEnabled
    size = sizeof(DWORD);
    if (RegQueryValueExW(key, OBS_CONFIG_VALUE_DOMAIN_ENABLED, NULL, &type,
                         (LPBYTE)&value, &size) == ERROR_SUCCESS && type == REG_DWORD)
    {
        cfg->DomainEnabled = (value != 0);
    }

    // Domain name override
    size = sizeof(cfg->SpoofDomainName) - sizeof(WCHAR);
    RegQueryValueExW(key, OBS_CONFIG_VALUE_DOMAIN_NAME, NULL, &type,
                     (LPBYTE)cfg->SpoofDomainName, &size);

    RegCloseKey(key);
    return cfg;
}

static DWORD WINAPI ConfigUpdateThread(LPVOID param)
{
    (VOID)param;

    // First load
    POBS_CONFIG initial = ReadConfigFromRegistry();
    EnterCriticalSection(&s_configLock);
    s_config = initial;
    LeaveCriticalSection(&s_configLock);

    while (TRUE)
    {
        Sleep(1000);

        POBS_CONFIG fresh = ReadConfigFromRegistry();

        EnterCriticalSection(&s_configLock);
        POBS_CONFIG old = (POBS_CONFIG)s_config;
        s_config = fresh;
        LeaveCriticalSection(&s_configLock);

        if (old) HeapFree(GetProcessHeap(), 0, old);
    }

    return 0;
}

// ------------------------------------------------------------
//  Lifecycle
// ------------------------------------------------------------

VOID InitializeObsConfig(VOID)
{
    InitializeCriticalSection(&s_configLock);
    s_configThread = CreateThread(NULL, 0, ConfigUpdateThread, NULL, 0, NULL);
}

VOID UninitializeObsConfig(VOID)
{
    if (s_configThread)
    {
        TerminateThread(s_configThread, 0);
        CloseHandle(s_configThread);
        s_configThread = NULL;
    }

    EnterCriticalSection(&s_configLock);
    POBS_CONFIG cfg = (POBS_CONFIG)s_config;
    s_config = NULL;
    LeaveCriticalSection(&s_configLock);

    if (cfg) HeapFree(GetProcessHeap(), 0, cfg);
    DeleteCriticalSection(&s_configLock);
}

// ------------------------------------------------------------
//  Accessors
// ------------------------------------------------------------

// Grab a stable pointer inside the lock.  Callers must not
// hold the pointer across a Sleep() – they read atomically.
#define LOCK_CFG(p) \
    EnterCriticalSection(&s_configLock); \
    POBS_CONFIG p = (POBS_CONFIG)s_config; \
    if (!p) { LeaveCriticalSection(&s_configLock);

#define UNLOCK_CFG() LeaveCriticalSection(&s_configLock);

BOOL ObsIsEnabled(VOID)
{
    EnterCriticalSection(&s_configLock);
    POBS_CONFIG cfg = (POBS_CONFIG)s_config;
    BOOL result = cfg ? cfg->Enabled : FALSE;
    LeaveCriticalSection(&s_configLock);
    return result;
}

DWORD ObsGetMode(VOID)
{
    EnterCriticalSection(&s_configLock);
    POBS_CONFIG cfg = (POBS_CONFIG)s_config;
    DWORD result = cfg ? cfg->Mode : OBS_MODE_DEFENSIVE;
    LeaveCriticalSection(&s_configLock);
    return result;
}

VOID ObsGetSpoofUsername(PWCHAR buf, DWORD bufCch)
{
    EnterCriticalSection(&s_configLock);
    POBS_CONFIG cfg = (POBS_CONFIG)s_config;
    if (cfg)
    {
        if (cfg->Mode == OBS_MODE_DEFENSIVE)
            StringCchCopyW(buf, bufCch, OBS_DEF_USERNAME);
        else
            StringCchCopyW(buf, bufCch, cfg->SpoofUsername);
    }
    else
    {
        StringCchCopyW(buf, bufCch, OBS_DEF_USERNAME);
    }
    LeaveCriticalSection(&s_configLock);
}

VOID ObsGetSpoofComputerName(PWCHAR buf, DWORD bufCch)
{
    EnterCriticalSection(&s_configLock);
    POBS_CONFIG cfg = (POBS_CONFIG)s_config;
    if (cfg)
    {
        if (cfg->Mode == OBS_MODE_DEFENSIVE)
            StringCchCopyW(buf, bufCch, OBS_DEF_COMPUTERNAME);
        else
            StringCchCopyW(buf, bufCch, cfg->SpoofComputerName);
    }
    else
    {
        StringCchCopyW(buf, bufCch, OBS_DEF_COMPUTERNAME);
    }
    LeaveCriticalSection(&s_configLock);
}

VOID ObsGetSpoofMacOUI(BYTE oui[3])
{
    EnterCriticalSection(&s_configLock);
    POBS_CONFIG cfg = (POBS_CONFIG)s_config;
    if (cfg)
    {
        if (cfg->Mode == OBS_MODE_DEFENSIVE)
        {
            static const BYTE defOUI[] = OBS_DEF_MAC_OUI;
            CopyMemory(oui, defOUI, 3);
        }
        else
        {
            CopyMemory(oui, cfg->SpoofMacOUI, 3);
        }
    }
    else
    {
        static const BYTE defOUI[] = OBS_DEF_MAC_OUI;
        CopyMemory(oui, defOUI, 3);
    }
    LeaveCriticalSection(&s_configLock);
}

ULONGLONG ObsGetSpoofMemoryBytes(VOID)
{
    EnterCriticalSection(&s_configLock);
    POBS_CONFIG cfg = (POBS_CONFIG)s_config;
    DWORD mode = cfg ? cfg->Mode : OBS_MODE_DEFENSIVE;
    LeaveCriticalSection(&s_configLock);

    if (mode == OBS_MODE_DEFENSIVE)
        return OBS_DEF_MEMORY_MB  * 1024ULL * 1024ULL;
    else
        return OBS_TRAP_MEMORY_MB * 1024ULL * 1024ULL;
}

VOID ObsGetSpoofResolution(PDWORD width, PDWORD height)
{
    EnterCriticalSection(&s_configLock);
    POBS_CONFIG cfg = (POBS_CONFIG)s_config;
    DWORD mode = cfg ? cfg->Mode : OBS_MODE_DEFENSIVE;
    LeaveCriticalSection(&s_configLock);

    if (mode == OBS_MODE_DEFENSIVE)
    {
        *width  = OBS_DEF_SCREEN_WIDTH;
        *height = OBS_DEF_SCREEN_HEIGHT;
    }
    else
    {
        *width  = OBS_TRAP_SCREEN_WIDTH;
        *height = OBS_TRAP_SCREEN_HEIGHT;
    }
}

BOOL ObsGetDomainEnabled(VOID)
{
    EnterCriticalSection(&s_configLock);
    POBS_CONFIG cfg = (POBS_CONFIG)s_config;
    BOOL result = cfg ? cfg->DomainEnabled : FALSE;
    LeaveCriticalSection(&s_configLock);
    return result;
}

VOID ObsGetSpoofDomainName(PWCHAR buf, DWORD bufCch)
{
    EnterCriticalSection(&s_configLock);
    POBS_CONFIG cfg = (POBS_CONFIG)s_config;
    if (cfg && cfg->DomainEnabled)
        StringCchCopyW(buf, bufCch, cfg->SpoofDomainName);
    else
        StringCchCopyW(buf, bufCch, OBS_SPOOF_DOMAIN_INACTIVE);
    LeaveCriticalSection(&s_configLock);
}
