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

// Per-process random identities, generated once at DLL load.
//   Defensive values mimic known sandbox environments → malware self-terminates.
//   Trap values mimic real corporate workstations → malware executes fully.
// Each injected process gets unique values so Obscurize itself has no fixed string
// signature that malware authors can hard-code as a detection bypass.
static WCHAR s_randomDefUsername[64];
static WCHAR s_randomDefComputerName[MAX_COMPUTERNAME_LENGTH + 1];
static WCHAR s_randomTrapUsername[64];
static WCHAR s_randomTrapComputerName[MAX_COMPUTERNAME_LENGTH + 1];
static DWORD s_rngState;

static DWORD SimpleRand(VOID)
{
    // Xorshift32 – fast, no CRT dependency
    s_rngState ^= s_rngState << 13;
    s_rngState ^= s_rngState >> 17;
    s_rngState ^= s_rngState << 5;
    return s_rngState;
}

static VOID GenerateRandomIdentities(VOID)
{
    // Seed with PID XOR tick so concurrent injections produce different values
    s_rngState = GetCurrentProcessId() ^ GetTickCount();
    if (s_rngState == 0) s_rngState = 0xAB3CF917;

    // Consonant-heavy uppercase alphanumeric for computer name fields;
    // avoids vowels to prevent accidental word formation.
    static const WCHAR kConsAlnum[] = L"BCDFGHJKLMNPQRSTVWXZ2345679";
    DWORD consAlnumLen = (DWORD)(ARRAYSIZE(kConsAlnum) - 1);

    // ----------------------------------------------------------------
    //  Defensive mode — look like a well-known sandbox system
    // ----------------------------------------------------------------

    // Base names seen in public sandboxes (Any.run, Joe, Cuckoo, etc.)
    static const LPCWSTR kSandboxNames[] = {
        L"admin", L"user", L"sandbox", L"malware", L"test", NULL
    };
    // Mixed-case alphanumeric suffix pool; avoids confusable chars (0 1 l o I)
    static const WCHAR kMixed[] =
        L"abcdefghjkmnpqrstvwxyzABCDEFGHJKMNPQRSTVWXYZ23456789";
    DWORD mixedLen = (DWORD)(ARRAYSIZE(kMixed) - 1);

    DWORD sandboxCount = 0;
    while (kSandboxNames[sandboxCount]) sandboxCount++;
    LPCWSTR sandboxBase = kSandboxNames[SimpleRand() % sandboxCount];

    // Append 6 mixed-case alphanumeric chars: "admin4Kj9Pq", "malwareXz7Wm2"
    // Malware using contains/startsWith still detects the sandbox keyword;
    // the suffix prevents Obscurize from having a fixed, signable output.
    WCHAR sandboxSuffix[7] = { 0 };
    for (int i = 0; i < 6; i++)
        sandboxSuffix[i] = kMixed[SimpleRand() % mixedLen];
    sandboxSuffix[6] = L'\0';
    StringCchPrintfW(s_randomDefUsername, 64, L"%s%s", sandboxBase, sandboxSuffix);

    // DESKTOP-XXXXXXX: the dominant naming pattern in public sandbox systems
    // AND the Windows 10/11 default — both trigger sandbox heuristics in malware.
    WCHAR desktopSuffix[8] = { 0 };
    for (int i = 0; i < 7; i++)
        desktopSuffix[i] = kConsAlnum[SimpleRand() % consAlnumLen];
    desktopSuffix[7] = L'\0';
    StringCchPrintfW(s_randomDefComputerName, MAX_COMPUTERNAME_LENGTH + 1,
                     L"DESKTOP-%s", desktopSuffix);

    // ----------------------------------------------------------------
    //  Trap mode — look like a real corporate workstation
    // ----------------------------------------------------------------

    static const LPCWSTR kFirstNames[] = {
        L"james", L"john", L"robert", L"michael", L"william",
        L"david", L"richard", L"joseph", L"thomas", L"charles",
        L"mary", L"patricia", L"jennifer", L"linda", L"barbara",
        L"sarah", L"jessica", L"karen", L"lisa", L"nancy", NULL
    };
    static const LPCWSTR kLastNames[] = {
        L"smith", L"jones", L"williams", L"brown", L"taylor",
        L"davies", L"evans", L"thomas", L"roberts", L"johnson",
        L"wilson", L"walker", L"wright", L"thompson", L"white", NULL
    };
    // Uppercase alpha only for the 3-letter org prefix
    static const WCHAR kAlpha[] = L"ABCDEFGHJKLMNPQRSTVWXYZ";
    DWORD alphaLen = (DWORD)(ARRAYSIZE(kAlpha) - 1);

    DWORD nameCount = 0, lastCount = 0;
    while (kFirstNames[nameCount]) nameCount++;
    while (kLastNames[lastCount]) lastCount++;

    LPCWSTR first = kFirstNames[SimpleRand() % nameCount];
    LPCWSTR last  = kLastNames[SimpleRand() % lastCount];
    StringCchPrintfW(s_randomTrapUsername, 64, L"%s.%s", first, last);

    // XXX-XXXXXX: 3-letter org prefix + 6 consonant-alnum, e.g. "WKS-4MBF7N"
    // Matches common corporate AD naming conventions; clearly not a sandbox name.
    WCHAR orgPrefix[4] = { 0 };
    for (int i = 0; i < 3; i++)
        orgPrefix[i] = kAlpha[SimpleRand() % alphaLen];
    orgPrefix[3] = L'\0';

    WCHAR corpSuffix[7] = { 0 };
    for (int i = 0; i < 6; i++)
        corpSuffix[i] = kConsAlnum[SimpleRand() % consAlnumLen];
    corpSuffix[6] = L'\0';
    StringCchPrintfW(s_randomTrapComputerName, MAX_COMPUTERNAME_LENGTH + 1,
                     L"%s-%s", orgPrefix, corpSuffix);
}

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
    cfg->HasCustomUsername     = FALSE;
    cfg->HasCustomComputerName = FALSE;
    static const BYTE trapOUI[] = OBS_TRAP_MAC_OUI;
    CopyMemory(cfg->SpoofMacOUI, trapOUI, 3);
    cfg->CustomMacOUI = FALSE;
    cfg->DomainMode = OBS_DOMAIN_MODE_OFF;
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

    // Trap-mode username override (empty registry value → fall back to per-process random)
    size = sizeof(cfg->SpoofUsername) - sizeof(WCHAR);
    if (RegQueryValueExW(key, OBS_CONFIG_VALUE_USERNAME, NULL, &type,
                         (LPBYTE)cfg->SpoofUsername, &size) == ERROR_SUCCESS
        && type == REG_SZ && size > sizeof(WCHAR))
    {
        cfg->HasCustomUsername = TRUE;
    }

    // Trap-mode computer name override (empty registry value → fall back to per-process random)
    size = sizeof(cfg->SpoofComputerName) - sizeof(WCHAR);
    if (RegQueryValueExW(key, OBS_CONFIG_VALUE_COMPNAME, NULL, &type,
                         (LPBYTE)cfg->SpoofComputerName, &size) == ERROR_SUCCESS
        && type == REG_SZ && size > sizeof(WCHAR))
    {
        cfg->HasCustomComputerName = TRUE;
    }

    // Trap-mode MAC OUI override (3 bytes stored as REG_BINARY)
    BYTE ouiBuf[3];
    size = 3;
    if (RegQueryValueExW(key, OBS_CONFIG_VALUE_MACVENDOR, NULL, &type,
                         ouiBuf, &size) == ERROR_SUCCESS && type == REG_BINARY && size == 3)
    {
        CopyMemory(cfg->SpoofMacOUI, ouiBuf, 3);
        cfg->CustomMacOUI = TRUE;
    }

    // DomainMode
    size = sizeof(DWORD);
    if (RegQueryValueExW(key, OBS_CONFIG_VALUE_DOMAIN_MODE, NULL, &type,
                         (LPBYTE)&value, &size) == ERROR_SUCCESS && type == REG_DWORD)
    {
        cfg->DomainMode = (value <= OBS_DOMAIN_MODE_JOINED) ? value : OBS_DOMAIN_MODE_OFF;
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

    // First load happens synchronously in InitializeObsConfig (below), BEFORE
    // InitializeHooks arms the hooks, so this thread only handles refresh.
    //
    // Do not move the first read here or make it lazy: once the hooks are live,
    // ReadConfigFromRegistry's Reg* calls re-enter our own NtQueryValueKey /
    // NtEnumerateKey hooks while this thread holds s_configLock, and any other
    // thread calling ObsIsEnabled() blocks behind it.  In a multi-threaded WMI
    // client like systeminfo.exe that stalls data collection indefinitely.
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
    GenerateRandomIdentities();
    InitializeCriticalSection(&s_configLock);

    // Synchronous first load, BEFORE InitializeHooks arms the hooks.  Reading
    // here means the Reg* calls run through the ORIGINAL APIs (no hooks yet)
    // and on a single thread with no lock contention — which is why this is
    // safe in WMI clients, whereas a lazy post-hook load is not.
    POBS_CONFIG initial = ReadConfigFromRegistry();
    EnterCriticalSection(&s_configLock);
    s_config = initial;
    LeaveCriticalSection(&s_configLock);

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
            StringCchCopyW(buf, bufCch, s_randomDefUsername);
        else if (cfg->HasCustomUsername)
            StringCchCopyW(buf, bufCch, cfg->SpoofUsername);
        else
            StringCchCopyW(buf, bufCch, s_randomTrapUsername);
    }
    else
    {
        // s_config not yet ready (pre-init window); use defensive random as safe default
        StringCchCopyW(buf, bufCch, s_randomDefUsername);
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
            StringCchCopyW(buf, bufCch, s_randomDefComputerName);
        else if (cfg->HasCustomComputerName)
            StringCchCopyW(buf, bufCch, cfg->SpoofComputerName);
        else
            StringCchCopyW(buf, bufCch, s_randomTrapComputerName);
    }
    else
    {
        // s_config not yet ready (pre-init window); use defensive random as safe default
        StringCchCopyW(buf, bufCch, s_randomDefComputerName);
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

DWORD ObsGetDomainMode(VOID)
{
    EnterCriticalSection(&s_configLock);
    POBS_CONFIG cfg = (POBS_CONFIG)s_config;
    DWORD result = cfg ? cfg->DomainMode : OBS_DOMAIN_MODE_OFF;
    LeaveCriticalSection(&s_configLock);
    return result;
}

VOID ObsGetSpoofDomainName(PWCHAR buf, DWORD bufCch)
{
    EnterCriticalSection(&s_configLock);
    POBS_CONFIG cfg = (POBS_CONFIG)s_config;
    if (cfg && cfg->DomainMode == OBS_DOMAIN_MODE_JOINED)
        StringCchCopyW(buf, bufCch, cfg->SpoofDomainName);
    else
        StringCchCopyW(buf, bufCch, OBS_SPOOF_DOMAIN_INACTIVE);
    LeaveCriticalSection(&s_configLock);
}
