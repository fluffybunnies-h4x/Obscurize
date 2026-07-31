// winsock2.h MUST come before Windows.h / Hooks.h.
// <iptypes.h> (pulled by iphlpapi.h) needs ws2def.h structs for
// IP_ADAPTER_ADDRESSES.  Including winsock2.h first sets _WINSOCK2API_
// so that Windows.h skips the incompatible winsock.h (v1).
#include <winsock2.h>
#include <ws2tcpip.h>

#include "Hooks.h"
#include "Config.h"
#include "Spoof.h"
#include "SmbiosSpoof.h"
#include "../ObscurizeShared/ObscurizeDef.h"

// r77api headers – include by relative path to the submodule
#include "../r77-rootkit/r77-rootkit-master/r77api/ntdll.h"
#include "../r77-rootkit/r77-rootkit-master/r77api/r77mindef.h"

#include "detours.h"

#include <Windows.h>
#include <winternl.h>
// winreg.h defines PKEY_VALUE_PARTIAL_INFORMATION / PKEY_VALUE_FULL_INFORMATION.
// Include explicitly in case winternl.h's partial type definitions block the
// automatic inclusion that Windows.h would otherwise perform.
#include <winreg.h>
#include <iphlpapi.h>
#include <Shlwapi.h>
#include <strsafe.h>
#include <wchar.h>
#include <string.h>

// NTSTATUS constants not provided by Windows.h without <ntstatus.h>.
// Define only what HookedNtQueryValueKey needs; guards prevent redefinition.
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS          ((NTSTATUS)0x00000000L)
#endif
#ifndef STATUS_BUFFER_TOO_SMALL
#define STATUS_BUFFER_TOO_SMALL ((NTSTATUS)0xC0000023L)
#endif

// KEY_VALUE_PARTIAL_INFORMATION is defined in winnt.h but may be suppressed
// by the winternl.h include guard interaction.  Define it locally to guarantee
// availability.  r77's ntdll.h already provides NT_KEY_VALUE_FULL_INFORMATION /
// PNT_KEY_VALUE_FULL_INFORMATION so we reuse those for the full-info path.
typedef struct _OBS_KEY_VALUE_PARTIAL_INFORMATION {
    ULONG TitleIndex;
    ULONG Type;
    ULONG DataLength;
    UCHAR Data[1];
} OBS_KEY_VALUE_PARTIAL_INFORMATION, *POBS_KEY_VALUE_PARTIAL_INFORMATION;

// ============================================================
//  ObscurizeAgent – Hooks.c
//
//  Hooks installed in every process (via reflective DLL
//  injection from ObscurizeService) to intercept the system
//  queries that malware uses for VM / sandbox detection.
//
//  Defensive mode  →  make the host look like a VM
//  Trap mode       →  make a VM look like real hardware
//
//  DEADVAX checks covered:
//    ✓ Username == "admin"           → HookedGetUserNameW/A
//    ✓ RAM < 3 GB via WMI            → HookedGlobalMemoryStatusEx
//    ✓ VMware in Win32_ComputerSystem→ HookedNtQueryValueKey (BIOS key)
//    ✓ Artifact files in %TEMP%      → HookedNtQueryDirectoryFile
//
//  Additional common checks covered:
//    ✓ Computer / hostname           → HookedGetComputerNameExW/A
//    ✓ MAC address OUI               → HookedGetAdaptersAddresses /
//                                      HookedGetAdaptersInfo
//    ✓ Screen resolution             → HookedEnumDisplaySettingsW
//    ✓ VM processes in process list  → HookedNtQuerySystemInformation
//    ✓ VM services                   → HookedEnumServicesStatusExW/A
//    ✓ VM registry vendor keys       → HookedNtEnumerateKey /
//                                      HookedNtQueryKey
// ============================================================

// ============================================================
//  NT native function typedefs not in r77's ntdll.h
//  NT_KEY_VALUE_INFORMATION_CLASS is r77's own enum (same values
//  as the SDK KEY_VALUE_INFORMATION_CLASS) and is always defined
//  via ntdll.h above – no winreg.h dependency in the typedef.
// ============================================================

typedef NTSTATUS (NTAPI *NT_NTQUERYVALUEKEY)(
    HANDLE                         KeyHandle,
    PUNICODE_STRING                ValueName,
    NT_KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
    PVOID                          KeyValueInformation,
    ULONG                          Length,
    PULONG                         ResultLength);

// ============================================================
//  Original function pointers
// ============================================================

// advapi32 / kernel32
static BOOL  (WINAPI *OriginalGetUserNameW)     (LPWSTR, LPDWORD)             = NULL;
static BOOL  (WINAPI *OriginalGetUserNameA)     (LPSTR,  LPDWORD)             = NULL;
static BOOL  (WINAPI *OriginalGetComputerNameExW)(COMPUTER_NAME_FORMAT, LPWSTR,  LPDWORD) = NULL;
static BOOL  (WINAPI *OriginalGetComputerNameExA)(COMPUTER_NAME_FORMAT, LPSTR,   LPDWORD) = NULL;

// kernel32
static VOID  (WINAPI *OriginalGlobalMemoryStatusEx)(LPMEMORYSTATUSEX)          = NULL;

// user32
static BOOL  (WINAPI *OriginalEnumDisplaySettingsW)(LPCWSTR, DWORD, LPDEVMODEW) = NULL;
static int   (WINAPI *OriginalGetSystemMetrics)(int)                            = NULL;

// iphlpapi
static ULONG (WINAPI *OriginalGetAdaptersAddresses)(ULONG, ULONG, PVOID,
                                                    PIP_ADAPTER_ADDRESSES,
                                                    PULONG)                    = NULL;
static DWORD (WINAPI *OriginalGetAdaptersInfo)     (PIP_ADAPTER_INFO, PULONG)  = NULL;

// advapi32 – service enumeration
static BOOL  (WINAPI *OriginalEnumServicesStatusExW)(SC_HANDLE, SC_ENUM_TYPE,
                                                     DWORD, DWORD, LPBYTE,
                                                     DWORD, LPDWORD, LPDWORD,
                                                     LPDWORD, LPCWSTR)         = NULL;
static BOOL  (WINAPI *OriginalEnumServicesStatusExA)(SC_HANDLE, SC_ENUM_TYPE,
                                                     DWORD, DWORD, LPBYTE,
                                                     DWORD, LPDWORD, LPDWORD,
                                                     LPDWORD, LPCSTR)          = NULL;

// DIAGNOSTIC ONLY – testing whether some callers (e.g. .NET's
// ServiceController.GetServices(), used by PowerShell's Get-Service)
// reach the plain (non-Ex) EnumServicesStatus instead of the Ex variant
// above.  ENUM_SERVICE_STATUSW has no ProcessId field, unlike
// ENUM_SERVICE_STATUS_PROCESSW, so filtering here is structurally simpler.
static BOOL  (WINAPI *OriginalEnumServicesStatusW)(SC_HANDLE, DWORD, DWORD,
                                                    LPBYTE, DWORD, LPDWORD,
                                                    LPDWORD, LPDWORD)         = NULL;
static BOOL  (WINAPI *OriginalEnumServicesStatusA)(SC_HANDLE, DWORD, DWORD,
                                                    LPBYTE, DWORD, LPDWORD,
                                                    LPDWORD, LPDWORD)         = NULL;

// ntdll
static NT_NTQUERYSYSTEMINFORMATION  OriginalNtQuerySystemInformation  = NULL;
static NT_NTENUMERATEKEY            OriginalNtEnumerateKey            = NULL;
static NT_NTQUERYKEY                OriginalNtQueryKey                = NULL;
static NT_NTQUERYVALUEKEY           OriginalNtQueryValueKey           = NULL;

// kernel32 – SMBIOS firmware table
static UINT (WINAPI *OriginalGetSystemFirmwareTable)(DWORD, DWORD, PVOID, DWORD) = NULL;

// kernel32 – process creation
static BOOL (WINAPI *OriginalCreateProcessW)(LPCWSTR, LPWSTR,
    LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD,
    LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION)          = NULL;
static BOOL (WINAPI *OriginalCreateProcessA)(LPCSTR, LPSTR,
    LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD,
    LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION)           = NULL;

// kernelbase – stdout patching for systeminfo.exe and wmic.exe
// Resolved from kernelbase.dll (actual implementation) not kernel32 forwarding stubs,
// and WriteConsoleW added to handle ConPTY / Windows Terminal paths.
static BOOL (WINAPI *OriginalWriteFile)(
    HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED)                   = NULL;
static BOOL (WINAPI *OriginalWriteConsoleA)(
    HANDLE, const VOID *, DWORD, LPDWORD, LPVOID)                    = NULL;
static BOOL (WINAPI *OriginalWriteConsoleW)(
    HANDLE, const VOID *, DWORD, LPDWORD, LPVOID)                    = NULL;

// Set once at InitializeHooks time – TRUE only when injected into systeminfo.exe / wmic.exe
static BOOL   g_IsSystemInfo  = FALSE;
static BOOL   g_IsWmic        = FALSE;
static BOOL   g_IsWhoami      = FALSE;
static HANDLE g_StdoutHandle  = INVALID_HANDLE_VALUE;

// Stateful serial-number replacement for wmic.exe output.
// 0 = scanning for SerialNumber header line
// 1 = next non-empty/non-whitespace line is the value to replace
static volatile int g_WmicSerialState = 0;

// TLS slots for NtEnumerateKey O(N) cache (same pattern as r77)
static DWORD TlsEnumKeyCacheKey;
static DWORD TlsEnumKeyCacheIndex;
static DWORD TlsEnumKeyCacheI;
static DWORD TlsEnumKeyCacheCorrectedIndex;

// ============================================================
//  Utility helpers
// ============================================================

// Return TRUE if the UNICODE_STRING matches the wide string literal.
static BOOL UniStrEqI(PUNICODE_STRING us, LPCWSTR literal)
{
    if (!us || !us->Buffer || !literal) return FALSE;
    SIZE_T litLen = wcslen(literal);
    if (us->Length / sizeof(WCHAR) != litLen) return FALSE;
    return _wcsnicmp(us->Buffer, literal, litLen) == 0;
}

// Build a null-terminated copy of a UNICODE_STRING into a local buffer.
static VOID UnicodeStringToBuffer(PUNICODE_STRING us, PWCHAR buf, SIZE_T bufCch)
{
    SIZE_T copyChars = us->Length / sizeof(WCHAR);
    if (copyChars >= bufCch) copyChars = bufCch - 1;
    CopyMemory(buf, us->Buffer, copyChars * sizeof(WCHAR));
    buf[copyChars] = L'\0';
}

// Resolve the full NT path of an open registry key handle.
// Equivalent to r77api/r77win.c GetRegistryKeyName(), implemented inline
// so we do not need to compile the entire r77win.c translation unit.
// Must be called after OriginalNtQueryKey is resolved in InitializeHooks().
static BOOL GetRegistryKeyNameLocal(HANDLE key, PWCHAR name, DWORD nameCch)
{
    if (!OriginalNtQueryKey || !name || nameCch == 0) return FALSE;

    BYTE   buf[1024];
    ULONG  resultLen = 0;
    NTSTATUS st = OriginalNtQueryKey(key, KeyNameInformation,
                                     buf, sizeof(buf), &resultLen);
    if (!NT_SUCCESS(st)) return FALSE;

    PNT_KEY_NAME_INFORMATION info = (PNT_KEY_NAME_INFORMATION)buf;
    ULONG copyChars = info->NameLength / sizeof(WCHAR);
    if (copyChars >= nameCch) copyChars = nameCch - 1;
    CopyMemory(name, info->Name, copyChars * sizeof(WCHAR));
    name[copyChars] = L'\0';
    return TRUE;
}

// ============================================================
//  Hook implementations
// ============================================================

// ------------------------------------------------------------
//  GetUserNameW / GetUserNameA
//  DEADVAX: exits if username == "admin"
//  Defensive: return "admin"   Trap: return config username
// ------------------------------------------------------------
static BOOL WINAPI HookedGetUserNameW(LPWSTR lpBuffer, LPDWORD pcbBuffer)
{
    if (!ObsIsEnabled()) return OriginalGetUserNameW(lpBuffer, pcbBuffer);

    WCHAR spoofed[64];
    ObsGetSpoofUsername(spoofed, 64);

    DWORD needed = (DWORD)(wcslen(spoofed) + 1);
    if (*pcbBuffer < needed)
    {
        *pcbBuffer = needed;
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }
    StringCchCopyW(lpBuffer, *pcbBuffer, spoofed);
    *pcbBuffer = needed;
    return TRUE;
}

static BOOL WINAPI HookedGetUserNameA(LPSTR lpBuffer, LPDWORD pcbBuffer)
{
    if (!ObsIsEnabled()) return OriginalGetUserNameA(lpBuffer, pcbBuffer);

    WCHAR spoofedW[64];
    ObsGetSpoofUsername(spoofedW, 64);

    // Convert to ANSI
    int needed = WideCharToMultiByte(CP_ACP, 0, spoofedW, -1, NULL, 0, NULL, NULL);
    if ((int)*pcbBuffer < needed)
    {
        *pcbBuffer = (DWORD)needed;
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }
    WideCharToMultiByte(CP_ACP, 0, spoofedW, -1, lpBuffer, *pcbBuffer, NULL, NULL);
    *pcbBuffer = (DWORD)needed;
    return TRUE;
}

// ------------------------------------------------------------
//  GetComputerNameExW / GetComputerNameExA
//  Return a mode-appropriate computer name.
// ------------------------------------------------------------
static BOOL WINAPI HookedGetComputerNameExW(COMPUTER_NAME_FORMAT fmt, LPWSTR buf, LPDWORD size)
{
    if (!ObsIsEnabled()) return OriginalGetComputerNameExW(fmt, buf, size);

    // Only spoof the simple NetBIOS and DNS hostname; leave domain queries alone
    if (fmt != ComputerNameNetBIOS && fmt != ComputerNameDnsHostname)
        return OriginalGetComputerNameExW(fmt, buf, size);

    WCHAR spoofed[MAX_COMPUTERNAME_LENGTH + 1];
    ObsGetSpoofComputerName(spoofed, MAX_COMPUTERNAME_LENGTH + 1);

    DWORD needed = (DWORD)(wcslen(spoofed) + 1);
    if (!buf || *size < needed)
    {
        *size = needed;
        SetLastError(ERROR_MORE_DATA);
        return FALSE;
    }
    StringCchCopyW(buf, *size, spoofed);
    *size = needed - 1;  // GetComputerNameEx returns char count without null
    return TRUE;
}

static BOOL WINAPI HookedGetComputerNameExA(COMPUTER_NAME_FORMAT fmt, LPSTR buf, LPDWORD size)
{
    if (!ObsIsEnabled()) return OriginalGetComputerNameExA(fmt, buf, size);

    if (fmt != ComputerNameNetBIOS && fmt != ComputerNameDnsHostname)
        return OriginalGetComputerNameExA(fmt, buf, size);

    WCHAR spoofedW[MAX_COMPUTERNAME_LENGTH + 1];
    ObsGetSpoofComputerName(spoofedW, MAX_COMPUTERNAME_LENGTH + 1);

    int needed = WideCharToMultiByte(CP_ACP, 0, spoofedW, -1, NULL, 0, NULL, NULL);
    if (!buf || (int)*size < needed)
    {
        *size = (DWORD)needed;
        SetLastError(ERROR_MORE_DATA);
        return FALSE;
    }
    WideCharToMultiByte(CP_ACP, 0, spoofedW, -1, buf, *size, NULL, NULL);
    *size = (DWORD)(needed - 1);
    return TRUE;
}

// ------------------------------------------------------------
//  GetUserNameExW  (secur32.dll)
//  Returns DOMAIN\user in the NameSamCompatible format.  NOTE: plain `whoami`
//  does NOT use this — it resolves the token SID via LookupAccountSidW (see
//  below).  GetUserNameExW is imported by whoami only for /upn and /fqdn.  We
//  still spoof the NameSamCompatible format here for any OTHER tool that reaches
//  for it, and pass every other EXTENDED_NAME_FORMAT (NameUserPrincipal,
//  NameFullyQualifiedDN, …) through untouched so auth / SSO paths keep working.
// ------------------------------------------------------------

// Defined inline to avoid a <security.h> dependency (mirrors the OBS_NetSetup*
// constants defined near the NetGetJoinInformation hook).  SEC_ENTRY is __stdcall
// on x86 and a no-op under the x64 calling convention.
#ifndef SEC_ENTRY
#define SEC_ENTRY __stdcall
#endif
#define OBS_NameSamCompatible  2   // EXTENDED_NAME_FORMAT value used by whoami

typedef BOOLEAN (SEC_ENTRY *PFN_GetUserNameExW)(int, LPWSTR, PULONG);
static PFN_GetUserNameExW OriginalGetUserNameExW = NULL;

static BOOLEAN SEC_ENTRY HookedGetUserNameExW(int NameFormat, LPWSTR lpNameBuffer, PULONG nSize)
{
    if (!ObsIsEnabled() || NameFormat != OBS_NameSamCompatible)
        return OriginalGetUserNameExW(NameFormat, lpNameBuffer, nSize);

    // Build PREFIX\username.  PREFIX is the spoofed computer name (workgroup),
    // or the NetBIOS form of the spoofed domain when domain-joined, so whoami
    // lines up with systeminfo's Host Name / Domain fields.
    WCHAR username[64];
    ObsGetSpoofUsername(username, ARRAYSIZE(username));

    WCHAR prefix[256];
    if (ObsGetDomainMode() == OBS_DOMAIN_MODE_JOINED)
    {
        ObsGetSpoofDomainName(prefix, ARRAYSIZE(prefix));
        WCHAR *dot = wcschr(prefix, L'.');   // NetBIOS form: strip at first '.'
        if (dot) *dot = L'\0';
        CharUpperW(prefix);
    }
    else
    {
        ObsGetSpoofComputerName(prefix, ARRAYSIZE(prefix));
    }

    WCHAR spoofed[320];
    StringCchPrintfW(spoofed, ARRAYSIZE(spoofed), L"%s\\%s", prefix, username);

    ULONG needed = (ULONG)(wcslen(spoofed) + 1);
    if (!lpNameBuffer || !nSize || *nSize < needed)
    {
        if (nSize) *nSize = needed;              // required size, including null
        SetLastError(ERROR_MORE_DATA);
        return FALSE;
    }
    StringCchCopyW(lpNameBuffer, *nSize, spoofed);
    *nSize = needed - 1;                          // success: count excludes null
    return TRUE;
}

// ------------------------------------------------------------
//  LookupAccountSidW  (advapi32.dll)
//  This is what plain `whoami` and `whoami /all` actually use: read the token's
//  user SID (GetTokenInformation/TokenUser) and resolve it to Name + Domain.
//  We spoof ONLY the current process user's own SID — every other SID (groups,
//  other users, well-known SIDs) passes straight through, so ACL/security
//  displays in other injected processes are unaffected.  The token still holds
//  the real SID; we only rewrite the name it resolves to.
// ------------------------------------------------------------

typedef BOOL (WINAPI *PFN_LookupAccountSidW)(LPCWSTR, PSID, LPWSTR, LPDWORD, LPWSTR, LPDWORD, PSID_NAME_USE);
static PFN_LookupAccountSidW OriginalLookupAccountSidW = NULL;

// Cache the current process user's SID once (it does not change per process).
static BOOL g_UserSidValid = FALSE;
static BYTE g_UserSid[SECURITY_MAX_SID_SIZE];

static BOOL IsCurrentUserSid(PSID sid)
{
    if (!g_UserSidValid)
    {
        HANDLE tok = NULL;
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok) && tok)
        {
            BYTE  buf[SECURITY_MAX_SID_SIZE + sizeof(TOKEN_USER)];
            DWORD len = 0;
            if (GetTokenInformation(tok, TokenUser, buf, sizeof(buf), &len))
            {
                PSID  u  = ((PTOKEN_USER)buf)->User.Sid;
                DWORD sl = GetLengthSid(u);
                if (sl <= sizeof(g_UserSid))
                {
                    CopyMemory(g_UserSid, u, sl);
                    g_UserSidValid = TRUE;
                }
            }
            CloseHandle(tok);
        }
    }
    return g_UserSidValid && sid && IsValidSid(sid) && EqualSid(sid, (PSID)g_UserSid);
}

static BOOL WINAPI HookedLookupAccountSidW(
    LPCWSTR lpSystemName, PSID Sid,
    LPWSTR Name, LPDWORD cchName,
    LPWSTR ReferencedDomainName, LPDWORD cchReferencedDomainName,
    PSID_NAME_USE peUse)
{
    if (!ObsIsEnabled() || !IsCurrentUserSid(Sid))
        return OriginalLookupAccountSidW(lpSystemName, Sid, Name, cchName,
                                         ReferencedDomainName, cchReferencedDomainName, peUse);

    WCHAR spoofName[64];
    ObsGetSpoofUsername(spoofName, ARRAYSIZE(spoofName));

    WCHAR spoofDom[256];
    if (ObsGetDomainMode() == OBS_DOMAIN_MODE_JOINED)
    {
        ObsGetSpoofDomainName(spoofDom, ARRAYSIZE(spoofDom));
        WCHAR *dot = wcschr(spoofDom, L'.');   // NetBIOS form: strip at first '.'
        if (dot) *dot = L'\0';
        CharUpperW(spoofDom);
    }
    else
    {
        ObsGetSpoofComputerName(spoofDom, ARRAYSIZE(spoofDom));
    }

    DWORD needName = (DWORD)(wcslen(spoofName) + 1);
    DWORD needDom  = (DWORD)(wcslen(spoofDom)  + 1);
    DWORD haveName = cchName ? *cchName : 0;
    DWORD haveDom  = cchReferencedDomainName ? *cchReferencedDomainName : 0;

    if (!Name || !ReferencedDomainName || haveName < needName || haveDom < needDom)
    {
        if (cchName)                 *cchName                 = needName;   // incl. null
        if (cchReferencedDomainName) *cchReferencedDomainName = needDom;
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }

    StringCchCopyW(Name, haveName, spoofName);
    StringCchCopyW(ReferencedDomainName, haveDom, spoofDom);
    *cchName                 = needName - 1;   // success: counts exclude null
    *cchReferencedDomainName = needDom - 1;
    if (peUse) *peUse = SidTypeUser;
    return TRUE;
}

// ------------------------------------------------------------
//  GlobalMemoryStatusEx
//  DEADVAX: exits if TotalPhysicalMemory < 3 GB
//  Defensive: report 2 GB    Trap: report 16 GB
// ------------------------------------------------------------
static VOID WINAPI HookedGlobalMemoryStatusEx(LPMEMORYSTATUSEX lpBuffer)
{
    OriginalGlobalMemoryStatusEx(lpBuffer);
    if (!ObsIsEnabled()) return;

    ULONGLONG spoofBytes = ObsGetSpoofMemoryBytes();
    lpBuffer->ullTotalPhys  = spoofBytes;
    // Keep available memory plausible (≈ half of total)
    if (lpBuffer->ullAvailPhys > spoofBytes)
        lpBuffer->ullAvailPhys = spoofBytes / 2;
}

// ------------------------------------------------------------
//  EnumDisplaySettingsW
//  Sandboxes often run at 800×600; real desktops at 1920×1080.
//  Defensive: 800×600    Trap: 1920×1080
// ------------------------------------------------------------
static BOOL WINAPI HookedEnumDisplaySettingsW(LPCWSTR lpszDeviceName,
                                               DWORD   iModeNum,
                                               LPDEVMODEW lpDevMode)
{
    if (!ObsIsEnabled())
        return OriginalEnumDisplaySettingsW(lpszDeviceName, iModeNum, lpDevMode);

    // Pass through enumeration of specific mode indices unchanged.
    if (iModeNum != ENUM_CURRENT_SETTINGS && iModeNum != ENUM_REGISTRY_SETTINGS)
        return OriginalEnumDisplaySettingsW(lpszDeviceName, iModeNum, lpDevMode);

    // For current/registry settings queries, call the original to populate other
    // DEVMODE fields (dmBitsPerPel, dmDisplayFrequency, etc.) but always return
    // the spoofed resolution regardless of whether the original succeeds.
    // VMware virtual displays can return FALSE for ENUM_CURRENT_SETTINGS even
    // when a display is present, which would otherwise prevent spoofing.
    OriginalEnumDisplaySettingsW(lpszDeviceName, iModeNum, lpDevMode);

    if (!lpDevMode) return FALSE;

    DWORD w, h;
    ObsGetSpoofResolution(&w, &h);
    lpDevMode->dmPelsWidth  = w;
    lpDevMode->dmPelsHeight = h;
    return TRUE;
}

// ------------------------------------------------------------
//  GetSystemMetrics
//  SM_CXSCREEN (0) / SM_CYSCREEN (1) return display dimensions.
//  Complements EnumDisplaySettingsW for callers that use this path.
//  Defensive: 800×600    Trap: 1920×1080
// ------------------------------------------------------------
static int WINAPI HookedGetSystemMetrics(int nIndex)
{
    if (!ObsIsEnabled()) return OriginalGetSystemMetrics(nIndex);
    if (nIndex == SM_CXSCREEN || nIndex == SM_CYSCREEN)
    {
        DWORD w, h;
        ObsGetSpoofResolution(&w, &h);
        return (nIndex == SM_CXSCREEN) ? (int)w : (int)h;
    }
    return OriginalGetSystemMetrics(nIndex);
}

// ------------------------------------------------------------
//  GetAdaptersAddresses / GetAdaptersInfo
//  Replace the first 3 bytes (OUI) of every adapter's MAC.
//  Defensive: VMware OUI 00:0C:29    Trap: Intel OUI 00:1B:21
// ------------------------------------------------------------
static ULONG WINAPI HookedGetAdaptersAddresses(ULONG Family, ULONG Flags,
                                                PVOID Reserved,
                                                PIP_ADAPTER_ADDRESSES AdapterAddresses,
                                                PULONG SizePointer)
{
    ULONG result = OriginalGetAdaptersAddresses(Family, Flags, Reserved,
                                                AdapterAddresses, SizePointer);
    if (result != NO_ERROR || !ObsIsEnabled()) return result;

    BYTE oui[3];
    ObsGetSpoofMacOUI(oui);

    PIP_ADAPTER_ADDRESSES adapter = AdapterAddresses;
    while (adapter)
    {
        if (adapter->PhysicalAddressLength >= 3)
            CopyMemory(adapter->PhysicalAddress, oui, 3);
        adapter = adapter->Next;
    }
    return result;
}

static DWORD WINAPI HookedGetAdaptersInfo(PIP_ADAPTER_INFO pAdapterInfo, PULONG pOutBufLen)
{
    DWORD result = OriginalGetAdaptersInfo(pAdapterInfo, pOutBufLen);
    if (result != ERROR_SUCCESS || !ObsIsEnabled()) return result;

    BYTE oui[3];
    ObsGetSpoofMacOUI(oui);

    PIP_ADAPTER_INFO adapter = pAdapterInfo;
    while (adapter)
    {
        if (adapter->AddressLength >= 3)
            CopyMemory(adapter->Address, oui, 3);
        adapter = adapter->Next;
    }
    return result;
}

// ------------------------------------------------------------
//  EnumServicesStatusExW / EnumServicesStatusExA
//  Trap mode: remove VM services from the returned list.
//  (Defensive mode: VM services are created as real services
//   by the Service component, so no injection needed here.)
// ------------------------------------------------------------
static BOOL WINAPI HookedEnumServicesStatusExW(SC_HANDLE hSCManager,
                                                SC_ENUM_TYPE InfoLevel,
                                                DWORD dwServiceType,
                                                DWORD dwServiceState,
                                                LPBYTE lpServices,
                                                DWORD cbBufSize,
                                                LPDWORD pcbBytesNeeded,
                                                LPDWORD lpServicesReturned,
                                                LPDWORD lpResumeHandle,
                                                LPCWSTR pszGroupName)
{
    BOOL result = OriginalEnumServicesStatusExW(hSCManager, InfoLevel, dwServiceType,
                                                dwServiceState, lpServices, cbBufSize,
                                                pcbBytesNeeded, lpServicesReturned,
                                                lpResumeHandle, pszGroupName);

    if (!result || !ObsIsEnabled() || ObsGetMode() != OBS_MODE_TRAP)
        return result;

    if (InfoLevel != SC_ENUM_PROCESS_INFO || !lpServices || !lpServicesReturned)
        return result;

    LPENUM_SERVICE_STATUS_PROCESSW entries = (LPENUM_SERVICE_STATUS_PROCESSW)lpServices;
    DWORD count = *lpServicesReturned;
    DWORD writeIdx = 0;

    for (DWORD i = 0; i < count; i++)
    {
        if (!IsVmServiceName(entries[i].lpServiceName))
        {
            if (writeIdx != i)
                CopyMemory(&entries[writeIdx], &entries[i],
                           sizeof(ENUM_SERVICE_STATUS_PROCESSW));
            writeIdx++;
        }
    }
    *lpServicesReturned = writeIdx;
    return result;
}

static BOOL WINAPI HookedEnumServicesStatusExA(SC_HANDLE hSCManager,
                                                SC_ENUM_TYPE InfoLevel,
                                                DWORD dwServiceType,
                                                DWORD dwServiceState,
                                                LPBYTE lpServices,
                                                DWORD cbBufSize,
                                                LPDWORD pcbBytesNeeded,
                                                LPDWORD lpServicesReturned,
                                                LPDWORD lpResumeHandle,
                                                LPCSTR pszGroupName)
{
    BOOL result = OriginalEnumServicesStatusExA(hSCManager, InfoLevel, dwServiceType,
                                                dwServiceState, lpServices, cbBufSize,
                                                pcbBytesNeeded, lpServicesReturned,
                                                lpResumeHandle, pszGroupName);

    if (!result || !ObsIsEnabled() || ObsGetMode() != OBS_MODE_TRAP)
        return result;

    if (InfoLevel != SC_ENUM_PROCESS_INFO || !lpServices || !lpServicesReturned)
        return result;

    LPENUM_SERVICE_STATUS_PROCESSA entries = (LPENUM_SERVICE_STATUS_PROCESSA)lpServices;
    DWORD count = *lpServicesReturned;
    DWORD writeIdx = 0;

    for (DWORD i = 0; i < count; i++)
    {
        // Convert service name to wide for lookup
        WCHAR wname[256] = { 0 };
        MultiByteToWideChar(CP_ACP, 0, entries[i].lpServiceName, -1, wname, 256);

        if (!IsVmServiceName(wname))
        {
            if (writeIdx != i)
                CopyMemory(&entries[writeIdx], &entries[i],
                           sizeof(ENUM_SERVICE_STATUS_PROCESSA));
            writeIdx++;
        }
    }
    *lpServicesReturned = writeIdx;
    return result;
}

// ------------------------------------------------------------
//  EnumServicesStatusW / EnumServicesStatusA  (plain, non-Ex)
//  .NET's ServiceController.GetServices() – and therefore
//  PowerShell's Get-Service – calls this older API rather than
//  the Ex variant above, so both must be hooked for Trap mode
//  service hiding to cover both native (Ex) and managed (non-Ex)
//  callers. ENUM_SERVICE_STATUSW/A has no InfoLevel parameter and
//  no ProcessId field – it's always the "process info" shape.
// ------------------------------------------------------------
static BOOL WINAPI HookedEnumServicesStatusW(SC_HANDLE hSCManager,
                                              DWORD dwServiceType,
                                              DWORD dwServiceState,
                                              LPBYTE lpServices,
                                              DWORD cbBufSize,
                                              LPDWORD pcbBytesNeeded,
                                              LPDWORD lpServicesReturned,
                                              LPDWORD lpResumeHandle)
{
    BOOL result = OriginalEnumServicesStatusW(hSCManager, dwServiceType,
                                              dwServiceState, lpServices, cbBufSize,
                                              pcbBytesNeeded, lpServicesReturned,
                                              lpResumeHandle);

    if (!result || !ObsIsEnabled() || ObsGetMode() != OBS_MODE_TRAP)
        return result;

    if (!lpServices || !lpServicesReturned)
        return result;

    LPENUM_SERVICE_STATUSW entries = (LPENUM_SERVICE_STATUSW)lpServices;
    DWORD count = *lpServicesReturned;
    DWORD writeIdx = 0;

    for (DWORD i = 0; i < count; i++)
    {
        if (!IsVmServiceName(entries[i].lpServiceName))
        {
            if (writeIdx != i)
                CopyMemory(&entries[writeIdx], &entries[i],
                           sizeof(ENUM_SERVICE_STATUSW));
            writeIdx++;
        }
    }
    *lpServicesReturned = writeIdx;
    return result;
}

static BOOL WINAPI HookedEnumServicesStatusA(SC_HANDLE hSCManager,
                                              DWORD dwServiceType,
                                              DWORD dwServiceState,
                                              LPBYTE lpServices,
                                              DWORD cbBufSize,
                                              LPDWORD pcbBytesNeeded,
                                              LPDWORD lpServicesReturned,
                                              LPDWORD lpResumeHandle)
{
    BOOL result = OriginalEnumServicesStatusA(hSCManager, dwServiceType,
                                              dwServiceState, lpServices, cbBufSize,
                                              pcbBytesNeeded, lpServicesReturned,
                                              lpResumeHandle);

    if (!result || !ObsIsEnabled() || ObsGetMode() != OBS_MODE_TRAP)
        return result;

    if (!lpServices || !lpServicesReturned)
        return result;

    LPENUM_SERVICE_STATUSA entries = (LPENUM_SERVICE_STATUSA)lpServices;
    DWORD count = *lpServicesReturned;
    DWORD writeIdx = 0;

    for (DWORD i = 0; i < count; i++)
    {
        WCHAR wname[256] = { 0 };
        MultiByteToWideChar(CP_ACP, 0, entries[i].lpServiceName, -1, wname, 256);

        if (!IsVmServiceName(wname))
        {
            if (writeIdx != i)
                CopyMemory(&entries[writeIdx], &entries[i],
                           sizeof(ENUM_SERVICE_STATUSA));
            writeIdx++;
        }
    }
    *lpServicesReturned = writeIdx;
    return result;
}

// ------------------------------------------------------------
//  NtQuerySystemInformation
//  Trap mode: filter VM process names from SystemProcessInformation.
//  Defensive mode: real VM processes are started by the Service;
//  no process injection needed in the hook.
// ------------------------------------------------------------
static NTSTATUS NTAPI HookedNtQuerySystemInformation(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength)
{
    NTSTATUS status = OriginalNtQuerySystemInformation(
        SystemInformationClass, SystemInformation,
        SystemInformationLength, ReturnLength);

    if (!NT_SUCCESS(status) || !ObsIsEnabled() || ObsGetMode() != OBS_MODE_TRAP)
        return status;

    if (SystemInformationClass != SystemProcessInformation)
        return status;

    // Walk the linked process list, unlinking VM-named entries.
    PSYSTEM_PROCESS_INFORMATION current =
        (PSYSTEM_PROCESS_INFORMATION)SystemInformation;
    PSYSTEM_PROCESS_INFORMATION previous = NULL;

    while (TRUE)
    {
        BOOL hide = FALSE;

        if (current->ImageName.Buffer)
        {
            WCHAR name[MAX_PATH + 1] = { 0 };
            UnicodeStringToBuffer(&current->ImageName, name, MAX_PATH);
            hide = IsVmProcessName(name);
        }

        ULONG nextOffset = current->NextEntryOffset;

        if (hide)
        {
            if (previous)
            {
                if (nextOffset)
                    previous->NextEntryOffset += nextOffset;
                else
                    previous->NextEntryOffset = 0;
            }
            else if (nextOffset)
            {
                // Hidden entry is first – shift remaining data forward
                CopyMemory(current,
                           (LPBYTE)current + nextOffset,
                           SystemInformationLength - nextOffset -
                           ((LPBYTE)current - (LPBYTE)SystemInformation));
                continue;  // Re-examine the now-current entry
            }
        }
        else
        {
            previous = current;
        }

        if (!nextOffset) break;
        current = (PSYSTEM_PROCESS_INFORMATION)((LPBYTE)current + nextOffset);
    }

    return status;
}

// ------------------------------------------------------------
//  NtQueryValueKey
//  Intercept reads of the HARDWARE\DESCRIPTION\System\BIOS key.
//  Both modes: substitute the appropriate manufacturer/product/
//  BIOS vendor strings so WMI and direct registry reads see the
//  correct spoofed data even when the Service hasn't (yet) been
//  able to write the keys directly.
// ------------------------------------------------------------
static NTSTATUS NTAPI HookedNtQueryValueKey(
    HANDLE                         KeyHandle,
    PUNICODE_STRING                ValueName,
    NT_KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
    PVOID                          KeyValueInformation,
    ULONG                          Length,
    PULONG                         ResultLength)
{
    NTSTATUS status = OriginalNtQueryValueKey(KeyHandle, ValueName,
                                              KeyValueInformationClass,
                                              KeyValueInformation,
                                              Length, ResultLength);

    if (!NT_SUCCESS(status) || !ObsIsEnabled()) return status;

    // Only handle KeyValuePartialInformation and KeyValueFullInformation
    if (KeyValueInformationClass != KeyValuePartialInformation &&
        KeyValueInformationClass != KeyValueFullInformation)
        return status;

    // Resolve the key name and check it's the BIOS key we care about.
    // (Uses GetRegistryKeyNameLocal defined above, which calls NtQueryKey
    //  via the already-resolved OriginalNtQueryKey pointer.)
    WCHAR keyPath[512] = { 0 };
    if (!GetRegistryKeyNameLocal(KeyHandle, keyPath, 512)) return status;

    if (_wcsicmp(keyPath, OBS_NT_BIOS_PATH) != 0) return status;

    // Extract the value name as a null-terminated string.
    WCHAR valNameBuf[128] = { 0 };
    if (ValueName && ValueName->Buffer)
        UnicodeStringToBuffer(ValueName, valNameBuf, 128);

    LPCWSTR spoofed = GetSpoofedBiosValue(valNameBuf, ObsGetMode());
    if (!spoofed) return status;

    // Write the spoofed string into the output buffer.
    DWORD dataLen = (DWORD)((wcslen(spoofed) + 1) * sizeof(WCHAR));

    if (KeyValueInformationClass == KeyValuePartialInformation)
    {
        POBS_KEY_VALUE_PARTIAL_INFORMATION info =
            (POBS_KEY_VALUE_PARTIAL_INFORMATION)KeyValueInformation;

        if (Length < FIELD_OFFSET(OBS_KEY_VALUE_PARTIAL_INFORMATION, Data) + dataLen)
            return STATUS_BUFFER_TOO_SMALL;

        info->Type       = REG_SZ;
        info->DataLength = dataLen;
        CopyMemory(info->Data, spoofed, dataLen);
        if (ResultLength) *ResultLength =
            FIELD_OFFSET(OBS_KEY_VALUE_PARTIAL_INFORMATION, Data) + dataLen;
    }
    else  // KeyValueFullInformation
    {
        PNT_KEY_VALUE_FULL_INFORMATION info =
            (PNT_KEY_VALUE_FULL_INFORMATION)KeyValueInformation;

        DWORD dataOffset = info->DataOffset;
        if (Length < dataOffset + dataLen)
            return STATUS_BUFFER_TOO_SMALL;

        info->Type       = REG_SZ;
        info->DataLength = dataLen;
        CopyMemory((LPBYTE)info + dataOffset, spoofed, dataLen);
        if (ResultLength) *ResultLength = dataOffset + dataLen;
    }

    return STATUS_SUCCESS;
}

// ------------------------------------------------------------
//  NtEnumerateKey / NtQueryKey
//
//  Two filtering behaviours, both active whenever Obscurize is
//  enabled (not just in Trap mode):
//
//  1. OBS_NT_CONFIG_PARENT (\...\CurrentVersion)
//     Always hide the "DeviceCache" config key so a threat actor
//     enumerating CurrentVersion subkeys never sees it.
//
//  2. \REGISTRY\MACHINE\SOFTWARE  (Trap mode only)
//     Suppress VM-vendor subkeys (VMware, Inc. / Oracle / VBOX)
//     so the registry looks like bare-metal.
//
//  Uses the same TLS-cache O(N) pattern from r77.
// ------------------------------------------------------------

// Returns TRUE if `name` is the Obscurize config subkey that
// should always be hidden from enumeration.
static BOOL IsObscurizeConfigKey(LPCWSTR name)
{
    return name && _wcsicmp(name, L"DeviceCache") == 0;
}

static NTSTATUS NTAPI HookedNtEnumerateKey(
    HANDLE                  Key,
    ULONG                   Index,
    NT_KEY_INFORMATION_CLASS KeyInformationClass,
    LPVOID                  KeyInformation,
    ULONG                   KeyInformationLength,
    PULONG                  ResultLength)
{
    if (!ObsIsEnabled())
        return OriginalNtEnumerateKey(Key, Index, KeyInformationClass,
                                      KeyInformation, KeyInformationLength,
                                      ResultLength);

    // Skip NodeInformation class (r77 pattern – avoids edge cases)
    if (KeyInformationClass == KeyNodeInformation)
        return OriginalNtEnumerateKey(Key, Index, KeyInformationClass,
                                      KeyInformation, KeyInformationLength,
                                      ResultLength);

    // Determine which filters apply for this parent key.
    // Applying filters to any other key causes STATUS_NO_MORE_ENTRIES
    // during CLR/.NET init, breaking shell startup.
    WCHAR keyPath[512] = { 0 };
    if (!GetRegistryKeyNameLocal(Key, keyPath, 512))
        return OriginalNtEnumerateKey(Key, Index, KeyInformationClass,
                                      KeyInformation, KeyInformationLength,
                                      ResultLength);

    BOOL filterVmKeys    = (ObsGetMode() == OBS_MODE_TRAP &&
                             _wcsicmp(keyPath, L"\\REGISTRY\\MACHINE\\SOFTWARE") == 0);
    BOOL filterConfigKey = (_wcsicmp(keyPath, OBS_NT_CONFIG_PARENT) == 0);

    if (!filterVmKeys && !filterConfigKey)
        return OriginalNtEnumerateKey(Key, Index, KeyInformationClass,
                                      KeyInformation, KeyInformationLength,
                                      ResultLength);

    // Retrieve TLS cache for O(N) sequential enumeration.
    // Cast via ULONG_PTR to suppress C4311 pointer-truncation warning.
    HANDLE cacheKey            = (HANDLE)           TlsGetValue(TlsEnumKeyCacheKey);
    ULONG  cacheIndex          = (ULONG)(ULONG_PTR) TlsGetValue(TlsEnumKeyCacheIndex);
    ULONG  cacheI              = (ULONG)(ULONG_PTR) TlsGetValue(TlsEnumKeyCacheI);
    ULONG  cacheCorrectedIndex = (ULONG)(ULONG_PTR) TlsGetValue(TlsEnumKeyCacheCorrectedIndex);

    ULONG i = 0, correctedIndex = 0;
    if (cacheKey == Key && cacheIndex == Index - 1)
    {
        i = cacheI;
        correctedIndex = cacheCorrectedIndex + 1;
    }

    BYTE  buffer[1024];
    PNT_KEY_BASIC_INFORMATION basic = (PNT_KEY_BASIC_INFORMATION)buffer;

    for (; i <= Index; correctedIndex++)
    {
        NTSTATUS st = OriginalNtEnumerateKey(Key, correctedIndex,
                                              KeyBasicInformation,
                                              basic, sizeof(buffer), ResultLength);
        if (!NT_SUCCESS(st))
            return OriginalNtEnumerateKey(Key, correctedIndex, KeyInformationClass,
                                          KeyInformation, KeyInformationLength,
                                          ResultLength);

        // Null-terminate the name
        basic->Name[basic->NameLength / sizeof(WCHAR)] = L'\0';

        BOOL hidden = (filterVmKeys    && IsVmRegistryVendorKey(basic->Name)) ||
                      (filterConfigKey && IsObscurizeConfigKey(basic->Name));

        if (!hidden)
            i++;  // Advance logical index only for visible keys
    }

    // correctedIndex now points to the actual raw entry matching logical Index.
    // Update TLS cache.
    TlsSetValue(TlsEnumKeyCacheKey,            Key);
    TlsSetValue(TlsEnumKeyCacheIndex,          (LPVOID)(ULONG_PTR)Index);
    TlsSetValue(TlsEnumKeyCacheI,              (LPVOID)(ULONG_PTR)i);
    TlsSetValue(TlsEnumKeyCacheCorrectedIndex, (LPVOID)(ULONG_PTR)(correctedIndex - 1));

    return OriginalNtEnumerateKey(Key, correctedIndex - 1, KeyInformationClass,
                                  KeyInformation, KeyInformationLength, ResultLength);
}

static NTSTATUS NTAPI HookedNtQueryKey(
    HANDLE                  Key,
    NT_KEY_INFORMATION_CLASS KeyInformationClass,
    LPVOID                  KeyInformation,
    ULONG                   Length,
    PULONG                  ResultLength)
{
    NTSTATUS status = OriginalNtQueryKey(Key, KeyInformationClass,
                                         KeyInformation, Length, ResultLength);

    if (!NT_SUCCESS(status) || !ObsIsEnabled())
        return status;

    if (KeyInformationClass != KeyFullInformation &&
        KeyInformationClass != KeyCachedInformation)
        return status;

    WCHAR keyPath[512] = { 0 };
    if (!GetRegistryKeyNameLocal(Key, keyPath, 512))
        return status;

    ULONG hiddenSubKeys = 0;
    BYTE  buffer[1024];
    PNT_KEY_BASIC_INFORMATION basic = (PNT_KEY_BASIC_INFORMATION)buffer;

    if (ObsGetMode() == OBS_MODE_TRAP &&
        _wcsicmp(keyPath, L"\\REGISTRY\\MACHINE\\SOFTWARE") == 0)
    {
        // Count VM vendor subkeys to subtract from SOFTWARE's SubKeys count.
        for (ULONG idx = 0; ; idx++)
        {
            ULONG dummy;
            if (!NT_SUCCESS(OriginalNtEnumerateKey(Key, idx, KeyBasicInformation,
                                                   basic, sizeof(buffer), &dummy)))
                break;
            basic->Name[basic->NameLength / sizeof(WCHAR)] = L'\0';
            if (IsVmRegistryVendorKey(basic->Name))
                hiddenSubKeys++;
        }
    }
    else if (_wcsicmp(keyPath, OBS_NT_CONFIG_PARENT) == 0)
    {
        // Count DeviceCache to subtract from CurrentVersion's SubKeys count.
        for (ULONG idx = 0; ; idx++)
        {
            ULONG dummy;
            if (!NT_SUCCESS(OriginalNtEnumerateKey(Key, idx, KeyBasicInformation,
                                                   basic, sizeof(buffer), &dummy)))
                break;
            basic->Name[basic->NameLength / sizeof(WCHAR)] = L'\0';
            if (IsObscurizeConfigKey(basic->Name))
                hiddenSubKeys++;
        }
    }

    if (hiddenSubKeys == 0) return status;

    if (KeyInformationClass == KeyFullInformation)
    {
        PNT_KEY_FULL_INFORMATION info = (PNT_KEY_FULL_INFORMATION)KeyInformation;
        if (info->SubKeys >= hiddenSubKeys) info->SubKeys -= hiddenSubKeys;
    }
    else
    {
        PNT_KEY_CACHED_INFORMATION info = (PNT_KEY_CACHED_INFORMATION)KeyInformation;
        if (info->SubKeys >= hiddenSubKeys) info->SubKeys -= hiddenSubKeys;
    }

    return status;
}

// ------------------------------------------------------------
//  GetSystemFirmwareTable
//  Intercept raw SMBIOS table reads used by WMI providers to
//  serve Win32_ComputerSystem.Manufacturer, Win32_BIOS, etc.
//
//  The function is called in two patterns:
//    1. Probe: BufferSize = 0  →  returns required byte count.
//    2. Fill:  BufferSize > 0  →  writes data, returns bytes written.
//
//  We inflate the probe result by OBS_SMBIOS_HEADROOM so the
//  caller allocates enough room for our patched (potentially
//  slightly larger) strings, then patch the filled buffer
//  in-place on the second call.
// ------------------------------------------------------------
static UINT WINAPI HookedGetSystemFirmwareTable(
    DWORD FirmwareTableProviderSignature,
    DWORD FirmwareTableID,
    PVOID pFirmwareTableBuffer,
    DWORD BufferSize)
{
    UINT result = OriginalGetSystemFirmwareTable(
        FirmwareTableProviderSignature, FirmwareTableID,
        pFirmwareTableBuffer, BufferSize);

    if (!ObsIsEnabled()) return result;

    // Only intercept Raw SMBIOS ('RSMB') provider, table ID 0.
    if (FirmwareTableProviderSignature != (DWORD)'RSMB' || FirmwareTableID != 0)
        return result;

    if (result == 0) return result;     // API failure – nothing to patch.

    // Probe call: buffer too small or not provided.
    // Inflate the returned size so callers allocate enough headroom.
    if (result > BufferSize)
        return result + OBS_SMBIOS_HEADROOM;

    // Fill call: data was written to pFirmwareTableBuffer.
    DWORD  patchedSize = 0;
    LPBYTE patched = PatchRSMBBuffer((LPCBYTE)pFirmwareTableBuffer,
                                     result, &patchedSize);
    if (patched)
    {
        if (patchedSize <= BufferSize)
        {
            CopyMemory(pFirmwareTableBuffer, patched, patchedSize);
            result = patchedSize;
        }
        HeapFree(GetProcessHeap(), 0, patched);
    }
    return result;
}

// ------------------------------------------------------------
//  RequestImmediateInjection
//  Connect to the Obscurize service pipe and ask it to inject
//  the agent into `pid` synchronously.  Called while the target
//  process is still suspended; returns after the service has
//  confirmed injection so the caller can safely ResumeThread.
// ------------------------------------------------------------
static BOOL RequestImmediateInjection(DWORD pid)
{
    // Wait up to 1 s for the pipe to be available.
    if (!WaitNamedPipeW(OBS_CONTROL_PIPE_NAME, 1000))
        return FALSE;

    HANDLE pipe = CreateFileW(
        OBS_CONTROL_PIPE_NAME,
        GENERIC_READ | GENERIC_WRITE,
        0, NULL,
        OPEN_EXISTING,
        SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, NULL);
    if (pipe == INVALID_HANDLE_VALUE)
        return FALSE;

    DWORD pipeMode = PIPE_READMODE_MESSAGE;
    SetNamedPipeHandleState(pipe, &pipeMode, NULL, NULL);

    BOOL  ok      = FALSE;
    DWORD written = 0;
    DWORD code    = OBS_CTRL_INJECT_PID;

    if (WriteFile(pipe, &code, sizeof(DWORD), &written, NULL) && written == sizeof(DWORD))
    {
        if (WriteFile(pipe, &pid, sizeof(DWORD), &written, NULL) && written == sizeof(DWORD))
        {
            DWORD reply = 0, bytesRead = 0;
            if (ReadFile(pipe, &reply, sizeof(DWORD), &bytesRead, NULL)
                && bytesRead == sizeof(DWORD))
            {
                ok = (reply == OBS_STATUS_OK);
            }
        }
    }

    CloseHandle(pipe);
    return ok;
}

// ------------------------------------------------------------
//  InjectAndWaitForAgent
//  Request injection into a suspended process, then block until its agent
//  reports that hooks are installed.
//
//  InjectDll() returns once the remote loader thread is CREATED, so the
//  service's OK reply does NOT mean the hooks are live.  Resuming on that
//  reply lets a fast process (plain `whoami`) run to completion before its
//  hooks attach.  The ready event MUST be created here, before injection is
//  requested — otherwise the agent may create, signal, and close the only
//  handle to it before this thread starts waiting, and we would then wait on a
//  brand-new unsignaled event until the timeout.
// ------------------------------------------------------------
static VOID InjectAndWaitForAgent(DWORD pid)
{
    WCHAR evName[64];
    StringCchPrintfW(evName, ARRAYSIZE(evName), OBS_AGENT_READY_EVENT_FMT, pid);
    HANDLE ready = CreateEventW(NULL, TRUE, FALSE, evName);   // manual reset

    RequestImmediateInjection(pid);

    if (ready)
    {
        // On timeout we resume anyway: worst case is the old unsynchronized
        // behaviour (hooks may not be attached yet), never a hang.
        WaitForSingleObject(ready, OBS_AGENT_READY_TIMEOUT_MS);
        CloseHandle(ready);
    }
}

// ------------------------------------------------------------
//  CreateProcessW / CreateProcessA
//  Two responsibilities:
//    1. Strip -NoProfile (and prefix abbreviations >= 3 body
//       chars) from PowerShell command lines so the system-wide
//       profile.ps1 is always loaded.
//    2. Create wmic.exe suspended, signal the service to inject
//       the agent synchronously, then resume – eliminating the
//       100 ms polling race that lets wmic finish before the
//       agent is installed.
// ------------------------------------------------------------

// Strip -noprofile / /noprofile (and prefix abbreviations >= 3 body chars)
// from a mutable wide command-line string, in-place.
// Inter-token whitespace before a stripped token is also removed.
// Returns TRUE if at least one token was removed.
static BOOL StripNoProfFlag(LPWSTR cmd)
{
    if (!cmd) return FALSE;
    static const WCHAR kTarget[] = L"noprofile";   // 9 chars

    BOOL   stripped = FALSE;
    LPWSTR w = cmd;   // write pointer
    LPWSTR r = cmd;   // read pointer

    while (*r)
    {
        // Collect inter-token whitespace; associate it with the NEXT token.
        LPWSTR wsStart = r;
        while (*r == L' ' || *r == L'\t') r++;
        SIZE_T wsLen = (SIZE_T)(r - wsStart);

        if (!*r)
        {
            // Trailing whitespace – preserve it.
            MoveMemory(w, wsStart, wsLen * sizeof(WCHAR));
            w += wsLen;
            break;
        }

        // Collect the token (non-whitespace run).
        LPWSTR tokStart = r;
        while (*r && *r != L' ' && *r != L'\t') r++;
        SIZE_T tokLen = (SIZE_T)(r - tokStart);

        // Check for -/noprofile prefix (body must be 3–9 chars).
        BOOL isNoProf = FALSE;
        if (tokLen >= 4 && (tokStart[0] == L'-' || tokStart[0] == L'/'))
        {
            SIZE_T bodyLen = tokLen - 1;
            if (bodyLen >= 3 && bodyLen <= 9 &&
                _wcsnicmp(tokStart + 1, kTarget, bodyLen) == 0)
                isNoProf = TRUE;
        }

        if (isNoProf)
        {
            stripped = TRUE;
            // Skip preceding whitespace and this token (copy nothing).
        }
        else
        {
            MoveMemory(w, wsStart, wsLen * sizeof(WCHAR));
            w += wsLen;
            MoveMemory(w, tokStart, tokLen * sizeof(WCHAR));
            w += tokLen;
        }
    }

    *w = L'\0';
    return stripped;
}

static BOOL WINAPI HookedCreateProcessW(
    LPCWSTR               lpApplicationName,
    LPWSTR                lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL                  bInheritHandles,
    DWORD                 dwCreationFlags,
    LPVOID                lpEnvironment,
    LPCWSTR               lpCurrentDirectory,
    LPSTARTUPINFOW        lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation)
{
    LPWSTR modifiedCmd = NULL;
    LPWSTR cmdToUse    = lpCommandLine;
    BOOL   injectShortLived = FALSE;
    BOOL   result;

    if (ObsIsEnabled())
    {
        // PowerShell: strip -NoProfile so system-wide profile.ps1 always loads.
        if (lpCommandLine)
        {
            BOOL isPs = (StrStrIW(lpCommandLine, L"powershell") != NULL ||
                         StrStrIW(lpCommandLine, L"pwsh")       != NULL);
            if (!isPs && lpApplicationName)
                isPs = (StrStrIW(lpApplicationName, L"powershell") != NULL ||
                        StrStrIW(lpApplicationName, L"pwsh")       != NULL);

            if (isPs)
            {
                SIZE_T cch = wcslen(lpCommandLine) + 1;
                modifiedCmd = (LPWSTR)HeapAlloc(GetProcessHeap(), 0, cch * sizeof(WCHAR));
                if (modifiedCmd)
                {
                    CopyMemory(modifiedCmd, lpCommandLine, cch * sizeof(WCHAR));
                    if (StripNoProfFlag(modifiedCmd))
                        cmdToUse = modifiedCmd;
                    else
                    {
                        HeapFree(GetProcessHeap(), 0, modifiedCmd);
                        modifiedCmd = NULL;
                    }
                }
            }
        }

        // Short-lived recon tools (wmic.exe, whoami.exe) exit faster than the
        // service's 100 ms process poll can inject them, so pre-inject them via a
        // suspended start (same race the wmic path was built to close).
        BOOL isWmic = (lpApplicationName && StrStrIW(lpApplicationName, L"wmic.exe") != NULL) ||
                      (lpCommandLine     && StrStrIW(lpCommandLine,     L"wmic.exe") != NULL);
        if (!isWmic && lpCommandLine)
        {
            // Bare "wmic" without .exe extension (word-boundary check).
            LPCWSTR pos = StrStrIW(lpCommandLine, L"wmic");
            if (pos)
            {
                WCHAR after = *(pos + 4);
                isWmic = (after == L'\0' || after == L' ' || after == L'\t' || after == L'"');
            }
        }

        // whoami.exe: prints DOMAIN\user via GetUserNameExW (secur32), which our
        // hook spoofs — but only if the agent is present before it runs.
        BOOL isWhoami = (lpApplicationName && StrStrIW(lpApplicationName, L"whoami") != NULL) ||
                        (lpCommandLine     && StrStrIW(lpCommandLine,     L"whoami") != NULL);

        injectShortLived = isWmic || isWhoami;
    }

    // Create the target suspended so the agent is installed before it runs.
    BOOL                  wasAlreadySuspended = (dwCreationFlags & CREATE_SUSPENDED) != 0;
    DWORD                 flagsToUse          = dwCreationFlags;
    PROCESS_INFORMATION   localPi             = { 0 };
    LPPROCESS_INFORMATION piToUse             = lpProcessInformation ? lpProcessInformation : &localPi;

    if (injectShortLived)
        flagsToUse |= CREATE_SUSPENDED;

    result = OriginalCreateProcessW(
        lpApplicationName, cmdToUse,
        lpProcessAttributes, lpThreadAttributes,
        bInheritHandles, flagsToUse,
        lpEnvironment, lpCurrentDirectory,
        lpStartupInfo, piToUse);

    if (result && injectShortLived)
    {
        InjectAndWaitForAgent(piToUse->dwProcessId);
        if (!wasAlreadySuspended)
            ResumeThread(piToUse->hThread);
        if (!lpProcessInformation)
        {
            CloseHandle(piToUse->hProcess);
            CloseHandle(piToUse->hThread);
        }
    }

    if (modifiedCmd)
        HeapFree(GetProcessHeap(), 0, modifiedCmd);

    return result;
}

static BOOL WINAPI HookedCreateProcessA(
    LPCSTR                lpApplicationName,
    LPSTR                 lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL                  bInheritHandles,
    DWORD                 dwCreationFlags,
    LPVOID                lpEnvironment,
    LPCSTR                lpCurrentDirectory,
    LPSTARTUPINFOA        lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation)
{
    LPSTR modifiedCmd = NULL;
    LPSTR cmdToUse    = lpCommandLine;
    BOOL  injectShortLived = FALSE;
    BOOL  result;

    if (ObsIsEnabled())
    {
        // PowerShell: strip -NoProfile.
        if (lpCommandLine)
        {
            BOOL isPs = (StrStrIA(lpCommandLine, "powershell") != NULL ||
                         StrStrIA(lpCommandLine, "pwsh")       != NULL);
            if (!isPs && lpApplicationName)
                isPs = (StrStrIA(lpApplicationName, "powershell") != NULL ||
                        StrStrIA(lpApplicationName, "pwsh")       != NULL);

            if (isPs)
            {
                // Convert to wide for uniform StripNoProfFlag processing.
                int    wCch    = MultiByteToWideChar(CP_ACP, 0, lpCommandLine, -1, NULL, 0);
                LPWSTR wideCmd = (LPWSTR)HeapAlloc(GetProcessHeap(), 0,
                                                   (SIZE_T)wCch * sizeof(WCHAR));
                if (wideCmd)
                {
                    MultiByteToWideChar(CP_ACP, 0, lpCommandLine, -1, wideCmd, wCch);
                    if (StripNoProfFlag(wideCmd))
                    {
                        int   mbLen = WideCharToMultiByte(CP_ACP, 0, wideCmd, -1,
                                                         NULL, 0, NULL, NULL);
                        modifiedCmd = (LPSTR)HeapAlloc(GetProcessHeap(), 0, (SIZE_T)mbLen);
                        if (modifiedCmd)
                        {
                            WideCharToMultiByte(CP_ACP, 0, wideCmd, -1,
                                               modifiedCmd, mbLen, NULL, NULL);
                            cmdToUse = modifiedCmd;
                        }
                    }
                    HeapFree(GetProcessHeap(), 0, wideCmd);
                }
            }
        }

        // Short-lived recon tools (wmic.exe, whoami.exe) exit faster than the
        // 100 ms process poll can inject them, so pre-inject via suspended start.
        BOOL isWmic = (lpApplicationName && StrStrIA(lpApplicationName, "wmic.exe") != NULL) ||
                      (lpCommandLine     && StrStrIA(lpCommandLine,     "wmic.exe") != NULL);
        if (!isWmic && lpCommandLine)
        {
            LPCSTR pos = StrStrIA(lpCommandLine, "wmic");
            if (pos)
            {
                char after = *(pos + 4);
                isWmic = (after == '\0' || after == ' ' || after == '\t' || after == '"');
            }
        }

        BOOL isWhoami = (lpApplicationName && StrStrIA(lpApplicationName, "whoami") != NULL) ||
                        (lpCommandLine     && StrStrIA(lpCommandLine,     "whoami") != NULL);

        injectShortLived = isWmic || isWhoami;
    }

    BOOL                  wasAlreadySuspended = (dwCreationFlags & CREATE_SUSPENDED) != 0;
    DWORD                 flagsToUse          = dwCreationFlags;
    PROCESS_INFORMATION   localPi             = { 0 };
    LPPROCESS_INFORMATION piToUse             = lpProcessInformation ? lpProcessInformation : &localPi;

    if (injectShortLived)
        flagsToUse |= CREATE_SUSPENDED;

    result = OriginalCreateProcessA(
        lpApplicationName, cmdToUse,
        lpProcessAttributes, lpThreadAttributes,
        bInheritHandles, flagsToUse,
        lpEnvironment, lpCurrentDirectory,
        lpStartupInfo, piToUse);

    if (result && injectShortLived)
    {
        InjectAndWaitForAgent(piToUse->dwProcessId);
        if (!wasAlreadySuspended)
            ResumeThread(piToUse->hThread);
        if (!lpProcessInformation)
        {
            CloseHandle(piToUse->hProcess);
            CloseHandle(piToUse->hThread);
        }
    }

    if (modifiedCmd)
        HeapFree(GetProcessHeap(), 0, modifiedCmd);

    return result;
}

// ------------------------------------------------------------
//  WriteFile / WriteConsoleA – systeminfo.exe stdout patching
//  Only active when injected into systeminfo.exe (g_IsSystemInfo).
//  Intercepts the final formatted text output and replaces VM
//  strings with Trap-mode real-hardware strings so a human
//  attacker running systeminfo sees Dell values, not VMware.
//
//  Three patterns, applied in order (longest/most specific first
//  to prevent partial clobber):
//    "VMware, Inc. VMW" + rest of BIOS value  →  Dell BIOS ver
//    "VMware20,1"                              →  "Precision 5560"
//    "VMware, Inc."                            →  "Dell Inc."
// ------------------------------------------------------------

// Allocate and return a patched copy of [src, src+srcLen).
// Sets *outLen to the length of the patched buffer.
// Returns NULL if no VM strings were found (caller uses original).
// Caller must HeapFree the returned pointer.
// systeminfo emits each field's label and value in SEPARATE WriteConsole /
// WriteFile calls (label+padding first, value next), so the label-anchored
// replacements must carry state across calls — a label seen in one call is
// matched against a value that arrives in a later call.  These identify which
// field's value the patcher is currently waiting to swap.
enum { OBS_SI_NONE = 0, OBS_SI_HOST, OBS_SI_MEM, OBS_SI_DOM };

// NOTE: the Processor(s) COUNT line is deliberately left untouched.  Rewriting
// it to "1 Processor(s) Installed." required holding each entry line's
// indentation across write boundaries to drop the surplus entries, and that
// machinery is what regressed systeminfo.  Every entry's CPU model is still
// spoofed, so a 2-socket host reports two identical Trap CPUs — coherent, and
// invisible to enumeration.

// ------------------------------------------------------------
//  Shared value builders for the systeminfo stdout patch.
//  Each fills a wide buffer with the mode-appropriate replacement
//  for one label-anchored field.  The ANSI patch path converts the
//  result with WideCharToMultiByte; the wide path uses it directly.
//  Only reached in Trap mode (the caller gates on OBS_MODE_TRAP).
// ------------------------------------------------------------

// Host Name: spoofed computer name, uppercased (systeminfo shows it uppercase).
static VOID BuildSysInfoHostName(PWCHAR out, DWORD cch)
{
    ObsGetSpoofComputerName(out, cch);
    CharUpperW(out);
}

// Total Physical Memory: "<n,nnn> MB" from the spoofed byte count.
static VOID BuildSysInfoMemory(PWCHAR out, DWORD cch)
{
    ULONGLONG mb = ObsGetSpoofMemoryBytes() / (1024ULL * 1024ULL);

    WCHAR digits[32];
    StringCchPrintfW(digits, ARRAYSIZE(digits), L"%I64u", mb);

    // Insert thousands separators.
    int   len = (int)wcslen(digits);
    WCHAR grouped[48];
    int   gi = 0;
    for (int i = 0; i < len && gi < (int)ARRAYSIZE(grouped) - 1; i++)
    {
        if (i > 0 && ((len - i) % 3) == 0)
            grouped[gi++] = L',';
        grouped[gi++] = digits[i];
    }
    grouped[gi] = L'\0';

    StringCchPrintfW(out, cch, L"%s MB", grouped);
}

// Domain: mode-appropriate name.  Returns FALSE when the domain hook is off
// (leave the real value untouched, consistent with the NetGetJoinInformation hook).
static BOOL BuildSysInfoDomain(PWCHAR out, DWORD cch)
{
    if (ObsGetDomainMode() == OBS_DOMAIN_MODE_OFF)
        return FALSE;
    ObsGetSpoofDomainName(out, cch);
    return TRUE;
}

// Copy a matched label (or "[0N]: " entry prefix) plus its run of padding
// spaces, append the replacement value, then skip the original value to EOL.
// Preserves systeminfo's column alignment and the entry's own index.  Returns
// FALSE (caller falls back to a plain byte copy) if the emit would exceed 'cap'.
static BOOL EmitSysInfoLabelA(LPBYTE dst, DWORD *pwi, DWORD cap,
                              LPCBYTE src, DWORD *pri, DWORD srcLen,
                              DWORD lblLen, const char *repl)
{
    DWORD wi = *pwi, ri = *pri;
    DWORD replLen = (DWORD)strlen(repl);

    if (wi + lblLen > cap) return FALSE;
    CopyMemory(dst + wi, src + ri, lblLen);
    wi += lblLen; ri += lblLen;

    while (ri < srcLen && src[ri] == ' ')
    {
        if (wi >= cap) return FALSE;
        dst[wi++] = src[ri++];
    }

    if (wi + replLen > cap) return FALSE;
    CopyMemory(dst + wi, repl, replLen);
    wi += replLen;

    while (ri < srcLen && src[ri] != '\r' && src[ri] != '\n')
        ri++;

    *pwi = wi; *pri = ri;
    return TRUE;
}

static LPBYTE PatchSysInfoOutput(LPCBYTE src, DWORD srcLen, DWORD *outLen)
{
    static const char kBiosPfx[]   = "VMware, Inc. VMW";
    static const char kBiosRepl[]  = "Dell Inc. 1.22.0, 04/14/2023";
    static const char kModelFind[] = "VMware20,1";
    static const char kModelRepl[] = "Precision 5560";
    static const char kMfgFind[]   = "VMware, Inc.";
    static const char kMfgRepl[]   = "Dell Inc.";

    const DWORD kBiosPfxLen   = (DWORD)(sizeof(kBiosPfx)   - 1);
    const DWORD kBiosReplLen  = (DWORD)(sizeof(kBiosRepl)   - 1);
    const DWORD kModelFindLen = (DWORD)(sizeof(kModelFind)  - 1);
    const DWORD kModelReplLen = (DWORD)(sizeof(kModelRepl)  - 1);
    const DWORD kMfgFindLen   = (DWORD)(sizeof(kMfgFind)    - 1);
    const DWORD kMfgReplLen   = (DWORD)(sizeof(kMfgRepl)    - 1);

    // Label-anchored replacements can be LONGER than the original value, so give
    // generous headroom (each field appears once) and bounds-check every emit.
    DWORD  cap = srcLen + 512;
    LPBYTE dst = (LPBYTE)HeapAlloc(GetProcessHeap(), 0, cap);
    if (!dst) return NULL;

    // Field labels for the new Trap-mode fields.
    static const char kHostLbl[] = "Host Name:";
    static const char kMemLbl[]  = "Total Physical Memory:";
    static const char kDomLbl[]  = "Domain:";
    static const char kProcLbl[] = "Processor(s):";
    static const char kCpuLbl[]  = "[01]: ";   // length of any "[0N]: " prefix
    const DWORD kHostLblLen = (DWORD)(sizeof(kHostLbl) - 1);
    const DWORD kMemLblLen  = (DWORD)(sizeof(kMemLbl)  - 1);
    const DWORD kDomLblLen  = (DWORD)(sizeof(kDomLbl)  - 1);
    const DWORD kProcLblLen = (DWORD)(sizeof(kProcLbl) - 1);
    const DWORD kCpuLblLen  = (DWORD)(sizeof(kCpuLbl)  - 1);

    // Build the mode-appropriate replacement values once.
    WCHAR wbuf[64];
    char  hostVal[128], memVal[64], domVal[512], cpuVal[160];

    BuildSysInfoHostName(wbuf, ARRAYSIZE(wbuf));
    WideCharToMultiByte(CP_ACP, 0, wbuf, -1, hostVal, sizeof(hostVal), NULL, NULL);
    BuildSysInfoMemory(wbuf, ARRAYSIZE(wbuf));
    WideCharToMultiByte(CP_ACP, 0, wbuf, -1, memVal, sizeof(memVal), NULL, NULL);
    WideCharToMultiByte(CP_ACP, 0, OBS_TRAP_CPU_SYSINFO, -1, cpuVal, sizeof(cpuVal), NULL, NULL);

    WCHAR domW[256];
    BOOL  domOk = BuildSysInfoDomain(domW, ARRAYSIZE(domW));
    if (domOk)
        WideCharToMultiByte(CP_ACP, 0, domW, -1, domVal, sizeof(domVal), NULL, NULL);

    // Cross-call state (systeminfo.exe is single-shot, so process-static is safe).
    static int  s_pending   = OBS_SI_NONE;  // value awaited for a matched label
    static BOOL s_expectCpu = FALSE;         // inside the Processor(s) entry block
    static BOOL s_lineStart = TRUE;          // at the start of a logical line

    BOOL  changed = FALSE;
    DWORD ri = 0, wi = 0;

    while (ri < srcLen && wi < cap)
    {
        DWORD   rem = srcLen - ri;
        LPCBYTE p   = src + ri;

        // (1) A label was matched earlier; consume (and swap) its value, which
        //     may begin in a previous call and continue into this one.
        if (s_pending != OBS_SI_NONE)
        {
            char c = (char)src[ri];
            if (c == ' ' || c == '\t')            // copy the alignment padding
            {
                dst[wi++] = src[ri++];
                s_lineStart = FALSE;
                continue;
            }
            if (c != '\r' && c != '\n')           // first value char → replace
            {
                const char *repl = (s_pending == OBS_SI_HOST) ? hostVal :
                                   (s_pending == OBS_SI_MEM)  ? memVal  : domVal;
                DWORD rlen = (DWORD)strlen(repl);
                if (wi + rlen <= cap)
                {
                    CopyMemory(dst + wi, repl, rlen);
                    wi += rlen;
                    while (ri < srcLen && src[ri] != '\r' && src[ri] != '\n')
                        ri++;                     // drop the real value
                    changed = TRUE;
                }
                else
                {
                    dst[wi++] = src[ri++];        // no room – leave value as-is
                }
                s_pending = OBS_SI_NONE;
                s_lineStart = FALSE;
                continue;
            }
            s_pending = OBS_SI_NONE;              // empty value – fall through
        }

        // (2) A column-0 line ends the Processor(s) entry block (entries are
        //     indented; the next real field label starts at column 0).
        if (s_expectCpu && s_lineStart && src[ri] != ' ')
            s_expectCpu = FALSE;

        // (3) Replace the CPU model on every "[0N]: ..." processor entry.
        //     Matched mid-line (NOT gated on line start) because systeminfo
        //     writes a line's indentation and its content as separate calls.
        //     EmitSysInfoLabelA copies the entry's own "[0N]: " prefix, so each
        //     entry keeps its index and only the model text is swapped.
        if (s_expectCpu && rem >= kCpuLblLen && src[ri] == '[' && src[ri + 1] == '0' &&
            EmitSysInfoLabelA(dst, &wi, cap, src, &ri, srcLen, kCpuLblLen, cpuVal))
        {
            changed = TRUE; s_lineStart = FALSE; continue;
        }

        // (4) Field labels: copy the label, then await its value in step (1).
        //     Processor(s): count line is left as-is; it only arms step (3).
        if (s_lineStart)
        {
            DWORD lbl = 0; int field = OBS_SI_NONE; BOOL isProc = FALSE;
            if      (rem >= kHostLblLen && _strnicmp((const char *)p, kHostLbl, kHostLblLen) == 0) { lbl = kHostLblLen; field = OBS_SI_HOST; }
            else if (rem >= kMemLblLen  && _strnicmp((const char *)p, kMemLbl,  kMemLblLen)  == 0) { lbl = kMemLblLen;  field = OBS_SI_MEM;  }
            else if (domOk && rem >= kDomLblLen && _strnicmp((const char *)p, kDomLbl, kDomLblLen) == 0) { lbl = kDomLblLen; field = OBS_SI_DOM; }
            else if (rem >= kProcLblLen && _strnicmp((const char *)p, kProcLbl, kProcLblLen) == 0) { lbl = kProcLblLen; isProc = TRUE; }

            if ((field != OBS_SI_NONE || isProc) && wi + lbl <= cap)
            {
                CopyMemory(dst + wi, src + ri, lbl);
                wi += lbl; ri += lbl;
                if (isProc) s_expectCpu = TRUE;   // count line untouched
                else        s_pending   = field;
                s_lineStart = FALSE;
                continue;
            }
        }

        // (4) Existing value-based BIOS patterns.

        // Pattern 1: BIOS version prefix → replace value up to EOL
        if (rem >= kBiosPfxLen &&
            _strnicmp((const char *)p, kBiosPfx, kBiosPfxLen) == 0)
        {
            CopyMemory(dst + wi, kBiosRepl, kBiosReplLen);
            wi += kBiosReplLen;
            ri += kBiosPfxLen;
            // Skip the rest of the original VMware BIOS version string
            while (ri < srcLen && src[ri] != '\r' && src[ri] != '\n')
                ri++;
            changed = TRUE; s_lineStart = FALSE;
            continue;
        }

        // Pattern 2: model string
        if (rem >= kModelFindLen &&
            _strnicmp((const char *)p, kModelFind, kModelFindLen) == 0)
        {
            CopyMemory(dst + wi, kModelRepl, kModelReplLen);
            wi += kModelReplLen;
            ri += kModelFindLen;
            changed = TRUE; s_lineStart = FALSE;
            continue;
        }

        // Pattern 3: manufacturer (must follow pattern 1 to avoid double-hit)
        if (rem >= kMfgFindLen &&
            _strnicmp((const char *)p, kMfgFind, kMfgFindLen) == 0)
        {
            CopyMemory(dst + wi, kMfgRepl, kMfgReplLen);
            wi += kMfgReplLen;
            ri += kMfgFindLen;
            changed = TRUE; s_lineStart = FALSE;
            continue;
        }

        // (5) Default copy.
        s_lineStart = (src[ri] == '\n');
        dst[wi++] = src[ri++];
    }

    if (!changed)
    {
        HeapFree(GetProcessHeap(), 0, dst);
        return NULL;
    }

    *outLen = wi;
    return dst;
}

// ------------------------------------------------------------
//  wmic.exe stdout patching  (g_IsWmic)
//  Covers both modes – Defensive reports "None" (typical VMware
//  BIOS serial), Trap reports a realistic Dell service tag.
//
//  Uses a stateful two-phase parser so the header line and the
//  value line can arrive in separate Write calls:
//    State 0: scan for "SerialNumber" column header
//    State 1: next non-empty line is the value; replace it
//
//  The state variable (g_WmicSerialState) lives for the lifetime
//  of the wmic.exe process, which terminates after one query.
// ------------------------------------------------------------

static LPBYTE PatchWmicOutput(LPCBYTE src, DWORD srcLen, DWORD *outLen)
{
    static const char kHeader[]      = "SerialNumber";
    static const DWORD kHeaderLen    = (DWORD)(sizeof(kHeader) - 1);
    static const char kSerialDef[]   = "None";
    static const char kSerialTrap[]  = "7X8K9P2";

    const char *spoofSerial    = (ObsGetMode() == OBS_MODE_DEFENSIVE)
                                 ? kSerialDef : kSerialTrap;
    DWORD       spoofSerialLen = (DWORD)strlen(spoofSerial);

    DWORD  cap = srcLen + spoofSerialLen + 16;
    LPBYTE dst = (LPBYTE)HeapAlloc(GetProcessHeap(), 0, cap);
    if (!dst) return NULL;

    BOOL  changed = FALSE;
    DWORD ri = 0, wi = 0;

    while (ri < srcLen && wi < cap)
    {
        if (g_WmicSerialState == 0)
        {
            DWORD rem = srcLen - ri;

            if (rem >= kHeaderLen &&
                _strnicmp((const char *)(src + ri), kHeader, kHeaderLen) == 0)
            {
                // Copy "SerialNumber" header
                CopyMemory(dst + wi, src + ri, kHeaderLen);
                wi += kHeaderLen;
                ri += kHeaderLen;
                // Copy rest of header line
                while (ri < srcLen && src[ri] != '\n')
                    dst[wi++] = src[ri++];
                if (ri < srcLen)
                    dst[wi++] = src[ri++];  // '\n'
                g_WmicSerialState = 1;
                continue;
            }

            dst[wi++] = src[ri++];
        }
        else  // state == 1
        {
            // Skip blank lines and leading whitespace before the value
            if (src[ri] == '\r' || src[ri] == '\n' || src[ri] == ' ' || src[ri] == '\t')
            {
                dst[wi++] = src[ri++];
                continue;
            }

            // This is the serial number value; write the spoofed one
            CopyMemory(dst + wi, spoofSerial, spoofSerialLen);
            wi += spoofSerialLen;
            // Skip the original serial value
            while (ri < srcLen && src[ri] != '\r' && src[ri] != '\n')
                ri++;
            g_WmicSerialState = 0;
            changed = TRUE;
        }
    }

    if (!changed)
    {
        HeapFree(GetProcessHeap(), 0, dst);
        return NULL;
    }

    *outLen = wi;
    return dst;
}

static LPWSTR PatchWmicOutputW(LPCWSTR src, DWORD srcCch, DWORD *outCch)
{
    static const WCHAR kHeader[]     = L"SerialNumber";
    static const DWORD kHeaderLen    = (DWORD)(ARRAYSIZE(kHeader) - 1);
    static const WCHAR kSerialDef[]  = L"None";
    static const WCHAR kSerialTrap[] = L"7X8K9P2";

    const WCHAR *spoofSerial    = (ObsGetMode() == OBS_MODE_DEFENSIVE)
                                  ? kSerialDef : kSerialTrap;
    DWORD        spoofSerialLen = (DWORD)(
        (ObsGetMode() == OBS_MODE_DEFENSIVE)
            ? ARRAYSIZE(kSerialDef)  - 1
            : ARRAYSIZE(kSerialTrap) - 1);

    DWORD  cap = srcCch + spoofSerialLen + 16;
    LPWSTR dst = (LPWSTR)HeapAlloc(GetProcessHeap(), 0, cap * sizeof(WCHAR));
    if (!dst) return NULL;

    BOOL  changed = FALSE;
    DWORD ri = 0, wi = 0;

    while (ri < srcCch && wi < cap)
    {
        if (g_WmicSerialState == 0)
        {
            DWORD rem = srcCch - ri;

            if (rem >= kHeaderLen &&
                _wcsnicmp(src + ri, kHeader, kHeaderLen) == 0)
            {
                CopyMemory(dst + wi, src + ri, kHeaderLen * sizeof(WCHAR));
                wi += kHeaderLen;
                ri += kHeaderLen;
                while (ri < srcCch && src[ri] != L'\n')
                    dst[wi++] = src[ri++];
                if (ri < srcCch)
                    dst[wi++] = src[ri++];  // L'\n'
                g_WmicSerialState = 1;
                continue;
            }

            dst[wi++] = src[ri++];
        }
        else  // state == 1
        {
            if (src[ri] == L'\r' || src[ri] == L'\n' ||
                src[ri] == L' '  || src[ri] == L'\t')
            {
                dst[wi++] = src[ri++];
                continue;
            }

            CopyMemory(dst + wi, spoofSerial, spoofSerialLen * sizeof(WCHAR));
            wi += spoofSerialLen;
            while (ri < srcCch && src[ri] != L'\r' && src[ri] != L'\n')
                ri++;
            g_WmicSerialState = 0;
            changed = TRUE;
        }
    }

    if (!changed)
    {
        HeapFree(GetProcessHeap(), 0, dst);
        return NULL;
    }

    *outCch = wi;
    return dst;
}

static BOOL WINAPI HookedWriteFile(
    HANDLE       hFile,
    LPCVOID      lpBuffer,
    DWORD        nNumberOfBytesToWrite,
    LPDWORD      lpNumberOfBytesWritten,
    LPOVERLAPPED lpOverlapped)
{
    if (ObsIsEnabled() && hFile == g_StdoutHandle &&
        lpBuffer && nNumberOfBytesToWrite > 0)
    {
        if (g_IsSystemInfo && ObsGetMode() == OBS_MODE_TRAP)
        {
            DWORD  pLen = 0;
            LPBYTE p    = PatchSysInfoOutput((LPCBYTE)lpBuffer, nNumberOfBytesToWrite, &pLen);
            if (p)
            {
                BOOL r = OriginalWriteFile(hFile, p, pLen, lpNumberOfBytesWritten, lpOverlapped);
                HeapFree(GetProcessHeap(), 0, p);
                if (lpNumberOfBytesWritten) *lpNumberOfBytesWritten = nNumberOfBytesToWrite;
                return r;
            }
        }
        else if (g_IsWmic)
        {
            // wmic writes UTF-16 LE to pipes/files; detect by checking if every
            // second byte is 0x00 (valid for ASCII-range content).
            BOOL wideOut = (nNumberOfBytesToWrite >= 4 &&
                            ((LPCBYTE)lpBuffer)[1] == 0x00);
            if (wideOut)
            {
                DWORD  pCch = 0;
                LPWSTR p    = PatchWmicOutputW((LPCWSTR)lpBuffer,
                                               nNumberOfBytesToWrite / sizeof(WCHAR), &pCch);
                if (p)
                {
                    BOOL r = OriginalWriteFile(hFile, p, pCch * sizeof(WCHAR),
                                               lpNumberOfBytesWritten, lpOverlapped);
                    HeapFree(GetProcessHeap(), 0, p);
                    if (lpNumberOfBytesWritten) *lpNumberOfBytesWritten = nNumberOfBytesToWrite;
                    return r;
                }
            }
            else
            {
                DWORD  pLen = 0;
                LPBYTE p    = PatchWmicOutput((LPCBYTE)lpBuffer, nNumberOfBytesToWrite, &pLen);
                if (p)
                {
                    BOOL r = OriginalWriteFile(hFile, p, pLen, lpNumberOfBytesWritten, lpOverlapped);
                    HeapFree(GetProcessHeap(), 0, p);
                    if (lpNumberOfBytesWritten) *lpNumberOfBytesWritten = nNumberOfBytesToWrite;
                    return r;
                }
            }
        }
    }
    return OriginalWriteFile(hFile, lpBuffer, nNumberOfBytesToWrite,
                             lpNumberOfBytesWritten, lpOverlapped);
}

static BOOL WINAPI HookedWriteConsoleA(
    HANDLE      hConsoleOutput,
    const VOID *lpBuffer,
    DWORD       nNumberOfCharsToWrite,
    LPDWORD     lpNumberOfCharsWritten,
    LPVOID      lpReserved)
{
    if (ObsIsEnabled() && hConsoleOutput == g_StdoutHandle &&
        lpBuffer && nNumberOfCharsToWrite > 0)
    {
        if (g_IsSystemInfo && ObsGetMode() == OBS_MODE_TRAP)
        {
            DWORD  pLen = 0;
            LPBYTE p    = PatchSysInfoOutput((LPCBYTE)lpBuffer, nNumberOfCharsToWrite, &pLen);
            if (p)
            {
                BOOL r = OriginalWriteConsoleA(hConsoleOutput, p, pLen,
                                               lpNumberOfCharsWritten, lpReserved);
                HeapFree(GetProcessHeap(), 0, p);
                if (lpNumberOfCharsWritten) *lpNumberOfCharsWritten = nNumberOfCharsToWrite;
                return r;
            }
        }
        else if (g_IsWmic)
        {
            DWORD  pLen = 0;
            LPBYTE p    = PatchWmicOutput((LPCBYTE)lpBuffer, nNumberOfCharsToWrite, &pLen);
            if (p)
            {
                BOOL r = OriginalWriteConsoleA(hConsoleOutput, p, pLen,
                                               lpNumberOfCharsWritten, lpReserved);
                HeapFree(GetProcessHeap(), 0, p);
                if (lpNumberOfCharsWritten) *lpNumberOfCharsWritten = nNumberOfCharsToWrite;
                return r;
            }
        }
    }
    return OriginalWriteConsoleA(hConsoleOutput, lpBuffer, nNumberOfCharsToWrite,
                                 lpNumberOfCharsWritten, lpReserved);
}

// Wide-string (WriteConsoleW) variant of PatchSysInfoOutput.
// Handles the ConPTY path on Windows 11 / Windows Terminal where
// systeminfo's UCRT detects a console handle and calls WriteConsoleW.
// Allocate and return a patched copy of [src, src+srcCch).
// Sets *outCch to the character count of the patched buffer.
// Returns NULL if no VM strings were found (caller uses original).
// Caller must HeapFree the returned pointer.
// Wide-string counterpart of EmitSysInfoLabelA (see there for behaviour).
static BOOL EmitSysInfoLabelW(LPWSTR dst, DWORD *pwi, DWORD cap,
                              LPCWSTR src, DWORD *pri, DWORD srcCch,
                              DWORD lblLen, LPCWSTR repl)
{
    DWORD wi = *pwi, ri = *pri;
    DWORD replLen = (DWORD)wcslen(repl);

    if (wi + lblLen > cap) return FALSE;
    CopyMemory(dst + wi, src + ri, lblLen * sizeof(WCHAR));
    wi += lblLen; ri += lblLen;

    while (ri < srcCch && src[ri] == L' ')
    {
        if (wi >= cap) return FALSE;
        dst[wi++] = src[ri++];
    }

    if (wi + replLen > cap) return FALSE;
    CopyMemory(dst + wi, repl, replLen * sizeof(WCHAR));
    wi += replLen;

    while (ri < srcCch && src[ri] != L'\r' && src[ri] != L'\n')
        ri++;

    *pwi = wi; *pri = ri;
    return TRUE;
}

static LPWSTR PatchSysInfoOutputW(LPCWSTR src, DWORD srcCch, DWORD *outCch)
{
    static const WCHAR kBiosPfx[]   = L"VMware, Inc. VMW";
    static const WCHAR kBiosRepl[]  = L"Dell Inc. 1.22.0, 04/14/2023";
    static const WCHAR kModelFind[] = L"VMware20,1";
    static const WCHAR kModelRepl[] = L"Precision 5560";
    static const WCHAR kMfgFind[]   = L"VMware, Inc.";
    static const WCHAR kMfgRepl[]   = L"Dell Inc.";

    const DWORD kBiosPfxLen   = (DWORD)(ARRAYSIZE(kBiosPfx)   - 1);
    const DWORD kBiosReplLen  = (DWORD)(ARRAYSIZE(kBiosRepl)   - 1);
    const DWORD kModelFindLen = (DWORD)(ARRAYSIZE(kModelFind)  - 1);
    const DWORD kModelReplLen = (DWORD)(ARRAYSIZE(kModelRepl)  - 1);
    const DWORD kMfgFindLen   = (DWORD)(ARRAYSIZE(kMfgFind)    - 1);
    const DWORD kMfgReplLen   = (DWORD)(ARRAYSIZE(kMfgRepl)    - 1);

    // Label-anchored replacements can be LONGER than the original value, so give
    // generous headroom (each field appears once) and bounds-check every emit.
    DWORD  cap = srcCch + 512;
    LPWSTR dst = (LPWSTR)HeapAlloc(GetProcessHeap(), 0, cap * sizeof(WCHAR));
    if (!dst) return NULL;

    // Field labels for the new Trap-mode fields.
    static const WCHAR kHostLbl[] = L"Host Name:";
    static const WCHAR kMemLbl[]  = L"Total Physical Memory:";
    static const WCHAR kDomLbl[]  = L"Domain:";
    static const WCHAR kProcLbl[] = L"Processor(s):";
    static const WCHAR kCpuLbl[]  = L"[01]: ";  // length of any "[0N]: " prefix
    const DWORD kHostLblLen = (DWORD)(ARRAYSIZE(kHostLbl) - 1);
    const DWORD kMemLblLen  = (DWORD)(ARRAYSIZE(kMemLbl)  - 1);
    const DWORD kDomLblLen  = (DWORD)(ARRAYSIZE(kDomLbl)  - 1);
    const DWORD kProcLblLen = (DWORD)(ARRAYSIZE(kProcLbl) - 1);
    const DWORD kCpuLblLen  = (DWORD)(ARRAYSIZE(kCpuLbl)  - 1);

    // Build the mode-appropriate replacement values once.
    WCHAR hostVal[128], memVal[64], domVal[256];
    BuildSysInfoHostName(hostVal, ARRAYSIZE(hostVal));
    BuildSysInfoMemory(memVal, ARRAYSIZE(memVal));
    BOOL  domOk = BuildSysInfoDomain(domVal, ARRAYSIZE(domVal));

    // Cross-call state (systeminfo.exe is single-shot, so process-static is safe).
    static int  s_pending   = OBS_SI_NONE;  // value awaited for a matched label
    static BOOL s_expectCpu = FALSE;         // inside the Processor(s) entry block
    static BOOL s_lineStart = TRUE;          // at the start of a logical line

    BOOL  changed = FALSE;
    DWORD ri = 0, wi = 0;

    while (ri < srcCch && wi < cap)
    {
        DWORD   rem = srcCch - ri;
        LPCWSTR p   = src + ri;

        // (1) A label was matched earlier; consume (and swap) its value, which
        //     may begin in a previous call and continue into this one.
        if (s_pending != OBS_SI_NONE)
        {
            WCHAR c = src[ri];
            if (c == L' ' || c == L'\t')          // copy the alignment padding
            {
                dst[wi++] = src[ri++];
                s_lineStart = FALSE;
                continue;
            }
            if (c != L'\r' && c != L'\n')         // first value char → replace
            {
                LPCWSTR repl = (s_pending == OBS_SI_HOST) ? hostVal :
                               (s_pending == OBS_SI_MEM)  ? memVal  : domVal;
                DWORD rlen = (DWORD)wcslen(repl);
                if (wi + rlen <= cap)
                {
                    CopyMemory(dst + wi, repl, rlen * sizeof(WCHAR));
                    wi += rlen;
                    while (ri < srcCch && src[ri] != L'\r' && src[ri] != L'\n')
                        ri++;                     // drop the real value
                    changed = TRUE;
                }
                else
                {
                    dst[wi++] = src[ri++];        // no room – leave value as-is
                }
                s_pending = OBS_SI_NONE;
                s_lineStart = FALSE;
                continue;
            }
            s_pending = OBS_SI_NONE;              // empty value – fall through
        }

        // (2) A column-0 line ends the Processor(s) entry block (entries are
        //     indented; the next real field label starts at column 0).
        if (s_expectCpu && s_lineStart && src[ri] != L' ')
            s_expectCpu = FALSE;

        // (3) Replace the CPU model on every "[0N]: ..." processor entry.
        //     Matched mid-line (NOT gated on line start) because systeminfo
        //     writes a line's indentation and its content as separate calls.
        //     EmitSysInfoLabelW copies the entry's own "[0N]: " prefix, so each
        //     entry keeps its index and only the model text is swapped.
        if (s_expectCpu && rem >= kCpuLblLen && src[ri] == L'[' && src[ri + 1] == L'0' &&
            EmitSysInfoLabelW(dst, &wi, cap, src, &ri, srcCch, kCpuLblLen, OBS_TRAP_CPU_SYSINFO))
        {
            changed = TRUE; s_lineStart = FALSE; continue;
        }

        // (4) Field labels: copy the label, then await its value in step (1).
        //     Processor(s): count line is left as-is; it only arms step (3).
        if (s_lineStart)
        {
            DWORD lbl = 0; int field = OBS_SI_NONE; BOOL isProc = FALSE;
            if      (rem >= kHostLblLen && _wcsnicmp(p, kHostLbl, kHostLblLen) == 0) { lbl = kHostLblLen; field = OBS_SI_HOST; }
            else if (rem >= kMemLblLen  && _wcsnicmp(p, kMemLbl,  kMemLblLen)  == 0) { lbl = kMemLblLen;  field = OBS_SI_MEM;  }
            else if (domOk && rem >= kDomLblLen && _wcsnicmp(p, kDomLbl, kDomLblLen) == 0) { lbl = kDomLblLen; field = OBS_SI_DOM; }
            else if (rem >= kProcLblLen && _wcsnicmp(p, kProcLbl, kProcLblLen) == 0) { lbl = kProcLblLen; isProc = TRUE; }

            if ((field != OBS_SI_NONE || isProc) && wi + lbl <= cap)
            {
                CopyMemory(dst + wi, src + ri, lbl * sizeof(WCHAR));
                wi += lbl; ri += lbl;
                if (isProc) s_expectCpu = TRUE;   // count line untouched
                else        s_pending   = field;
                s_lineStart = FALSE;
                continue;
            }
        }

        // (4) Existing value-based BIOS patterns.

        // Pattern 1: BIOS version prefix → replace value up to EOL
        if (rem >= kBiosPfxLen &&
            _wcsnicmp(p, kBiosPfx, kBiosPfxLen) == 0)
        {
            CopyMemory(dst + wi, kBiosRepl, kBiosReplLen * sizeof(WCHAR));
            wi += kBiosReplLen;
            ri += kBiosPfxLen;
            // Skip the rest of the original VMware BIOS version string
            while (ri < srcCch && src[ri] != L'\r' && src[ri] != L'\n')
                ri++;
            changed = TRUE; s_lineStart = FALSE;
            continue;
        }

        // Pattern 2: model string
        if (rem >= kModelFindLen &&
            _wcsnicmp(p, kModelFind, kModelFindLen) == 0)
        {
            CopyMemory(dst + wi, kModelRepl, kModelReplLen * sizeof(WCHAR));
            wi += kModelReplLen;
            ri += kModelFindLen;
            changed = TRUE; s_lineStart = FALSE;
            continue;
        }

        // Pattern 3: manufacturer (must follow pattern 1 to avoid double-hit)
        if (rem >= kMfgFindLen &&
            _wcsnicmp(p, kMfgFind, kMfgFindLen) == 0)
        {
            CopyMemory(dst + wi, kMfgRepl, kMfgReplLen * sizeof(WCHAR));
            wi += kMfgReplLen;
            ri += kMfgFindLen;
            changed = TRUE; s_lineStart = FALSE;
            continue;
        }

        // (5) Default copy.
        s_lineStart = (src[ri] == L'\n');
        dst[wi++] = src[ri++];
    }

    if (!changed)
    {
        HeapFree(GetProcessHeap(), 0, dst);
        return NULL;
    }

    *outCch = wi;
    return dst;
}

static BOOL WINAPI HookedWriteConsoleW(
    HANDLE      hConsoleOutput,
    const VOID *lpBuffer,
    DWORD       nNumberOfCharsToWrite,
    LPDWORD     lpNumberOfCharsWritten,
    LPVOID      lpReserved)
{
    if (ObsIsEnabled() && hConsoleOutput == g_StdoutHandle &&
        lpBuffer && nNumberOfCharsToWrite > 0)
    {
        if (g_IsSystemInfo && ObsGetMode() == OBS_MODE_TRAP)
        {
            DWORD  pCch = 0;
            LPWSTR p    = PatchSysInfoOutputW((LPCWSTR)lpBuffer, nNumberOfCharsToWrite, &pCch);
            if (p)
            {
                BOOL r = OriginalWriteConsoleW(hConsoleOutput, p, pCch,
                                               lpNumberOfCharsWritten, lpReserved);
                HeapFree(GetProcessHeap(), 0, p);
                if (lpNumberOfCharsWritten) *lpNumberOfCharsWritten = nNumberOfCharsToWrite;
                return r;
            }
        }
        else if (g_IsWmic)
        {
            DWORD  pCch = 0;
            LPWSTR p    = PatchWmicOutputW((LPCWSTR)lpBuffer, nNumberOfCharsToWrite, &pCch);
            if (p)
            {
                BOOL r = OriginalWriteConsoleW(hConsoleOutput, p, pCch,
                                               lpNumberOfCharsWritten, lpReserved);
                HeapFree(GetProcessHeap(), 0, p);
                if (lpNumberOfCharsWritten) *lpNumberOfCharsWritten = nNumberOfCharsToWrite;
                return r;
            }
        }
    }
    return OriginalWriteConsoleW(hConsoleOutput, lpBuffer, nNumberOfCharsToWrite,
                                 lpNumberOfCharsWritten, lpReserved);
}

// ============================================================
//  NetGetJoinInformation hook
//
//  Win32_ComputerSystem.PartOfDomain and .Domain are both backed
//  by NetGetJoinInformation (netapi32.dll).  This covers:
//    Get-WmiObject  -Class Win32_ComputerSystem | Select PartOfDomain
//    Get-CimInstance -ClassName Win32_ComputerSystem | Select PartOfDomain
//
//  When DomainMode = 0 (OFF):       passes through – real domain info returned
//  When DomainMode = 1 (WORKGROUP): reports WORKGROUP / PartOfDomain = False
//  When DomainMode = 2 (JOINED):    reports CORP.DEV  / PartOfDomain = True
// ============================================================

// NetSetupJoinStatus values (from lmjoin.h – defined inline to avoid lm.h dependency)
#define OBS_NetSetupWorkgroupName  2
#define OBS_NetSetupDomainName     3

typedef DWORD (WINAPI *PFN_NetGetJoinInformation)(LPCWSTR, LPWSTR *, DWORD *);
typedef DWORD (WINAPI *PFN_NetApiBufferAllocate)(DWORD, LPVOID *);
typedef DWORD (WINAPI *PFN_NetApiBufferFree)(LPVOID);

static PFN_NetGetJoinInformation OriginalNetGetJoinInformation = NULL;
static PFN_NetApiBufferAllocate  g_NetApiBufferAllocate        = NULL;

static DWORD WINAPI HookedNetGetJoinInformation(
    LPCWSTR lpServer, LPWSTR *lpNameBuffer, DWORD *BufferType)
{
    if (!ObsIsEnabled() || !lpNameBuffer || !BufferType)
        return OriginalNetGetJoinInformation(lpServer, lpNameBuffer, BufferType);

    DWORD domainMode = ObsGetDomainMode();
    if (domainMode == OBS_DOMAIN_MODE_OFF)
        return OriginalNetGetJoinInformation(lpServer, lpNameBuffer, BufferType);

    WCHAR domainName[256];
    ObsGetSpoofDomainName(domainName, 256);
    DWORD spoofStatus = (domainMode == OBS_DOMAIN_MODE_JOINED)
                        ? OBS_NetSetupDomainName
                        : OBS_NetSetupWorkgroupName;

    // Allocate the output buffer via NetApiBufferAllocate so the caller
    // can free it normally with NetApiBufferFree.
    DWORD nameBytes = (DWORD)(wcslen(domainName) + 1) * sizeof(WCHAR);
    LPVOID buf = NULL;
    if (g_NetApiBufferAllocate &&
        g_NetApiBufferAllocate(nameBytes, &buf) == 0 && buf)
    {
        CopyMemory(buf, domainName, nameBytes);
        *lpNameBuffer = (LPWSTR)buf;
        *BufferType   = spoofStatus;
        return 0; // NERR_Success
    }

    // Allocation failed – fall through to original
    return OriginalNetGetJoinInformation(lpServer, lpNameBuffer, BufferType);
}

// ============================================================
//  Detours attach / detach helpers
// ============================================================

// Resolve a function from a DLL and return a pointer, or NULL on failure.
static LPVOID ResolveFunction(LPCSTR dll, LPCSTR function)
{
    HMODULE hMod = GetModuleHandleA(dll);
    if (!hMod) hMod = LoadLibraryA(dll);
    if (!hMod) return NULL;
    return (LPVOID)GetProcAddress(hMod, function);
}

// Convenience wrappers for ntdll functions (GetProcAddress on ntdll.dll)
#define RESOLVE_NTDLL(name)  ResolveFunction("ntdll.dll", #name)
#define RESOLVE_K32(name)    ResolveFunction("kernel32.dll", #name)
#define RESOLVE_ADV(name)    ResolveFunction("advapi32.dll", #name)
#define RESOLVE_USER(name)   ResolveFunction("user32.dll", #name)
#define RESOLVE_IPHLP(name)  ResolveFunction("iphlpapi.dll", #name)

VOID InitializeHooks(VOID)
{
    // Allocate TLS slots for NtEnumerateKey O(N) cache
    TlsEnumKeyCacheKey            = TlsAlloc();
    TlsEnumKeyCacheIndex          = TlsAlloc();
    TlsEnumKeyCacheI              = TlsAlloc();
    TlsEnumKeyCacheCorrectedIndex = TlsAlloc();

    // Detect systeminfo.exe and wmic.exe – only install stdout hooks there
    {
        CHAR path[MAX_PATH] = { 0 };
        GetModuleFileNameA(NULL, path, MAX_PATH);
        CHAR *last = strrchr(path, '\\');
        g_IsSystemInfo = (last != NULL && _stricmp(last + 1, "systeminfo.exe") == 0);
        g_IsWmic       = (last != NULL && _stricmp(last + 1, "wmic.exe")       == 0);
        g_IsWhoami     = (last != NULL && _stricmp(last + 1, "whoami.exe")     == 0);
        if (g_IsSystemInfo || g_IsWmic)
        {
            // Resolve from kernelbase.dll (actual implementation), not kernel32 forwarding
            // stubs.  Modern executables import WriteFile and WriteConsoleA/W directly from
            // kernelbase via the ApiSet, so hooking the kernel32 stub leaves the IAT un-patched.
            // WriteConsoleW covers the ConPTY / Windows Terminal path (wide console output).
            g_StdoutHandle        = GetStdHandle(STD_OUTPUT_HANDLE);
            OriginalWriteFile     = (BOOL(WINAPI*)(HANDLE,LPCVOID,DWORD,LPDWORD,LPOVERLAPPED)) ResolveFunction("kernelbase.dll", "WriteFile");
            OriginalWriteConsoleA = (BOOL(WINAPI*)(HANDLE,const VOID*,DWORD,LPDWORD,LPVOID))   ResolveFunction("kernelbase.dll", "WriteConsoleA");
            OriginalWriteConsoleW = (BOOL(WINAPI*)(HANDLE,const VOID*,DWORD,LPDWORD,LPVOID))   ResolveFunction("kernelbase.dll", "WriteConsoleW");
        }
    }

    // Resolve originals
    OriginalGetUserNameW           = (BOOL  (WINAPI*)(LPWSTR,LPDWORD))               RESOLVE_ADV(GetUserNameW);
    OriginalGetUserNameA           = (BOOL  (WINAPI*)(LPSTR, LPDWORD))               RESOLVE_ADV(GetUserNameA);
    OriginalGetComputerNameExW     = (BOOL  (WINAPI*)(COMPUTER_NAME_FORMAT,LPWSTR,LPDWORD)) RESOLVE_K32(GetComputerNameExW);
    OriginalGetComputerNameExA     = (BOOL  (WINAPI*)(COMPUTER_NAME_FORMAT,LPSTR,LPDWORD))  RESOLVE_K32(GetComputerNameExA);
    OriginalGlobalMemoryStatusEx   = (VOID  (WINAPI*)(LPMEMORYSTATUSEX))             RESOLVE_K32(GlobalMemoryStatusEx);
    OriginalEnumDisplaySettingsW   = (BOOL  (WINAPI*)(LPCWSTR,DWORD,LPDEVMODEW))     RESOLVE_USER(EnumDisplaySettingsW);
    OriginalGetSystemMetrics       = (int   (WINAPI*)(int))                           RESOLVE_USER(GetSystemMetrics);
    OriginalGetAdaptersAddresses   = (ULONG (WINAPI*)(ULONG,ULONG,PVOID,PIP_ADAPTER_ADDRESSES,PULONG)) RESOLVE_IPHLP(GetAdaptersAddresses);
    OriginalGetAdaptersInfo        = (DWORD (WINAPI*)(PIP_ADAPTER_INFO,PULONG))       RESOLVE_IPHLP(GetAdaptersInfo);
    OriginalEnumServicesStatusExW  = (BOOL  (WINAPI*)(SC_HANDLE,SC_ENUM_TYPE,DWORD,DWORD,LPBYTE,DWORD,LPDWORD,LPDWORD,LPDWORD,LPCWSTR)) RESOLVE_ADV(EnumServicesStatusExW);
    OriginalEnumServicesStatusExA  = (BOOL  (WINAPI*)(SC_HANDLE,SC_ENUM_TYPE,DWORD,DWORD,LPBYTE,DWORD,LPDWORD,LPDWORD,LPDWORD,LPCSTR))  RESOLVE_ADV(EnumServicesStatusExA);
    OriginalEnumServicesStatusW    = (BOOL  (WINAPI*)(SC_HANDLE,DWORD,DWORD,LPBYTE,DWORD,LPDWORD,LPDWORD,LPDWORD)) RESOLVE_ADV(EnumServicesStatusW);
    OriginalEnumServicesStatusA    = (BOOL  (WINAPI*)(SC_HANDLE,DWORD,DWORD,LPBYTE,DWORD,LPDWORD,LPDWORD,LPDWORD)) RESOLVE_ADV(EnumServicesStatusA);
    OriginalNtQuerySystemInformation = (NT_NTQUERYSYSTEMINFORMATION)RESOLVE_NTDLL(NtQuerySystemInformation);
    OriginalNtEnumerateKey           = (NT_NTENUMERATEKEY)          RESOLVE_NTDLL(NtEnumerateKey);
    OriginalNtQueryKey               = (NT_NTQUERYKEY)              RESOLVE_NTDLL(NtQueryKey);
    OriginalNtQueryValueKey          = (NT_NTQUERYVALUEKEY)         RESOLVE_NTDLL(NtQueryValueKey);
    OriginalGetSystemFirmwareTable   = (UINT(WINAPI*)(DWORD,DWORD,PVOID,DWORD)) RESOLVE_K32(GetSystemFirmwareTable);
    OriginalCreateProcessW           = (BOOL(WINAPI*)(LPCWSTR,LPWSTR,LPSECURITY_ATTRIBUTES,LPSECURITY_ATTRIBUTES,BOOL,DWORD,LPVOID,LPCWSTR,LPSTARTUPINFOW,LPPROCESS_INFORMATION)) RESOLVE_K32(CreateProcessW);
    OriginalCreateProcessA           = (BOOL(WINAPI*)(LPCSTR,LPSTR,LPSECURITY_ATTRIBUTES,LPSECURITY_ATTRIBUTES,BOOL,DWORD,LPVOID,LPCSTR,LPSTARTUPINFOA,LPPROCESS_INFORMATION))  RESOLVE_K32(CreateProcessA);
    OriginalNetGetJoinInformation    = (PFN_NetGetJoinInformation) ResolveFunction("netapi32.dll", "NetGetJoinInformation");
    g_NetApiBufferAllocate           = (PFN_NetApiBufferAllocate)  ResolveFunction("netapi32.dll", "NetApiBufferAllocate");
    OriginalGetUserNameExW           = (PFN_GetUserNameExW)        ResolveFunction("secur32.dll", "GetUserNameExW");
    OriginalLookupAccountSidW        = (PFN_LookupAccountSidW)     RESOLVE_ADV(LookupAccountSidW);

    // Begin Detours transaction
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    if (OriginalGetUserNameW)          DetourAttach(&(PVOID)OriginalGetUserNameW,          HookedGetUserNameW);
    if (OriginalGetUserNameA)          DetourAttach(&(PVOID)OriginalGetUserNameA,          HookedGetUserNameA);
    if (OriginalGetComputerNameExW)    DetourAttach(&(PVOID)OriginalGetComputerNameExW,    HookedGetComputerNameExW);
    if (OriginalGetComputerNameExA)    DetourAttach(&(PVOID)OriginalGetComputerNameExA,    HookedGetComputerNameExA);
    if (OriginalGlobalMemoryStatusEx)  DetourAttach(&(PVOID)OriginalGlobalMemoryStatusEx,  HookedGlobalMemoryStatusEx);
    if (OriginalEnumDisplaySettingsW)  DetourAttach(&(PVOID)OriginalEnumDisplaySettingsW,  HookedEnumDisplaySettingsW);
    if (OriginalGetSystemMetrics)      DetourAttach(&(PVOID)OriginalGetSystemMetrics,      HookedGetSystemMetrics);
    if (OriginalGetAdaptersAddresses)  DetourAttach(&(PVOID)OriginalGetAdaptersAddresses,  HookedGetAdaptersAddresses);
    if (OriginalGetAdaptersInfo)       DetourAttach(&(PVOID)OriginalGetAdaptersInfo,       HookedGetAdaptersInfo);
    if (OriginalEnumServicesStatusExW) DetourAttach(&(PVOID)OriginalEnumServicesStatusExW, HookedEnumServicesStatusExW);
    if (OriginalEnumServicesStatusExA) DetourAttach(&(PVOID)OriginalEnumServicesStatusExA, HookedEnumServicesStatusExA);
    if (OriginalEnumServicesStatusW)   DetourAttach(&(PVOID)OriginalEnumServicesStatusW,   HookedEnumServicesStatusW);
    if (OriginalEnumServicesStatusA)   DetourAttach(&(PVOID)OriginalEnumServicesStatusA,   HookedEnumServicesStatusA);
    if (OriginalNtQuerySystemInformation) DetourAttach(&(PVOID)OriginalNtQuerySystemInformation, HookedNtQuerySystemInformation);
    if (OriginalNtEnumerateKey)        DetourAttach(&(PVOID)OriginalNtEnumerateKey,        HookedNtEnumerateKey);
    if (OriginalNtQueryKey)            DetourAttach(&(PVOID)OriginalNtQueryKey,            HookedNtQueryKey);
    if (OriginalNtQueryValueKey)          DetourAttach(&(PVOID)OriginalNtQueryValueKey,          HookedNtQueryValueKey);
    if (OriginalGetSystemFirmwareTable)   DetourAttach(&(PVOID)OriginalGetSystemFirmwareTable,   HookedGetSystemFirmwareTable);
    if (OriginalCreateProcessW)           DetourAttach(&(PVOID)OriginalCreateProcessW,           HookedCreateProcessW);
    if (OriginalCreateProcessA)           DetourAttach(&(PVOID)OriginalCreateProcessA,           HookedCreateProcessA);
    if (OriginalNetGetJoinInformation)    DetourAttach(&(PVOID)OriginalNetGetJoinInformation,    HookedNetGetJoinInformation);
    if (OriginalGetUserNameExW)           DetourAttach(&(PVOID)OriginalGetUserNameExW,           HookedGetUserNameExW);
    // LookupAccountSidW is used by the security/COM stack (e.g. systeminfo's WMI
    // client resolves the current-user SID during connection setup); spoofing it
    // process-wide breaks those.  Only whoami.exe needs it, so scope it there.
    if (g_IsWhoami && OriginalLookupAccountSidW)
        DetourAttach(&(PVOID)OriginalLookupAccountSidW, HookedLookupAccountSidW);
    if (g_IsSystemInfo || g_IsWmic)
    {
        if (OriginalWriteFile)            DetourAttach(&(PVOID)OriginalWriteFile,            HookedWriteFile);
        if (OriginalWriteConsoleA)        DetourAttach(&(PVOID)OriginalWriteConsoleA,        HookedWriteConsoleA);
        if (OriginalWriteConsoleW)        DetourAttach(&(PVOID)OriginalWriteConsoleW,        HookedWriteConsoleW);
    }

    DetourTransactionCommit();

    // Injection-confirmation trace removed for release builds.  To bring it
    // back while debugging, re-add here:
    //   WCHAR procPath[MAX_PATH] = { 0 };
    //   GetModuleFileNameW(NULL, procPath, MAX_PATH);
    //   WCHAR dbg[MAX_PATH + 64];
    //   wsprintfW(dbg, L"[Obs] Agent initialized in: %s\n", procPath);
    //   OutputDebugStringW(dbg);
}

VOID UninitializeHooks(VOID)
{
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    if (OriginalGetUserNameW)          DetourDetach(&(PVOID)OriginalGetUserNameW,          HookedGetUserNameW);
    if (OriginalGetUserNameA)          DetourDetach(&(PVOID)OriginalGetUserNameA,          HookedGetUserNameA);
    if (OriginalGetComputerNameExW)    DetourDetach(&(PVOID)OriginalGetComputerNameExW,    HookedGetComputerNameExW);
    if (OriginalGetComputerNameExA)    DetourDetach(&(PVOID)OriginalGetComputerNameExA,    HookedGetComputerNameExA);
    if (OriginalGlobalMemoryStatusEx)  DetourDetach(&(PVOID)OriginalGlobalMemoryStatusEx,  HookedGlobalMemoryStatusEx);
    if (OriginalEnumDisplaySettingsW)  DetourDetach(&(PVOID)OriginalEnumDisplaySettingsW,  HookedEnumDisplaySettingsW);
    if (OriginalGetSystemMetrics)      DetourDetach(&(PVOID)OriginalGetSystemMetrics,      HookedGetSystemMetrics);
    if (OriginalGetAdaptersAddresses)  DetourDetach(&(PVOID)OriginalGetAdaptersAddresses,  HookedGetAdaptersAddresses);
    if (OriginalGetAdaptersInfo)       DetourDetach(&(PVOID)OriginalGetAdaptersInfo,       HookedGetAdaptersInfo);
    if (OriginalEnumServicesStatusExW) DetourDetach(&(PVOID)OriginalEnumServicesStatusExW, HookedEnumServicesStatusExW);
    if (OriginalEnumServicesStatusExA) DetourDetach(&(PVOID)OriginalEnumServicesStatusExA, HookedEnumServicesStatusExA);
    if (OriginalEnumServicesStatusW)   DetourDetach(&(PVOID)OriginalEnumServicesStatusW,   HookedEnumServicesStatusW);
    if (OriginalEnumServicesStatusA)   DetourDetach(&(PVOID)OriginalEnumServicesStatusA,   HookedEnumServicesStatusA);
    if (OriginalNtQuerySystemInformation) DetourDetach(&(PVOID)OriginalNtQuerySystemInformation, HookedNtQuerySystemInformation);
    if (OriginalNtEnumerateKey)        DetourDetach(&(PVOID)OriginalNtEnumerateKey,        HookedNtEnumerateKey);
    if (OriginalNtQueryKey)            DetourDetach(&(PVOID)OriginalNtQueryKey,            HookedNtQueryKey);
    if (OriginalNtQueryValueKey)          DetourDetach(&(PVOID)OriginalNtQueryValueKey,          HookedNtQueryValueKey);
    if (OriginalGetSystemFirmwareTable)   DetourDetach(&(PVOID)OriginalGetSystemFirmwareTable,   HookedGetSystemFirmwareTable);
    if (OriginalCreateProcessW)           DetourDetach(&(PVOID)OriginalCreateProcessW,           HookedCreateProcessW);
    if (OriginalCreateProcessA)           DetourDetach(&(PVOID)OriginalCreateProcessA,           HookedCreateProcessA);
    if (OriginalNetGetJoinInformation)    DetourDetach(&(PVOID)OriginalNetGetJoinInformation,    HookedNetGetJoinInformation);
    if (OriginalGetUserNameExW)           DetourDetach(&(PVOID)OriginalGetUserNameExW,           HookedGetUserNameExW);
    if (g_IsWhoami && OriginalLookupAccountSidW)
        DetourDetach(&(PVOID)OriginalLookupAccountSidW, HookedLookupAccountSidW);
    if (g_IsSystemInfo || g_IsWmic)
    {
        if (OriginalWriteFile)            DetourDetach(&(PVOID)OriginalWriteFile,            HookedWriteFile);
        if (OriginalWriteConsoleA)        DetourDetach(&(PVOID)OriginalWriteConsoleA,        HookedWriteConsoleA);
        if (OriginalWriteConsoleW)        DetourDetach(&(PVOID)OriginalWriteConsoleW,        HookedWriteConsoleW);
    }

    DetourTransactionCommit();

    // Free TLS slots
    if (TlsEnumKeyCacheKey            != TLS_OUT_OF_INDEXES) TlsFree(TlsEnumKeyCacheKey);
    if (TlsEnumKeyCacheIndex          != TLS_OUT_OF_INDEXES) TlsFree(TlsEnumKeyCacheIndex);
    if (TlsEnumKeyCacheI              != TLS_OUT_OF_INDEXES) TlsFree(TlsEnumKeyCacheI);
    if (TlsEnumKeyCacheCorrectedIndex != TLS_OUT_OF_INDEXES) TlsFree(TlsEnumKeyCacheCorrectedIndex);
}
