// winsock2.h MUST come before Windows.h / Hooks.h.
// <iptypes.h> (pulled by iphlpapi.h) needs ws2def.h structs for
// IP_ADAPTER_ADDRESSES.  Including winsock2.h first sets _WINSOCK2API_
// so that Windows.h skips the incompatible winsock.h (v1).
#include <winsock2.h>
#include <ws2tcpip.h>

#include "Hooks.h"
#include "Config.h"
#include "Spoof.h"
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

// ntdll
static NT_NTQUERYSYSTEMINFORMATION  OriginalNtQuerySystemInformation  = NULL;
static NT_NTENUMERATEKEY            OriginalNtEnumerateKey            = NULL;
static NT_NTQUERYKEY                OriginalNtQueryKey                = NULL;
static NT_NTQUERYVALUEKEY           OriginalNtQueryValueKey           = NULL;

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
    BOOL result = OriginalEnumDisplaySettingsW(lpszDeviceName, iModeNum, lpDevMode);
    if (!result || !ObsIsEnabled()) return result;

    // Only alter the ENUM_CURRENT_SETTINGS / ENUM_REGISTRY_SETTINGS queries
    if (iModeNum != ENUM_CURRENT_SETTINGS && iModeNum != ENUM_REGISTRY_SETTINGS)
        return result;

    DWORD w, h;
    ObsGetSpoofResolution(&w, &h);
    lpDevMode->dmPelsWidth  = w;
    lpDevMode->dmPelsHeight = h;
    return TRUE;
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
//  Trap mode: suppress VM-vendor subkeys when SOFTWARE is
//  enumerated (hides VMware, Inc. and Oracle/VirtualBox keys).
//  Uses the same TLS-cache O(N) pattern from r77.
// ------------------------------------------------------------
static NTSTATUS NTAPI HookedNtEnumerateKey(
    HANDLE                  Key,
    ULONG                   Index,
    NT_KEY_INFORMATION_CLASS KeyInformationClass,
    LPVOID                  KeyInformation,
    ULONG                   KeyInformationLength,
    PULONG                  ResultLength)
{
    if (!ObsIsEnabled() || ObsGetMode() != OBS_MODE_TRAP)
        return OriginalNtEnumerateKey(Key, Index, KeyInformationClass,
                                      KeyInformation, KeyInformationLength,
                                      ResultLength);

    // Skip NodeInformation class (r77 pattern – avoids edge cases)
    if (KeyInformationClass == KeyNodeInformation)
        return OriginalNtEnumerateKey(Key, Index, KeyInformationClass,
                                      KeyInformation, KeyInformationLength,
                                      ResultLength);

    // Retrieve TLS cache for O(N) sequential enumeration.
    // Cast via ULONG_PTR to suppress C4311 pointer-truncation warning.
    HANDLE cacheKey            = (HANDLE)                    TlsGetValue(TlsEnumKeyCacheKey);
    ULONG  cacheIndex          = (ULONG)(ULONG_PTR)          TlsGetValue(TlsEnumKeyCacheIndex);
    ULONG  cacheI              = (ULONG)(ULONG_PTR)          TlsGetValue(TlsEnumKeyCacheI);
    ULONG  cacheCorrectedIndex = (ULONG)(ULONG_PTR)          TlsGetValue(TlsEnumKeyCacheCorrectedIndex);

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

        if (!IsVmRegistryVendorKey(basic->Name))
        {
            i++;  // Advance logical index only for non-hidden keys
        }
    }

    // correctedIndex now points to the actual raw entry matching logical Index.
    // Update TLS cache.
    TlsSetValue(TlsEnumKeyCacheKey,            Key);
    TlsSetValue(TlsEnumKeyCacheIndex,          (LPVOID)(ULONG_PTR)Index);
    TlsSetValue(TlsEnumKeyCacheI,              (LPVOID)(ULONG_PTR)(i - 1));
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

    if (!NT_SUCCESS(status) || !ObsIsEnabled() || ObsGetMode() != OBS_MODE_TRAP)
        return status;

    if (KeyInformationClass != KeyFullInformation &&
        KeyInformationClass != KeyCachedInformation)
        return status;

    // Count how many subkeys are VM vendor keys so we can correct the count.
    BYTE  buffer[1024];
    PNT_KEY_BASIC_INFORMATION basic = (PNT_KEY_BASIC_INFORMATION)buffer;
    ULONG hiddenSubKeys = 0;

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

    if (hiddenSubKeys == 0) return status;

    if (KeyInformationClass == KeyFullInformation)
        ((PNT_KEY_FULL_INFORMATION)KeyInformation)->SubKeys -= hiddenSubKeys;
    else
        ((PNT_KEY_CACHED_INFORMATION)KeyInformation)->SubKeys -= hiddenSubKeys;

    return status;
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

    // Resolve originals
    OriginalGetUserNameW           = (BOOL  (WINAPI*)(LPWSTR,LPDWORD))               RESOLVE_ADV(GetUserNameW);
    OriginalGetUserNameA           = (BOOL  (WINAPI*)(LPSTR, LPDWORD))               RESOLVE_ADV(GetUserNameA);
    OriginalGetComputerNameExW     = (BOOL  (WINAPI*)(COMPUTER_NAME_FORMAT,LPWSTR,LPDWORD)) RESOLVE_K32(GetComputerNameExW);
    OriginalGetComputerNameExA     = (BOOL  (WINAPI*)(COMPUTER_NAME_FORMAT,LPSTR,LPDWORD))  RESOLVE_K32(GetComputerNameExA);
    OriginalGlobalMemoryStatusEx   = (VOID  (WINAPI*)(LPMEMORYSTATUSEX))             RESOLVE_K32(GlobalMemoryStatusEx);
    OriginalEnumDisplaySettingsW   = (BOOL  (WINAPI*)(LPCWSTR,DWORD,LPDEVMODEW))     RESOLVE_USER(EnumDisplaySettingsW);
    OriginalGetAdaptersAddresses   = (ULONG (WINAPI*)(ULONG,ULONG,PVOID,PIP_ADAPTER_ADDRESSES,PULONG)) RESOLVE_IPHLP(GetAdaptersAddresses);
    OriginalGetAdaptersInfo        = (DWORD (WINAPI*)(PIP_ADAPTER_INFO,PULONG))       RESOLVE_IPHLP(GetAdaptersInfo);
    OriginalEnumServicesStatusExW  = (BOOL  (WINAPI*)(SC_HANDLE,SC_ENUM_TYPE,DWORD,DWORD,LPBYTE,DWORD,LPDWORD,LPDWORD,LPDWORD,LPCWSTR)) RESOLVE_ADV(EnumServicesStatusExW);
    OriginalEnumServicesStatusExA  = (BOOL  (WINAPI*)(SC_HANDLE,SC_ENUM_TYPE,DWORD,DWORD,LPBYTE,DWORD,LPDWORD,LPDWORD,LPDWORD,LPCSTR))  RESOLVE_ADV(EnumServicesStatusExA);
    OriginalNtQuerySystemInformation = (NT_NTQUERYSYSTEMINFORMATION)RESOLVE_NTDLL(NtQuerySystemInformation);
    OriginalNtEnumerateKey           = (NT_NTENUMERATEKEY)          RESOLVE_NTDLL(NtEnumerateKey);
    OriginalNtQueryKey               = (NT_NTQUERYKEY)              RESOLVE_NTDLL(NtQueryKey);
    OriginalNtQueryValueKey          = (NT_NTQUERYVALUEKEY)         RESOLVE_NTDLL(NtQueryValueKey);

    // Begin Detours transaction
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    if (OriginalGetUserNameW)          DetourAttach(&(PVOID)OriginalGetUserNameW,          HookedGetUserNameW);
    if (OriginalGetUserNameA)          DetourAttach(&(PVOID)OriginalGetUserNameA,          HookedGetUserNameA);
    if (OriginalGetComputerNameExW)    DetourAttach(&(PVOID)OriginalGetComputerNameExW,    HookedGetComputerNameExW);
    if (OriginalGetComputerNameExA)    DetourAttach(&(PVOID)OriginalGetComputerNameExA,    HookedGetComputerNameExA);
    if (OriginalGlobalMemoryStatusEx)  DetourAttach(&(PVOID)OriginalGlobalMemoryStatusEx,  HookedGlobalMemoryStatusEx);
    if (OriginalEnumDisplaySettingsW)  DetourAttach(&(PVOID)OriginalEnumDisplaySettingsW,  HookedEnumDisplaySettingsW);
    if (OriginalGetAdaptersAddresses)  DetourAttach(&(PVOID)OriginalGetAdaptersAddresses,  HookedGetAdaptersAddresses);
    if (OriginalGetAdaptersInfo)       DetourAttach(&(PVOID)OriginalGetAdaptersInfo,       HookedGetAdaptersInfo);
    if (OriginalEnumServicesStatusExW) DetourAttach(&(PVOID)OriginalEnumServicesStatusExW, HookedEnumServicesStatusExW);
    if (OriginalEnumServicesStatusExA) DetourAttach(&(PVOID)OriginalEnumServicesStatusExA, HookedEnumServicesStatusExA);
    if (OriginalNtQuerySystemInformation) DetourAttach(&(PVOID)OriginalNtQuerySystemInformation, HookedNtQuerySystemInformation);
    if (OriginalNtEnumerateKey)        DetourAttach(&(PVOID)OriginalNtEnumerateKey,        HookedNtEnumerateKey);
    if (OriginalNtQueryKey)            DetourAttach(&(PVOID)OriginalNtQueryKey,            HookedNtQueryKey);
    if (OriginalNtQueryValueKey)       DetourAttach(&(PVOID)OriginalNtQueryValueKey,       HookedNtQueryValueKey);

    DetourTransactionCommit();
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
    if (OriginalGetAdaptersAddresses)  DetourDetach(&(PVOID)OriginalGetAdaptersAddresses,  HookedGetAdaptersAddresses);
    if (OriginalGetAdaptersInfo)       DetourDetach(&(PVOID)OriginalGetAdaptersInfo,       HookedGetAdaptersInfo);
    if (OriginalEnumServicesStatusExW) DetourDetach(&(PVOID)OriginalEnumServicesStatusExW, HookedEnumServicesStatusExW);
    if (OriginalEnumServicesStatusExA) DetourDetach(&(PVOID)OriginalEnumServicesStatusExA, HookedEnumServicesStatusExA);
    if (OriginalNtQuerySystemInformation) DetourDetach(&(PVOID)OriginalNtQuerySystemInformation, HookedNtQuerySystemInformation);
    if (OriginalNtEnumerateKey)        DetourDetach(&(PVOID)OriginalNtEnumerateKey,        HookedNtEnumerateKey);
    if (OriginalNtQueryKey)            DetourDetach(&(PVOID)OriginalNtQueryKey,            HookedNtQueryKey);
    if (OriginalNtQueryValueKey)       DetourDetach(&(PVOID)OriginalNtQueryValueKey,       HookedNtQueryValueKey);

    DetourTransactionCommit();

    // Free TLS slots
    if (TlsEnumKeyCacheKey            != TLS_OUT_OF_INDEXES) TlsFree(TlsEnumKeyCacheKey);
    if (TlsEnumKeyCacheIndex          != TLS_OUT_OF_INDEXES) TlsFree(TlsEnumKeyCacheIndex);
    if (TlsEnumKeyCacheI              != TLS_OUT_OF_INDEXES) TlsFree(TlsEnumKeyCacheI);
    if (TlsEnumKeyCacheCorrectedIndex != TLS_OUT_OF_INDEXES) TlsFree(TlsEnumKeyCacheCorrectedIndex);
}
