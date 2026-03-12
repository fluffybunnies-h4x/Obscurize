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

// kernel32 – SMBIOS firmware table
static UINT (WINAPI *OriginalGetSystemFirmwareTable)(DWORD, DWORD, PVOID, DWORD) = NULL;

// kernel32 – process creation
static BOOL (WINAPI *OriginalCreateProcessW)(LPCWSTR, LPWSTR,
    LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD,
    LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION)          = NULL;
static BOOL (WINAPI *OriginalCreateProcessA)(LPCSTR, LPSTR,
    LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD,
    LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION)           = NULL;

// kernelbase – systeminfo.exe stdout patching (only installed in systeminfo.exe)
// Resolved from kernelbase.dll (actual implementation) not kernel32 forwarding stubs,
// and WriteConsoleW added to handle ConPTY / Windows Terminal paths.
static BOOL (WINAPI *OriginalWriteFile)(
    HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED)                   = NULL;
static BOOL (WINAPI *OriginalWriteConsoleA)(
    HANDLE, const VOID *, DWORD, LPDWORD, LPVOID)                    = NULL;
static BOOL (WINAPI *OriginalWriteConsoleW)(
    HANDLE, const VOID *, DWORD, LPDWORD, LPVOID)                    = NULL;

// Set once at InitializeHooks time – TRUE only when injected into systeminfo.exe
static BOOL   g_IsSystemInfo  = FALSE;
static HANDLE g_StdoutHandle  = INVALID_HANDLE_VALUE;

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

    // VM vendor keys (VMware, Inc. / Oracle / VBOX) are direct children of
    // HKLM\SOFTWARE only.  Applying the filter to any other key causes
    // STATUS_NO_MORE_ENTRIES to be returned unexpectedly during PowerShell /
    // CLR / .NET initialization, producing "No more data is available." errors
    // and preventing shell startup.  Pass through all other keys immediately.
    WCHAR keyPath[512] = { 0 };
    if (!GetRegistryKeyNameLocal(Key, keyPath, 512) ||
        _wcsicmp(keyPath, L"\\REGISTRY\\MACHINE\\SOFTWARE") != 0)
    {
        return OriginalNtEnumerateKey(Key, Index, KeyInformationClass,
                                      KeyInformation, KeyInformationLength,
                                      ResultLength);
    }

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
    TlsSetValue(TlsEnumKeyCacheI,              (LPVOID)(ULONG_PTR)i);   // Save i, not i-1
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

    // Only correct the SubKeys count for HKLM\SOFTWARE — the only key where
    // VM vendor subkeys exist as direct children.
    WCHAR keyPath[512] = { 0 };
    if (!GetRegistryKeyNameLocal(Key, keyPath, 512) ||
        _wcsicmp(keyPath, L"\\REGISTRY\\MACHINE\\SOFTWARE") != 0)
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
//  CreateProcessW / CreateProcessA
//  Strip -NoProfile (and any case-insensitive prefix abbreviation
//  of "noprofile" with at least 3 body chars: -nop, -nopr, …,
//  -noprofile) from PowerShell command lines so the system-wide
//  profile.ps1 is always loaded, even when the spawning process
//  passes -NoProfile explicitly.
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
    BOOL   result;

    if (ObsIsEnabled() && lpCommandLine)
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

    result = OriginalCreateProcessW(
        lpApplicationName, cmdToUse,
        lpProcessAttributes, lpThreadAttributes,
        bInheritHandles, dwCreationFlags,
        lpEnvironment, lpCurrentDirectory,
        lpStartupInfo, lpProcessInformation);

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
    BOOL  result;

    if (ObsIsEnabled() && lpCommandLine)
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

    result = OriginalCreateProcessA(
        lpApplicationName, cmdToUse,
        lpProcessAttributes, lpThreadAttributes,
        bInheritHandles, dwCreationFlags,
        lpEnvironment, lpCurrentDirectory,
        lpStartupInfo, lpProcessInformation);

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

    // Replacements are all equal-length or shorter, +16 for any edge case.
    DWORD  cap = srcLen + 16;
    LPBYTE dst = (LPBYTE)HeapAlloc(GetProcessHeap(), 0, cap);
    if (!dst) return NULL;

    BOOL  changed = FALSE;
    DWORD ri = 0, wi = 0;

    while (ri < srcLen && wi < cap)
    {
        DWORD      rem = srcLen - ri;
        LPCBYTE    p   = src + ri;

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
            changed = TRUE;
            continue;
        }

        // Pattern 2: model string
        if (rem >= kModelFindLen &&
            _strnicmp((const char *)p, kModelFind, kModelFindLen) == 0)
        {
            CopyMemory(dst + wi, kModelRepl, kModelReplLen);
            wi += kModelReplLen;
            ri += kModelFindLen;
            changed = TRUE;
            continue;
        }

        // Pattern 3: manufacturer (must follow pattern 1 to avoid double-hit)
        if (rem >= kMfgFindLen &&
            _strnicmp((const char *)p, kMfgFind, kMfgFindLen) == 0)
        {
            CopyMemory(dst + wi, kMfgRepl, kMfgReplLen);
            wi += kMfgReplLen;
            ri += kMfgFindLen;
            changed = TRUE;
            continue;
        }

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

static BOOL WINAPI HookedWriteFile(
    HANDLE       hFile,
    LPCVOID      lpBuffer,
    DWORD        nNumberOfBytesToWrite,
    LPDWORD      lpNumberOfBytesWritten,
    LPOVERLAPPED lpOverlapped)
{
    if (g_IsSystemInfo && ObsIsEnabled() && ObsGetMode() == OBS_MODE_TRAP &&
        hFile == g_StdoutHandle && lpBuffer && nNumberOfBytesToWrite > 0)
    {
        DWORD  pLen = 0;
        LPBYTE p    = PatchSysInfoOutput((LPCBYTE)lpBuffer, nNumberOfBytesToWrite, &pLen);
        if (p)
        {
            BOOL r = OriginalWriteFile(hFile, p, pLen, lpNumberOfBytesWritten, lpOverlapped);
            HeapFree(GetProcessHeap(), 0, p);
            // Report original byte count so the caller never sees a short write
            if (lpNumberOfBytesWritten) *lpNumberOfBytesWritten = nNumberOfBytesToWrite;
            return r;
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
    if (g_IsSystemInfo && ObsIsEnabled() && ObsGetMode() == OBS_MODE_TRAP &&
        hConsoleOutput == g_StdoutHandle && lpBuffer && nNumberOfCharsToWrite > 0)
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

    // Replacements are all equal-length or shorter, +16 for any edge case.
    DWORD  cap = srcCch + 16;
    LPWSTR dst = (LPWSTR)HeapAlloc(GetProcessHeap(), 0, cap * sizeof(WCHAR));
    if (!dst) return NULL;

    BOOL  changed = FALSE;
    DWORD ri = 0, wi = 0;

    while (ri < srcCch && wi < cap)
    {
        DWORD   rem = srcCch - ri;
        LPCWSTR p   = src + ri;

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
            changed = TRUE;
            continue;
        }

        // Pattern 2: model string
        if (rem >= kModelFindLen &&
            _wcsnicmp(p, kModelFind, kModelFindLen) == 0)
        {
            CopyMemory(dst + wi, kModelRepl, kModelReplLen * sizeof(WCHAR));
            wi += kModelReplLen;
            ri += kModelFindLen;
            changed = TRUE;
            continue;
        }

        // Pattern 3: manufacturer (must follow pattern 1 to avoid double-hit)
        if (rem >= kMfgFindLen &&
            _wcsnicmp(p, kMfgFind, kMfgFindLen) == 0)
        {
            CopyMemory(dst + wi, kMfgRepl, kMfgReplLen * sizeof(WCHAR));
            wi += kMfgReplLen;
            ri += kMfgFindLen;
            changed = TRUE;
            continue;
        }

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
    if (g_IsSystemInfo && ObsIsEnabled() && ObsGetMode() == OBS_MODE_TRAP &&
        hConsoleOutput == g_StdoutHandle && lpBuffer && nNumberOfCharsToWrite > 0)
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
    return OriginalWriteConsoleW(hConsoleOutput, lpBuffer, nNumberOfCharsToWrite,
                                 lpNumberOfCharsWritten, lpReserved);
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

    // Detect systeminfo.exe – only install WriteFile/WriteConsoleA hooks there
    {
        CHAR path[MAX_PATH] = { 0 };
        GetModuleFileNameA(NULL, path, MAX_PATH);
        CHAR *last = strrchr(path, '\\');
        g_IsSystemInfo = (last != NULL && _stricmp(last + 1, "systeminfo.exe") == 0);
        if (g_IsSystemInfo)
        {
            // Resolve from kernelbase.dll (actual implementation), not kernel32 forwarding
            // stubs.  Modern executables (including systeminfo.exe) import WriteFile and
            // WriteConsoleA/W directly from kernelbase via the ApiSet, so hooking the
            // kernel32 stub would leave their IAT slot un-patched.
            // WriteConsoleW is added to cover the ConPTY / Windows Terminal path where
            // systeminfo's UCRT detects a console handle and calls WriteConsoleW (wide).
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
    OriginalGetAdaptersAddresses   = (ULONG (WINAPI*)(ULONG,ULONG,PVOID,PIP_ADAPTER_ADDRESSES,PULONG)) RESOLVE_IPHLP(GetAdaptersAddresses);
    OriginalGetAdaptersInfo        = (DWORD (WINAPI*)(PIP_ADAPTER_INFO,PULONG))       RESOLVE_IPHLP(GetAdaptersInfo);
    OriginalEnumServicesStatusExW  = (BOOL  (WINAPI*)(SC_HANDLE,SC_ENUM_TYPE,DWORD,DWORD,LPBYTE,DWORD,LPDWORD,LPDWORD,LPDWORD,LPCWSTR)) RESOLVE_ADV(EnumServicesStatusExW);
    OriginalEnumServicesStatusExA  = (BOOL  (WINAPI*)(SC_HANDLE,SC_ENUM_TYPE,DWORD,DWORD,LPBYTE,DWORD,LPDWORD,LPDWORD,LPDWORD,LPCSTR))  RESOLVE_ADV(EnumServicesStatusExA);
    OriginalNtQuerySystemInformation = (NT_NTQUERYSYSTEMINFORMATION)RESOLVE_NTDLL(NtQuerySystemInformation);
    OriginalNtEnumerateKey           = (NT_NTENUMERATEKEY)          RESOLVE_NTDLL(NtEnumerateKey);
    OriginalNtQueryKey               = (NT_NTQUERYKEY)              RESOLVE_NTDLL(NtQueryKey);
    OriginalNtQueryValueKey          = (NT_NTQUERYVALUEKEY)         RESOLVE_NTDLL(NtQueryValueKey);
    OriginalGetSystemFirmwareTable   = (UINT(WINAPI*)(DWORD,DWORD,PVOID,DWORD)) RESOLVE_K32(GetSystemFirmwareTable);
    OriginalCreateProcessW           = (BOOL(WINAPI*)(LPCWSTR,LPWSTR,LPSECURITY_ATTRIBUTES,LPSECURITY_ATTRIBUTES,BOOL,DWORD,LPVOID,LPCWSTR,LPSTARTUPINFOW,LPPROCESS_INFORMATION)) RESOLVE_K32(CreateProcessW);
    OriginalCreateProcessA           = (BOOL(WINAPI*)(LPCSTR,LPSTR,LPSECURITY_ATTRIBUTES,LPSECURITY_ATTRIBUTES,BOOL,DWORD,LPVOID,LPCSTR,LPSTARTUPINFOA,LPPROCESS_INFORMATION))  RESOLVE_K32(CreateProcessA);

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
    if (OriginalNtQueryValueKey)          DetourAttach(&(PVOID)OriginalNtQueryValueKey,          HookedNtQueryValueKey);
    if (OriginalGetSystemFirmwareTable)   DetourAttach(&(PVOID)OriginalGetSystemFirmwareTable,   HookedGetSystemFirmwareTable);
    if (OriginalCreateProcessW)           DetourAttach(&(PVOID)OriginalCreateProcessW,           HookedCreateProcessW);
    if (OriginalCreateProcessA)           DetourAttach(&(PVOID)OriginalCreateProcessA,           HookedCreateProcessA);
    if (g_IsSystemInfo)
    {
        if (OriginalWriteFile)            DetourAttach(&(PVOID)OriginalWriteFile,            HookedWriteFile);
        if (OriginalWriteConsoleA)        DetourAttach(&(PVOID)OriginalWriteConsoleA,        HookedWriteConsoleA);
        if (OriginalWriteConsoleW)        DetourAttach(&(PVOID)OriginalWriteConsoleW,        HookedWriteConsoleW);
    }

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
    if (OriginalNtQueryValueKey)          DetourDetach(&(PVOID)OriginalNtQueryValueKey,          HookedNtQueryValueKey);
    if (OriginalGetSystemFirmwareTable)   DetourDetach(&(PVOID)OriginalGetSystemFirmwareTable,   HookedGetSystemFirmwareTable);
    if (OriginalCreateProcessW)           DetourDetach(&(PVOID)OriginalCreateProcessW,           HookedCreateProcessW);
    if (OriginalCreateProcessA)           DetourDetach(&(PVOID)OriginalCreateProcessA,           HookedCreateProcessA);
    if (g_IsSystemInfo)
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
