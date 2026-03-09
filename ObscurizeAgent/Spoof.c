#include "Spoof.h"
#include <Shlwapi.h>

// ============================================================
//  ObscurizeAgent – Spoof.c
//  Lookup tables and helper functions for VM / hardware
//  artefact identification and value substitution.
// ============================================================

// ------------------------------------------------------------
//  VM process names
// ------------------------------------------------------------

static const LPCWSTR s_vmProcessNames[] = OBS_VM_PROCESSES;

BOOL IsVmProcessName(LPCWSTR processName)
{
    if (!processName) return FALSE;
    for (int i = 0; s_vmProcessNames[i] != NULL; i++)
    {
        if (StrCmpIW(processName, s_vmProcessNames[i]) == 0)
            return TRUE;
    }
    return FALSE;
}

// ------------------------------------------------------------
//  VM service names
// ------------------------------------------------------------

static const LPCWSTR s_vmServiceNames[] = OBS_VM_SERVICES;

BOOL IsVmServiceName(LPCWSTR serviceName)
{
    if (!serviceName) return FALSE;
    for (int i = 0; s_vmServiceNames[i] != NULL; i++)
    {
        if (StrCmpIW(serviceName, s_vmServiceNames[i]) == 0)
            return TRUE;
    }
    return FALSE;
}

// ------------------------------------------------------------
//  VM registry vendor keys
// ------------------------------------------------------------

static const LPCWSTR s_vmRegKeys[] = OBS_VM_REGKEYS;

BOOL IsVmRegistryVendorKey(LPCWSTR subkeyName)
{
    if (!subkeyName) return FALSE;
    for (int i = 0; s_vmRegKeys[i] != NULL; i++)
    {
        if (StrCmpIW(subkeyName, s_vmRegKeys[i]) == 0)
            return TRUE;
    }
    return FALSE;
}

// ------------------------------------------------------------
//  BIOS value spoofing table
// ------------------------------------------------------------

// Each entry maps a registry value name to Defensive and Trap strings.
typedef struct _BIOS_SPOOF_ENTRY
{
    LPCWSTR ValueName;
    LPCWSTR Defensive;
    LPCWSTR Trap;
} BIOS_SPOOF_ENTRY;

static const BIOS_SPOOF_ENTRY s_biosTable[] =
{
    { OBS_REG_BIOS_MANUFACTURER, OBS_DEF_MANUFACTURER, OBS_TRAP_MANUFACTURER },
    { OBS_REG_BIOS_PRODUCT,      OBS_DEF_PRODUCT,      OBS_TRAP_PRODUCT      },
    { OBS_REG_BIOS_VENDOR,       OBS_DEF_BIOS_VENDOR,  OBS_TRAP_BIOS_VENDOR  },
    { OBS_REG_BIOS_VERSION,      OBS_DEF_BIOS_VERSION, OBS_TRAP_BIOS_VERSION },
    { OBS_REG_BIOS_RELEASEDATE,  OBS_DEF_BIOS_DATE,    OBS_TRAP_BIOS_DATE    },
    { NULL, NULL, NULL }
};

LPCWSTR GetSpoofedBiosValue(LPCWSTR valueName, DWORD mode)
{
    if (!valueName) return NULL;
    for (int i = 0; s_biosTable[i].ValueName != NULL; i++)
    {
        if (StrCmpIW(valueName, s_biosTable[i].ValueName) == 0)
        {
            return (mode == OBS_MODE_DEFENSIVE)
                ? s_biosTable[i].Defensive
                : s_biosTable[i].Trap;
        }
    }
    return NULL;
}

// ------------------------------------------------------------
//  Defensive-mode registry artefact management
// ------------------------------------------------------------

// Helper: create a key and optionally write a single SZ value.
static BOOL CreateRegKeyWithValue(LPCWSTR path, LPCWSTR valueName, LPCWSTR value)
{
    HKEY key = NULL;
    LONG result = RegCreateKeyExW(
        HKEY_LOCAL_MACHINE, path, 0, NULL,
        REG_OPTION_NON_VOLATILE,
        KEY_SET_VALUE | KEY_WOW64_64KEY,
        NULL, &key, NULL);

    if (result != ERROR_SUCCESS) return FALSE;

    if (valueName && value)
    {
        RegSetValueExW(key, valueName, 0, REG_SZ,
                       (const BYTE*)value,
                       (DWORD)((wcslen(value) + 1) * sizeof(WCHAR)));
    }

    RegCloseKey(key);
    return TRUE;
}

BOOL InstallDefensiveRegistryArtefacts(VOID)
{
    BOOL ok = TRUE;

    // VMware Tools
    ok &= CreateRegKeyWithValue(OBS_REG_VMWARE_ROOT,  NULL,                    NULL);
    ok &= CreateRegKeyWithValue(OBS_REG_VMWARE_TOOLS, OBS_REG_VMWARE_TOOLS_VER, OBS_REG_VMWARE_TOOLS_VERVAL);

    // VirtualBox Guest Additions
    ok &= CreateRegKeyWithValue(OBS_REG_VBOX_ROOT, NULL,               NULL);
    ok &= CreateRegKeyWithValue(OBS_REG_VBOX_GA,   OBS_REG_VBOX_GA_VER, OBS_REG_VBOX_GA_VERVAL);

    // BIOS strings – write all Defensive values to the BIOS key.
    // These are read by WMI Win32_ComputerSystem / Win32_BIOS.
    // The key already exists on all Windows systems; we only modify values.
    HKEY biosKey = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, OBS_REG_BIOS_KEY, 0,
                      KEY_SET_VALUE | KEY_WOW64_64KEY, &biosKey) == ERROR_SUCCESS)
    {
        for (int i = 0; s_biosTable[i].ValueName != NULL; i++)
        {
            LPCWSTR val = s_biosTable[i].Defensive;
            RegSetValueExW(biosKey, s_biosTable[i].ValueName, 0, REG_SZ,
                           (const BYTE*)val,
                           (DWORD)((wcslen(val) + 1) * sizeof(WCHAR)));
        }
        RegCloseKey(biosKey);
    }

    return ok;
}

VOID RemoveDefensiveRegistryArtefacts(VOID)
{
    // Delete VMware keys
    RegDeleteKeyExW(HKEY_LOCAL_MACHINE, OBS_REG_VMWARE_TOOLS, KEY_WOW64_64KEY, 0);
    RegDeleteKeyExW(HKEY_LOCAL_MACHINE, OBS_REG_VMWARE_ROOT,  KEY_WOW64_64KEY, 0);

    // Delete VirtualBox keys
    RegDeleteKeyExW(HKEY_LOCAL_MACHINE, OBS_REG_VBOX_GA,   KEY_WOW64_64KEY, 0);
    RegDeleteKeyExW(HKEY_LOCAL_MACHINE, OBS_REG_VBOX_ROOT, KEY_WOW64_64KEY, 0);

    // Restore Trap-mode BIOS strings (so the real hardware strings come back)
    HKEY biosKey = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, OBS_REG_BIOS_KEY, 0,
                      KEY_SET_VALUE | KEY_WOW64_64KEY, &biosKey) == ERROR_SUCCESS)
    {
        for (int i = 0; s_biosTable[i].ValueName != NULL; i++)
        {
            LPCWSTR val = s_biosTable[i].Trap;
            RegSetValueExW(biosKey, s_biosTable[i].ValueName, 0, REG_SZ,
                           (const BYTE*)val,
                           (DWORD)((wcslen(val) + 1) * sizeof(WCHAR)));
        }
        RegCloseKey(biosKey);
    }
}
