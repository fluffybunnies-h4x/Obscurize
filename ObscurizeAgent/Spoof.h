#ifndef _OBS_SPOOF_H
#define _OBS_SPOOF_H

#include <Windows.h>
#include "../ObscurizeShared/ObscurizeDef.h"

// ============================================================
//  ObscurizeAgent – Spoof.h
//  Helper functions and lookup tables used by the hooks to
//  identify and substitute VM or hardware artefacts.
// ============================================================

// ------------------------------------------------------------
//  Process-name classification
// ------------------------------------------------------------

/// <summary>
/// Returns TRUE if <paramref name="processName"/> is a known VM
/// guest-tool process that should be hidden in Trap mode.
/// Comparison is case-insensitive.
/// </summary>
BOOL IsVmProcessName(LPCWSTR processName);

// ------------------------------------------------------------
//  Service-name classification
// ------------------------------------------------------------

/// <summary>
/// Returns TRUE if <paramref name="serviceName"/> is a known VM
/// service that should be hidden in Trap mode.
/// Comparison is case-insensitive.
/// </summary>
BOOL IsVmServiceName(LPCWSTR serviceName);

// ------------------------------------------------------------
//  Registry-key classification
// ------------------------------------------------------------

/// <summary>
/// Returns TRUE if <paramref name="subkeyName"/> is a known VM
/// vendor key that should be suppressed during HKLM\SOFTWARE
/// enumeration in Trap mode (e.g. "VMware, Inc.", "Oracle").
/// Comparison is case-insensitive.
/// </summary>
BOOL IsVmRegistryVendorKey(LPCWSTR subkeyName);

// ------------------------------------------------------------
//  BIOS / hardware value spoofing
// ------------------------------------------------------------

/// <summary>
/// Returns the spoofed REG_SZ string value (in the current mode)
/// for the given BIOS value name, or NULL if the value name is
/// not one Obscurize manages.
/// The returned pointer is to a static string – do not free.
/// </summary>
/// <param name="valueName">Unicode value name (e.g. L"SystemManufacturer").</param>
/// <param name="mode">Current mode (OBS_MODE_DEFENSIVE / OBS_MODE_TRAP).</param>
LPCWSTR GetSpoofedBiosValue(LPCWSTR valueName, DWORD mode);

// ------------------------------------------------------------
//  Defensive-mode registry artefact management
//  (Called by ObscurizeService, not by the injected agent)
// ------------------------------------------------------------

/// <summary>
/// Creates all VM presence registry keys under HKLM for
/// Defensive mode.  Requires SYSTEM / admin privilege.
/// Returns TRUE if all keys were created successfully.
/// </summary>
BOOL InstallDefensiveRegistryArtefacts(VOID);

/// <summary>
/// Removes the VM presence registry keys created by
/// InstallDefensiveRegistryArtefacts.
/// </summary>
VOID RemoveDefensiveRegistryArtefacts(VOID);

#endif  // _OBS_SPOOF_H
