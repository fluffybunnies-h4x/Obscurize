#ifndef _SMBIOS_SPOOF_H
#define _SMBIOS_SPOOF_H

#include <Windows.h>

// ============================================================
//  SmbiosSpoof.h  –  SMBIOS table patching for Obscurize
//
//  GetSystemFirmwareTable('RSMB', 0, ...) returns raw SMBIOS
//  data directly from firmware.  WMI's CIMWIN32 provider uses
//  this call (not the registry) to populate Win32_ComputerSystem
//  and Win32_BIOS, bypassing the NtQueryValueKey hook entirely.
//
//  PatchRSMBBuffer() rebuilds the table with spoofed strings so
//  that WMI and any direct GetSystemFirmwareTable callers see
//  the correct spoofed manufacturer/product/BIOS values.
// ============================================================

// Extra bytes allocated (and advertised to probing callers) to
// accommodate replacement strings that are longer than the
// originals.  256 bytes is well above the worst-case delta.
#define OBS_SMBIOS_HEADROOM  256

/// <summary>
/// Patch an RSMB buffer returned by
///   GetSystemFirmwareTable('RSMB', 0, pBuf, size)
/// replacing BIOS vendor/version/date and system
/// manufacturer/product strings with spoofed values that
/// match the current Obscurize mode.
/// </summary>
/// <param name="original">Buffer as returned by the real API.</param>
/// <param name="originalSize">Byte count of original.</param>
/// <param name="pOutPatchedSize">Receives byte count of the returned buffer.</param>
/// <returns>
/// Heap-allocated patched buffer.
/// Caller MUST HeapFree(GetProcessHeap(), 0, result).
/// Returns NULL on failure; caller should fall back to the original buffer.
/// </returns>
LPBYTE PatchRSMBBuffer(LPCBYTE original, DWORD originalSize, LPDWORD pOutPatchedSize);

#endif  // _SMBIOS_SPOOF_H
