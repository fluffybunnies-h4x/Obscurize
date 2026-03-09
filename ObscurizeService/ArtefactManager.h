#ifndef _OBS_ARTEFACTMANAGER_H
#define _OBS_ARTEFACTMANAGER_H

#include <Windows.h>

// ============================================================
//  ObscurizeService – ArtefactManager.h
//
//  Manages the physical system artefacts that Defensive and
//  Trap modes require beyond what the in-process Agent hooks
//  can provide.
//
//  Defensive mode artefacts (created when mode is applied):
//    • Registry keys   – VMware Tools, VirtualBox Guest Additions
//    • BIOS strings    – SystemManufacturer, SystemProductName, etc.
//    • Decoy files     – %TEMP%\mapping.csv  (DEADVAX Stage 3 check)
//    • Low RAM signal  – Agent hooks handle this at runtime
//
//  Trap mode artefacts (cleaned up when mode is applied):
//    • Remove all Defensive-mode registry keys created above
//    • Restore BIOS strings to real hardware values
//    • Remove decoy files
//
//  Note: The Agent hooks provide the runtime layer that intercepts
//  in-process queries.  The artefact manager handles the persistent
//  layer visible to any process (WMI, direct registry reads, etc.)
//  before injection has happened or for processes that bypass hooks.
// ============================================================

/// <summary>
/// Applies the artefacts appropriate for <paramref name="mode"/>
/// (OBS_MODE_DEFENSIVE or OBS_MODE_TRAP).  Calling this while
/// the mode is already active is idempotent.
/// </summary>
VOID ApplyModeArtefacts(DWORD mode);

/// <summary>
/// Removes all artefacts that Obscurize has placed.  Called on
/// service shutdown regardless of the current mode.
/// </summary>
VOID RemoveModeArtefacts(VOID);

#endif  // _OBS_ARTEFACTMANAGER_H
