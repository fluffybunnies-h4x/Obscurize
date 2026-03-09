#ifndef _OBS_CONFIG_H
#define _OBS_CONFIG_H

#include <Windows.h>

// ============================================================
//  ObscurizeAgent – Config
//  Reads the active mode and per-mode spoof overrides from
//  HKLM\SOFTWARE\ObscurizeConfig every second in a background
//  thread, exactly as r77 does for its config key.
// ============================================================

/// <summary>
/// Runtime configuration snapshot.  Replaced atomically when
/// the registry is updated so hooks always see a consistent view.
/// </summary>
typedef struct _OBS_CONFIG
{
    BOOL  Enabled;                          // Master on/off switch
    DWORD Mode;                             // OBS_MODE_DEFENSIVE / OBS_MODE_TRAP

    // Trap mode overrideable values (read from registry; fall back to
    // the compile-time defaults in ObscurizeDef.h if not set).
    WCHAR SpoofUsername[64];
    WCHAR SpoofComputerName[MAX_COMPUTERNAME_LENGTH + 1];
    BYTE  SpoofMacOUI[3];                   // First 3 bytes of the spoofed MAC
    BOOL  CustomMacOUI;                     // TRUE if SpoofMacOUI was set in registry
} OBS_CONFIG, *POBS_CONFIG;

// ------------------------------------------------------------
//  Lifecycle
// ------------------------------------------------------------

/// <summary>Starts the background config-reload thread.</summary>
VOID InitializeObsConfig(VOID);

/// <summary>Stops the background config-reload thread.</summary>
VOID UninitializeObsConfig(VOID);

// ------------------------------------------------------------
//  Accessors called by hooks (thread-safe reads)
// ------------------------------------------------------------

/// <summary>Returns TRUE if Obscurize is currently enabled.</summary>
BOOL ObsIsEnabled(VOID);

/// <summary>Returns the current operating mode (OBS_MODE_*).</summary>
DWORD ObsGetMode(VOID);

/// <summary>
/// Fills <paramref name="buf"/> with the spoofed username for the
/// current mode.  Buffer must be at least 64 WCHARs.
/// </summary>
VOID ObsGetSpoofUsername(PWCHAR buf, DWORD bufCch);

/// <summary>
/// Fills <paramref name="buf"/> with the spoofed computer name for
/// the current mode.
/// </summary>
VOID ObsGetSpoofComputerName(PWCHAR buf, DWORD bufCch);

/// <summary>
/// Copies the 3-byte OUI to use for MAC address spoofing into
/// <paramref name="oui"/>.
/// </summary>
VOID ObsGetSpoofMacOUI(BYTE oui[3]);

/// <summary>
/// Returns the total physical memory in bytes to report.
/// </summary>
ULONGLONG ObsGetSpoofMemoryBytes(VOID);

/// <summary>
/// Writes the spoofed screen width into <paramref name="width"/> and
/// height into <paramref name="height"/>.
/// </summary>
VOID ObsGetSpoofResolution(PDWORD width, PDWORD height);

#endif  // _OBS_CONFIG_H
