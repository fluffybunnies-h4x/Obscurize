#include "ArtefactManager.h"
#include "../ObscurizeShared/ObscurizeDef.h"
#include "../ObscurizeAgent/Spoof.h"   // InstallDefensiveRegistryArtefacts / Remove...

#include <Shlwapi.h>
#include <strsafe.h>

// ============================================================
//  ObscurizeService – ArtefactManager.c
//
//  Manages the persistent (non-hook) artefacts for each mode.
//
//  Two-layer spoofing model:
//    Layer 1 (persistent, this file):
//      Physical registry writes and file creation that survive
//      hook removal and are visible to WMI / uninjected processes.
//    Layer 2 (runtime, Hooks.c in the Agent):
//      In-process API interception for processes that are already
//      injected.  Catches queries the persistent layer misses
//      (e.g. live GetUserNameW calls, GetAdaptersAddresses, etc.)
//
//  DEADVAX-specific artefacts:
//    • mapping.csv in %TEMP% – DEADVAX Stage 3 checks for this
//      file.  In Defensive mode we deliberately DO NOT create it
//      so Stage 3 exits ("artifacts missing → abort").
//      In Trap mode we DO create it so Stage 3 proceeds.
//    • 'VBE' in %TEMP% – same logic (Stage 2 marker file).
// ============================================================

// --------------------------------------------------------
//  Decoy file helpers
// --------------------------------------------------------

/// Build the path %TEMP%\<filename> into buf (MAX_PATH).
static BOOL BuildTempPath(LPCWSTR filename, LPWSTR buf, DWORD bufCch)
{
    WCHAR tmpDir[MAX_PATH + 1] = { 0 };
    if (!GetTempPathW(MAX_PATH, tmpDir)) return FALSE;
    return SUCCEEDED(StringCchPrintfW(buf, bufCch, L"%s%s", tmpDir, filename));
}

/// Create an empty file at path if it does not already exist.
static VOID CreateDecoyFile(LPCWSTR path)
{
    if (GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES) return;  // Already exists

    HANDLE h = CreateFileW(path, GENERIC_WRITE, 0, NULL,
                           CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE)
    {
        // Write a plausible CSV header line so the file looks authentic.
        static const char header[] = "timestamp,event,value\r\n";
        DWORD written;
        WriteFile(h, header, (DWORD)sizeof(header) - 1, &written, NULL);
        CloseHandle(h);
    }
}

/// Delete a file if it exists.
static VOID DeleteDecoyFile(LPCWSTR path)
{
    DeleteFileW(path);
}

// --------------------------------------------------------
//  Trap mode – decoy campaign artefact files
//  (DEADVAX Stage 3 checks for these; create them in Trap
//  mode so the malware believes its prior stages ran.)
// --------------------------------------------------------

static VOID CreateTrapDecoyFiles(VOID)
{
    WCHAR path[MAX_PATH + 1];

    // mapping.csv – checked by DEADVAX Batch Stage 3
    if (BuildTempPath(L"mapping.csv", path, MAX_PATH))
        CreateDecoyFile(path);

    // VBE marker – also checked by DEADVAX Stage 3
    // DEADVAX looks for any file whose name contains "VBE"
    if (BuildTempPath(L"VBE_marker.tmp", path, MAX_PATH))
        CreateDecoyFile(path);
}

static VOID RemoveTrapDecoyFiles(VOID)
{
    WCHAR path[MAX_PATH + 1];

    if (BuildTempPath(L"mapping.csv", path, MAX_PATH))
        DeleteDecoyFile(path);

    if (BuildTempPath(L"VBE_marker.tmp", path, MAX_PATH))
        DeleteDecoyFile(path);
}

// --------------------------------------------------------
//  Track which mode's artefacts are currently active
// --------------------------------------------------------

static DWORD s_activeArtefactMode = 0;  // 0 = none applied yet

// --------------------------------------------------------
//  Public API
// --------------------------------------------------------

VOID ApplyModeArtefacts(DWORD mode)
{
    // Remove previous mode's artefacts if switching.
    if (s_activeArtefactMode != 0 && s_activeArtefactMode != mode)
        RemoveModeArtefacts();

    if (mode == OBS_MODE_DEFENSIVE)
    {
        // Layer 1 – write physical VM registry artefacts.
        // (Layer 2 Agent hooks cover runtime interception.)
        InstallDefensiveRegistryArtefacts();

        // In Defensive mode do NOT create the campaign decoy files.
        // Their absence is what triggers DEADVAX Stage 3 to abort,
        // which is exactly what we want on a defended host.
        // Ensure they are absent in case we're switching from Trap.
        RemoveTrapDecoyFiles();
    }
    else if (mode == OBS_MODE_TRAP)
    {
        // Remove Defensive artefacts (restore real hardware strings).
        RemoveDefensiveRegistryArtefacts();

        // Create campaign decoy files so malware proceeds past
        // its pre-execution artefact checks.
        CreateTrapDecoyFiles();
    }

    s_activeArtefactMode = mode;
}

VOID RemoveModeArtefacts(VOID)
{
    if (s_activeArtefactMode == OBS_MODE_DEFENSIVE)
    {
        RemoveDefensiveRegistryArtefacts();
    }
    else if (s_activeArtefactMode == OBS_MODE_TRAP)
    {
        RemoveTrapDecoyFiles();
        // No registry cleanup needed for Trap mode – we only removed keys,
        // so there is nothing Obscurize needs to restore.
    }

    s_activeArtefactMode = 0;
}
