#ifndef _OBS_CONTROLPIPELISTENER_H
#define _OBS_CONTROLPIPELISTENER_H

#include <Windows.h>

// ============================================================
//  ObscurizeService – ControlPipeListener.h
//
//  Listens on the named pipe OBS_CONTROL_PIPE_NAME for
//  commands from ObscurizeGUI (or any admin process).
//
//  Protocol (all values are little-endian DWORDs):
//    Client → Service :  DWORD control_code
//    Service → Client :  DWORD status_code   (OBS_CTRL_QUERY_STATUS only)
//
//  The pipe has a DACL that allows any authenticated user to
//  connect so the GUI running in an interactive session can
//  send commands to the SYSTEM service.
// ============================================================

typedef VOID (*OBS_CTRL_CALLBACK)(DWORD controlCode, HANDLE pipe);

/// <summary>
/// Starts the control pipe listener thread.
/// Returns the thread handle or NULL on failure.
/// </summary>
HANDLE StartControlPipeListener(OBS_CTRL_CALLBACK callback);

// --------------------------------------------------------
//  Client-side helper (used by GUI / test tools)
// --------------------------------------------------------

/// <summary>
/// Sends a control code to ObscurizeService via the named pipe.
/// For OBS_CTRL_QUERY_STATUS, reads a DWORD reply into
/// <paramref name="statusOut"/> (may be NULL for other codes).
/// Returns TRUE on success.
/// </summary>
BOOL SendControlCode(DWORD controlCode, LPDWORD statusOut);

#endif  // _OBS_CONTROLPIPELISTENER_H
