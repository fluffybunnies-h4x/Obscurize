#ifndef _OBS_AGENT_H
#define _OBS_AGENT_H

#include <Windows.h>
#include "../ObscurizeShared/ObscurizeDef.h"

// ============================================================
//  ObscurizeAgent – Agent.h
//  DLL entry point and reflective loader exports.
// ============================================================

/// <summary>
/// Called by ReflectiveDllMain after the DLL is mapped.
/// Initialises config polling and attaches all hooks.
/// Returns TRUE on success, FALSE if already injected or
/// if this process is excluded.
/// </summary>
BOOL InitializeAgent(VOID);

/// <summary>
/// Detaches all hooks and stops the config thread.
/// Called via a remote thread created by ObscurizeService
/// when detaching from a process.
/// </summary>
VOID UninitializeAgent(VOID);

// Forward-declare the reflective loader entry used by the
// injection mechanism.  Defined in ReflectiveDllMain.c from r77.
BOOL WINAPI ReflectiveDllMain(LPBYTE dllBase);

#endif  // _OBS_AGENT_H
