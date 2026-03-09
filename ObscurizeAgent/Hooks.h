#ifndef _OBS_HOOKS_H
#define _OBS_HOOKS_H

#include <Windows.h>

// ============================================================
//  ObscurizeAgent – Hooks.h
//  Declares the Detours hook lifecycle functions.
// ============================================================

/// <summary>
/// Attaches all Detours hooks.  Must be called after
/// InitializeObsConfig().
/// </summary>
VOID InitializeHooks(VOID);

/// <summary>
/// Detaches all Detours hooks.  Must be called before
/// UninitializeObsConfig().
/// </summary>
VOID UninitializeHooks(VOID);

#endif  // _OBS_HOOKS_H
