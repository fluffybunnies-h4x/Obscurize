#ifndef _OBS_SERVICEMAIN_H
#define _OBS_SERVICEMAIN_H

#include <Windows.h>
#include "../ObscurizeShared/ObscurizeDef.h"

// ============================================================
//  ObscurizeService – ServiceMain.h
//
//  Windows Service entry point declarations.
//
//  ObscurizeService runs as LocalSystem so it has the access
//  rights required to inject the Agent DLL into every process.
//  It must be installed via sc.exe or the ObscurizeGUI
//  installer before it can be started:
//
//    sc create ObscurizeService \
//       binPath= "C:\path\ObscurizeService.exe" \
//       start= auto  obj= LocalSystem
// ============================================================

#define OBS_SERVICE_NAME        L"ObscurizeService"
#define OBS_SERVICE_DISPLAY     L"Obscurize Deception Service"
#define OBS_SERVICE_DESC        L"Provides VM/hardware identity spoofing for defensive deception."

// Resource IDs for the embedded Agent DLLs (defined in ObscurizeService.rc)
#define IDR_AGENT_DLL32         101
#define IDR_AGENT_DLL64         102

// Registry value names under HKLM\SOFTWARE\ObscurizeConfig where
// the service caches the Agent DLL bytes so the NtResumeThread
// injection path (when added in a future Agent update) can
// retrieve them from within any injected process.
#define OBS_REG_AGENT32_VALUE   L"AgentDll32"
#define OBS_REG_AGENT64_VALUE   L"AgentDll64"

// --------------------------------------------------------
//  Globals exported to sub-modules
// --------------------------------------------------------

/// Agent DLL bytes (32-bit) extracted from resources at startup.
extern LPBYTE  g_AgentDll32;
extern DWORD   g_AgentDll32Size;

/// Agent DLL bytes (64-bit) extracted from resources at startup.
extern LPBYTE  g_AgentDll64;
extern DWORD   g_AgentDll64Size;

/// Set TRUE while injection is paused (e.g. during mode switch).
extern volatile BOOL g_InjectionPaused;

// --------------------------------------------------------
//  Functions
// --------------------------------------------------------

/// <summary>Windows Service entry point registered with SCM.</summary>
VOID WINAPI ObsServiceMain(DWORD argc, LPWSTR *argv);

/// <summary>SCM control handler (stop, pause, continue).</summary>
VOID WINAPI ObsServiceCtrlHandler(DWORD control);

/// <summary>
/// Core initialisation: loads Agent DLLs, creates config registry
/// key, installs artefacts for current mode, starts listener threads.
/// Returns FALSE on failure; the service reports STOPPED to SCM.
/// </summary>
BOOL InitializeObscurizeService(VOID);

/// <summary>
/// Graceful shutdown: stops all threads, detaches agents from all
/// processes, cleans up artefacts, frees resources.
/// </summary>
VOID UninitializeObscurizeService(VOID);

#endif  // _OBS_SERVICEMAIN_H
