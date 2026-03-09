#ifndef _OBS_PROCESSLISTENER_H
#define _OBS_PROCESSLISTENER_H

#include <Windows.h>

// ============================================================
//  ObscurizeService – ProcessListener.h
//
//  Polls the system process list every 100 ms and invokes a
//  callback for each newly-appeared process ID.
//  Direct port of r77's ProcessListener with Obscurize naming.
// ============================================================

typedef VOID (*OBS_PID_CALLBACK)(DWORD processId);

/// <summary>
/// Starts the process-watcher thread.  Returns the thread handle
/// or NULL on failure.  The thread runs until TerminateThread is
/// called (done by UninitializeObscurizeService).
/// </summary>
HANDLE StartNewProcessListener(OBS_PID_CALLBACK callback);

#endif  // _OBS_PROCESSLISTENER_H
