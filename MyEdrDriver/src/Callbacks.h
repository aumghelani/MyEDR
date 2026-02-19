/*
    Kernel notification callbacks.

    Windows lets a driver subscribe to system-wide events without hooking
    anything. We use two of the documented notification routines:

      PsSetCreateProcessNotifyRoutineEx  -> process create / exit
      PsSetCreateThreadNotifyRoutine     -> thread create / exit

    These run in the context of the thread causing the event, so they are the
    right place to observe "who did what to whom". We turn observations into
    EDR_EVENT records and push them onto the shared queue.
*/

#pragma once

#include <ntddk.h>

NTSTATUS EdrRegisterCallbacks(void);
void     EdrUnregisterCallbacks(void);
