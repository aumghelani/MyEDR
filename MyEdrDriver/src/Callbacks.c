#include "Callbacks.h"
#include "EventQueue.h"
#include "Driver.h"

// Defined in Driver.c - the single global queue the IOCTL path drains.
extern EDR_EVENT_QUEUE g_eventQueue;

// --------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------

// Copy an ANSI image name (what PsGetProcessImageFileName returns, max 15
// chars) into the event's wide imageName field. Best-effort only.
static void EdrFillShortName(EDR_EVENT* ev, PEPROCESS proc) {
    PCHAR name = PsGetProcessImageFileName(proc);   // up to 15 bytes, NUL-padded
    if (name == NULL) {
        return;
    }
    for (ULONG i = 0; i < 15 && name[i] != '\0'; i++) {
        ev->imageName[i] = (wchar_t)(UCHAR)name[i];
    }
}

static void EdrSetMessage(EDR_EVENT* ev, const char* msg) {
    size_t i = 0;
    for (; i < EDR_MSG_LEN - 1 && msg[i] != '\0'; i++) {
        ev->message[i] = msg[i];
    }
    ev->message[i] = '\0';
}

// --------------------------------------------------------------------------
// Process create / exit
// --------------------------------------------------------------------------
static void EdrCreateProcessNotify(
    PEPROCESS Process,
    HANDLE ProcessId,
    PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    EDR_EVENT ev;
    RtlZeroMemory(&ev, sizeof(ev));
    ev.pid = HandleToUlong(ProcessId);

    if (CreateInfo != NULL) {
        // Process is being created.
        ev.type       = EdrEventProcessCreate;
        ev.severity   = EdrSeverityInfo;
        ev.parentPid  = HandleToUlong(CreateInfo->ParentProcessId);
        ev.creatorPid = HandleToUlong(CreateInfo->CreatingThreadId.UniqueProcess);
        EdrFillShortName(&ev, Process);

        // Heuristic: PPID spoofing (T1134.004).
        // The "parent" a process claims can be forged via
        // PROC_THREAD_ATTRIBUTE_PARENT_PROCESS. But the thread that actually
        // issued the create still belongs to the real creator. If the claimed
        // parent differs from the real creator, flag it.
        if (CreateInfo->ParentProcessId != CreateInfo->CreatingThreadId.UniqueProcess) {
            ev.severity = EdrSeverityWarning;
            EdrSetMessage(&ev, "Possible PPID spoofing: claimed parent != real creator");
        } else {
            EdrSetMessage(&ev, "Process created");
        }
    } else {
        // Process is exiting.
        ev.type     = EdrEventProcessExit;
        ev.severity = EdrSeverityInfo;
        EdrFillShortName(&ev, Process);
        EdrSetMessage(&ev, "Process exited");
    }

    EdrQueuePush(&g_eventQueue, &ev);
}

// --------------------------------------------------------------------------
// Thread create / exit
// --------------------------------------------------------------------------
static void EdrCreateThreadNotify(
    HANDLE ProcessId,
    HANDLE ThreadId,
    BOOLEAN Create)
{
    if (!Create) {
        return;  // we only care about thread creation here
    }

    // Heuristic: remote thread creation (classic injection primitive, T1055).
    // If the thread is being injected into ProcessId by a *different* process,
    // the current process id will not match the target process id.
    HANDLE creator = PsGetCurrentProcessId();
    if (creator == ProcessId) {
        return;  // normal: a process spawning its own thread
    }

    EDR_EVENT ev;
    RtlZeroMemory(&ev, sizeof(ev));
    ev.type       = EdrEventRemoteThread;
    ev.severity   = EdrSeverityCritical;
    ev.pid        = HandleToUlong(ProcessId);   // the victim
    ev.creatorPid = HandleToUlong(creator);     // the injector

    PEPROCESS target = NULL;
    if (NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &target))) {
        EdrFillShortName(&ev, target);
        ObDereferenceObject(target);
    }
    EdrSetMessage(&ev, "Remote thread created into another process");

    UNREFERENCED_PARAMETER(ThreadId);
    EdrQueuePush(&g_eventQueue, &ev);
}

// --------------------------------------------------------------------------
// (Un)registration
// --------------------------------------------------------------------------
static BOOLEAN g_processCbOn = FALSE;
static BOOLEAN g_threadCbOn  = FALSE;

NTSTATUS EdrRegisterCallbacks(void) {
    NTSTATUS status;

    status = PsSetCreateProcessNotifyRoutineEx(EdrCreateProcessNotify, FALSE);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[MyEDR] PsSetCreateProcessNotifyRoutineEx failed: 0x%X\n", status);
        return status;
    }
    g_processCbOn = TRUE;

    status = PsSetCreateThreadNotifyRoutine(EdrCreateThreadNotify);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[MyEDR] PsSetCreateThreadNotifyRoutine failed: 0x%X\n", status);
        PsSetCreateProcessNotifyRoutineEx(EdrCreateProcessNotify, TRUE);
        g_processCbOn = FALSE;
        return status;
    }
    g_threadCbOn = TRUE;

    DbgPrint("[MyEDR] callbacks registered\n");
    return STATUS_SUCCESS;
}

void EdrUnregisterCallbacks(void) {
    if (g_processCbOn) {
        PsSetCreateProcessNotifyRoutineEx(EdrCreateProcessNotify, TRUE);
        g_processCbOn = FALSE;
    }
    if (g_threadCbOn) {
        PsRemoveCreateThreadNotifyRoutine(EdrCreateThreadNotify);
        g_threadCbOn = FALSE;
    }
    DbgPrint("[MyEDR] callbacks unregistered\n");
}
