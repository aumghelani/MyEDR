/*
    Object (handle) notification callbacks.

    ObRegisterCallbacks lets a driver intercept handle creation/duplication for
    process and thread objects. This is the classic place to detect and blunt
    credential dumping (MITRE T1003.001): something opening LSASS with
    PROCESS_VM_READ to scrape secrets out of its memory.

    Unlike the notify routines, the PRE callback can MODIFY the requested
    access mask. We use that to strip the dangerous bits when a non-system
    caller reaches for LSASS, turning detection into light prevention.
*/

#include "ObjectGuard.h"
#include "EventQueue.h"
#include "Driver.h"

extern EDR_EVENT_QUEUE g_eventQueue;

static PVOID   g_obHandle = NULL;
static BOOLEAN g_obCbOn   = FALSE;

// The access bits an attacker needs to read LSASS memory.
#define EDR_LSASS_DANGEROUS (PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION)

static BOOLEAN EdrProcessIsLsass(PEPROCESS proc) {
    PCHAR name = PsGetProcessImageFileName(proc);  // short name, <= 15 chars
    if (name == NULL) {
        return FALSE;
    }
    // "lsass.exe" case-insensitive compare on the short name.
    static const char target[] = "lsass.exe";
    for (int i = 0; target[i]; i++) {
        char c = name[i];
        if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
        if (c != target[i]) {
            return FALSE;
        }
    }
    return TRUE;
}

static void EdrReportLsassAccess(HANDLE targetPid, ACCESS_MASK desired) {
    EDR_EVENT ev;
    RtlZeroMemory(&ev, sizeof(ev));
    ev.type       = EdrEventLsassAccess;
    ev.severity   = EdrSeverityCritical;
    ev.pid        = HandleToUlong(targetPid);
    ev.creatorPid = HandleToUlong(PsGetCurrentProcessId());

    const char* msg = "Handle to LSASS with memory-read access (cred dumping?)";
    size_t i = 0;
    for (; i < EDR_MSG_LEN - 1 && msg[i]; i++) ev.message[i] = msg[i];
    ev.message[i] = '\0';

    UNREFERENCED_PARAMETER(desired);
    EdrQueuePush(&g_eventQueue, &ev);
}

static OB_PREOP_CALLBACK_STATUS EdrPreProcessHandle(
    PVOID context, POB_PRE_OPERATION_INFORMATION info)
{
    UNREFERENCED_PARAMETER(context);

    PEPROCESS target = (PEPROCESS)info->Object;

    // Never interfere with the kernel/system opening things itself.
    if (info->KernelHandle) {
        return OB_PREOP_SUCCESS;
    }
    if (!EdrProcessIsLsass(target)) {
        return OB_PREOP_SUCCESS;
    }
    // The process opening its own handle is fine.
    if (PsGetCurrentProcessId() == PsGetProcessId(target)) {
        return OB_PREOP_SUCCESS;
    }

    ACCESS_MASK* desired = NULL;
    if (info->Operation == OB_OPERATION_HANDLE_CREATE) {
        desired = &info->Parameters->CreateHandleInformation.DesiredAccess;
    } else if (info->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
        desired = &info->Parameters->DuplicateHandleInformation.DesiredAccess;
    }

    if (desired && (*desired & EDR_LSASS_DANGEROUS)) {
        EdrReportLsassAccess(PsGetProcessId(target), *desired);
        // Light prevention: strip the memory-read/write bits.
        *desired &= ~EDR_LSASS_DANGEROUS;
    }

    return OB_PREOP_SUCCESS;
}

NTSTATUS EdrRegisterObjectCallback(void) {
    OB_OPERATION_REGISTRATION op;
    RtlZeroMemory(&op, sizeof(op));
    op.ObjectType = PsProcessType;
    op.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    op.PreOperation = EdrPreProcessHandle;

    OB_CALLBACK_REGISTRATION reg;
    RtlZeroMemory(&reg, sizeof(reg));
    reg.Version = OB_FLT_REGISTRATION_VERSION;
    reg.OperationRegistrationCount = 1;
    reg.RegistrationContext = NULL;
    RtlInitUnicodeString(&reg.Altitude, L"360100");
    reg.OperationRegistration = &op;

    NTSTATUS status = ObRegisterCallbacks(&reg, &g_obHandle);
    if (NT_SUCCESS(status)) {
        g_obCbOn = TRUE;
        DbgPrint("[MyEDR] object callback registered\n");
    } else {
        DbgPrint("[MyEDR] ObRegisterCallbacks failed: 0x%X\n", status);
    }
    return status;
}

void EdrUnregisterObjectCallback(void) {
    if (g_obCbOn && g_obHandle) {
        ObUnRegisterCallbacks(g_obHandle);
        g_obHandle = NULL;
        g_obCbOn = FALSE;
    }
}
