/*
    Registry notification callback.

    CmRegisterCallbackEx lets a driver observe (and optionally block) registry
    operations system-wide. A huge amount of persistence and configuration
    tampering shows up here. We start with the single most common persistence
    signal: a write to a "Run" autostart key (MITRE T1547.001).

    The callback runs synchronously in the context of the thread doing the
    registry op, so it must be fast and must not block.
*/

#include "Registry.h"
#include "EventQueue.h"
#include "Driver.h"

extern EDR_EVENT_QUEUE g_eventQueue;

static LARGE_INTEGER g_cookie;
static BOOLEAN       g_regCbOn = FALSE;

static BOOLEAN EdrKeyNameIsRunKey(PCUNICODE_STRING name) {
    if (name == NULL || name->Buffer == NULL) {
        return FALSE;
    }
    // Cheap substring test for the classic autostart locations.
    static const WCHAR* patterns[] = {
        L"\\currentversion\\run",
        L"\\currentversion\\runonce",
    };
    USHORT hLen = name->Length / sizeof(WCHAR);

    for (int p = 0; p < 2; p++) {
        UNICODE_STRING pat;
        RtlInitUnicodeString(&pat, patterns[p]);
        USHORT nLen = pat.Length / sizeof(WCHAR);
        if (nLen == 0 || nLen > hLen) continue;

        for (USHORT i = 0; i + nLen <= hLen; i++) {
            BOOLEAN match = TRUE;
            for (USHORT j = 0; j < nLen; j++) {
                if (RtlDowncaseUnicodeChar(name->Buffer[i + j]) !=
                    RtlDowncaseUnicodeChar(pat.Buffer[j])) { match = FALSE; break; }
            }
            if (match) return TRUE;
        }
    }
    return FALSE;
}

static void EdrReportRunKey(PCUNICODE_STRING keyName) {
    EDR_EVENT ev;
    RtlZeroMemory(&ev, sizeof(ev));
    ev.type     = EdrEventRegistryPersist;
    ev.severity = EdrSeverityWarning;
    ev.pid      = HandleToUlong(PsGetCurrentProcessId());

    if (keyName && keyName->Buffer) {
        USHORT chars = keyName->Length / sizeof(WCHAR);
        if (chars > EDR_IMAGE_NAME_LEN - 1) chars = EDR_IMAGE_NAME_LEN - 1;
        RtlCopyMemory(ev.imageName, keyName->Buffer, chars * sizeof(WCHAR));
        ev.imageName[chars] = L'\0';
    }

    const char* msg = "Write to autostart Run key (persistence)";
    size_t i = 0;
    for (; i < EDR_MSG_LEN - 1 && msg[i]; i++) ev.message[i] = msg[i];
    ev.message[i] = '\0';

    EdrQueuePush(&g_eventQueue, &ev);
}

static NTSTATUS EdrRegistryCallback(PVOID context, PVOID arg1, PVOID arg2) {
    UNREFERENCED_PARAMETER(context);

    REG_NOTIFY_CLASS op = (REG_NOTIFY_CLASS)(ULONG_PTR)arg1;

    if (op == RegNmPreSetValueKey) {
        PREG_SET_VALUE_KEY_INFORMATION info = (PREG_SET_VALUE_KEY_INFORMATION)arg2;
        if (info == NULL) {
            return STATUS_SUCCESS;
        }

        PCUNICODE_STRING keyName = NULL;
        if (NT_SUCCESS(CmCallbackGetKeyObjectIDEx(&g_cookie, info->Object, NULL, &keyName, 0))) {
            if (EdrKeyNameIsRunKey(keyName)) {
                EdrReportRunKey(keyName);
            }
            CmCallbackReleaseKeyObjectIDEx(keyName);
        }
    }

    return STATUS_SUCCESS;  // observe only; never block in the skeleton
}

NTSTATUS EdrRegisterRegistryCallback(PDRIVER_OBJECT DriverObject) {
    UNICODE_STRING altitude = RTL_CONSTANT_STRING(L"360000");  // a free Cm altitude
    NTSTATUS status = CmRegisterCallbackEx(
        EdrRegistryCallback, &altitude, DriverObject, NULL, &g_cookie, NULL);

    if (NT_SUCCESS(status)) {
        g_regCbOn = TRUE;
        DbgPrint("[MyEDR] registry callback registered\n");
    } else {
        DbgPrint("[MyEDR] CmRegisterCallbackEx failed: 0x%X\n", status);
    }
    return status;
}

void EdrUnregisterRegistryCallback(void) {
    if (g_regCbOn) {
        CmUnRegisterCallback(g_cookie);
        g_regCbOn = FALSE;
    }
}
