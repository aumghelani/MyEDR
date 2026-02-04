/*
    Image-load notification callback.

    PsSetLoadImageNotifyRoutine fires every time an executable image (EXE, DLL,
    or driver) is mapped into a process. It is the natural place to spot
    suspicious modules: DLLs loaded from world-writable or temp paths, images
    mapped into processes that should never load them, or unsigned code in a
    signed process.

    Here we start with one cheap, high-signal heuristic: a DLL loaded from a
    temp / downloads / public path. Real products add signature checks and
    path-allowlists; this is the hook those build on.
*/

#include "ImageLoad.h"
#include "EventQueue.h"
#include "Driver.h"

extern EDR_EVENT_QUEUE g_eventQueue;

static BOOLEAN g_imageCbOn = FALSE;

// Case-insensitive "does haystack contain needle" over a UNICODE_STRING.
static BOOLEAN EdrUnicodeContains(PCUNICODE_STRING haystack, PCWSTR needle) {
    if (haystack == NULL || haystack->Buffer == NULL) {
        return FALSE;
    }
    UNICODE_STRING n;
    RtlInitUnicodeString(&n, needle);

    USHORT hLen = haystack->Length / sizeof(WCHAR);
    USHORT nLen = n.Length / sizeof(WCHAR);
    if (nLen == 0 || nLen > hLen) {
        return FALSE;
    }

    for (USHORT i = 0; i + nLen <= hLen; i++) {
        BOOLEAN match = TRUE;
        for (USHORT j = 0; j < nLen; j++) {
            WCHAR a = RtlDowncaseUnicodeChar(haystack->Buffer[i + j]);
            WCHAR b = RtlDowncaseUnicodeChar(n.Buffer[j]);
            if (a != b) { match = FALSE; break; }
        }
        if (match) {
            return TRUE;
        }
    }
    return FALSE;
}

static void EdrCopyImagePath(EDR_EVENT* ev, PCUNICODE_STRING fullImageName) {
    if (fullImageName == NULL || fullImageName->Buffer == NULL) {
        return;
    }
    USHORT chars = fullImageName->Length / sizeof(WCHAR);
    if (chars > EDR_IMAGE_NAME_LEN - 1) {
        chars = EDR_IMAGE_NAME_LEN - 1;
    }
    RtlCopyMemory(ev->imageName, fullImageName->Buffer, chars * sizeof(WCHAR));
    ev->imageName[chars] = L'\0';
}

static void EdrLoadImageNotify(
    PUNICODE_STRING FullImageName,
    HANDLE ProcessId,
    PIMAGE_INFO ImageInfo)
{
    UNREFERENCED_PARAMETER(ImageInfo);

    // Only score user-mode images from suspicious locations.
    if (FullImageName == NULL) {
        return;
    }

    BOOLEAN suspicious =
        EdrUnicodeContains(FullImageName, L"\\temp\\") ||
        EdrUnicodeContains(FullImageName, L"\\downloads\\") ||
        EdrUnicodeContains(FullImageName, L"\\users\\public\\") ||
        EdrUnicodeContains(FullImageName, L"\\appdata\\local\\temp\\");

    if (!suspicious) {
        return;
    }

    EDR_EVENT ev;
    RtlZeroMemory(&ev, sizeof(ev));
    ev.type     = EdrEventImageLoad;
    ev.severity = EdrSeverityWarning;
    ev.pid      = HandleToUlong(ProcessId);
    EdrCopyImagePath(&ev, FullImageName);

    const char* msg = "Image loaded from suspicious path";
    size_t i = 0;
    for (; i < EDR_MSG_LEN - 1 && msg[i]; i++) ev.message[i] = msg[i];
    ev.message[i] = '\0';

    EdrQueuePush(&g_eventQueue, &ev);
}

NTSTATUS EdrRegisterImageCallback(void) {
    NTSTATUS status = PsSetLoadImageNotifyRoutine(EdrLoadImageNotify);
    if (NT_SUCCESS(status)) {
        g_imageCbOn = TRUE;
        DbgPrint("[MyEDR] image-load callback registered\n");
    } else {
        DbgPrint("[MyEDR] PsSetLoadImageNotifyRoutine failed: 0x%X\n", status);
    }
    return status;
}

void EdrUnregisterImageCallback(void) {
    if (g_imageCbOn) {
        PsRemoveLoadImageNotifyRoutine(EdrLoadImageNotify);
        g_imageCbOn = FALSE;
    }
}
