/*
    MyEDR user-mode client.

    Opens the \\.\MyEdr device the driver exposes and polls it for events,
    printing each one with a severity tag. This is the "console" half of the
    EDR: the driver produces telemetry, this drains and displays it.

    Run as Administrator (the device has default ACLs and DeviceIoControl
    needs the handle). Start the driver first (see tutorial step 2).
*/

#include <windows.h>
#include <stdio.h>

// Pull in the shared contract. Relative path into the driver's src.
#include "../../MyEdrDriver/src/Driver.h"

static const char* SeverityTag(EDR_SEVERITY s) {
    switch (s) {
    case EdrSeverityCritical: return "CRIT";
    case EdrSeverityWarning:  return "WARN";
    default:                  return "INFO";
    }
}

static const char* TypeName(EDR_EVENT_TYPE t) {
    switch (t) {
    case EdrEventProcessCreate:   return "proc-create";
    case EdrEventProcessExit:     return "proc-exit";
    case EdrEventRemoteThread:    return "remote-thread";
    case EdrEventImageLoad:       return "image-load";
    case EdrEventRegistryPersist: return "reg-persist";
    case EdrEventLsassAccess:     return "lsass-access";
    default:                      return "unknown";
    }
}

int wmain(void) {
    HANDLE h = CreateFileW(MYEDR_USER_PATH, GENERIC_READ | GENERIC_WRITE,
                           0, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        printf("[-] could not open %ls (err %lu). Is the driver loaded? Are you admin?\n",
               MYEDR_USER_PATH, GetLastError());
        return 1;
    }

    printf("[+] connected to MyEDR. Watching events (Ctrl+C to stop)...\n");

    for (;;) {
        EDR_EVENT ev;
        DWORD returned = 0;

        BOOL ok = DeviceIoControl(h, IOCTL_MYEDR_GET_EVENT,
                                  NULL, 0,
                                  &ev, sizeof(ev), &returned, NULL);

        if (ok && returned == sizeof(ev)) {
            printf("[%s] %-13s pid=%u creator=%u parent=%u  %ls :: %s\n",
                   SeverityTag(ev.severity), TypeName(ev.type),
                   ev.pid, ev.creatorPid, ev.parentPid,
                   ev.imageName[0] ? ev.imageName : L"?",
                   ev.message);
        } else {
            // Empty queue (STATUS_NO_MORE_ENTRIES -> DeviceIoControl returns
            // FALSE with ERROR_NO_MORE_ITEMS). Back off briefly and retry.
            Sleep(50);
        }
    }

    CloseHandle(h);  // not reached; kept for clarity
    return 0;
}
