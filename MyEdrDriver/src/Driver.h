/*
    MyEDR - a minimal educational Windows EDR driver.
    Shared definitions between the driver and the user-mode client.

    This header is included by BOTH the kernel driver and the user-mode
    client, so keep it free of kernel-only or user-only types.
*/

#pragma once

// ---------------------------------------------------------------------------
// Device + symbolic link names.
//
// The driver creates a device object at \Device\MyEdr and a symbolic link
// \??\MyEdr so user-mode can open it with CreateFile(L"\\\\.\\MyEdr", ...).
// ---------------------------------------------------------------------------
#define MYEDR_DEVICE_NAME   L"\\Device\\MyEdr"
#define MYEDR_SYMLINK_NAME  L"\\??\\MyEdr"
#define MYEDR_USER_PATH     L"\\\\.\\MyEdr"

// ---------------------------------------------------------------------------
// IOCTL codes.
//
// CTL_CODE packs (device type, function, method, access) into one 32-bit code.
// METHOD_BUFFERED means the I/O manager copies input/output through a single
// system buffer (Irp->AssociatedIrp.SystemBuffer), which is the simplest and
// safest transfer method to start with.
// ---------------------------------------------------------------------------
#define MYEDR_DEVICE_TYPE  0x8000  // vendor-defined device types start at 0x8000

#define IOCTL_MYEDR_GET_EVENT \
    CTL_CODE(MYEDR_DEVICE_TYPE, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

// ---------------------------------------------------------------------------
// Event model.
//
// The driver observes the system and pushes EDR_EVENT records into a queue.
// The user-mode client polls IOCTL_MYEDR_GET_EVENT to drain that queue.
// Keep this struct flat (no pointers) so it can be copied across the boundary
// in one RtlCopyMemory with no fix-ups.
// ---------------------------------------------------------------------------
typedef enum _EDR_EVENT_TYPE {
    EdrEventProcessCreate   = 1,
    EdrEventProcessExit     = 2,
    EdrEventRemoteThread    = 3,  // a thread created into a process by another process
    EdrEventImageLoad       = 4,  // image mapped from a suspicious path
    EdrEventRegistryPersist = 5,  // write to an autostart Run key
    EdrEventLsassAccess     = 6,  // handle to LSASS with memory-read access
} EDR_EVENT_TYPE;

typedef enum _EDR_SEVERITY {
    EdrSeverityInfo     = 0,
    EdrSeverityWarning  = 1,
    EdrSeverityCritical = 2,
} EDR_SEVERITY;

#define EDR_IMAGE_NAME_LEN 260
#define EDR_MSG_LEN        128

typedef struct _EDR_EVENT {
    EDR_EVENT_TYPE type;
    EDR_SEVERITY   severity;

    unsigned int   pid;              // subject process id
    unsigned int   parentPid;        // reported parent pid (for creates)
    unsigned int   creatorPid;       // the process that actually created it

    wchar_t        imageName[EDR_IMAGE_NAME_LEN];  // subject image path/name
    char           message[EDR_MSG_LEN];           // human-readable reason
} EDR_EVENT, *PEDR_EVENT;
