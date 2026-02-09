/*
    MyEDR driver entry point, device setup and IOCTL dispatch.

    Lifecycle:
      DriverEntry      -> create device + symlink, init queue, register callbacks
      IRP_MJ_CREATE    -> user-mode CreateFile opens the device
      IRP_MJ_DEVICE_CONTROL -> user-mode DeviceIoControl drains events
      IRP_MJ_CLOSE     -> handle closed
      EdrUnload        -> tear everything down in reverse order
*/

#include <ntddk.h>
#include "Driver.h"
#include "EventQueue.h"
#include "Callbacks.h"
#include "ImageLoad.h"
#include "Registry.h"
#include "ObjectGuard.h"

// The one global queue. Callbacks.c reaches it via 'extern'.
EDR_EVENT_QUEUE g_eventQueue;

static PDEVICE_OBJECT g_deviceObject = NULL;

// --------------------------------------------------------------------------
// IRP handlers
// --------------------------------------------------------------------------
static NTSTATUS EdrCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS EdrDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);

    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_SUCCESS;
    ULONG bytesReturned = 0;

    switch (stack->Parameters.DeviceIoControl.IoControlCode) {
    case IOCTL_MYEDR_GET_EVENT: {
        // With METHOD_BUFFERED the output buffer is SystemBuffer.
        if (stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(EDR_EVENT)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        EDR_EVENT ev;
        if (EdrQueuePop(&g_eventQueue, &ev)) {
            RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, &ev, sizeof(ev));
            bytesReturned = sizeof(ev);
            status = STATUS_SUCCESS;
        } else {
            status = STATUS_NO_MORE_ENTRIES;  // queue empty; client should back off
        }
        break;
    }
    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = bytesReturned;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

// --------------------------------------------------------------------------
// Unload
// --------------------------------------------------------------------------
static void EdrUnload(PDRIVER_OBJECT DriverObject) {
    EdrUnregisterObjectCallback();
    EdrUnregisterRegistryCallback();
    EdrUnregisterImageCallback();
    EdrUnregisterCallbacks();

    UNICODE_STRING symLink = RTL_CONSTANT_STRING(MYEDR_SYMLINK_NAME);
    IoDeleteSymbolicLink(&symLink);

    if (DriverObject->DeviceObject != NULL) {
        IoDeleteDevice(DriverObject->DeviceObject);
    }
    DbgPrint("[MyEDR] unloaded\n");
}

// --------------------------------------------------------------------------
// Entry
// --------------------------------------------------------------------------
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);
    NTSTATUS status;

    DbgPrint("[MyEDR] loading\n");

    EdrQueueInit(&g_eventQueue);

    UNICODE_STRING devName = RTL_CONSTANT_STRING(MYEDR_DEVICE_NAME);
    status = IoCreateDevice(DriverObject, 0, &devName, FILE_DEVICE_UNKNOWN,
                            FILE_DEVICE_SECURE_OPEN, FALSE, &g_deviceObject);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[MyEDR] IoCreateDevice failed: 0x%X\n", status);
        return status;
    }

    UNICODE_STRING symLink = RTL_CONSTANT_STRING(MYEDR_SYMLINK_NAME);
    status = IoCreateSymbolicLink(&symLink, &devName);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[MyEDR] IoCreateSymbolicLink failed: 0x%X\n", status);
        IoDeleteDevice(g_deviceObject);
        return status;
    }

    DriverObject->DriverUnload = EdrUnload;
    DriverObject->MajorFunction[IRP_MJ_CREATE]         = EdrCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]          = EdrCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = EdrDeviceControl;

    status = EdrRegisterCallbacks();
    if (!NT_SUCCESS(status)) {
        IoDeleteSymbolicLink(&symLink);
        IoDeleteDevice(g_deviceObject);
        return status;
    }

    // The extra callbacks are best-effort: if one fails to register we log it
    // and keep running with whatever telemetry we have.
    EdrRegisterImageCallback();
    EdrRegisterRegistryCallback(DriverObject);
    EdrRegisterObjectCallback();

    DbgPrint("[MyEDR] loaded\n");
    return STATUS_SUCCESS;
}
