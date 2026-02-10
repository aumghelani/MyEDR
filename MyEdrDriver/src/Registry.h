#pragma once
#include <ntddk.h>

NTSTATUS EdrRegisterRegistryCallback(PDRIVER_OBJECT DriverObject);
void     EdrUnregisterRegistryCallback(void);
