#pragma once
#include <ntddk.h>

NTSTATUS EdrRegisterImageCallback(void);
void     EdrUnregisterImageCallback(void);
