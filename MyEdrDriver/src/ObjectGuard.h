#pragma once
#include <ntddk.h>

NTSTATUS EdrRegisterObjectCallback(void);
void     EdrUnregisterObjectCallback(void);
