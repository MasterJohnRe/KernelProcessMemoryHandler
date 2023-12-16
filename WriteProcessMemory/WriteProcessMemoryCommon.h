#pragma once
#include <ntddk.h>

// Custom structure to hold parameters
typedef struct _WRITE_REQUEST {
    ULONG ProcessId;
    ULONG_PTR BaseAddress;
    SIZE_T Size;
    PVOID Buffer;  // Variable-sized buffer
} WRITE_REQUEST, * PWRITE_REQUEST;