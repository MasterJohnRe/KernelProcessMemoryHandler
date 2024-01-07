#pragma once
#include <ntddk.h>

#define IO_READ_REQUEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x667, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)


// Custom structure to hold parameters
typedef struct _WRITE_REQUEST {
    ULONG ProcessId;
    ULONG_PTR BaseAddress;
    SIZE_T Size;
    PVOID Buffer;  // Variable-sized buffer
} WRITE_REQUEST, * PWRITE_REQUEST;

typedef struct _IO_REQUEST {
    ULONG ProcessId;
    ULONG_PTR BaseAddress;
    SIZE_T Size;
    PVOID Buffer; 
} IO_REQUEST, * PIO_REQUEST;