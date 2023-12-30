#pragma once
#include "ntifs.h"

extern "C" NTSTATUS NTAPI MmCopyVirtualMemory
(
	PEPROCESS SourceProcess,
	PVOID SourceAddress,
	PEPROCESS TargetProcess,
	PVOID TargetAddress,
	SIZE_T BufferSize,
	KPROCESSOR_MODE PreviousMode,
	PSIZE_T ReturnSize
);

extern "C" NTSTATUS NTAPI ZwProtectVirtualMemory(
	IN HANDLE               ProcessHandle,
	IN OUT PVOID 			*BaseAddress,
	IN OUT PULONG           NumberOfBytesToProtect,
	IN ULONG                NewAccessProtection,
	OUT PULONG              OldAccessProtection);

NTSTATUS KernelWriteVirtualMemory(PEPROCESS process, PVOID sourceAddress, PVOID targetAddress, SIZE_T size);

NTSTATUS KernelReadVirtualMemory(PEPROCESS process, PVOID sourceAddress, PVOID targetAddress, SIZE_T size);
