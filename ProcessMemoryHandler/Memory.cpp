#include "Memory.h"

NTSTATUS KernelWriteVirtualMemory(PEPROCESS process, PVOID sourceAddress, PVOID targetAddress, SIZE_T size) {
	SIZE_T Bytes;
	NTSTATUS copyVirtualMemoryStatus = MmCopyVirtualMemory(PsGetCurrentProcess(), sourceAddress, process, targetAddress, size, KernelMode, &Bytes);;
	KdPrint(("copied %Iu bytes", Bytes));
	return copyVirtualMemoryStatus;
}

NTSTATUS KernelReadVirtualMemory(PEPROCESS process, PVOID sourceAddress, PVOID targetAddress, SIZE_T size) {
	SIZE_T Bytes;
	NTSTATUS copyVirtualMemoryStatus = MmCopyVirtualMemory(process, sourceAddress, PsGetCurrentProcess(), targetAddress, size, KernelMode, &Bytes);;
	KdPrint(("copied %Iu bytes", Bytes));
	return copyVirtualMemoryStatus;
}