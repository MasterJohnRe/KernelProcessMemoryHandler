#pragma once

#include "Memory.h"
#include "ProcessMemoryHandlerCommon.h"


NTSTATUS CompleteIrp(PIRP Irp, NTSTATUS status = STATUS_SUCCESS, ULONG_PTR info = 0)
{
	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = info;
	IoCompleteRequest(Irp, 0);
	return status;
}

NTSTATUS ProcessMemoryHandlerCreateClose(PDEVICE_OBJECT deviceObject, PIRP irp) {
	UNREFERENCED_PARAMETER(deviceObject);
	return CompleteIrp(irp);
}


NTSTATUS ChangeMemoryProtection(
	PEPROCESS targetProcess,
	PVOID targetUserAddress,
	SIZE_T newSize,
	ULONG newProtection,
	PULONG oldProtection
)
{
	NTSTATUS protectionStatus = STATUS_SUCCESS;
	KAPC_STATE apcState;

	// Attach to the target process
	KeStackAttachProcess(targetProcess, &apcState);

	__try {
		// Change the protection of the user-mode address
		protectionStatus = ZwProtectVirtualMemory(ZwCurrentProcess(), &targetUserAddress, (PULONG)&newSize, newProtection, oldProtection);
		if (!NT_SUCCESS(protectionStatus))
			KdPrint(("Failed to change protection: 0x%X\n", protectionStatus));

	}
	__finally {
		// Detach from the target process
		KeUnstackDetachProcess(&apcState);
	}

	return protectionStatus;
}


NTSTATUS ProcessMemoryHandlerWrite(PDEVICE_OBJECT deviceObject, PIRP irp) {

	UNREFERENCED_PARAMETER(deviceObject);
	KdPrint(("ProcessMemoryHandler Write dispatch routine invoked\n"));
	auto stack = IoGetCurrentIrpStackLocation(irp);
	auto writeBufferLength = stack->Parameters.Write.Length;
	if (writeBufferLength < sizeof(WRITE_REQUEST)) {
		return CompleteIrp(irp, STATUS_INVALID_BUFFER_SIZE);
	}
	PWRITE_REQUEST writeRequest = (PWRITE_REQUEST)irp->AssociatedIrp.SystemBuffer;
	// Extract parameters from the structure	
	PEPROCESS process;
	if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)writeRequest->ProcessId, &process)))
	{
		return CompleteIrp(irp, STATUS_INVALID_ADDRESS); //TODO: change to different invalid status
	}

	PVOID baseAddress = reinterpret_cast<PVOID>(writeRequest->BaseAddress);
	SIZE_T size = writeRequest->Size;


	PVOID userBuffer = writeRequest->Buffer;
	KdPrint(("ProcessId: %lu, BaseAddress: %p, Size: %u, Data: %p\n", writeRequest->ProcessId, baseAddress, (unsigned  int)size, userBuffer));

	ULONG oldProtection;
	if (!NT_SUCCESS(ChangeMemoryProtection(process, baseAddress, size, PAGE_EXECUTE_READWRITE, &oldProtection))) {
		return CompleteIrp(irp, STATUS_INVALID_ADDRESS); //TODO: change to different invalid status
	}
	NTSTATUS isWriteSucceeded = KernelWriteVirtualMemory(process, userBuffer, baseAddress, size);
	if (isWriteSucceeded)
		KdPrint(("isWriteSucceeded: %08x\n", isWriteSucceeded));
	
	//set back old protection
	ChangeMemoryProtection(process, baseAddress, size, oldProtection, &oldProtection);

	return CompleteIrp(irp, STATUS_SUCCESS, size);
}

NTSTATUS ProcessMemoryHandlerRead(PDEVICE_OBJECT deviceObject, PIRP irp) {
	UNREFERENCED_PARAMETER(deviceObject);
	KdPrint(("ProcessMemoryHandler Read dispatch routine invoked\n"));
	auto stack = IoGetCurrentIrpStackLocation(irp);
	auto readBufferLength = stack->Parameters.Read.Length;
	if (readBufferLength < sizeof(IO_REQUEST)) {
		return CompleteIrp(irp, STATUS_INVALID_BUFFER_SIZE);
	}
	PIO_REQUEST readRequest = (PIO_REQUEST)irp->AssociatedIrp.SystemBuffer;
	// Extract parameters from the structure	
	PEPROCESS process;
	if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)readRequest->ProcessId, &process)))
	{
		return CompleteIrp(irp, STATUS_INVALID_ADDRESS); //TODO: change to different invalid status
	}

	PVOID baseAddress = reinterpret_cast<PVOID>(readRequest->BaseAddress);
	SIZE_T size = readRequest->Size;
	PVOID userBuffer = readRequest->Buffer;
	KdPrint(("ProcessId: %lu, BaseAddress: %p, Size: %u, Data: %p\n", readRequest->ProcessId, baseAddress, (unsigned  int)size, userBuffer));
	NTSTATUS isReadSucceeded = KernelReadVirtualMemory(process, baseAddress, userBuffer, size);
	if (isReadSucceeded) {
		KdPrint(("isReadSucceeded: %08x\n", isReadSucceeded));
	}
	return CompleteIrp(irp, STATUS_SUCCESS, size);

}

NTSTATUS IoControl(PDEVICE_OBJECT deviceObject, PIRP irp) {
	UNREFERENCED_PARAMETER(deviceObject);
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	ULONG byteIO = 0;
	auto stack = IoGetCurrentIrpStackLocation(irp);
	ULONG controlCode = stack->Parameters.DeviceIoControl.IoControlCode;
	if (controlCode == IO_READ_REQUEST) {
		KdPrint(("ProcessMemoryHandler Read invoked\n"));
		auto readBufferLength = stack->Parameters.Read.Length;
		if (readBufferLength < sizeof(IO_REQUEST)) {
			return CompleteIrp(irp, STATUS_INVALID_BUFFER_SIZE);
		}
		PIO_REQUEST readRequest = (PIO_REQUEST)irp->AssociatedIrp.SystemBuffer;
		// Extract parameters from the structure	
		PEPROCESS process;
		if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)readRequest->ProcessId, &process)))
		{
			return CompleteIrp(irp, STATUS_INVALID_ADDRESS); //TODO: change to different invalid status
		}
		KdPrint(("ProcessId: %lu, BaseAddress: %p, Size: %u, Data: %p\n", readRequest->ProcessId, readRequest->BaseAddress, (unsigned int)readRequest->Size, readRequest->Buffer));
		NTSTATUS isReadSucceeded = KernelReadVirtualMemory(process, (PVOID)readRequest->BaseAddress, readRequest->Buffer, readRequest->Size);
		if (isReadSucceeded) {
			KdPrint(("isReadSucceeded: %08x\n", isReadSucceeded));
		}
		return CompleteIrp(irp, STATUS_SUCCESS, readRequest->Size);
	}
	return CompleteIrp(irp, status, byteIO);
}


void ProcessMemoryHandlerUnload(__in PDRIVER_OBJECT driverObject) {
	UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\ProcessMemoryHandler");
	IoDeleteSymbolicLink(&symLink);
	IoDeleteDevice(driverObject->DeviceObject);
	KdPrint(("ProcessMemoryHandler driver unload called\n"));
}


extern "C" NTSTATUS DriverEntry(__in PDRIVER_OBJECT driverObject, __in PUNICODE_STRING registryPath) {
	UNREFERENCED_PARAMETER(registryPath);
	driverObject->DriverUnload = ProcessMemoryHandlerUnload;
	KdPrint(("ProcessMemoryHandler driver initialized successfully\n"));

	driverObject->MajorFunction[IRP_MJ_CREATE] = driverObject->MajorFunction[IRP_MJ_CLOSE] = ProcessMemoryHandlerCreateClose;
	driverObject->MajorFunction[IRP_MJ_WRITE] = ProcessMemoryHandlerWrite;
	driverObject->MajorFunction[IRP_MJ_READ] = ProcessMemoryHandlerRead;
	driverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IoControl;

	UNICODE_STRING devName = RTL_CONSTANT_STRING(L"\\DEVICE\\ProcessMemoryHandler");
	UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\ProcessMemoryHandler");
	bool symLinkCreated = false;
	PDEVICE_OBJECT deviceObject = nullptr;
	auto status = STATUS_SUCCESS;

	do {
		status = IoCreateDevice(driverObject, 0, &devName, FILE_DEVICE_UNKNOWN, 0, FALSE, &deviceObject);
		if (!NT_SUCCESS(status)) {
			KdPrint(("failed to create device (0x%08X)\n", status));
			break;
		}
		deviceObject->Flags |= DO_BUFFERED_IO;

		status = IoCreateSymbolicLink(&symLink, &devName);
		if (!NT_SUCCESS(status)) {
			KdPrint(("failed  to create symbolic link (0x%08X)\n", status));
			break;
		}
		symLinkCreated = true;

	} while (false);

	if (!NT_SUCCESS(status)) {
		if (deviceObject)
			IoDeleteDevice(deviceObject);
		if (symLinkCreated)
			IoDeleteSymbolicLink(&symLink);
	}

	return status;
}