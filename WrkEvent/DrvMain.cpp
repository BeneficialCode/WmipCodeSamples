/*
=======================================================================

Work event driver
=================

Companion test program to What Makes It Page?

Copyright (c), 2012 by Enrico Martignetti - All rights reserved.




=======================================================================



*/
#include <ntddk.h>
#include "DrvR3.h"
#include "Logging.h"
#include "WrkEvent.h"

DRIVER_UNLOAD DriverUnload;
DRIVER_DISPATCH DriverCreate, DriverClose, DriverDeviceControl;


extern "C" NTSTATUS
DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath) {
	UNREFERENCED_PARAMETER(RegistryPath);
	NTSTATUS status;
	LogInfo("WrkEvent - Work event driver, compiled %s %s\n", __DATE__, __TIME__);
	
	PCHAR pKeSetEvent = (PCHAR)&KeSetEvent;
	g_pKeSignalGateBoostPriority = (PKeInitializeGate)(pKeSetEvent - KE_SIGNAL_GATE_BOOST_PRIORITY_OFFSET);
	g_pKeInitializeGate = (PKeInitializeGate)(pKeSetEvent - KE_INITIALIZE_GATE_OFFSET);

	DriverObject->DriverUnload = DriverUnload;
	DriverObject->MajorFunction[IRP_MJ_CREATE] = DriverCreate;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = DriverClose;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverDeviceControl;

	UNICODE_STRING devName = RTL_CONSTANT_STRING(L"\\Device\\WrkEventDevice");
	PDEVICE_OBJECT DeviceObject = nullptr;

	status = IoCreateDevice(
		DriverObject,
		sizeof(DeviceExtension),
		&devName,
		FILE_DEVICE_UNKNOWN,
		0,
		FALSE,
		&DeviceObject
	);

	if (!NT_SUCCESS(status)) {
		return status;
	}

	LogInfo("WrkEvent - Device created\n");
	// Request buffered I/O
	DeviceObject->Flags |= DO_BUFFERED_IO;
	auto ext = (DeviceExtension*)DeviceObject->DeviceExtension;
	ext->DeviceObject = DeviceObject; // back pointer
	for (int i = 0; i < sizeof ext->EventV / sizeof(KEVENT); i++) {
		KeInitializeEvent(&ext->EventV[i], NotificationEvent, FALSE);
		ext->EventPtrsV[i] = &ext->EventV[i];
	}
	g_pKeInitializeGate(&ext->Gate);

	// Create a symbolic link to the device object
	UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\WrkEventDevice");
	RtlInitUnicodeString(&ext->SymName, L"\\??\\WrkEventDevice");
	status = IoCreateSymbolicLink(&symLink, &devName);
	if (!NT_SUCCESS(status)) {
		IoDeleteDevice(DeviceObject);
		return status;
	}

	LogInfo("WrkEvent - Work event driver successfully loaded.\n");
	return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS DriverCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	UNREFERENCED_PARAMETER(DeviceObject);

	NTSTATUS status = CompleteIrp(Irp);

	LogInfo("Device opened\n");

	return status;
}

_Use_decl_annotations_
NTSTATUS DriverClose(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	UNREFERENCED_PARAMETER(DeviceObject);

	NTSTATUS status = CompleteIrp(Irp);

	LogInfo("Device closed\n");

	return status;
}

void DriverUnload(_In_ PDRIVER_OBJECT DriverObject) {
	// delete symbolic link
	UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\WrkEventDevice");
	IoDeleteSymbolicLink(&symLink);
	// delete device object
	IoDeleteDevice(DriverObject->DeviceObject);

	LogInfo("Driver unloaded.\n");
}

_Use_decl_annotations_
NTSTATUS DriverDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	NTSTATUS status = STATUS_SUCCESS;
	ULONG len = 0;

	auto& dic = IoGetCurrentIrpStackLocation(Irp)->Parameters.DeviceIoControl;
	DeviceExtension* pDevExt = (DeviceExtension*)DeviceObject->DeviceExtension;
	switch (dic.IoControlCode)
	{
	case IOCTL_WRKEVENT_SIGNAL_EVENT:
		status = SignalEvent(pDevExt, Irp);
		break;

	case IOCTL_WRKEVENT_CLEAR_EVENT:
		status = ClearEvent(pDevExt, Irp);
		break;

	case IOCTL_WRKEVENT_SIGNAL_GATE:
		status = SignalGate(pDevExt);
		break;

	case IOCTL_WRKEVENT_PRINT_OBJ_ADDRS:
		PrintObjAddresses(pDevExt);
		status = STATUS_SUCCESS;
		break;
	default:
		status = STATUS_INVALID_DEVICE_REQUEST;
		break;
	}

	if (status == STATUS_PENDING)
		return status;

	CompleteIrp(Irp, status, len);
	return status;
}