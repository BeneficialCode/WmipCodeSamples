#include <ntddk.h>
#include "KaDrvR3.h"
#include "Logging.h"
#include "MemTest.h"


DRIVER_UNLOAD DriverUnload;
DRIVER_DISPATCH DriverCreate, DriverClose, DriverDeviceControl;

NTSTATUS CompleteIrp(PIRP Irp, NTSTATUS status = STATUS_SUCCESS, ULONG info = 0);

struct DeviceExtension {
	PDEVICE_OBJECT DeviceObject;
	UNICODE_STRING SymName;
};

void DriverUnload(_In_ PDRIVER_OBJECT DriverObject) {
	// delete symbolic link
	UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\MemTestDevice");
	IoDeleteSymbolicLink(&symLink);
	// delete device object
	IoDeleteDevice(DriverObject->DeviceObject);

	Log(LogLevel::Information, "Driver unloaded.\n");
}

extern "C" NTSTATUS
DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath) {
	NTSTATUS status;
	Log(LogLevel::Information, "driver, compiled %s %s\n", __DATE__, __TIME__);
	
	DriverObject->DriverUnload = DriverUnload;
	DriverObject->MajorFunction[IRP_MJ_CREATE] = DriverCreate;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = DriverClose;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverDeviceControl;

	// Create a device object
	UNICODE_STRING devName = RTL_CONSTANT_STRING(L"\\Device\\MemTestDevice");
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

	// Request buffered I/O
	DeviceObject->Flags |= DO_BUFFERED_IO;
	auto ext = (DeviceExtension*)DeviceObject->DeviceExtension;
	ext->DeviceObject = DeviceObject; // back pointer
	
	// Create a symbolic link to the device object
	UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\MemTestDevice");
	RtlInitUnicodeString(&ext->SymName, L"\\??\\MemTestDevice");
	status = IoCreateSymbolicLink(&symLink, &devName);
	if (!NT_SUCCESS(status)) {
		IoDeleteDevice(DeviceObject);
		return status;
	}

	Log(LogLevel::Information, "driver successfully loaded.\n");

	return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS DriverCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	UNREFERENCED_PARAMETER(DeviceObject);

	NTSTATUS status = CompleteIrp(Irp);

	Log(LogLevel::Information, "Device opened\n");

	return status;
}

_Use_decl_annotations_
NTSTATUS DriverClose(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	UNREFERENCED_PARAMETER(DeviceObject);

	NTSTATUS status = CompleteIrp(Irp);

	Log(LogLevel::Information, "Device closed\n");

	return status;
}

NTSTATUS CompleteIrp(PIRP Irp, NTSTATUS status, ULONG info){
	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = info;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}

_Use_decl_annotations_
NTSTATUS DriverDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	NTSTATUS status = STATUS_SUCCESS;

	const auto& dic = IoGetCurrentIrpStackLocation(Irp)->Parameters.DeviceIoControl;
	ULONG len = 0;

	switch (dic.IoControlCode)
	{
	case IOCTL_MEMTEST_ALLOCATEMDL:
		
		break;

	case IOCTL_MEMTEST_ALLOCMAPADDR:

		break;

	case IOCTL_MEMTEST_ALLOCPAGESMDL:

		break;

	case IOCTL_MEMTEST_CALLPAGEABLE:

		break;

	case IOCTL_MEMTEST_FREEMAPADDR:

		break;

	case IOCTL_MEMTEST_FREEMDL:

		break;

	case IOCTL_MEMTEST_FREEPAGESMDL:

		break;

	case IOCTL_MEMTEST_KMEMTOUCH:

		break;

	case IOCTL_MEMTEST_LOCKPAGEABLE:

		break;

	case IOCTL_MEMTEST_MAPLOCKPAGES:

		break;

	case IOCTL_MEMTEST_MAPLPAGESRESMAP:

		break;

	case IOCTL_MEMTEST_MDL_FOR_USER_BUFFER:

		break;

	case IOCTL_MEMTEST_PROBEANDLOCK:

		break;

	case IOCTL_MEMTEST_UNLOCKPAGEABLE:

		break;

	case IOCTL_MEMTEST_UNLOCKPAGES:

		break;

	case IOCTL_MEMTEST_UNMAPLOCKPAG:

		break;

	case IOCTL_MEMTEST_UNMAPRESMAP:

		break;

	default:
		status = STATUS_INVALID_DEVICE_REQUEST;
		break;
	}
	// If the request isn't complete, return STATUS_PENDING.
	if (status == STATUS_PENDING)
		return status;

	// Note: IoMarkIrpPending must have already been called
	// by the function which returned STATUS_PENDING.

	// Otherwise, complete the IRP.
	//
	CompleteIrp(Irp, status, len);
	return status;
}