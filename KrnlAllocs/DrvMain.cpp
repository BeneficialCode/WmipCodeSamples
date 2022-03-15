#include <ntddk.h>
#include "KaDrvR3.h"
#include "Logging.h"
#include "MemTest.h"


DRIVER_UNLOAD DriverUnload;
DRIVER_DISPATCH DriverCreate, DriverClose, DriverDeviceControl;

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

	LogInfo("Driver unloaded.\n");
}

extern "C" NTSTATUS
DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath) {
	UNREFERENCED_PARAMETER(RegistryPath);

	NTSTATUS status;
	LogInfo("driver, compiled %s %s\n", __DATE__, __TIME__);
	
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

	LogInfo("driver successfully loaded.\n");

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

_Use_decl_annotations_
NTSTATUS DriverDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	UNREFERENCED_PARAMETER(DeviceObject);
	NTSTATUS status = STATUS_SUCCESS;

	const auto& dic = IoGetCurrentIrpStackLocation(Irp)->Parameters.DeviceIoControl;
	ULONG len = 0;

	switch (dic.IoControlCode)
	{
	case IOCTL_MEMTEST_ALLOCATEMDL:
		status = IoAllocateMdlTest(Irp);
		if (NT_SUCCESS(status)) {
			len = sizeof PMDL;
		}
		break;

	case IOCTL_MEMTEST_ALLOCMAPADDR:
		status = MmAllocateMappingAddressTest(Irp);
		break;

	case IOCTL_MEMTEST_ALLOCPAGESMDL:
		status = MmAllocatePagesForMdlExTest(Irp);
		if (NT_SUCCESS(status)) {
			len = sizeof PMDL;
		}
		break;

	case IOCTL_MEMTEST_CALLPAGEABLE:
		status = PageableFunction(DeviceObject, Irp);
		break;

	case IOCTL_MEMTEST_FREEMAPADDR:
		status = MmFreeMappingAddressTest(Irp);
		break;

	case IOCTL_MEMTEST_FREEMDL:
		status = IoFreeMdlTest(Irp);
		break;

	case IOCTL_MEMTEST_FREEPAGESMDL:
		status = MmFreePagesFromMdlTest(Irp);
		break;

	case IOCTL_MEMTEST_KMEMTOUCH:
		status = KmemTouchTest(Irp);
		break;

	case IOCTL_MEMTEST_LOCKPAGEABLE:
		status = LockPagFunTest();
		break;

	case IOCTL_MEMTEST_MAPLOCKPAGES:
		status = MmMapLockedPagesSpecifyCacheTest(Irp);
		if (NT_SUCCESS(status)) {
			len = sizeof PVOID;
		}
		break;

	case IOCTL_MEMTEST_MAPLPAGESRESMAP:
		status = MmMapLockedPagesWithReservedMappingTest(Irp);
		if (NT_SUCCESS(status)) {
			len = sizeof PVOID;
		}
		break;

	case IOCTL_MEMTEST_MDL_FOR_USER_BUFFER:
		status = MdlForUserBufferTest(Irp);
		break;

	case IOCTL_MEMTEST_PROBEANDLOCK:
		status = MmProbeAndLockPagesTest(Irp);
		break;

	case IOCTL_MEMTEST_UNLOCKPAGEABLE:
		status = UnlockPagFunTest(DeviceObject, Irp);
		break;

	case IOCTL_MEMTEST_UNLOCKPAGES:
		status = MmUnlockPagesTest(Irp);
		break;

	case IOCTL_MEMTEST_UNMAPLOCKPAG:
		status = MmUnmapLockedPagesTest(Irp);
		break;

	case IOCTL_MEMTEST_UNMAPRESMAP:
		status = MmUnmapReservedMappingTest(Irp);
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