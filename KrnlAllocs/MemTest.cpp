#include "MemTest.h"
#include "KaDrvR3.h"
#include "Logging.h"

_Use_decl_annotations_
NTSTATUS IoAllocateMdlTest(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	Log(LogLevel::Information, "IoAllocateMdlTest\n");
	auto& dic = IoGetCurrentIrpStackLocation(Irp)->Parameters.DeviceIoControl;
	
}

_Use_decl_annotations_
NTSTATUS IoFreeMdlTest(PDEVICE_OBJECT DeviceObject, PIRP Irp) {

}

_Use_decl_annotations_
NTSTATUS KmemTouchTest(PDEVICE_OBJECT DeviceObject, PIRP Irp) {

}

_Use_decl_annotations_
NTSTATUS LockPagFunTest(PDEVICE_OBJECT DeviceObject, PIRP Irp) {

}

_Use_decl_annotations_
NTSTATUS MdlForUserBufferTest(PDEVICE_OBJECT DeviceObject, PIRP Irp) {

}

_Use_decl_annotations_
NTSTATUS MmAllocateMappingAddressTest(PDEVICE_OBJECT DeviceObject, PIRP Irp) {

}

_Use_decl_annotations_
NTSTATUS MmAllocatePagesForMdlExTest(PDEVICE_OBJECT DeviceObject, PIRP Irp) {

}

_Use_decl_annotations_
NTSTATUS MmFreeMappingAddressTest(PDEVICE_OBJECT DeviceObject, PIRP Irp) {

}

_Use_decl_annotations_
NTSTATUS MmFreePagesFromMdlTest(PDEVICE_OBJECT DeviceObject, PIRP Irp) {

}

_Use_decl_annotations_
NTSTATUS MmMapLockedPagesSpecifyCacheTest(PDEVICE_OBJECT DeviceObject, PIRP Irp) {

}

_Use_decl_annotations_
NTSTATUS MmMapLockedPagesWithReservedMappingTest(PDEVICE_OBJECT DeviceObject, PIRP Irp) {

}

_Use_decl_annotations_
NTSTATUS MmProbeAndLockPagesTest(PDEVICE_OBJECT DeviceObject, PIRP Irp) {

}

_Use_decl_annotations_
NTSTATUS MmUnlockPagesTest(PDEVICE_OBJECT DeviceObject, PIRP Irp) {

}

_Use_decl_annotations_
NTSTATUS MmUnmapLockedPagesTest(PDEVICE_OBJECT DeviceObject, PIRP Irp) {

}

_Use_decl_annotations_
NTSTATUS MmUnmapReservedMappingTest(PDEVICE_OBJECT DeviceObject, PIRP Irp) {

}

_Use_decl_annotations_
NTSTATUS PageableFunction(PDEVICE_OBJECT DeviceObject, PIRP Irp) {

}

_Use_decl_annotations_
NTSTATUS UnlockPagFunTest(PDEVICE_OBJECT DeviceObject, PIRP Irp) {

}