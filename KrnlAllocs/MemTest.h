#pragma once
#include <ntddk.h>

NTSTATUS IoAllocateMdlTest(_Inout_ PIRP Irp);
NTSTATUS IoFreeMdlTest(_Inout_ PIRP Irp);
NTSTATUS KmemTouchTest(_Inout_ PIRP Irp);
NTSTATUS MdlForUserBufferTest(_Inout_ PIRP Irp);
NTSTATUS MmAllocateMappingAddressTest(_Inout_ PIRP Irp);
NTSTATUS MmAllocatePagesForMdlExTest(_Inout_ PIRP Irp);
NTSTATUS MmFreeMappingAddressTest(_Inout_ PIRP Irp);
NTSTATUS MmFreePagesFromMdlTest(_Inout_ PIRP Irp);
NTSTATUS MmMapLockedPagesSpecifyCacheTest(_Inout_ PIRP Irp);
NTSTATUS MmMapLockedPagesWithReservedMappingTest(_Inout_ PIRP Irp);
NTSTATUS MmProbeAndLockPagesTest(_Inout_ PIRP Irp);
NTSTATUS MmUnlockPagesTest(_Inout_ PIRP Irp);
NTSTATUS MmUnmapLockedPagesTest(_Inout_ PIRP Irp);
NTSTATUS MmUnmapReservedMappingTest(_Inout_ PIRP Irp);

NTSTATUS LockPagFunTest();
DRIVER_DISPATCH UnlockPagFunTest;
extern "C" DRIVER_DISPATCH PageableFunction;

NTSTATUS CompleteIrp(PIRP Irp, NTSTATUS status = STATUS_SUCCESS, ULONG info = 0);