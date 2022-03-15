#include "MemTest.h"
#include "KaDrvR3.h"
#include "Logging.h"

char g_DummyByte;

PVOID g_pDrvLockHandle = nullptr;

NTSTATUS CompleteIrp(PIRP Irp, NTSTATUS status, ULONG info) {
	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = info;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}

_Use_decl_annotations_
NTSTATUS IoAllocateMdlTest(PIRP Irp) {
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	LogInfo("IoAllocateMdlTest\n");
	auto& dic = IoGetCurrentIrpStackLocation(Irp)->Parameters.DeviceIoControl;
	ULONG len = dic.InputBufferLength;
	if (len < sizeof AllocaMdl) {
		status = STATUS_INVALID_PARAMETER;
		LogError("Input data too short: %d\n", len);
		return status;
	}

	auto data = (AllocaMdl*)Irp->AssociatedIrp.SystemBuffer;
	if (!data->VirtualAddress) {
		status = STATUS_INVALID_PARAMETER;
		LogError("data->VirtualAddress = 0\n");
		return status;
	}
	if (!data->Length) {
		status = STATUS_INVALID_PARAMETER;
		LogError("data->Length = 0\n");
		return status;
	}
	LogInfo("About to allocate MDL\n");
	LogInfo("VirtualAddress = 0x%16p\n", data->VirtualAddress);
	LogInfo("Length = %0x8x\n", data->Length);
	PMDL pMdl = IoAllocateMdl(
		data->VirtualAddress,
		data->Length,
		FALSE,
		FALSE,
		nullptr
	);
	if (pMdl == nullptr) {
		LogError("IoAllocateMdl returned nullptr\n");
		return status;
	}
	// %#表示的输出提示方式，如果是8进制，在前面加0，
	// 如果是十进制，不加任何字符，如果是十六进制，会加上0x
	LogInfo("Allocated MDL at %#p\n", pMdl);
	Irp->AssociatedIrp.SystemBuffer = pMdl;
	status = STATUS_SUCCESS;
	return status;
}

_Use_decl_annotations_
NTSTATUS IoFreeMdlTest(PIRP Irp) {
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	LogInfo("IoFreeMdlTest\n");

	auto& dic = IoGetCurrentIrpStackLocation(Irp)->Parameters.DeviceIoControl;
	ULONG len = dic.InputBufferLength;
	if (len < sizeof PVOID) {
		status = STATUS_INVALID_PARAMETER;
		LogError("Input data too short: %d\n", len);
		return status;
	}

	auto buffer = Irp->AssociatedIrp.SystemBuffer;
	PMDL pMdl = *static_cast<PMDL*>(buffer);
	if (!pMdl) {
		status = STATUS_INVALID_PARAMETER;
		LogError("pMdl = nullptr\n");
		return status;
	}
	LogInfo("About to free MDL\n");
	LogInfo("Address = 0x%16p\n",pMdl);
	IoFreeMdl(pMdl);
	LogInfo("Freed MDL at %#p\n", pMdl);
	status = STATUS_SUCCESS;
	return status;
}

_Use_decl_annotations_
NTSTATUS KmemTouchTest(PIRP Irp) {
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	LogInfo("KmemTouchTest\n");
	auto& dic = IoGetCurrentIrpStackLocation(Irp)->Parameters.DeviceIoControl;
	ULONG len = dic.InputBufferLength;
	if (len < sizeof KmemTouch) {
		status = STATUS_INVALID_PARAMETER;
		LogError("Input data too short: %d\n", len);
		return status;
	}
	auto data = (KmemTouch*)Irp->AssociatedIrp.SystemBuffer;
	if (!data->Start) {
		status = STATUS_INVALID_PARAMETER;
		LogError("data->Start = 0\n");
		return status;
	}
	if (!data->Length) {
		status = STATUS_INVALID_PARAMETER;
		LogError("data->Length = 0\n");
		return status;
	}
	if ((data->AccessType != AccessType::Read)
		&& (data->AccessType != AccessType::Write)) {
		status = STATUS_INVALID_PARAMETER;
		LogError("data->AccessType invalid: %d\n");
		return status;
	}
	PVOID pEnd = (PCHAR)data->Start + data->Length;
	LogInfo("About to touch region 0x%16p - 0x%16p\n", data->Start, pEnd);
	PCHAR pTouch = (PCHAR)data->Start;
	__try {
		for (; pTouch < pEnd; pTouch += 0x1000) {
			if (data->AccessType == AccessType::Read) {
				g_DummyByte = *pTouch;
			}
			else {
				*((PULONGLONG)pTouch) = (ULONGLONG)pTouch;
			}
		}
		status = STATUS_SUCCESS;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		ULONG code = GetExceptionCode();
		LogError("Exception while touching memory. Code = 0x%8x\n", code);
	}
	return status;
}

NTSTATUS LockPagFunTest() {
	g_pDrvLockHandle = MmLockPagableCodeSection(PageableFunction);
	LogInfo("PageableFunction locked. Handle = 0x%8p\n", g_pDrvLockHandle);
	return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS MdlForUserBufferTest(PIRP Irp) {
	BOOLEAN locked = false;
	PVOID pMapping = nullptr;
	PMDL pMdl = nullptr;
	NTSTATUS status = STATUS_SUCCESS;

	LogInfo("MDL for User Buffer Test\n");
	auto& dic = IoGetCurrentIrpStackLocation(Irp)->Parameters.DeviceIoControl;
	ULONG len = dic.InputBufferLength;
	if (len < sizeof MdlForUserBuffer) {
		status = STATUS_INVALID_PARAMETER;
		LogError("Input data too short: %d", len);
		return status;
	}
	auto data = (MdlForUserBuffer*)Irp->AssociatedIrp.SystemBuffer;
	if (!data->Buffer) {
		status = STATUS_INVALID_PARAMETER;
		LogError("buffer address = nullptr\n");
		return status;
	}
	if ((ULONGLONG)data->Buffer > 0x80000000000) {
		status = STATUS_INVALID_PARAMETER;
		LogError("buffer address not in user range: %#p\n");
		return status;
	}

	ULONG size = data->BufSize;
	if (!size) {
		status = STATUS_INVALID_PARAMETER;
		LogError("buffer size = 0\n");
		return status;
	}

	do
	{
		__try {
			LogError("About to probe user buffer\n");
			switch (data->AccessType)
			{
			case AccessType::Write:
				ProbeForWrite(data->Buffer, size, 1);
				break;

			case AccessType::Read:
				ProbeForRead(data->Buffer, size, 1);
				break;
			default:
				break;
			}
			LogInfo("user buffer probed\n");
			pMdl = IoAllocateMdl(data->Buffer, size, FALSE, FALSE, nullptr);
			if (pMdl == nullptr) {
				status = STATUS_UNSUCCESSFUL;
				LogError("IoAllocateMdl() failed\n");
				// 直接跳出当前的__try作用域
				__leave;
			}
			MmProbeAndLockPages(pMdl, 
				static_cast<KPROCESSOR_MODE>(data->AccessMode),
				static_cast<LOCK_OPERATION>(data->AccessType));
			locked = true;
			pMapping = MmMapLockedPagesSpecifyCache(
				pMdl,
				static_cast<KPROCESSOR_MODE>(data->AccessMode),
				static_cast<MEMORY_CACHING_TYPE>(data->CacheType),
				nullptr,
				FALSE,
				LowPagePriority
			);
			if (pMapping == nullptr) {
				status = STATUS_UNSUCCESSFUL;
				LogError("MmMapLockedPagesSpecifyCache() failed\n");
				__leave;
			}
			DbgBreakPoint();
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			LogError("Caught exception: %08x\n", GetExceptionCode());
			status = STATUS_UNSUCCESSFUL;
		}
	} while (false);
	if (pMapping != nullptr) {
		MmUnmapLockedPages(pMapping, pMdl);
	}
	if (locked) {
		MmUnlockPages(pMdl);
	}
	if (pMdl != nullptr) {
		IoFreeMdl(pMdl);
	}
	

	return status;
}

_Use_decl_annotations_
NTSTATUS MmAllocateMappingAddressTest(PIRP Irp) {
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	LogInfo("MmAllocateMappingAddressTest\n");

	auto& dic = IoGetCurrentIrpStackLocation(Irp)->Parameters.DeviceIoControl;
	ULONG len = dic.InputBufferLength;
	if (len < sizeof AllMapAddr) {
		status = STATUS_INVALID_PARAMETER;
		LogError("Input data too short: %d\n", len);
		return status;
	}
	auto data = (AllMapAddr*)Irp->AssociatedIrp.SystemBuffer;
	if (!data->Size) {
		status = STATUS_INVALID_PARAMETER;
		LogError("data->Size = 0\n");
		return status;
	}
	LogInfo("About to allocate mapping address\n");
	LogInfo("Size = 0x%I64x\n", data->Size);
	data->Address = MmAllocateMappingAddress(data->Size, MAP_REGION_TAG);
	LogInfo("Reserved region at %#p, size = %I64x\n", data->Address, data->Size);
	status = STATUS_SUCCESS;
	return status;
}

_Use_decl_annotations_
NTSTATUS MmAllocatePagesForMdlExTest(PIRP Irp) {
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	LogError("MmAllocatePagesForMdlTest\n");

	auto& dic = IoGetCurrentIrpStackLocation(Irp)->Parameters.DeviceIoControl;
	ULONG len = dic.InputBufferLength;
	if (len < sizeof AllPagesForMdl) {
		status = STATUS_INVALID_PARAMETER;
		LogError("Input data too short: %d\n", len);
		return status;
	}
	auto data = (AllPagesForMdl*)Irp->AssociatedIrp.SystemBuffer;
	PHYSICAL_ADDRESS lowAddress;
	lowAddress.QuadPart = (LONGLONG)data->LowAddress;
	if (!data->HighAddress) {
		status = STATUS_INVALID_PARAMETER;
		LogError("data->HighAddress = 0\n");
		return status;
	}

	PHYSICAL_ADDRESS highAddress;
	highAddress.QuadPart = (LONGLONG)data->HighAddress;

	if (!data->SkipBytes) {
		status = STATUS_INVALID_PARAMETER;
		LogError("data->SkipBytes = 0\n");
		return status;
	}

	PHYSICAL_ADDRESS skipBytes;
	skipBytes.QuadPart = (LONGLONG)data->SkipBytes;

	if (!data->TotalBytes) {
		status = STATUS_INVALID_PARAMETER;
		LogError("data->TotalBytes = 0\n");
		return status;
	}
	
	LogInfo("About to call MmAllocatePagesForMdlEx()\n");
	LogInfo("LowAddress = 0x%I64x\n", lowAddress.QuadPart);
	LogInfo("HighAddress = 0xI64x\n", highAddress.QuadPart);
	LogInfo("SkipBytes = 0x%I64x\n", skipBytes.QuadPart);
	LogInfo("TotalBytes = 0x%I64x\n", data->TotalBytes);
	LogInfo("CacheType = %d\n", data->CacheType);
	LogInfo("Flags = 0x%x\n", data->Flags);
	PMDL pMdl = MmAllocatePagesForMdlEx(
		lowAddress,
		highAddress,
		skipBytes,
		data->TotalBytes,
		static_cast<MEMORY_CACHING_TYPE>(data->CacheType),
		data->Flags
	);
	if (pMdl == nullptr) {
		LogError("MmAllocatePagesForMdlEx() failed");
		return status;
	}
	LogInfo("MmAllocatePagesForMdlEx() allocated MDL at 0x%16p for %d bytes",
		pMdl, MmGetMdlByteCount(pMdl));
	Irp->AssociatedIrp.SystemBuffer = pMdl;
	status = STATUS_SUCCESS;
	return status;
}

_Use_decl_annotations_
NTSTATUS MmFreeMappingAddressTest(PIRP Irp) {
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	LogInfo("MmFreeMappingAddressTest\n");
	auto& dic = IoGetCurrentIrpStackLocation(Irp)->Parameters.DeviceIoControl;
	if (dic.InputBufferLength < sizeof PVOID) {
		status = STATUS_INVALID_PARAMETER;
		LogError("Input data too short: %d\n", dic.InputBufferLength);
		return status;
	}
	auto buffer = Irp->AssociatedIrp.SystemBuffer;
	PVOID pRegion = *static_cast<PVOID*>(buffer);
	if (!pRegion) {
		status = STATUS_INVALID_PARAMETER;
		LogError("pRegion = nullptr\n");
		return status;
	}
	LogInfo("About to free mapping address = 0x%16p\n", pRegion);
	MmFreeMappingAddress(pRegion, MAP_REGION_TAG);
	LogInfo("Freed region at %#p\n", pRegion);
	status = STATUS_SUCCESS;
	return status;
}

_Use_decl_annotations_
NTSTATUS MmFreePagesFromMdlTest(PIRP Irp) {
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	LogError("MmFreePagesFromMdlTest\n");
	auto& dic = IoGetCurrentIrpStackLocation(Irp)->Parameters.DeviceIoControl;
	ULONG len = dic.InputBufferLength;
	if (len < sizeof PVOID) {
		status = STATUS_INVALID_PARAMETER;
		LogError("Input data too short: %d\n");
		return status;
	}
	auto buffer = Irp->AssociatedIrp.SystemBuffer;
	PMDL pMdl = *static_cast<PMDL*>(buffer);
	if (!pMdl) {
		status = STATUS_INVALID_PARAMETER;
		LogError("pMdl = nullptr\n");
		return status;
	}
	LogInfo("About to free MDL pages\n");
	LogInfo("Address = %0x16p\n", pMdl);
	MmFreePagesFromMdl(pMdl);
	LogInfo("Pages from MDL at 0x%16p released\n",pMdl);
	status = STATUS_SUCCESS;
	return status;
}

_Use_decl_annotations_
NTSTATUS MmMapLockedPagesSpecifyCacheTest(PIRP Irp) {
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	LogError("MmMapLockedPagesSpecifyCacheTest\n");
	auto& dic = IoGetCurrentIrpStackLocation(Irp)->Parameters.DeviceIoControl;
	ULONG len = dic.InputBufferLength;
	if (len < sizeof MapLockPages) {
		status = STATUS_INVALID_PARAMETER;
		LogError("Input data too short: %d\n", len);
		return status;
	}

	auto data = (MapLockPages*)Irp->AssociatedIrp.SystemBuffer;
	if (!data->Mdl) {
		status = STATUS_INVALID_PARAMETER;
		LogError("data->Mdl = nullptr\n");
		return status;
	}
	auto cacheType = static_cast<MEMORY_CACHING_TYPE>(data->CacheType);
	auto mode = static_cast<KPROCESSOR_MODE>(data->AccessMode);
	LogInfo("About to call MmMapLockedPagesSpecifyCache()\n");
	LogInfo("MemoryDescriptorList = 0x%16p\n", data->Mdl);
	LogInfo("AccessMode = %d\n", mode);
	LogInfo("CacheType = %d\n", cacheType);
	LogInfo("BaseAddress = 0x%16p\n", data->BaseAddress);
	PVOID pMappedRegion = MmMapLockedPagesSpecifyCache(
		(PMDLX)data->Mdl,
		mode, 
		cacheType, 
		data->BaseAddress,
		FALSE, 
		LowPagePriority);
	if (pMappedRegion == nullptr) {
		LogError("MmMapLockedPagesSpecifyCache() failed");
		return status;
	}
	LogInfo("Mapped region at 0x%16p\n", pMappedRegion);
	*((PVOID*)Irp->AssociatedIrp.SystemBuffer) = pMappedRegion;
	status = STATUS_SUCCESS;
	return status;
}

_Use_decl_annotations_
NTSTATUS MmMapLockedPagesWithReservedMappingTest(PIRP Irp) {
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	LogInfo("MmMapLockedPagesWithReservedMappingTest\n");

	auto& dic = IoGetCurrentIrpStackLocation(Irp)->Parameters.DeviceIoControl;
	ULONG len = dic.InputBufferLength;
	if (len < sizeof MapLPagesResMap) {
		status = STATUS_INVALID_PARAMETER;
		LogInfo("Input data too short: %d\n", len);
		return status;
	}
	auto data = (MapLPagesResMap*)Irp->AssociatedIrp.SystemBuffer;
	if (!data->MappingAddress) {
		status = STATUS_INVALID_PARAMETER;
		LogError("data->MappingAddress = nullptr");
		return status;
	}
	if (!data->Mdl) {
		status = STATUS_INVALID_PARAMETER;
		LogError("data->Mdl = nullptr\n");
		return status;
	}
	auto cacheType = static_cast<MEMORY_CACHING_TYPE>(data->CacheType);
	LogInfo("About to call MmMapLockedPagesWithReservedMapping()\n");
	LogInfo("MappingAddress = 0x%16p\n", data->MappingAddress);
	LogInfo("MemoryDescriptorList = 0x%16p\n", data->Mdl);
	LogInfo("CacheType = 0x%d\n", cacheType);
	PVOID pMappedRegion = MmMapLockedPagesWithReservedMapping(
		data->MappingAddress,
		MAP_REGION_TAG,
		(PMDLX)data->Mdl,
		cacheType
	);
	if (pMappedRegion == nullptr) {
		LogError("MmMapLockedPagesWithReservedMapping() failed\n");
		return status;
	}
	LogInfo("Mapped region at 0x%16p", pMappedRegion);
	*((PVOID*)Irp->AssociatedIrp.SystemBuffer) = pMappedRegion;
	status = STATUS_SUCCESS;
	return status;
}

_Use_decl_annotations_
NTSTATUS MmProbeAndLockPagesTest(PIRP Irp) {
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	LogInfo("MmProbeAndLockPagesTest\n");
	auto& dic = IoGetCurrentIrpStackLocation(Irp)->Parameters.DeviceIoControl;
	if (dic.InputBufferLength < sizeof ProbeAndLock) {
		status = STATUS_INVALID_PARAMETER;
		LogInfo("Input data too short: %d\n",dic.InputBufferLength);
		return status;
	}
	auto data = (ProbeAndLock*)Irp->AssociatedIrp.SystemBuffer;
	if (!data->Mdl) {
		status = STATUS_INVALID_PARAMETER;
		LogError("data->Mdl = nullptr\n");
		return status;
	}
	KPROCESSOR_MODE mode = static_cast<KPROCESSOR_MODE>(data->AccessMode);
	LOCK_OPERATION operation = static_cast<LOCK_OPERATION>(data->Operation);

	__try {
		LogInfo("About to probe and lock MDL pages\n");
		LogInfo("Mdl address = 0x%16p\n", data->Mdl);
		LogInfo("Access mode = %d\n", mode);
		LogInfo("Operation = %d\n", operation);
		MmProbeAndLockPages(
			(PMDLX)data->Mdl,
			mode,
			operation
		);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		ULONG code = GetExceptionCode();
		LogError("MmProbeAndLockPages() raised exception 0x%8x\n",code);
		return status;
	}

	LogInfo(" Probed and locked MDL at %#p\n", data->Mdl);
	status = STATUS_SUCCESS;
	return status;
}

_Use_decl_annotations_
NTSTATUS MmUnlockPagesTest(PIRP Irp) {
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	LogInfo("MmUnlockPagesTest\n");
	auto& dic = IoGetCurrentIrpStackLocation(Irp)->Parameters.DeviceIoControl;
	ULONG len = dic.InputBufferLength;
	if (len < sizeof PVOID) {
		status = STATUS_INVALID_PARAMETER;
		LogInfo("Input data too short: %d\n", len);
		return status;
	}
	auto buffer = Irp->AssociatedIrp.SystemBuffer;
	PMDLX pMdl = *static_cast<PMDLX*>(buffer);
	if (!pMdl) {
		status = STATUS_INVALID_PARAMETER;
		LogError("pMdl = nullptr\n");
		return status;
	}
	LogInfo("About to unlock MDL pages\n");
	LogInfo("Mdl address = 0x%16p\n",pMdl);
	MmUnlockPages(pMdl);
	LogInfo("Unlocked MDL at %#p\n", pMdl);
	status = STATUS_SUCCESS;
	return status;
}

_Use_decl_annotations_
NTSTATUS MmUnmapLockedPagesTest(PIRP Irp) {
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	LogInfo("MmUnmapLockedPagesTest\n");
	auto& dic = IoGetCurrentIrpStackLocation(Irp)->Parameters.DeviceIoControl;
	if (dic.InputBufferLength < sizeof UnmapLockPag) {
		status = STATUS_INVALID_PARAMETER;
		LogError("Input data too short: %d\n", dic.InputBufferLength);
		return status;
	}
	auto data = (UnmapLockPag*)Irp->AssociatedIrp.SystemBuffer;
	if (!data->BaseAddress) {
		status = STATUS_INVALID_PARAMETER;
		LogError("data->BaseAddress = nullptr\n");
		return status;
	}
	if (!data->Mdl) {
		status = STATUS_INVALID_PARAMETER;
		LogError("data->Mdl = nullptr\n");
		return status;
	}
	LogInfo("About to call MmUnmapLockedPages()\n");
	LogInfo("BaseAddress = 0x%16p\n", data->BaseAddress);
	LogInfo("MemoryDescriptorList = 0x%16p\n", data->Mdl);
	MmUnmapLockedPages(
		data->BaseAddress,
		(PMDL)data->Mdl
	);
	LogInfo("Unmapped region at 0x%16p", data->BaseAddress);
	status = STATUS_SUCCESS;
	return status;
}

_Use_decl_annotations_
NTSTATUS MmUnmapReservedMappingTest(PIRP Irp) {

	NTSTATUS status = STATUS_UNSUCCESSFUL;

	LogInfo("MmUnmapReservedMappingTest\n");
	auto& dic = IoGetCurrentIrpStackLocation(Irp)->Parameters.DeviceIoControl;
	ULONG len = dic.InputBufferLength;
	if (len < sizeof UnmapResMap) {
		status = STATUS_INVALID_PARAMETER;
		LogError("Input data too short: %d\n", len);
		return status;
	}
	auto data = (UnmapResMap*)Irp->AssociatedIrp.SystemBuffer;
	if (!data->BaseAddress) {
		LogError("data->BaseAddress = nullptr\n");
		return status;
	}
	if (!data->Mdl) {
		status = STATUS_INVALID_PARAMETER;
		LogError("data->Mdl = nullptr\n");
		return status;
	}
	LogInfo("About to call MmUnmapReservedMapping()\n");
	LogInfo("BaseAddress = 0x%16p\n", data->BaseAddress);
	LogInfo("MemoryDescriptorList = 0x%16p\n", data->Mdl);
	MmUnmapReservedMapping(data->BaseAddress, MAP_REGION_TAG, (PMDLX)data->Mdl);
	LogInfo("Unmapped region at 0x%16p\n", data->BaseAddress);
	status = STATUS_SUCCESS;
	return status;
}

#pragma alloc_text("PAGEme",PageableFunction)
_Use_decl_annotations_
NTSTATUS PageableFunction(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	UNREFERENCED_PARAMETER(DeviceObject);
	UNREFERENCED_PARAMETER(Irp);

	LogInfo("PageableFunction called\n");
	return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS UnlockPagFunTest(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	UNREFERENCED_PARAMETER(DeviceObject);
	UNREFERENCED_PARAMETER(Irp);
	MmUnlockPagableImageSection(g_pDrvLockHandle);
	return STATUS_SUCCESS;
}