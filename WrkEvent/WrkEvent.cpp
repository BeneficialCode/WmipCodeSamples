#include "WrkEvent.h"
#include "DrvR3.h"
#include "Logging.h"

PKeSignalGateBoostPriority g_pKeSignalGateBoostPriority = nullptr;
PKeInitializeGate g_pKeInitializeGate = nullptr;

NTSTATUS CompleteIrp(PIRP Irp, NTSTATUS status, ULONG info) {
	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = info;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}

NTSTATUS ClearEvent(DeviceExtension* pDevExt, PIRP Irp) {
	auto& dic = IoGetCurrentIrpStackLocation(Irp)->Parameters.DeviceIoControl;
	if (dic.InputBufferLength < sizeof INT) {
		return STATUS_INVALID_PARAMETER;
	}
	UINT32 index = *((UINT32*)Irp->AssociatedIrp.SystemBuffer);
	if (index >= sizeof pDevExt->EventV / sizeof KEVENT)
		return STATUS_INVALID_PARAMETER;
	LogInfo("Clearing event #%d\n", index);
	KeClearEvent(&(pDevExt->EventV[index]));
	return STATUS_SUCCESS;
}

void PrintObjAddresses(DeviceExtension* pDevExt) {
	LogInfo("Object addresses: \n");
	for (int i = 0; i < sizeof pDevExt->EventV / sizeof(KEVENT); i++) {
		LogInfo("WrkEvent[%i] address: %#p\n", i,&(pDevExt->EventV[i]));
	}
	LogInfo("Ev ptr array address: %#p\n", pDevExt->EventPtrsV);
	LogInfo("Gate address %#p\n", &(pDevExt->Gate));
}

NTSTATUS SignalEvent(DeviceExtension* pDevExt, PIRP Irp) {
	auto& dic = IoGetCurrentIrpStackLocation(Irp)->Parameters.DeviceIoControl;
	if (dic.InputBufferLength < sizeof INT)
		return STATUS_INVALID_PARAMETER;
	UINT32 index = *((UINT32*)Irp->AssociatedIrp.SystemBuffer);
	if (index > sizeof pDevExt->EventV / sizeof KEVENT) {
		return STATUS_INVALID_PARAMETER;
	}
	LogInfo("Signaling event %#d\n", index);
	KeSetEvent(&(pDevExt->EventV[index]), 0, FALSE);
	return STATUS_SUCCESS;
}

NTSTATUS SignalGate(DeviceExtension* pDevExt) {
	LogInfo("Signaling the gate\n");
	g_pKeSignalGateBoostPriority(&pDevExt->Gate);
	return STATUS_SUCCESS;
}