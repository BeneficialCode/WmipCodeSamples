#pragma once
#include <ntddk.h>


// Number of elements of the events arrary
#define EVENT_COUNT 5

struct DeviceExtension {
	PDEVICE_OBJECT DeviceObject;
	UNICODE_STRING SymName;
	KEVENT EventV[EVENT_COUNT];
	PRKEVENT EventPtrsV[EVENT_COUNT];
	KGATE Gate;
};

// There are offsets of unexported functions of ntkrnlmp.exe from
// KeSetEvent. They are used to compute the function address from the
// one of KeSetEvent, which is exported and hence available in the program.
//
// The computed address are stored into function pointers
// which are used to call the functions
//
// CAUTION: these offsets are valid for Windows 7 x64 RTM. for any
// other Windows version, they are likely to give invalid addresses
// and lead to a system crash when thest functions are called.
#define KE_INITIALIZE_GATE_OFFSET				0x7c010
#define KE_SIGNAL_GATE_BOOST_PRIORITY_OFFSET	0x44264

using PKeSignalGateBoostPriority = VOID(NTAPI*)(
	_Inout_ PKGATE Gate
	);

using PKeInitializeGate = VOID(NTAPI*)(
	_Out_ PKGATE Gate
	);



NTSTATUS CompleteIrp(PIRP Irp, NTSTATUS status = STATUS_SUCCESS, ULONG info = 0);
NTSTATUS ClearEvent(DeviceExtension* pDevExt, PIRP Irp);
void PrintObjAddresses(DeviceExtension* pDevExt);
NTSTATUS SignalEvent(DeviceExtension* pDevExt, PIRP Irp);
NTSTATUS SignalGate(DeviceExtension* pDevExt);