#pragma once
// Driver Definitions Shared with User Mode Clients
// ================================================
//
// (c), 2003 by Enrico Martignetti - All rights reserved.

//----------------------------------------------------------------------
//
// Defines
// -------

// Name of the logical device managed by the driver
#define DRV_DEVICE_NAME		L"WrkEventDevice"

#define DRIVER_PREFIX "[WrkEvent]: "

#define WRKEVENT_DEVICE 0x8000

#define IOCTL_WRKEVENT_SIGNAL_EVENT CTL_CODE(WRKEVENT_DEVICE,\
	0x800,METHOD_BUFFERED,FILE_ANY_ACCESS)

#define IOCTL_WRKEVENT_CLEAR_EVENT CTL_CODE(WRKEVENT_DEVICE,\
	0x801,METHOD_BUFFERED,FILE_ANY_ACCESS)

// Caution!!! this IOCTL only works on Windows 7 x64 RTM. WILL CRASH
// any other version of Windows!
//
#define IOCTL_WRKEVENT_SIGNAL_GATE CTL_CODE(WRKEVENT_DEVICE,\
	0x802,METHOD_BUFFERED,FILE_ANY_ACCESS)

#define IOCTL_WRKEVENT_PRINT_OBJ_ADDRS CTL_CODE(WRKEVENT_DEVICE,\
	0x803,METHOD_BUFFERED,FILE_ANY_ACCESS)


