#pragma once
/*

=======================================================================

WrkEvClient
===========

Companion test program to What Makes It Page?

Copyright (c), 2012 by Enrico Martignetti - All rights reserved.

Minimal client fot the work event driver.

Controls the device through its I/O control codes.

=======================================================================


*/
#include <Windows.h>
#include <strsafe.h>
#include "../WrkEvent/DrvR3.h"

#define CLTFUN_CLEAR_EVENT				L'c'
#define CLTFUN_PRINT_ADDRESSES			L'p'
#define CLTFUN_QUIT						L'q'
#define CLTFUN_SIGNAL_EVENT				L's'
#define CLTFUN_SIGNAL_GATE				L't'

#define DRIVER_NAME			L"WrkEvent.sys"
#define DRV_SVC_NAME		L"WrkEvent"
#define DRIVER_NAME			L"WrkEvent.sys"
#define DRV_SVC_NAME		L"WrkEvent"

int ClearEvent();
bool LoadDriver();
HANDLE OpenWeDevice();
void PrintFunctions();
int PrintObjAddresses();
bool SendIoCtl(HANDLE hDevice, int code, LPVOID inBuffer,
	int inSize, LPVOID outBuffer, int outSize);
int SignalEvent();
int SignalGate();
bool UnloadDriver();