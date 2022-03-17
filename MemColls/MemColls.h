#pragma once
/*


=======================================================================

MemColls
========

Companion test program to What Makes It Page?

Copyright (c), 2012 by Enrico Martignetti - All rights reserved.

Program to test in-paging collisions.

=======================================================================

*/

#include <Windows.h>
#include <stdio.h>

#define PGM_NAME			L"MemColls"
#define VER_MAJ				L"1"
#define VER_MIN				L"0"


// Commands
//
#define CMD_ACCESS_RANGE	L'd'
#define CMD_CHANGE_RANGE_PROT	L'h'
#define CMD_CLEAR_BRK		L'c'
#define CMD_DECOMMIT		L'o'
#define CMD_FREE			L'f'
#define CMD_FREE_SYNC		L'y'
#define CMD_QUIT			L'q'
#define CMD_READ			L'r'
#define CMD_REALLOC			L'a'
#define CMD_SET_BRK			L't'
#define CMD_SHRINK			L's'
#define CMD_WRITE			L'w'


// Access codes for StartAccess()
//
#define ACC_READ			1
#define ACC_WRITE			2

#define ERR_MSG_SIZE		501

struct MemAccess {
	HANDLE hHeap;
	int AccessCode;
	PVOID Start;
	SIZE_T Size;
};

struct MemDecommit {
	HANDLE hHeap;
	PVOID Start;
	SIZE_T Size;
};

struct MemPChange {
	HANDLE hHeap;
	PVOID Start;
	SIZE_T Size;
	DWORD NewProt;
};

bool g_bBrk = false;
BYTE g_dummyByte;
DWORD g_initialProt;
PVOID g_pMem;
DWORD64 g_size;

DWORD WINAPI AccessMemory(void* param);
DWORD WINAPI ChangeProtection(void* param);
BOOL CreateThrWr(LPTHREAD_START_ROUTINE startAddress, LPVOID param);
DWORD WINAPI DecommitMemroy(void* param);
DWORD WINAPI FreeMemory(void* param);
void PrintCmdList();
void PrintHelp();
bool ProcessCommandLoop();
bool ProcessCommand(WCHAR cmd, PBOOL pbEndLoop);
PVOID PrvAlloc(DWORD64 size, DWORD protection);
DWORD WINAPI ShrinkWs(void* param);
bool StartAccess(int accessCode, PVOID pStart, SIZE_T size);
bool StartDecommit(PVOID pStart, SIZE_T length);
bool StartFree();
bool StartPchange(PVOID pStart, SIZE_T length, DWORD newProt);
bool StartRangeAccess();
bool StartRangeDecommit();
bool StartRangePchange();
bool StartShrink();
bool XtractParams(int argc, LPWSTR argv[]);


