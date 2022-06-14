/*

=======================================================================

MemTests
========

Companion test program to What Makes It Page?

Copyright (c), 2012 by Enrico Martignetti - All rights reserved.

=======================================================================


*/

#include <iostream>
#include <string>
#include <Windows.h>
#include <NTSecAPI.h>
#include <strsafe.h>
#include "../KrnlAllocs/KaDrvR3.h"
#include "MemTests.h"

#define PDE_RANGE_START     0xFFFFF6FB40000000
#define PDPTE_RANGE_START   0xFFFFF6FB7DA00000
#define PTE_RANGE_START     0xFFFFF68000000000

#define BYTE_PTR_SHIFT(lpByte, Shift)		((PBYTE) ((DWORD_PTR) lpByte >> Shift))

// Shift: 27 for PDPTE, 18 for PD, 9 for PT
// Range: PxE range start
#define VA_TO_PS_ADDR(lpVa, Shift, Range)			(((lpVa >> Shift) + Range) & 0xfffffffffffffff8);

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS  ((NTSTATUS)0x00000000L)
#endif

bool g_bExit;
byte g_dummyByte;
size_t g_size;
AllMapAddr g_AllMapin;
bool g_mdlLocked;
PVOID g_pMappedSystemRegion;

// Address within the range described by g_AllMapin, at which
// pages are mapped by MmMapLockedPagesWithReservedMapping
//
PVOID g_pResMappedRegion;
PVOID g_pMdl;
HANDLE g_hFile;
HANDLE g_hFileMapping;
PVOID g_pMappedRegionStart;
PVOID g_pMappedRegionEnd;
PVOID g_pPrivateRegionStart;
PVOID g_pPrivateRegionEnd;
WCHAR g_fileName[MAX_PATH];
WCHAR g_mappingName[MAX_PATH];
WCHAR g_cmd;



int main(){
	InitStatus();
	g_bExit = false;
	while (!g_bExit) {
		wprintf(L"\n\n");
		PrintStatus();
		wprintf(L"\n");
		PrintMenu();
		wprintf(L"\n");
		g_cmd = getwchar();
		ProcessOption();
		if (!g_bExit) {
			// drain stdin
			while (getwc(stdin) != L'\n') {}
			wprintf(L"\nany key to return to main menu...");
			int dummy = getwchar();
		}
	}
	ReleaseAll();
}


BOOL AccessRegion(PVOID regionStart, PVOID regionEnd) {
	bool bRet = false;
	DWORD error = ERROR_CANCELLED;

	do
	{
		PBYTE pEndLocal;
		PBYTE pStart;
		PBYTE pTouch;
		WCHAR key;
		wprintf(L"\n");
		if (!GetKey(&key,
			const_cast<PWSTR>(L"r - read memory, w - write memory"),
			FALSE,nullptr,const_cast<PWSTR>(L"rw"))) {
			break;
		}
		pStart = (PBYTE)regionStart;
		wprintf(L"\n\nstart address = [%#p]", pStart);
		if (!GetValue(L"%I64i", &pStart, TRUE)) {
			break;
		}
		pEndLocal = (PBYTE)regionEnd;
		wprintf(L"\n\nend address = [%#p]", pEndLocal);
		if (!GetValue(L"%I64i", &pEndLocal, TRUE)) {
			break;
		}
		wprintf(L"\nabout to %s from %#p to %#p",
			(key == L'r' ? L"read" : L"write"),
			pStart, pEndLocal);
		if (!ConfirmOper()) {
			error = ERROR_CANCELLED;
			break;
		}
		pTouch = pStart;
		__try {
			for (; pTouch < pEndLocal; pTouch += 0x1000) {
				if (key == L'r') {
					g_dummyByte = *pTouch;
				}
				else {
					*((PVOID*)pTouch) = pTouch;
				}
			}
			wprintf(L"\nMemory access completed");
			bRet = true;
			error = ERROR_SUCCESS;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			wprintf(L"\nCaught exception: %08x", GetExceptionCode());
			error = ERROR_NOT_ENOUGH_MEMORY;
			bRet = false;
		}
	} while (false);

	::SetLastError(error);
	return bRet;
}

BOOL AccessRegionInterface() {
	bool bRet = true;
	DWORD error = ERROR_CANCELLED;
	WCHAR key = L'p';
	do
	{
		if (!GetKey(&key,
			L"m - default to mapped region, \
		p - default to private region, \
		n - no default",
			TRUE, L":", L"mpn")) {
			break;
		}
		if (key == L'm') {
			bRet = AccessRegion(g_pMappedRegionStart, g_pMappedRegionEnd);
			if (bRet) {
				error = GetLastError();
				break;
			}
		}
		else if (key == L'p') {
			bRet = AccessRegion(g_pPrivateRegionStart, g_pPrivateRegionEnd);
			if (!bRet) {
				error = GetLastError();
				break;
			}
		}
		else if (key == L'n') {
			bRet = AccessRegion(nullptr, nullptr);
			if (!bRet) {
				error = GetLastError();
				break;
			}
		}
	} while (false);
	
	SetLastError(error);
	return bRet;
}

BOOL AddPrivilege(const wchar_t* priv) {
	BOOL bRet = false;
	DWORD error;
	LSA_HANDLE hPolicy = INVALID_HANDLE_VALUE;
	HANDLE hToken = INVALID_HANDLE_VALUE;
	NTSTATUS status;

	do
	{
		if (!::OpenProcessToken(
			::GetCurrentProcess(),
			TOKEN_QUERY, &hToken)) {
			error = ::GetLastError();
			hToken = INVALID_HANDLE_VALUE;
			wprintf(L"\nOpenProcessToken() failed with GetLastError() = %d", error);
			break;
		}
		PTOKEN_USER pTokenUser = nullptr;
		DWORD len = 0;
		::GetTokenInformation(hToken, TokenUser, pTokenUser, 0, &len);
		error = GetLastError();
		if (error != ERROR_INSUFFICIENT_BUFFER) {
			wprintf(L"\nGetTokenInformation() failed with GetLastError() = %d", error);
			break;
		}
		pTokenUser = (PTOKEN_USER)::HeapAlloc(GetCurrentProcess(), 0, len);
		if (pTokenUser == nullptr) {
			error = ERROR_NOT_ENOUGH_MEMORY;
			wprintf(L"\nHeapAlloc() failed for allocation size = %d", len);
			break;
		}
		if (!GetTokenInformation(
			hToken,
			TokenUser,
			pTokenUser,
			len,
			&len
		)) {
			error = GetLastError();
			wprintf(L"\nGetTokenInformation() failed with GetLastError() = %d", error);
			break;
		}

		LSA_OBJECT_ATTRIBUTES objAttributes;
		ZeroMemory(&objAttributes, sizeof(objAttributes));

		status = ::LsaOpenPolicy(
			nullptr,
			&objAttributes,
			POLICY_CREATE_ACCOUNT | POLICY_LOOKUP_NAMES,
			&hPolicy
		);
		if (status != STATUS_SUCCESS) {
			error = ::LsaNtStatusToWinError(status);
			hPolicy = INVALID_HANDLE_VALUE;
			wprintf(L"\nLasOpenPolicy() failed with status = 0x%8x", status);
			break;
		}

		LSA_UNICODE_STRING privString;
		SIZE_T length = ::wcslen(priv);
		privString.Buffer = (PWSTR)priv;
		privString.Length = (USHORT)length * sizeof(WCHAR);
		privString.MaximumLength = (USHORT)(length + 1) * sizeof(WCHAR);
		
		status = ::LsaAddAccountRights(
			hPolicy,
			pTokenUser->User.Sid,
			&privString,
			1
		);
		if (status != STATUS_SUCCESS) {
			error = ::LsaNtStatusToWinError(status);
			wprintf(L"\nLsaAddAccountRights() failed with status = 0x%8x",
				status);
			break;
		}

		bRet = true;
		error = ERROR_SUCCESS;
	} while (false);
	
	if (hPolicy != INVALID_HANDLE_VALUE)
		::LsaClose(hPolicy);
	if (hToken != INVALID_HANDLE_VALUE)
		::CloseHandle(hToken);
	::SetLastError(error);
	return bRet;
}

BOOL CallPageableFunTest() {
	bool bRet = false;
	DWORD error = STATUS_SUCCESS;
	HANDLE hDevice = INVALID_HANDLE_VALUE;

	do
	{
		hDevice = OpenSysRegDev();
		if (hDevice == INVALID_HANDLE_VALUE) {
			error = ::GetLastError();
			break;
		}
		if (!SendIoCtl(hDevice,
			IOCTL_MEMTEST_CALLPAGEABLE,
			nullptr,
			0,
			nullptr,
			0)) {
			error = ::GetLastError();
			break;
		}
		bRet = true;
		error = ERROR_SUCCESS;
	} while (false);
	
	if ((hDevice != INVALID_HANDLE_VALUE)&&(hDevice!=nullptr))
		::CloseHandle(hDevice);
	::SetLastError(error);
	return bRet;
}

BOOL CloseFile(PHANDLE phFile, BOOL interactive) {
	DWORD error;
	HANDLE hFile;

	if ((*phFile != INVALID_HANDLE_VALUE) && (*phFile != nullptr)) {
		if (interactive) {
			wprintf(L"\nabout to close the file");
			if (!ConfirmOper()) {
				::SetLastError(ERROR_CANCELLED);
				return TRUE;
			}
		}
		hFile = *phFile;
		*phFile = INVALID_HANDLE_VALUE;
		if (!CloseHandle(hFile)) {
			error = ::GetLastError();
			wprintf(L"CloseHandle() failed with GetLastError() = %d", error);
			::SetLastError(error);
			return false;
		}
	}
	return true;
}

BOOL ConfirmOper() {
	WCHAR key;

	wprintf(L"\nc - cancel, b - break, any other key to proceed");
	key = _getwch();
	switch (key)
	{
	case L'c':
		return false;
	
	case L'b':
		DebugBreak();
		return true;
	default:
		break;
	}

	return true;
}

HANDLE CreateFileWr(PWSTR fileName, DWORD access, DWORD sharedMode, DWORD crDisp) {
	DWORD error;
	HANDLE hFile;

	hFile = ::CreateFile(fileName,
		access,
		sharedMode,
		nullptr,
		crDisp,
		FILE_ATTRIBUTE_NORMAL,
		nullptr);
	if (hFile == INVALID_HANDLE_VALUE) {
		error = GetLastError();
		wprintf(L"\nCreateFile failed with GetLastError() = %d", error);
		::SetLastError(error);
		return INVALID_HANDLE_VALUE;
	}
	return hFile;
}

BOOL EnablePrivilege(const wchar_t* prvName) {
	BOOL bRet = true;
	DWORD error = ERROR_SUCCESS;
	HANDLE hToken = INVALID_HANDLE_VALUE;
	TOKEN_PRIVILEGES tp;

	do
	{
		if (!::OpenProcessToken(
			GetCurrentProcess(),
			TOKEN_ADJUST_PRIVILEGES,
			&hToken
		)) {
			error = ::GetLastError();
			hToken = INVALID_HANDLE_VALUE;
			bRet = false;
			wprintf(L"\nOpenProcessToken() failed with GetLastError() = %d", 
				error);
			break;
		}

		if (!::LookupPrivilegeValue(nullptr, prvName, &(tp.Privileges[0].Luid))) {
			error = ::GetLastError();
			bRet = false;
			wprintf(L"\nLookupPrivilegeValue() failed with GetLastError() = %d",
				error);
			break;
		}
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		tp.PrivilegeCount = 1;

		if (!::AdjustTokenPrivileges(
			hToken,
			FALSE,
			&tp,
			0,
			nullptr,
			nullptr
		)) {
			error = GetLastError();
			bRet = false;
			wprintf(L"\nAdjustTokenPrivileges() failed with GetLastError() = %d",
				error);
			break;
		}
		error = GetLastError();
		if (error == ERROR_NOT_ALL_ASSIGNED) {
			bRet = false;
			wprintf(L"\nPrivilege %s not assigned. Must add \
			privilege to account.", prvName);
			break;
		}
		else if (error != ERROR_SUCCESS) {
			wprintf(L"\nAdjustTokenPrivileges() succeeded but \
			GetLastError() = %d", error);
		}
		bRet = true;
		error = ERROR_SUCCESS;
	} while (false);

	if (hToken != INVALID_HANDLE_VALUE)
		::CloseHandle(hToken);
	return bRet;
}

HANDLE FileCreate(PWSTR fileName, BOOL incrementalExp, ULONGLONG fileSize) {
	bool closeAll = true;
	DWORD error = ERROR_SUCCESS;
	HANDLE hFile = INVALID_HANDLE_VALUE;

	do
	{
		wprintf(L"\nabout to create the file");
		if (!ConfirmOper()) {
			error = ERROR_CANCELLED;
			break;
		}
		hFile = CreateFileWr(fileName,
			GENERIC_WRITE | GENERIC_READ,
			0,
			CREATE_ALWAYS);
		if (hFile == INVALID_HANDLE_VALUE) {
			error = ::GetLastError();
			break;
		}
		if (incrementalExp) {
			wprintf(L"\nAbout to expand the file");
			if (!ConfirmOper()) {
				::SetLastError(ERROR_CANCELLED);
				break;
			}
			for (ULONGLONG i = 0; i < fileSize / sizeof i + 1; i++) {
				if (!WriteFileWr(
					hFile,
					&i,
					sizeof i)) {
					error = GetLastError();
					break;
				}
			}
		}
		closeAll = false;
		wprintf(L"\nfile %s created", fileName);
	} while (false);
	
	if (closeAll) {
		if ((hFile != INVALID_HANDLE_VALUE) && (hFile != nullptr)) {
			::CloseHandle(hFile);
			hFile = INVALID_HANDLE_VALUE;
		}
	}
	SetLastError(error);
	return hFile;
}

BOOL FileCreateInterface() {
	bool bRet = true;
	DWORD error = ERROR_CANCELLED;

	bool incExp;
	ULONGLONG fileSize = 0;
	WCHAR ch;

	do
	{
		wcscpy_s(g_fileName, sizeof g_fileName / sizeof g_fileName[0],
			L"memtests.tmp");
		wprintf(L"\nfile name [%s]: ", g_fileName);
		if (!GetValue(L"%s", g_fileName, true)) {
			break;
		}
		g_fileName[sizeof g_fileName / sizeof g_fileName[0] - 1] = L'\0';
		wprintf(L"\n");
		ch = L'n';
		if (!GetKey(&ch, L"incremental expansion", true,
			L"? ",
			L"yn")) {
			break;
		}

		incExp = (ch == L'y');
		if (incExp) {
			wprintf(L"\nfile size = ");
			if (!GetValue(L"%I64i", &fileSize, false))
				break;
		}
		g_hFile = FileCreate(g_fileName,incExp, fileSize);
		if (g_hFile == INVALID_HANDLE_VALUE) {
			// if last error is ERROR_CANCELLED,return success.
			// cancelling is not returned as an error from any funciton
			//
			error = GetLastError();
			bRet = (error == ERROR_CANCELLED);
			break;
		}
		error = ERROR_SUCCESS;

	} while (false);
	
	SetLastError(error);
	return bRet;
}

BOOL FileMappingTest(HANDLE hFileToMap, DWORD mapProtect, PULONGLONG pMapSize,
	DWORD viewAccess, DWORD offsetLow, DWORD offsetHigh, PSIZE_T pViewSize,
	BOOL explicitNumaNode, DWORD numaNode, PWCHAR mappingName, PVOID* ppRegion,
	LPHANDLE phMap) {
	bool bRet = true;
	bool bRelease = true;
	DWORD error = ERROR_SUCCESS;
	
	wprintf(L"\nhFileToMap		= %x", HandleToUlong(hFileToMap));
	wprintf(L"\nMapProtect		= 0x%x", mapProtect);
	wprintf(L"\nMapSize			= 0x%I64x", *pMapSize);
	if (mappingName != nullptr)
		wprintf(L"\nMappingName		= %s", mappingName);
	else
		wprintf(L"\nAnonymous MappingName");
	wprintf(L"\nViewAccess      = 0x%x", viewAccess);
	wprintf(L"\nOffsetHigh		= 0x%x", offsetHigh);
	wprintf(L"\nViewSize		= 0x%I64x", *pViewSize);
	wprintf(L"\nExplicitNumaNode = %s", explicitNumaNode ? L"True": L"false");
	if (explicitNumaNode) {
		wprintf(L"\nNumaNode	= %d", numaNode);
	}

	*ppRegion = nullptr;
	*phMap = INVALID_HANDLE_VALUE;
	if (!ConfirmOper()) {
		SetLastError(ERROR_CANCELLED);
		return TRUE;
	}

	do
	{
		ULONGLONG actualMapSize = *pMapSize;
		if (hFileToMap != INVALID_HANDLE_VALUE) {
			if (!actualMapSize) {
				LARGE_INTEGER fileSize;
				if (!::GetFileSizeEx(hFileToMap, &fileSize)) {
					error = ::GetLastError();
					wprintf(L"\nGetFileSizeEx() failed with GetLastError() = %d", error);
					::SetLastError(error);
					bRet = false;
					break;
				}
				actualMapSize = fileSize.QuadPart;
			}
		}

		// Create the file mapping
		// 
		wprintf(L"\nabout to create the mapping");
		if (!ConfirmOper()) {
			error = ERROR_CANCELLED;
			break;
		}
		*phMap = ::CreateFileMapping(
			hFileToMap,
			nullptr,
			mapProtect,
			*pMapSize >> 32,
			*pMapSize & 0xFFFFFFFF,
			mappingName
		);
		if (*phMap == nullptr) {
			error = GetLastError();
			wprintf(L"\nCreateFileMapping() failed with GetLastError() = %d", error);
			bRet = FALSE;
			break;
		}
		wprintf(L"\nabout to map the view");
		if (!ConfirmOper()) {
			error = ERROR_CANCELLED;
			break;
		}
		if (explicitNumaNode) {
			*ppRegion = (LPBYTE)::MapViewOfFileExNuma(
				*phMap,
				viewAccess,
				offsetHigh,
				offsetLow,
				*pViewSize,
				nullptr,
				numaNode
			);
		}
		else {
			*ppRegion = (LPBYTE)::MapViewOfFileEx(
				*phMap,
				viewAccess,
				offsetHigh,
				offsetLow,
				*pViewSize,
				nullptr
			);
		}
		if (*ppRegion == nullptr) {
			error = ::GetLastError();
			wprintf(L"\nMapViewOfFileEx() failed with GetLastError() = %d", error);
			bRet = false;
			break;
		}
		SIZE_T actualViewSize = *pViewSize;
		if (!actualViewSize) {
			actualViewSize = (SIZE_T)(actualMapSize - (((ULONGLONG)offsetHigh) << 32) - offsetLow);
		}
		wprintf(L"\nView range: %#p - %#p", 
			*ppRegion, (PBYTE)*ppRegion + actualViewSize);
		*pMapSize = actualMapSize;
		*pViewSize = actualViewSize;
		bRelease = false;
		bRet = true;
		error = ERROR_SUCCESS;
	} while (false);

	if (bRelease) {
		if (*ppRegion != nullptr) {
			::UnmapViewOfFile(*ppRegion);
			*ppRegion = nullptr;
		}
		if ((*phMap != nullptr) && (*phMap != INVALID_HANDLE_VALUE)) {
			::CloseHandle(*phMap);
			*phMap = INVALID_HANDLE_VALUE;
		}
	}
	::SetLastError(error);
	return bRet;
}

BOOL FileMappingOpenTest(DWORD access, PWCHAR name, DWORD offLow,
	DWORD offHigh, PSIZE_T pSize, PVOID* ppMappedRegion, PHANDLE phMapping) {
	BOOL bRet = true;
	BOOL bRelease = true;
	DWORD error = ERROR_SUCCESS;

	*phMapping = INVALID_HANDLE_VALUE;
	*ppMappedRegion = nullptr;

	// Open the file mapping
	//
	wprintf(L"\nAccess = 0x%x", access);
	wprintf(L"\nName = %s", name);
	wprintf(L"\nOffset = 0x%I64x", (((ULONGLONG)offHigh) << 32) + offLow);
	wprintf(L"\nSize = 0x%I64x", *pSize);
	wprintf(L"\nabout to open the mapping");
	if (!ConfirmOper()) {
		SetLastError(ERROR_CANCELLED);
		return true;
	}
	*phMapping = ::OpenFileMapping(access, FALSE, name);
	if (*phMapping == nullptr) {
		error = GetLastError();
		wprintf(L"OpenFileMapping() failed with GetLastError() = %d",
			error);
		return false;
	}

	do
	{
		wprintf(L"\nabout to map the view");
		if (!ConfirmOper()) {
			error = ERROR_CANCELLED;
			break;
		}
		*ppMappedRegion = ::MapViewOfFileEx(
			*phMapping,
			access,
			offHigh, offLow, *pSize,
			nullptr);
		if (*ppMappedRegion == nullptr) {
			error = GetLastError();
			wprintf(L"\nMapViewOfFileEx() failed with GetLastError() = %d",
				error);
			bRet = FALSE;
			break;
		}
		if (!(*pSize)) {
			MEMORY_BASIC_INFORMATION info;
			::SecureZeroMemory(&info, sizeof info);
			::VirtualQueryEx(GetCurrentProcess(),
				*ppMappedRegion,
				&info,
				sizeof info);
			*pSize = info.RegionSize;
		}
		wprintf(L"\nView range: %#p - %#p",
			*ppMappedRegion, (PBYTE)*ppMappedRegion + *pSize);
		bRet = true;
		error = ERROR_SUCCESS;
		bRelease = false;
	} while (false);

	if (bRelease) {
		if ((*phMapping != INVALID_HANDLE_VALUE) && (*phMapping != nullptr)) {
			::CloseHandle(*phMapping);
			*phMapping = INVALID_HANDLE_VALUE;
		}
		if (*ppMappedRegion != nullptr) {
			::UnmapViewOfFile(*ppMappedRegion);
			*ppMappedRegion = nullptr;
		}
	}
	SetLastError(error);
	return bRet;
}

BOOL FileMappingOpenTestInterface() {
	BOOL bRet = true;
	DWORD error = ERROR_CANCELLED;

	wprintf(L"\n\nOpen and map existing mapping\n");
	DWORD mapAccess = FILE_MAP_READ | FILE_MAP_WRITE;
	wprintf(L"\nAccess [0x%x]:", mapAccess);
	wprintf(L"\n"
		L"    FILE_MAP_ALL_ACCESS = 0x%x", FILE_MAP_ALL_ACCESS);
	wprintf(L"\n"
		L"    FILE_MAP_COPY       = 0x%x", FILE_MAP_COPY);
	wprintf(L"\n"
		L"    FILE_MAP_EXECUTE    = 0x%x", FILE_MAP_EXECUTE);
	wprintf(L"\n"
		L"    FILE_MAP_READ       = 0x%x", FILE_MAP_READ);
	wprintf(L"\n"
		L"    FILE_MAP_WRITE      = 0x%x", FILE_MAP_WRITE);
	wprintf(L"\n");

	do
	{
		if (!GetValue(L"%i", &mapAccess, true)) {
			break;
		}
		wcscpy_s(g_mappingName, sizeof g_mappingName / sizeof g_mappingName[0], L"map");
		wprintf(L"\nMapping name [%s]: ", g_mappingName);
		if (!GetValue(L"%s", g_mappingName, true))
			break;
		g_mappingName[sizeof g_mappingName / sizeof g_mappingName[0] - 1] = L'\0';

		LONGLONG value = 0;
		wprintf(L"\noffset [0x%I64x]: ", value);
		DWORD offHigh, offLow;
		if (!GetValue(L"%I64i", &value, true))
			break;
		offHigh = (DWORD)(value >> 32);
		offLow = (DWORD)value;

		SIZE_T size = 0;
		wprintf(L"\nview size [0x%I64x]: ", size);
		if (!GetValue(L"%I64i", &size, true))
			break;

		if (!::FileMappingOpenTest(
			mapAccess,
			g_mappingName,
			offLow,
			offHigh,
			&size,
			&g_pMappedRegionStart,
			&g_hFileMapping
		)) {
			error = GetLastError();
			bRet = false;
			break;
		}
		g_pMappedRegionEnd = (PBYTE)g_pMappedRegionStart + size;
		error = ERROR_SUCCESS;

	} while (false);
	
	::SetLastError(error);
	return bRet;
}

BOOL FileMappingTestInterface() {
	bool bRet = true;
	DWORD error = ERROR_CANCELLED;
	WCHAR ch;
	HANDLE hFileToMap = INVALID_HANDLE_VALUE;

	do
	{
		wprintf(L"\n");
		ch = L'm';
		if (!GetKey(&ch,
			L"map type (m = shared memory, f = mapped file)",
			TRUE,
			L":",
			L"mf")) {
			break;
		}

		if (ch == L'm') {
			hFileToMap = INVALID_HANDLE_VALUE;
		}
		else if (ch == L'f') {
			// if no file is open, create or open one
			if (g_hFile == INVALID_HANDLE_VALUE) {
				ch = L'o';
				wprintf(L"\n");
				if (!GetKey(&ch, L"c - createfile, o - open file", TRUE, L":", L"co"))
					break;
				if (ch == L'c') {
					if (!FileCreateInterface()) {
						error = GetLastError();
						bRet = false;
						break;
					}
					if (GetLastError() == ERROR_CANCELLED)
						break;
				}
				else if(ch == L'o') {
					if (!OpenFileInterface()) {
						error = GetLastError();
						bRet = false;
						break;
					}
					if (GetLastError() == ERROR_CANCELLED)
						break;
				}
			}
			hFileToMap = g_hFile;
		}

		DWORD mapProt = PAGE_READWRITE;
		wprintf(L"\nmap protection [0x%x]:", mapProt);
		wprintf(L"\n"
			L"		PAGE_READONLY			= 0x%x", PAGE_READONLY);
		wprintf(L"\n"
			L"		PAGE_READWRITE			= 0x%x", PAGE_READWRITE);
		wprintf(L"\n"
			L"		PAGE_WRITECOPY			= 0x%x", PAGE_WRITECOPY);
		wprintf(L"\n"
			L"		PAGE_EXECUTE_READ		= 0x%x", PAGE_EXECUTE_READ);
		wprintf(L"\n"
			L"		PAGE_EXECUTE_READWRITE	= 0x%x", PAGE_EXECUTE_READWRITE);
		wprintf(L"\n"
			L"		PAGE_EXECUTE_WRITECOPY	= 0x%x", PAGE_EXECUTE_WRITECOPY);
		wprintf(L"\n"
			L"		SEC_IMAGE				= 0x%x", SEC_IMAGE);
		wprintf(L"\n"
			L"		SEC_LARGE_LAGES			= 0x%x", SEC_LARGE_PAGES);
		wprintf(L"\n"
			L"		SEC_COMMIT				= 0x%x", SEC_COMMIT);
		wprintf(L"\n");
		if (!GetValue(L"%i", &mapProt, true))
			break;

		SIZE_T mapSize;
		wprintf(L"\nMap size: ");
		if (!GetValue(L"%I64i", &mapSize, false))
			break;

		ch = L'y';
		if (!GetKey(&ch, L"sepcify the name", true, L"?", L"yn"))
			break;
		bool bAnonymous = false;
		if (ch == L'y') {
			wcscpy_s(g_mappingName, sizeof g_mappingName / sizeof g_mappingName[0], L"map");
			wprintf(L"\nmapping name [%s]:", g_mappingName);
			if (!GetValue(L"%s", g_mappingName, true))
				break;
			g_mappingName[sizeof g_mappingName / sizeof g_mappingName[0] - 1] = L'\0';
		}
		else if (ch == L'n') {
			bAnonymous = true;
		}

		

		DWORD viewAcc = FILE_MAP_READ | FILE_MAP_WRITE;
		wprintf(L"\nView Access [0x%x]:", viewAcc);
		wprintf(L"\n"
			L"    FILE_MAP_ALL_ACCESS = 0x%x", FILE_MAP_ALL_ACCESS);
		wprintf(L"\n"
			L"    FILE_MAP_COPY       = 0x%x", FILE_MAP_COPY);
		wprintf(L"\n"
			L"    FILE_MAP_EXECUTE    = 0x%x", FILE_MAP_EXECUTE);
		wprintf(L"\n"
			L"    FILE_MAP_READ       = 0x%x", FILE_MAP_READ);
		wprintf(L"\n"
			L"    FILE_MAP_WRITE      = 0x%x", FILE_MAP_WRITE);
		wprintf(L"\n");
		if (!GetValue(L"%i", &viewAcc, true))
			break;

		LONGLONG value = 0;
		DWORD offHigh, offLow;
		wprintf(L"\noffset [0x%I64x]:", value);
		if (!GetValue(L"%I64i", &value, true))
			break;
		offHigh = (DWORD)(value >> 32);
		offLow = (DWORD)value;

		SIZE_T size = 0;
		wprintf(L"\nview size [0x%I64x]:", size);
		if (!GetValue(L"%I64i", &size, true))
			break;

		bool bExplicitNumaNode = false;
		DWORD numaNode = 0;
		wprintf(L"\n");
		ch = L'n';
		if (!GetKey(&ch, L"sepcify NUMA node", true, L"?", L"yn"))
			break;
		if (ch == L'y') {
			bExplicitNumaNode = true;
			wprintf(L"\nNuma node: ");
			if (!GetValue(L"%d", &numaNode, false))
				break;
		}
		else if (ch == L'n') {
			bExplicitNumaNode = false;
		}

		if (!FileMappingTest(
			hFileToMap,
			mapProt,
			&mapSize,
			viewAcc,
			offLow,
			offHigh,
			&size,
			bExplicitNumaNode,
			numaNode,
			bAnonymous?nullptr:g_mappingName,
			&g_pMappedRegionStart,
			&g_hFileMapping
		)) {
			bRet = false;
			error = GetLastError();
			break;
		}
		g_pMappedRegionEnd = (PBYTE)g_pMappedRegionStart + size;
		error = ERROR_SUCCESS;
	} while (false);
	
	

	SetLastError(error);
	return bRet;
}

BOOL FileOpenCreateInterface() {
	bool bRet = true;
	DWORD error = ERROR_CANCELLED;

	WCHAR ch;
	wprintf(L"\n");
	do
	{
		if (!GetKey(&ch,
			L"c - create file, o - open file",
			FALSE,
			L": ",
			L"co")) {
			break;
		}
		if (ch == L'c') {
			if (!FileCreateInterface()) {
				error = GetLastError();
				bRet = FALSE;
				break;
			}
		}
		else if (ch == L'o') {
			if (!OpenFileInterface()) {
				bRet = false;
				break;
			}
		}

		error = ERROR_SUCCESS;
	} while (false);
	::SetLastError(error);
	return bRet;
}

BOOL FileReadTest(HANDLE hFile, ULONGLONG offset, DWORD length) {

	const int BUF_SIZE = 0x100000;
	BOOL bRet = true;
	DWORD error = ERROR_SUCCESS;
	LARGE_INTEGER dist;
	PVOID buffer = nullptr;

	if (hFile == INVALID_HANDLE_VALUE) {
		wprintf(L"\ninvalid file handle");
		SetLastError(ERROR_NOT_SUPPORTED);
		return false;
	}
	do
	{
		buffer = ::VirtualAllocEx(GetCurrentProcess(),
			nullptr,
			BUF_SIZE,
			MEM_RESERVE | MEM_COMMIT,
			PAGE_READWRITE);
		if (buffer == nullptr) {
			error = GetLastError();
			bRet = FALSE;
			wprintf(L"\nVirtualAllocEx() failed with GetLastError() = %d", error);
			break;
		}
		dist.QuadPart = offset;
		wprintf(L"\nabout to move the file pointer");
		if (!ConfirmOper()) {
			error = ERROR_CANCELLED;
			break;
		}
		if (!::SetFilePointerEx(hFile, dist, nullptr, FILE_BEGIN)) {
			error = GetLastError();
			bRet = false;
			wprintf(L"\nSetFilePointerEx() failed with GetLastError() = %d", error);
			break;
		}
		DWORD bytesRead;
		DWORD readSize;
		DWORD remaining;
		remaining = length;
		wprintf(L"\nabout to read the file");
		if (!ConfirmOper()) {
			error = ERROR_CANCELLED;
			break;
		}
		while (remaining) {
			readSize = (BUF_SIZE < remaining ? BUF_SIZE : remaining);
			if (!ReadFile(hFile,
				buffer, readSize, &bytesRead, nullptr)) {
				error = GetLastError();
				bRet = false;
				wprintf(L"\nReadFile() failed with GetLastError() = %d", error);
				break;
			}
			remaining -= readSize;
		}
		wprintf(L"\nfile read completed");

	} while (false);
	
	if (buffer != nullptr) {
		::VirtualFreeEx(GetCurrentProcess(), buffer, 0, MEM_RELEASE);
	}
	SetLastError(error);
	return bRet;
}

BOOL FileReadTestInterface() {
	bool bRet = true;
	DWORD error = ERROR_CANCELLED;
	DWORD length;
	ULONGLONG offset;

	do
	{
		// Open the file if it has not been done yet
		//
		if (g_hFile == INVALID_HANDLE_VALUE) {
			if (!OpenFileInterface()) {
				bRet = false;
				error = GetLastError();
				break;
			}
			if (GetLastError() == ERROR_CANCELLED)
				break;
		}
		offset = 0;
		wprintf(L"\noffset [0x%I64x] = ", offset);
		if (!GetValue(L"%I64i", &offset, true))
			break;
		wprintf(L"\nlength = ");
		if (!GetValue(L"%i", &length, false))
			break;
		if (!FileReadTest(g_hFile, offset, length)) {
			error = GetLastError();
			bRet = false;
			break;
		}
		error = ERROR_SUCCESS;
	} while (false);
	
	SetLastError(error);
	return bRet;
}

BOOL FileWriteTest(HANDLE hFile, ULONGLONG offset, ULONGLONG byteCount) {
	DWORD error;
	LARGE_INTEGER dist;
	dist.QuadPart = offset;
	wprintf(L"\nabout to move the file pointer");
	if (!ConfirmOper()) {
		SetLastError(ERROR_CANCELLED);
		return true;
	}
	if (!SetFilePointerEx(hFile, dist, nullptr, FILE_BEGIN)) {
		error = GetLastError();
		wprintf(L"\nSetFilePointerEx() failed with GetLastError() = %d", error);
		SetLastError(error);
		return false;
	}
	wprintf(L"\nabout to write into the file");
	if (!ConfirmOper()) {
		SetLastError(ERROR_CANCELLED);
		return true;
	}
	BYTE j = 0;
	for (ULONGLONG i = 0; i < byteCount; i++, j++) {
		if (!WriteFileWr(hFile, &j, sizeof j)) {
			return false;
		}
	}
	wprintf(L"\nfile write completed");
	return true;
}

BOOL FileWriteTestInterface() {
	BOOL bRet = true;
	DWORD error = ERROR_CANCELLED;

	do
	{
		if (g_hFile == INVALID_HANDLE_VALUE) {
			if (!FileOpenCreateInterface()) {
				bRet = false;
				error = GetLastError();
				break;
			}
			if (GetLastError() == ERROR_CANCELLED)
				break;
		}

		ULONGLONG offset = 0;
		wprintf(L"\noffset [0x%I64x] = ", offset);
		if (!GetValue(L"%I64i", &offset, true))
			break;

		ULONGLONG byteCount;
		wprintf(L"\nbyte count = ");
		if (!GetValue(L"%I64i", &byteCount, false))
			break;
		if (!FileWriteTest(g_hFile, offset, byteCount)) {
			error = GetLastError();
			bRet = false;
			break;
		}
		error = ERROR_SUCCESS;
	} while (false);
	
	SetLastError(error);

	return bRet;
}

BOOL GetKey(PWCHAR pKey, const wchar_t* const msg, BOOL bDefault, 
	const wchar_t* const separator, const wchar_t* const validChars) {
	bool bLoop = true;
	WCHAR key;
	do
	{
		if (msg != nullptr)
			wprintf(msg);
		if (validChars != nullptr) {
			wprintf(L" (");
			auto pCurrent = validChars;
			while (*pCurrent != L'\0') {
				wprintf(L"%c", *pCurrent);
				pCurrent++;
				if (*pCurrent != L'\0')
					wprintf(L"/");
			}
			wprintf(L")");
		}
		if (bDefault)
			wprintf(L" [%c]", *pKey);
		if (separator != nullptr) {
			wprintf(separator);
		}
		key = _getwch();
		switch (key)
		{
		case 27:
			return false;
		case L'\r':
			if (bDefault) {
				key = *pKey;
				bLoop = false;
			}
			break;
		default:
			if (validChars != nullptr) {
				auto pCurrent = validChars;
				while (*pCurrent != L'\0') {
					if (key == *pCurrent)
						break;
					pCurrent++;
				}
				if (*pCurrent != L'\0') {
					bLoop = false;
				}
				else {
					wprintf(L"\ninvalid key: %c", key);
				}
			}
			else {
				bLoop = false;
			}
			break;
		}
		if (bLoop)
			wprintf(L"\n");
	} while (bLoop);
	wprintf(L"%c", key);
	*pKey = key;
	return true;
}

// --
// We want to use wscanf without getting warning C4996
// 
#pragma warning(push)
#pragma warning(disable:4096)
BOOL GetValue(const wchar_t* const format, PVOID value, BOOL bDefault) {
	HANDLE hStdin;
	INPUT_RECORD conInp;
	DWORD numberRead;
	hStdin = GetStdHandle(STD_INPUT_HANDLE);
	for (;;) {
		::WaitForSingleObject(hStdin, INFINITE);
		::PeekConsoleInput(hStdin, &conInp, 1, &numberRead);
		if ((conInp.EventType) != KEY_EVENT || !conInp.Event.KeyEvent.bKeyDown) {
			FlushConsoleInputBuffer(hStdin);
			continue;
		}
		WCHAR ch = conInp.Event.KeyEvent.uChar.UnicodeChar;
		switch (ch)
		{
		case 0:
			FlushConsoleInputBuffer(hStdin);
			continue;
			break;
		case 13:
			FlushConsoleInputBuffer(hStdin);
			if (bDefault)
				return true;
			else
				continue;
			break;

		case 27:
			FlushConsoleInputBuffer(hStdin);
			return false;

		default:
			if (!wscanf(format, value)) {
				wprintf(L"\nInvalid value,reenter: ");
				WCHAR wch;
				do
				{
					wscanf_s(L"%c", &wch);
				} while (wch!=L'\n');
				continue;
			}
			return true;
		}
	}
}
#pragma warning(pop)

void InitStatus() {
	g_pMappedRegionStart = nullptr;
	g_pMappedRegionEnd = nullptr;
	g_pPrivateRegionStart = nullptr;
	g_pPrivateRegionEnd = nullptr;
	g_hFileMapping = INVALID_HANDLE_VALUE;
	g_hFile = INVALID_HANDLE_VALUE;
	g_pMdl = nullptr;
	g_AllMapin.Size = 0;
	g_AllMapin.Address = nullptr;
	g_pMappedSystemRegion = nullptr;
	g_pResMappedRegion = nullptr;
}

bool IoAllocateMdlTest() {
	BOOL bRet = false;
	DWORD error = ERROR_SUCCESS;
	HANDLE hDevice = INVALID_HANDLE_VALUE;

	do
	{
		hDevice = OpenSysRegDev();
		if (hDevice == INVALID_HANDLE_VALUE) {
			error = GetLastError();
			break;
		}

		PVOID pVirtAddr;
		wprintf(L"\nVirtualAddress ");
		if (!GetValue(L"%I64i", 
			&pVirtAddr, false)) {
			bRet = true;
			break;
		}

		ULONG length;
		wprintf(L"\nLength ");
		if (!GetValue(L"%i", &length, false)) {
			bRet = true;
			break;
		}
		AllocaMdl data;
		data.VirtualAddress = pVirtAddr;
		data.Length = length;
		wprintf(L"\nAbout to call the driver");
		if (!ConfirmOper()) {
			bRet = true;
			error = ERROR_CANCELLED;
			break;
		}
		if (!SendIoCtl(hDevice,
			IOCTL_MEMTEST_ALLOCATEMDL,
			&data,
			sizeof data,
			&g_pMdl,
			sizeof g_pMdl)) {
			error = GetLastError();
			break;
		}
		bRet = true;
		error = ERROR_SUCCESS;
	} while (false);
	
	if ((hDevice != INVALID_HANDLE_VALUE)&&(hDevice!=nullptr))
		::CloseHandle(hDevice);
	SetLastError(error);
	return bRet;
}

bool IoFreeMdlTest() {
	bool bRet = false;
	DWORD error = ERROR_SUCCESS;
	HANDLE hDevice = INVALID_HANDLE_VALUE;

	do
	{
		hDevice = OpenSysRegDev();
		if (hDevice == INVALID_HANDLE_VALUE) {
			error = GetLastError();
			break;
		}

		PVOID pMdl = g_pMdl;
		wprintf(L"\nMdl addresss [%#p] ", pMdl);
		if (!GetValue(L"%I64i", &pMdl, true)) {
			bRet = true;
			break;
		}

		wprintf(L"\nAbout to call the driver");
		if (!ConfirmOper()) {
			bRet = true;
			error = ERROR_SUCCESS;
			break;
		}
		if (!SendIoCtl(hDevice, IOCTL_MEMTEST_FREEMDL,
			&pMdl,
			sizeof pMdl,
			nullptr,
			0)) {
			error = GetLastError();
			break;
		}
		if (pMdl == g_pMdl)
			g_pMdl = 0;
		bRet = true;
		error = ERROR_SUCCESS;

	} while (false);

	if ((hDevice != INVALID_HANDLE_VALUE) && (hDevice != nullptr))
		::CloseHandle(hDevice);
	::SetLastError(error);
	return bRet;
}

bool KMemTouchTest() {
	bool bRet = false;
	DWORD error = STATUS_SUCCESS;
	HANDLE hDevice = INVALID_HANDLE_VALUE;
	KmemTouch data;

	do
	{
		hDevice = OpenSysRegDev();
		if (hDevice == INVALID_HANDLE_VALUE) {
			error = GetLastError();
			break;
		}

		data.Length = 0x1000;
		wprintf(L"\nLength [0x%I64x]", data.Length);
		if (!GetValue(
			const_cast<PWSTR>(L"%I64i"), &data.Start, true)) {
			bRet = true;
			break;
		}
		ULONG operation = (ULONG)AccessType::Read;
		wprintf(L"\nAccess type");
		wprintf(L"\n	%d - Read", (ULONG)AccessType::Read);
		wprintf(L"\n	%d - Write", (ULONG)AccessType::Write);
		wprintf(L"\nEnter value [%d]", operation);
		if (!GetValue(L"%i", &operation, true)) {
			bRet = TRUE;
			break;
		}
		data.AccessType = (AccessType)operation;
		wprintf(L"\nAbout to call the driver");
		if (!ConfirmOper()) {
			bRet = true;
			break;
		}
		if (!SendIoCtl(hDevice,
			IOCTL_MEMTEST_KMEMTOUCH,
			&data,
			sizeof data,
			nullptr,
			0)) {
			error = GetLastError();
			break;
		}
	} while (false);	

	if ((hDevice != INVALID_HANDLE_VALUE) && (hDevice != nullptr))
		::CloseHandle(hDevice);
	SetLastError(error);
	return bRet;
}

// This function is based on the code of w2k_lib.dll written by
// Sven Schreiber and published on the companion CD to
// Undocumented Windows 2000 Secrets.
// 
bool LoadSysRegDrv() {
	bool bRet = true;
	DWORD error = ERROR_SUCCESS;
	SC_HANDLE hManager = nullptr;
	SC_HANDLE hService = nullptr;
	WCHAR drvPathName[MAX_PATH];

	do
	{
		hManager = ::OpenSCManager(nullptr,
			SERVICES_ACTIVE_DATABASE,
			SC_MANAGER_ALL_ACCESS);
		if (hManager == nullptr) {
			error = ::GetLastError();
			wprintf(L"\nOpenSCManager() failed with GetLastError() = %d",
				error);
			bRet = false;
			break;
		}

		DWORD len = sizeof drvPathName / sizeof WCHAR;
		DWORD nameLen = GetFullPathName(DRV_IMAGE, len,
			drvPathName, nullptr);
		if (!nameLen) {
			error = GetLastError();
			wprintf(L"\nGetFullPathName() failed with GetLastError() = %d", error);
			bRet = false;
			break;
		}
		if (nameLen > len) {
			wprintf(L"\nInsufficent pathname buffer");
			SetLastError(ERROR_INVALID_PARAMETER);
			bRet = false;
			break;
		}

		hService = ::CreateService(
			hManager,
			DRV_SVC_NAME,
			DRV_SVC_NAME,
			SERVICE_ALL_ACCESS,
			SERVICE_KERNEL_DRIVER,
			SERVICE_DEMAND_START,
			SERVICE_ERROR_NORMAL,
			drvPathName,
			nullptr, nullptr, nullptr, nullptr, nullptr
		);
		if (hService == nullptr) {
			error = ::GetLastError();
			if (error == ERROR_SERVICE_EXISTS) {
				// This usually happen if the system crashed
				// when the driver loaded. We can try to open the
				// existing service
				error = ERROR_SUCCESS;
				hService = ::OpenService(hManager, DRV_SVC_NAME, SERVICE_ALL_ACCESS);
				if (hService == nullptr) {
					error = ::GetLastError();
					bRet = false;
					wprintf(L"\nOpenService() failed with GetLastError() = %d",
						error);
					break;
				}
			}
			else {
				bRet = false;
				wprintf(L"\nCreateService() failed with GetLastError() = %d", error);
				break;
			}
		}

		if (!::StartService(hService, 0, nullptr)) {
			error = ::GetLastError();
			wprintf(L"\nStartService() failed with GetLastError() = %d", error);
			bRet = false;
			break;
		}

		bRet = true;
		error = ERROR_SUCCESS;
	} while (false);
	if (hManager != nullptr) {
		::CloseServiceHandle(hManager);
	}
	if (hService != nullptr) {
		::CloseServiceHandle(hService);
	}
	SetLastError(error);
	return bRet;
}

bool LockPageableDrvTest() {
	bool bRet = false;
	DWORD error = STATUS_SUCCESS;
	HANDLE hDevice = INVALID_HANDLE_VALUE;

	do
	{
		hDevice = OpenSysRegDev();
		if (hDevice == INVALID_HANDLE_VALUE) {
			error = ::GetLastError();
			break;
		}
		if (!SendIoCtl(hDevice,
			IOCTL_MEMTEST_LOCKPAGEABLE,
			nullptr,
			0,
			nullptr,
			0)) {
			error = GetLastError();
			break;
		}
		error = ERROR_SUCCESS;
		bRet = true;
	} while (false);

	if ((hDevice != INVALID_HANDLE_VALUE) && (hDevice != nullptr)) {
		::CloseHandle(hDevice);
	}
	SetLastError(error);
	return bRet;
}

bool MmAllocateMappingAddressTest() {
	bool bRet = false;
	DWORD error = STATUS_SUCCESS;
	HANDLE hDevice = INVALID_HANDLE_VALUE;

	do
	{
		wprintf(L"\nSize ");
		if (!GetValue(L"%I64i", &g_AllMapin.Size, false)) {
			bRet = true;
			break;
		}

		g_AllMapin.Address = 0;
		hDevice = OpenSysRegDev();
		if (hDevice == INVALID_HANDLE_VALUE) {
			error = GetLastError();
			break;
		}
		wprintf(L"\nAbout to call the driver");
		if (!ConfirmOper()) {
			bRet = true;
			break;
		}
		if (!SendIoCtl(hDevice, IOCTL_MEMTEST_ALLOCMAPADDR,
			&g_AllMapin,
			sizeof g_AllMapin,
			&g_AllMapin,
			sizeof g_AllMapin)) {
			error = GetLastError();
			break;
		}
	} while (false);

	if (!g_AllMapin.Address)
		g_AllMapin.Size = 0;
	if ((hDevice != INVALID_HANDLE_VALUE) && (hDevice != nullptr)) {
		::CloseHandle(hDevice);
	}
	SetLastError(error);
	return bRet;
	
}

bool MmAllocatePagesForMdlExTest() {
	bool bRet = false;
	DWORD error = STATUS_SUCCESS;
	HANDLE hDevice = INVALID_HANDLE_VALUE;

	do
	{
		hDevice = OpenSysRegDev();
		if (hDevice == INVALID_HANDLE_VALUE) {
			error = GetLastError();
			break;
		}

		AllPagesForMdl data;
		wprintf(L"\nLow address ");
		if (!GetValue(L"%I64i", &data.LowAddress, false)) {
			break;
		}

		wprintf(L"\nHigh address");
		if (!GetValue(L"%I64i", &data.HighAddress, false)) {
			break;
		}

		data.SkipBytes = 0x1000;
		wprintf(L"\nSkip bytes [%I64x]", data.SkipBytes);
		if (!GetValue(L"%I64i", &data.SkipBytes, true)) {
			break;
		}

		ULONGLONG totalBytes;
		wprintf(L"\nTotal bytes ");
		if (!GetValue(L"%I64i", &totalBytes, false)) {
			break;
		}
		data.TotalBytes = (SIZE_T)totalBytes;
		data.CacheType = CacheType::Cached;
		wprintf(L"\nCache type: ");
		wprintf(L"\n	%d - Not cahced", CacheType::NonCached);
		wprintf(L"\n	%d - Cached", CacheType::Cached);
		wprintf(L"\n	%d - Write combined", CacheType::WriteCombined);
		wprintf(L"\nEnter value: [%d]", data.CacheType);
		if (!GetValue(L"%i", &data.CacheType, true)) {
			break;
		}

		data.Flags = 0;
		wprintf(L"%i", data.Flags);
		if (!GetValue(L"%i", &data.Flags, true)) {
			break;
		}

		wprintf(L"\nAbout to call the driver");
		if (!ConfirmOper())
			break;
		if (!SendIoCtl(hDevice,
			IOCTL_MEMTEST_ALLOCPAGESMDL,
			&data,
			sizeof data,
			&g_pMdl,
			sizeof g_pMdl)) {
			error = GetLastError();
			g_pMdl = nullptr;
			break;
		}
		error = ERROR_SUCCESS;
		bRet = true;
	} while (false);
	
	if ((hDevice != INVALID_HANDLE_VALUE) && (hDevice != nullptr)) {
		::CloseHandle(hDevice);
	}
	SetLastError(error);
	return bRet;
}

bool MmFreeMappingAddressTest() {
	bool bRet = false;
	DWORD error = ERROR_SUCCESS;
	HANDLE hDevice = INVALID_HANDLE_VALUE;

	do
	{
		PVOID pRegion = g_AllMapin.Address;
		wprintf(L"\nBase address [%#p]", pRegion);
		if (!GetValue(L"%I64i", &pRegion, true)) {
			break;
		}

		hDevice = OpenSysRegDev();
		if (hDevice == INVALID_HANDLE_VALUE) {
			error = GetLastError();
			break;
		}

		wprintf(L"\nAbout to call the driver");
		if (!ConfirmOper()) {
			bRet = true;
			error = ERROR_SUCCESS;
			break;
		}
		if (!SendIoCtl(hDevice, IOCTL_MEMTEST_FREEMAPADDR,
			&pRegion, sizeof pRegion, nullptr, 0)) {
			error = GetLastError();
			break;
		}
		if (pRegion == g_AllMapin.Address) {
			g_AllMapin.Address = nullptr;
			g_AllMapin.Size = 0;
		}
		bRet = true;
		error = ERROR_SUCCESS;
	} while (false);
	
	if ((hDevice != INVALID_HANDLE_VALUE) && (hDevice != nullptr)) 
		::CloseHandle(hDevice);
	
	SetLastError(error);
	return bRet;
}

bool MmFreePagesFromMdlTest() {
	bool bRet = false;
	DWORD error = STATUS_SUCCESS;
	HANDLE hDevice = INVALID_HANDLE_VALUE;

	do
	{
		hDevice = OpenSysRegDev();
		if (hDevice == INVALID_HANDLE_VALUE) {
			error = GetLastError();
			break;
		}
		
		PVOID pMdl = g_pMdl;
		wprintf(L"\nMDL address [0x%16p]", pMdl);
		if (!GetValue(L"%I64i", &pMdl, true)) {
			bRet = true;
			break;
		}

		wprintf(L"\nAbout to call the driver");
		if (!ConfirmOper()) {
			bRet = true;
			break;
		}
		if (!SendIoCtl(hDevice,
			IOCTL_MEMTEST_FREEPAGESMDL,
			&pMdl,
			sizeof pMdl,
			nullptr,
			0)) {
			error = GetLastError();
			break;
		}
		if (pMdl == g_pMdl) {
			g_pMdl = nullptr;
		}
		error = ERROR_SUCCESS;
		bRet = true;
	} while (false);
	
	if ((hDevice != INVALID_HANDLE_VALUE) && (hDevice != nullptr))
		::CloseHandle(hDevice);

	SetLastError(error);
	return bRet;
}

bool MmMapLockedPagesSpecifyCacheTest() {
	bool bRet = false;
	DWORD error = STATUS_SUCCESS;
	HANDLE hDevice = INVALID_HANDLE_VALUE;

	do
	{
		hDevice = OpenSysRegDev();
		if (hDevice == INVALID_HANDLE_VALUE) {
			error = GetLastError();
			break;
		}

		MapLockPages data;
		data.Mdl = g_pMdl;
		wprintf(L"\nMDL address [%p]", data.Mdl);
		if (!GetValue(L"%I64i", &data.Mdl, true)) {
			break;
		}
		data.AccessMode = AccessMode::Kernel;
		wprintf(L"\nAccess mode (%d = KernelMode, %d = UserMode) [%d]",
			AccessMode::Kernel, AccessMode::User, data.AccessMode);
		if (!GetValue(L"%i", &data.AccessMode, true)) {
			bRet = true;
			break;
		}

		data.CacheType = CacheType::Cached;
		wprintf(L"\nCache type: ");
		wprintf(L"\n	%d - Not cahced", CacheType::NonCached);
		wprintf(L"\n	%d - Cached", CacheType::Cached);
		wprintf(L"\n	%d - Write combined", CacheType::WriteCombined);
		wprintf(L"\nEnter value: [%d]", data.CacheType);
		if (!GetValue(L"%i", &data.CacheType, true)) {
			break;
		}

		data.BaseAddress = 0;
		wprintf(L"\nBase address [%p]", data.BaseAddress);
		if (!GetValue(L"%I64i", &data.BaseAddress, true)) {
			bRet = true;
			break;
		}

		wprintf(L"\nAbout to call the driver");
		if (!ConfirmOper()) {
			bRet = true;
			break;
		}
		if (!SendIoCtl(hDevice,
			IOCTL_MEMTEST_MAPLOCKPAGES,
			&data,
			sizeof data,
			&g_pMappedSystemRegion,
			sizeof g_pMappedSystemRegion)) {
			error = GetLastError();
			g_pMappedSystemRegion = nullptr;
			break;
		}
	} while (false);

	if ((hDevice != INVALID_HANDLE_VALUE) && (hDevice != nullptr))
		::CloseHandle(hDevice);

	SetLastError(error);
	return bRet;
}

bool MmMapLockedPagesWithReservedMappingTest() {
	bool bRet = false;
	DWORD error = STATUS_SUCCESS;
	HANDLE hDevice = INVALID_HANDLE_VALUE;

	do
	{
		hDevice = OpenSysRegDev();
		if (hDevice == INVALID_HANDLE_VALUE) {
			error = GetLastError();
			break;
		}

		MapLPagesResMap data;
		data.MappingAddress = g_AllMapin.Address;
		wprintf(L"\nMapping address [0x%16p]", data.MappingAddress);
		if (!GetValue(L"%I64i", &data.MappingAddress, true)) {
			bRet = true;
			break;
		}

		data.Mdl = g_pMdl;
		wprintf(L"\nMDL address [%p]", data.Mdl);
		if (!GetValue(L"%I64i", &data.Mdl, true)) {
			break;
		}

		data.CacheType = CacheType::Cached;
		wprintf(L"\nCache type: ");
		wprintf(L"\n	%d - Not cahced", CacheType::NonCached);
		wprintf(L"\n	%d - Cached", CacheType::Cached);
		wprintf(L"\n	%d - Write combined", CacheType::WriteCombined);
		wprintf(L"\nEnter value: [%d]", data.CacheType);
		if (!GetValue(L"%i", &data.CacheType, true)) {
			break;
		}

		wprintf(L"\nAbout to call the driver");
		if (!ConfirmOper()) {
			bRet = true;
			break;
		}

		if (!SendIoCtl(hDevice,
			IOCTL_MEMTEST_MAPLPAGESRESMAP,
			&data,
			sizeof data,
			&g_pResMappedRegion,
			sizeof g_pResMappedRegion)) {
			error = GetLastError();
			g_pResMappedRegion = nullptr;
			break;
		}
		error = ERROR_SUCCESS;
		bRet = true;
	} while (false);

	if ((hDevice != INVALID_HANDLE_VALUE) && (hDevice != nullptr))
		::CloseHandle(hDevice);

	SetLastError(error);
	return bRet;
}

bool MmProbeAndLockPagesTest() {
	BOOL bRet = FALSE;
	DWORD error = STATUS_SUCCESS;
	HANDLE hDevice = INVALID_HANDLE_VALUE;

	do
	{
		ProbeAndLock data;
		data.Mdl = g_pMdl;
		wprintf(L"\nMdl address [%#p]", data.Mdl);
		if (!GetValue(L"%I64i", &data.Mdl, true)) {
			break;
		}

		AccessMode mode;
		wprintf(L"\nAccess mode ");
		wprintf(L"\n	%d - Kernel", AccessMode::Kernel);
		wprintf(L"\n	%d - User", AccessMode::User);
		wprintf(L"\nEnter value ");
		if (!GetValue(L"%i", &mode, false)) {
			break;
		}
		data.AccessMode = mode;

		AccessType operation = AccessType::Write;
		wprintf(L"\nOperation");
		wprintf(L"\n	%d - Read", AccessType::Read);
		wprintf(L"\n	%d - Write", AccessType::Write);
		wprintf(L"\nEnter value [%d]", operation);
		if (!GetValue(L"%i", &operation, true)) {
			break;
		}
		data.Operation = operation;

		hDevice = OpenSysRegDev();
		if (hDevice == INVALID_HANDLE_VALUE) {
			error = GetLastError();
			break;
		}

		wprintf(L"\nAbout to call the driver");
		if (!ConfirmOper()) {
			bRet = true;
			break;
		}
		if (!SendIoCtl(hDevice,
			IOCTL_MEMTEST_PROBEANDLOCK,
			&data,
			sizeof data,
			nullptr,
			0)) {
			error = GetLastError();
			break;
		}
		if (data.Mdl == g_pMdl)
			g_mdlLocked = true;
		bRet = true;
	} while (false);
	
	if ((hDevice != INVALID_HANDLE_VALUE) && (hDevice != nullptr))
		::CloseHandle(hDevice);

	SetLastError(error);
	return bRet;
}

bool MmUnlockPagesTest() {
	bool bRet = false;
	DWORD error = STATUS_SUCCESS;
	HANDLE hDevice = INVALID_HANDLE_VALUE;

	do
	{
		PVOID pMdl = g_pMdl;
		wprintf(L"\nMdl address [0x%16p]", pMdl);
		if (!GetValue(L"%I64i", &pMdl, true)) {
			break;
		}
		
		hDevice = OpenSysRegDev();
		if (hDevice == INVALID_HANDLE_VALUE) {
			error = GetLastError();
			break;
		}
		wprintf(L"\nAbout to call the driver");
		if (!ConfirmOper()) {
			break;
		}
		if (!SendIoCtl(hDevice, IOCTL_MEMTEST_UNLOCKPAGES,
			&pMdl,
			sizeof pMdl,
			nullptr,
			0)) {
			error = GetLastError();
			break;
		}
		if (pMdl == g_pMdl)
			g_mdlLocked = true;
		bRet = true;

	} while (false);
	if ((hDevice != INVALID_HANDLE_VALUE) && (hDevice != nullptr))
		::CloseHandle(hDevice);

	SetLastError(error);
	return bRet;
}

bool MmUnmapLockedPagesTest() {
	bool bRet = false;
	DWORD error = STATUS_SUCCESS;
	HANDLE hDevice = INVALID_HANDLE_VALUE;

	do
	{
		hDevice = OpenSysRegDev();
		if (hDevice == INVALID_HANDLE_VALUE) {
			error = GetLastError();
			break;
		}

		UnmapLockPag data;
		data.BaseAddress = g_pMappedSystemRegion;
		wprintf(L"\nBase address [0x%16p] ", data.BaseAddress);
		if (!GetValue(L"%I64i", &data.BaseAddress, true)) {
			break;
		}

		data.Mdl = g_pMdl;
		wprintf(L"\nMDL address [0x%16p]", data.Mdl);
		if (!GetValue(L"%I64i", &data.Mdl, true)) {
			break;
		}

		wprintf(L"\nAbout to call the driver");
		if (!ConfirmOper()) {
			break;
		}
		if (!SendIoCtl(hDevice,
			IOCTL_MEMTEST_UNMAPLOCKPAG,
			&data,
			sizeof data,
			nullptr,
			0)) {
			error = GetLastError();
			break;
		}
		// if the address has been unmapped is the one stored in
		// the static, set the latter to nullptr
		//
		if (data.BaseAddress == g_pMappedSystemRegion)
			g_pMappedSystemRegion = nullptr;
		bRet = true;
	} while (false);
	if ((hDevice != INVALID_HANDLE_VALUE) && (hDevice != nullptr))
		::CloseHandle(hDevice);

	SetLastError(error);
	return bRet;
}

bool MmUnmapReservedMappingTest() {
	bool bRet = false;
	DWORD error = STATUS_SUCCESS;
	HANDLE hDevice = INVALID_HANDLE_VALUE;

	do
	{
		hDevice = OpenSysRegDev();
		if (hDevice == INVALID_HANDLE_VALUE) {
			error = GetLastError();
			break;
		}
		UnmapResMap data;
		data.BaseAddress = g_AllMapin.Address;
		wprintf(L"\nBase Address [0x%16p]", data.BaseAddress);
		if (!GetValue(L"%I64i", &data.BaseAddress, true)) {
			break;
		}

		data.Mdl = g_pMdl;
		wprintf(L"\nMDL address [0x%16p]", data.Mdl);
		if (!GetValue(L"%I64i", &data.Mdl, true)) {
			break;
		}

		wprintf(L"\nAbout to call the driver");
		if (!ConfirmOper()) {
			break;
		}
		if (!SendIoCtl(hDevice,
			IOCTL_MEMTEST_UNMAPRESMAP,
			&data,
			sizeof data,
			nullptr,
			0)) {
			error = GetLastError();
			break;
		}
		// if the range which has been unmpped is the one decribed
		// by g_AllMapin,g_pResMappedRegion must be set to
		// nullptr, becasue it stores the address at which a mapping
		// has previous been made in the reange described by 
		// g_AllMapin.
		if (data.BaseAddress == g_AllMapin.Address)
			g_pResMappedRegion = nullptr;
		error = ERROR_SUCCESS;
		bRet = true;
	} while (false);

	if ((hDevice != INVALID_HANDLE_VALUE) && (hDevice != nullptr))
		::CloseHandle(hDevice);

	SetLastError(error);
	return bRet;
}

HANDLE MyOpenFile(PWSTR fileName, DWORD access) {
	wprintf(L"\nabout to open file %s", fileName);
	if (!ConfirmOper()) {
		SetLastError(ERROR_CANCELLED);
		return INVALID_HANDLE_VALUE;
	}
	HANDLE hRet = ::CreateFileWr(fileName, access, 0,
		OPEN_EXISTING);
	if (hRet == INVALID_HANDLE_VALUE)
		return INVALID_HANDLE_VALUE;
	wprintf(L"\nfile %s opened", fileName);
	return hRet;
}

bool OpenFileInterface() {
	bool bRet = true;
	DWORD error = ERROR_CANCELLED;

	wcscpy_s(g_fileName, sizeof g_fileName / sizeof g_fileName[0],
		L"memtests.tmp");
	wprintf(L"\nfile name [%s]:", g_fileName);
	do
	{
		if (!GetValue(L"%s", g_fileName, true)) {
			break;
		}
		g_fileName[sizeof g_fileName / sizeof g_fileName[0] - 1] = L'\0';
		
		DWORD access = GENERIC_READ | GENERIC_WRITE;
		wprintf(L"\ndwDesiredAccess [0x%x]:", access);
		wprintf(L"\n    0x%x - GENERIC_READ", GENERIC_READ);
		wprintf(L"\n    0x%x - GENERIC_WRITE", GENERIC_WRITE);
		wprintf(L"\n    0x%x - GENERIC_EXECUTE", GENERIC_EXECUTE);
		wprintf(L"\n");
		if (!GetValue(L"%i", &access, true)) {
			break;
		}
		g_hFile = MyOpenFile(g_fileName, access);
		if (g_hFile == INVALID_HANDLE_VALUE) {
			error = GetLastError();
			// if cacelled,no error
			bRet = (GetLastError() == ERROR_CANCELLED);
			break;
		}
		error = ERROR_SUCCESS;
	} while (false);
	SetLastError(error);
	return bRet;
}

HANDLE OpenSysRegDev() {
	DWORD error;
	HANDLE hDevice;
	WCHAR devPath[MAX_PATH];

	HRESULT hRes = StringCbPrintf(
		devPath,
		sizeof devPath,
		L"\\\\.\\%s",
		DRV_DEVICE_NAME
	);
	if (!SUCCEEDED(hRes)) {
		wprintf(L"\nOpenWeDevice - StringCbPrintf return %#x", hRes);
		// When in doubt, blame it one the memory
		SetLastError(ERROR_NOT_ENOUGH_MEMORY);
		return INVALID_HANDLE_VALUE;
	}

	hDevice = ::CreateFile(devPath, GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		nullptr,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		nullptr);
	if (hDevice == INVALID_HANDLE_VALUE) {
		error = GetLastError();
		wprintf(L"\nCreateFile() for device %s failed. GetLastError() = 0x%08x",
			devPath, error);
		SetLastError(error);
		return INVALID_HANDLE_VALUE;
	}
	return hDevice;
}

void PrintMenu() {
	wprintf(L"\n\nMemory Allocation\n");
	wprintf(L"\n    l - VirtualAllocEx() test");
	wprintf(L"\n    m - Memory section test");
	wprintf(L"\n    o - Open existing file mapping");
	wprintf(L"\n    v - VirtualProtectEx() test");
	wprintf(L"\n    s - Shrink WS");

	wprintf(L"\n\nMemory Access\n");
	wprintf(L"\n    a - Access region");

	wprintf(L"\n\nTest File Management\n");
	wprintf(L"\n    e - Create test file");
	wprintf(L"\n    c - Close test file");
	wprintf(L"\n    p - Open existing test file");

	wprintf(L"\n\nTest File Access\n");
	wprintf(L"\n    f - File read test");
	wprintf(L"\n    w - File write test");

	wprintf(L"\n\nResource Deallocation\n");
	wprintf(L"\n    r - Release private region");
	wprintf(L"\n    u - Release file mapping");
	wprintf(L"\n    R - Release all");

	wprintf(L"\n\nAccount Privileges");
	wprintf(L"\n    d - Add %s privilege", SE_LOCK_MEMORY_NAME);
	wprintf(L"\n    n - Enable %s privilege", SE_LOCK_MEMORY_NAME);

	wprintf(L"\n");
	wprintf(L"\n    y - System range tests");
	wprintf(L"\n    t - Print status");

	wprintf(L"\n\n    q - Exit\n");
}

//++
//
// Print the paging structure address for the range
//
//--
void PrintPagStructAddrs(PBYTE start, SIZE_T size) {
	DWORD_PTR pStart, pLastPage;
	DWORD_PTR pFirstPs, pLastPs;

	pStart = (DWORD_PTR)start;
	pLastPage = pStart + size - 0x1000;

	// PDPT

	pFirstPs = VA_TO_PS_ADDR(pStart, 27, PDPTE_RANGE_START);
	pLastPs = VA_TO_PS_ADDR(pLastPage, 27, PDPTE_RANGE_START);
	wprintf(L"\nPDPTE - first: %#p, last: %#p", pFirstPs, pLastPs);

	// PD
	pFirstPs = VA_TO_PS_ADDR(pStart, 18, PDE_RANGE_START);
	pLastPs = VA_TO_PS_ADDR(pLastPage, 18, PDE_RANGE_START);
	wprintf(L"\nPDE - first: %#p, last: %#p", pFirstPs, pLastPs);
	
	// PT
	pFirstPs = VA_TO_PS_ADDR(pStart, 9, PTE_RANGE_START);
	pLastPs = VA_TO_PS_ADDR(pLastPage, 9, PTE_RANGE_START);
	wprintf(L"\nPTE - first: %#p, last: %#p", pFirstPs, pLastPs);
}

void PrintStatus() {
	wprintf(L"\nMapped region  : 0x%16p - 0x%16p", 
		g_pMappedRegionStart, g_pMappedRegionEnd);
	wprintf(L"\nPrivate region : 0x%16p - 0x%16p", 
		g_pPrivateRegionStart, g_pPrivateRegionEnd);
	if ((g_hFileMapping != INVALID_HANDLE_VALUE) && (g_hFileMapping != nullptr)) {
		wprintf(L"\nFile mapping is open; name: %s", g_mappingName);
	}
	if ((g_hFile != INVALID_HANDLE_VALUE) && (g_hFile != nullptr)) {
		wprintf(L"\nFile is open; name: %s", g_fileName);
	}
	wprintf(L"\n");
	wprintf(L"\nMDL                            : 0x%16p - ", g_pMdl);
	wprintf(L"%slocked", (g_mdlLocked ? L"" : L"not "));
	wprintf(L"\nReserved sys region            : 0x%16p - 0x%16p",
		g_AllMapin.Address,
		(PBYTE)g_AllMapin.Address + g_AllMapin.Size);
	wprintf(L"\nMapped addr in reserved region : 0x%16p", g_pResMappedRegion);
	wprintf(L"\nMapped sys addr                : 0x%16p", g_pMappedSystemRegion);
}

bool ProcessOption() {
	switch (g_cmd) {
	case L'a':
		return AccessRegionInterface();
		break;
	case L'c':
		return CloseFile(&g_hFile, TRUE);
		break;
	case L'd':
		return AddPrivilege(SE_LOCK_MEMORY_NAME);
		break;
	case L'f':
		return FileReadTestInterface();
		break;
	case L'e':
		return FileCreateInterface();
		break;
	case L'l':
		return VirtAllocTestInterface();
		break;
	case L'm':
		return FileMappingTestInterface();
		break;
	case L'n':
		return EnablePrivilege(SE_LOCK_MEMORY_NAME);
		break;
	case L'o':
		return FileMappingOpenTestInterface();
		break;
	case L'p':
		return OpenFileInterface();
		break;
	case L'q':
		g_bExit = TRUE;
		return TRUE;
	case L'r':
		return ReleasePrivateRegion(TRUE);
		break;
	case L'R':
		return ReleaseAll();
		break;
	case L's':
		return ShrinkWs();
		break;
	case L't':
		PrintStatus();
		return TRUE;
		break;
	case L'u':
		return ReleaseFileMapping(TRUE);
		break;
	case L'v':
		return VirtProtTestInterface();
		break;
	case L'w':
		return FileWriteTestInterface();
		break;
	case L'y':
		return SystemRangeSubmenu();
		break;
	default:
		wprintf(L"\ninvalid option: %c", g_cmd);
		SetLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}
}

bool ReleaseAll() {
	bool bRet;
	DWORD error = ERROR_SUCCESS;

	bRet = CloseFile(&g_hFile, FALSE);
	if (!bRet && (error == ERROR_SUCCESS)) {
		error = GetLastError();
	}
	bRet = ReleaseFileMapping(false);
	if (!bRet && (error == ERROR_SUCCESS)) {
		error = GetLastError();
	}
	bRet = ReleasePrivateRegion(false);
	if (!bRet && (error == ERROR_SUCCESS)) {
		error = GetLastError();
	}
	SetLastError(error);
	return bRet;
}

bool ReleaseFileMapping(bool interactive) {
	DWORD error;
	if (g_pMappedRegionStart != nullptr) {
		if (interactive) {
			wprintf(L"\nabout to call UnmapViewOfFile()");
			if (!ConfirmOper()) {
				SetLastError(ERROR_CANCELLED);
				return TRUE;
			}
		}
		PVOID pRegionStartCopy = g_pMappedRegionStart;
		g_pMappedRegionStart = nullptr;
		g_pMappedRegionEnd = nullptr;
		if (!::UnmapViewOfFile(pRegionStartCopy)) {
			error = GetLastError();
			wprintf(L"\nUnmapViewOfFile() failed with GetLastError() = %d",
				error);
			SetLastError(error);
			return false;
		}
	}
	if ((g_hFileMapping != nullptr) && (g_hFileMapping != INVALID_HANDLE_VALUE)) {
		if (interactive) {
			wprintf(L"\nAbout to close the mapping handle");
			if (!ConfirmOper()) {
				SetLastError(ERROR_CANCELLED);
				return true;
			}
		}
		HANDLE hMapCopy = g_hFileMapping;
		g_mappingName[0] = L'\0';
		if (!::CloseHandle(hMapCopy)) {
			error = GetLastError();
			wprintf(L"\nCloseHandle() failed with GetLastError() = %d",
				error);
			return false;
		}
		return true;
	}
}

bool ReleasePrivateRegion(bool interactive) {
	DWORD error;
	if (g_pPrivateRegionStart != nullptr) {
		if (interactive) {
			wprintf(L"\nabout to release private region");
			if (!ConfirmOper()) {
				SetLastError(ERROR_CANCELLED);
				return TRUE;
			}
		}
		PVOID pRegionStartCopy = g_pPrivateRegionStart;
		g_pPrivateRegionStart = nullptr;
		g_pPrivateRegionEnd = nullptr;
		if (!::VirtualFreeEx(GetCurrentProcess(),
			pRegionStartCopy,
			0,
			MEM_RELEASE)) {
			error = GetLastError();
			wprintf(L"\nVirtualFreeEx() failed, GetLastError() = %d",
				error);
			SetLastError(error);
			return false;
		}
	}
	return true;
}

bool SendIoCtl(HANDLE hDevice,
	int code,
	LPVOID inBuffer,int inSize,LPVOID outBuffer,int outSize) {
	bool bRet;
	DWORD bytes;
	DWORD error;

	bRet = ::DeviceIoControl(hDevice, code, inBuffer, inSize, outBuffer, outSize, 
		&bytes, nullptr);
	if (!bRet) {
		error = GetLastError();
		wprintf(L"\nFailed to send IOCTL. Code: 0x%8x, GetLastError() = 0x%8x",
			code,
			error);
		SetLastError(error);
		return false;
	}
	return bRet;
}

bool ShrinkWs() {
	bool bRet = true;
	DWORD error = ERROR_CANCELLED;

	do
	{
		if (!ConfirmOper())
			break;

		bRet = ::SetProcessWorkingSetSize(
			GetCurrentProcess(),
			-1,
			-1);
		if (!bRet) {
			error = GetLastError();
			wprintf(L"\nSetProcessWorkingSetSize failed with GetLastError() = %d",
				error);
			break;
		}

		wprintf(L"\nworking set shrunk");
		error = ERROR_SUCCESS;
	} while (false);

	SetLastError(error);
	return bRet;
}

bool SRSChoice(PBOOL pbQuit) {
	*pbQuit = false;
	WCHAR ch = _getwch();
	switch (ch) {
	case L'a':
		return MmAllocateMappingAddressTest();
		break;
	case L'b':
		return MmMapLockedPagesSpecifyCacheTest();
		break;
	case L'c':
		return MmAllocatePagesForMdlExTest();
		break;
	case L'd':
		return LockPageableDrvTest();
		break;
	case L'e':
		return MmFreePagesFromMdlTest();
		break;
	case L'f':
		return IoFreeMdlTest();
		break;
	case L'g':
		return CallPageableFunTest();
		break;
	case L'h':
		return MmUnmapLockedPagesTest();
		break;
	case L'i':
		return UnlockPageableDrvTest();
		break;
	case L'k':
		return MmProbeAndLockPagesTest();
		break;
	case L'l':
		return LoadSysRegDrv();
		break;
	case L'm':
		return IoAllocateMdlTest();
		break;
	case L'n':
		return MmUnmapReservedMappingTest();
		break;
	case L'o':
		return MmUnlockPagesTest();
		break;
	case L'p':
		return MmMapLockedPagesWithReservedMappingTest();
		break;
	case L'q':
		*pbQuit = TRUE;
		return TRUE;
		break;
	case L'r':
		return MmFreeMappingAddressTest();
		break;
	case L't':
		return KMemTouchTest();
		break;
	case L'u':
		return UnloadSysRegDrv();
		break;
	default:
		wprintf(L"\n\nInvalid key: %c", ch);
		return TRUE;
	}
}

bool SystemRangeSubmenu() {
	BOOL	bQuit = FALSE;
	do {
		wprintf(L"\n\n\nSystem Range Tests\n\n");
		PrintStatus();
		wprintf(L"\n\nDriver control\n");
		wprintf(L"\n    l - Load kernel allocations driver");
		wprintf(L"\n    u - Unload kernel allocations driver");

		wprintf(L"\n\nTests\n");
		wprintf(L"\n    m - IoAllocateMdl() test");
		wprintf(L"\n    f - IoFreeMdl() test");
		wprintf(L"\n    a - MmAllocateMappingAddress() test");
		wprintf(L"\n    r - MmFreeMappingAddress() test");
		wprintf(L"\n    k - MmProbeAndLockPages() test");
		wprintf(L"\n    o - MmUnLockPages() test");
		wprintf(L"\n    p - MmMapLockedPagesWithReservedMapping() test");
		wprintf(L"\n    n - MmUnmapReservedMapping() test");
		wprintf(L"\n    b - MmMapLockedPagesSpecifyCache() test");
		wprintf(L"\n    h - MmUnmapLockedPages() test");
		wprintf(L"\n    c - MmAllocatePagesForMdlEx() test");
		wprintf(L"\n    e - MmFreePagesFromMdl() test");
		wprintf(L"\n    t - Memory touch test");
		wprintf(L"\n    g - Call pageable function test");
		wprintf(L"\n    d - Lock pageable driver test");
		wprintf(L"\n    i - Unlock pageable driver test");

		wprintf(L"\n\n    q - Quit\n\n");
		SRSChoice(&bQuit);
		if (!bQuit) {
			wprintf(L"\nany key to return to system tests menu...");
			_getwch();
		}
	} while (!bQuit);
	return TRUE;
}

bool UnloadSysRegDrv() {
	bool bRet = true;
	DWORD error = ERROR_SUCCESS;
	SC_HANDLE hManager = nullptr;
	SC_HANDLE hService = nullptr;
	SERVICE_STATUS srvStatus;

	::ZeroMemory(&srvStatus, sizeof srvStatus);
	do
	{
		hManager = ::OpenSCManager(nullptr, SERVICES_ACTIVE_DATABASE,
			SC_MANAGER_ALL_ACCESS);
		if (hManager == nullptr) {
			error = GetLastError();
			wprintf(L"\nOpenSCManager() failed with GetLastError() = %d",
				error);
			bRet = false;
			break;
		}
		hService = ::OpenService(hManager, DRV_SVC_NAME, SERVICE_ALL_ACCESS);
		if (hService == nullptr) {
			error = GetLastError();
			wprintf(L"\nOpenService() failed with GetLastError() = %d",
				error);
			bRet = FALSE;
			break;
		}
		if (!::ControlService(hService, SERVICE_CONTROL_STOP, &srvStatus)) {
			// print the error code but don't abort
			//
			error = GetLastError();
			wprintf(L"\nControlService() failed with GetLastError() =%d. Attempting to delete the service anyway",
				error);
			error = ERROR_SUCCESS;
		}
		if (!::DeleteService(hService)) {
			error = ::GetLastError();
			if (error == ERROR_SERVICE_MARKED_FOR_DELETE) {
				wprintf(L"\nDeleteService() failed with GetLastError() = ERROR_SERVICE_MARKED_FOR_DELETE");

				// Go on and return success
			}
			else {
				wprintf(L"\nDeleteService() failed with GetLastError() = %d",
					error);
				bRet = false;
				break;
			}
		}
		bRet = true;
		error = ERROR_SUCCESS;
	} while (false);
	
	if (hService != nullptr)
		::CloseServiceHandle(hService);
	if (hManager != nullptr)
		::CloseServiceHandle(hManager);
	SetLastError(error);
	return bRet;
}

bool UnlockPageableDrvTest() {
	bool bRet = false;
	DWORD error = STATUS_SUCCESS;
	HANDLE hDevice = INVALID_HANDLE_VALUE;

	do
	{
		hDevice = OpenSysRegDev();
		if (hDevice == INVALID_HANDLE_VALUE) {
			error = GetLastError();
			break;
		}
		if (!SendIoCtl(hDevice,
			IOCTL_MEMTEST_UNLOCKPAGEABLE,
			nullptr,
			0,
			nullptr,
			0)) {
			error = GetLastError();
			break;
		}
	} while (false);
	if (hDevice != INVALID_HANDLE_VALUE)
		::CloseHandle(hDevice);
	SetLastError(error);
	return bRet;
}

bool VirtAllocTest(PVOID address, SIZE_T size, DWORD allocationType,
	DWORD protect, BOOL explicitNumaNode, DWORD numaNode,
	PVOID* ppStart,
	PVOID* ppEnd) {

	DWORD error;
	HANDLE hProcess = GetCurrentProcess();

	wprintf(
		L"\nlpAddress        = %#p", address);
	wprintf(
		L"\ndwSize           = 0x%I64x", size);
	wprintf(
		L"\nflAllocationType = 0x%x", allocationType);
	wprintf(
		L"\nflProtect        = 0x%x", protect);
	wprintf(
		L"\nbExplicitNumaNode = %s",
		(explicitNumaNode ? L"TRUE" : L"FALSE"));
	if (explicitNumaNode) {
		wprintf(
			L"\nnndPreferred      = %d", numaNode);
	}
	if (explicitNumaNode) {
		wprintf(L"\n\nabout to call VirtualAllocExNuma()");
	}
	else {
		wprintf(L"\n\nabout to call VirtualAllocEx()");
	}
	if (!ConfirmOper()) {
		SetLastError(ERROR_CANCELLED);
		return TRUE;
	}

	PVOID pMem;
	if (explicitNumaNode) {
		pMem = (PBYTE)::VirtualAllocExNuma(hProcess,
			address, size, allocationType, protect, numaNode);
	}
	else {
		pMem = (PBYTE)::VirtualAllocEx(hProcess,
			address, size, allocationType, protect);
	}
	if (pMem == nullptr) {
		error = ::GetLastError();
		wprintf(L"\nVirtualAllocEx() failed with GetLastError() = %d", error);
		SetLastError(error);
		return false;
	}
	wprintf(L"\n");
	PrintPagStructAddrs((PBYTE)pMem, size);
	*ppStart = pMem;
	*ppEnd = (PBYTE)pMem + size;
	wprintf(L"\n\nstarting address = %#p", *ppStart);
	wprintf(L"\n\nending address = %#p", (UINT_PTR)*ppEnd - 1);
	return true;
}

bool VirtAllocTestInterface() {
	bool bRet = true;
	DWORD error = ERROR_SUCCESS;
	WCHAR ch;

	PVOID pAddress = nullptr;
	do
	{
		wprintf(L"\n\npAddress [0x%p] = ", pAddress);
		if (!GetValue(L"%I64i", &pAddress, true))
			break;

		SIZE_T size;
		wprintf(L"\nSize = ");
		if (!GetValue(L"%I64i", &size, false))
			break;

		DWORD allocationType = MEM_COMMIT | MEM_RESERVE;
		wprintf(L"\nflAllocationType [0x%x]:", allocationType);
		wprintf(L"\n    MEM_COMMIT      = 0x%x", MEM_COMMIT);
		wprintf(L"\n    MEM_RESERVE     = 0x%x", MEM_RESERVE);
		wprintf(L"\n    MEM_RESET       = 0x%x", MEM_RESET);
		wprintf(L"\n    MEM_LARGE_PAGES = 0x%x", MEM_LARGE_PAGES);
		wprintf(L"\n    MEM_PHYSICAL    = 0x%x", MEM_PHYSICAL);
		wprintf(L"\n    MEM_TOP_DOWN    = 0x%x", MEM_TOP_DOWN);
		wprintf(L"\n\n");
		if (!GetValue(L"%i", &allocationType, TRUE))
			break;

		DWORD protect = PAGE_READWRITE;
		wprintf(L"\nflProtect [0x%x]:", protect);
		wprintf(L"\n"
			L"    PAGE_READONLY          = 0x%x", PAGE_READONLY);
		wprintf(L"\n"
			L"    PAGE_READWRITE         = 0x%x", PAGE_READWRITE);
		wprintf(L"\n"
			L"    PAGE_WRITECOPY         = 0x%x", PAGE_WRITECOPY);
		wprintf(L"\n"
			L"    PAGE_EXECUTE_READ      = 0x%x", PAGE_EXECUTE_READ);
		wprintf(L"\n"
			L"    PAGE_EXECUTE_READWRITE = 0x%x", PAGE_EXECUTE_READWRITE);
		wprintf(L"\n"
			L"    PAGE_EXECUTE_WRITECOPY = 0x%x", PAGE_EXECUTE_WRITECOPY);
		wprintf(L"\n"
			L"    PAGE_EXECUTE           = 0x%x", PAGE_EXECUTE);
		wprintf(L"\n"
			L"    PAGE_NOACCESS          = 0x%x", PAGE_NOACCESS);
		wprintf(L"\n\n");
		if (!GetValue(L"%i", &protect, TRUE))
			break;

		bool explicitNumaNode = false;
		DWORD numaNode = 0;
		ch = 'n';
		wprintf(L"\n");
		if (!GetKey(&ch, L"specify NUMA node", true, L"?", L"yn"))
			break;
		if (ch == L'y') {
			explicitNumaNode = true;
			wprintf(L"\nPreferred: ");
			if (!GetValue(L"%d", &numaNode, FALSE))
				break;
		}
		else if (ch == L'n') {
			explicitNumaNode = false;
		}
		if (!::VirtAllocTest(pAddress, size, allocationType,
			protect,
			explicitNumaNode, numaNode,
			&g_pPrivateRegionStart,
			&g_pPrivateRegionEnd)) {
			bRet = false;
			error = ::GetLastError();
			break;
		}
		error = STATUS_SUCCESS;
	} while (false);
	
	SetLastError(error);
	return bRet;
}

bool VirtProtTestInterface() {
	BOOL bRet = TRUE;
	DWORD error = ERROR_CANCELLED;
	

	do
	{
		PVOID pAddress;
		wprintf(L"\naddress: ");
		if (!GetValue(L"%I64i", &pAddress, FALSE))
			break;

		SIZE_T	size;
		wprintf(L"\nsize: ");
		if (!GetValue(L"%I64i", &size, FALSE))
			break;

		DWORD newProtect;
		wprintf(L"\nNewProtect: ");
		if (!GetValue(L"%I64i", &newProtect, false))
			break;

		wprintf(L"\nsubregion      : %#p - %#p", pAddress, (PBYTE)pAddress + size);
		wprintf(L"\nnew protection : %x", newProtect);
		wprintf(L"\nabout to call VirtualProtectEx()...");
		if (!ConfirmOper()) {
			break;
		}
		DWORD oldProtect;
		if (!::VirtualProtectEx(GetCurrentProcess(),
			pAddress, size, newProtect, &oldProtect)) {
			error = GetLastError();
			bRet = false;
			wprintf(L"\nVirtualProtectEx() failed with GetLastError() = %d",
				error);
			break;
		}
		wprintf(L"\nold protection: %x", oldProtect);
		error = ERROR_SUCCESS;
	} while (false);
	SetLastError(error);
	return bRet;
}

bool WriteFileWr(
	HANDLE hFile,
	LPVOID buffer,
	DWORD count
) {
	DWORD error;

	DWORD bytes;
	if (!::WriteFile(hFile, buffer, count, &bytes, nullptr)) {
		error = GetLastError();
		wprintf(L"\nWriteFile failed with GetLastError() = %d", error);
		SetLastError(error);
		return false;
	}
	if (bytes != count) {
		wprintf(L"\nWriteFile failed to write %d bytes; written bytes count: %d",
			count,
			bytes);
		SetLastError(ERROR_WRITE_FAULT);
		return false;
	}
	return true;
}