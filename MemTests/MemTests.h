#pragma once

BOOL AccessRegion(PVOID regionStart, PVOID regionEnd);
BOOL AccessRegionInterface();
BOOL AddPrivilege(const wchar_t* priv);
BOOL CallPageableFunTest();
BOOL CloseFile(PHANDLE phFile, BOOL interactive);
BOOL ConfirmOper();
HANDLE CreateFileWr(PWSTR fileName,DWORD access,DWORD sharedMode,DWORD crDisp);
BOOL EnablePrivilege(const wchar_t* prvName);
HANDLE FileCreate(PWSTR fileName, BOOL incrementalExp, ULONGLONG fileSize);
BOOL FileCreateInterface();
BOOL FileMappingTest(HANDLE hFileToMap, DWORD mapProtect, PULONGLONG pMapSize,
	DWORD viewAccess, DWORD offsetLow, DWORD offsetHigh, PSIZE_T pViewSize,
	BOOL explicitNumaNode, DWORD numaNode, PWCHAR mappingName, PVOID* ppRegion,
	LPHANDLE phMap);
BOOL FileMappingOpenTest(DWORD access, PWCHAR name, DWORD offLow,
	DWORD offHigh, PSIZE_T pSize, PVOID* ppMappedRegion, PHANDLE phMapping);
BOOL FileMappingOpenTestInterface();
BOOL FileMappingTestInterface();
BOOL FileOpenCreateInterface();
BOOL FileReadTest(HANDLE hFile, ULONGLONG offset, DWORD length);
BOOL FileReadTestInterface();
BOOL FileWriteTest(HANDLE hFile, ULONGLONG offset, ULONGLONG byteCount);
BOOL FileWriteTestInterface();
BOOL GetKey(PWCHAR pKey, const wchar_t* const msg, BOOL bDefault,
	const wchar_t* const separator, const wchar_t* const validChars);
BOOL GetValue(const wchar_t* const format, PVOID value, BOOL bDefault);
void InitStatus();
bool IoAllocateMdlTest();
bool IoFreeMdlTest();
bool KMemTouchTest();
bool LoadSysRegDrv();
bool LockPageableDrvTest();
bool MmAllocateMappingAddressTest();
bool MmAllocatePagesForMdlExTest();
bool MmFreeMappingAddressTest();
bool MmFreePagesFromMdlTest();
bool MmMapLockedPagesSpecifyCacheTest();
bool MmMapLockedPagesWithReservedMappingTest();
bool MmProbeAndLockPagesTest();
bool MmUnlockPagesTest();
bool MmUnmapLockedPagesTest();
bool MmUnmapReservedMappingTest();
HANDLE MyOpenFile(PWSTR fileName,DWORD access);
bool OpenFileInterface();
HANDLE OpenSysRegDev();
void PrintMenu();
void PrintPagStructAddrs(PBYTE start, SIZE_T size);
void PrintStatus();
bool ProcessOption();
bool ReleaseAll();
bool ReleaseFileMapping(bool interactive);
bool ReleasePrivateRegion(bool interactive);
bool SendIoCtl(HANDLE hDevice, 
	int code, 
	LPVOID inBuffer, 
	int inSize, 
	LPVOID outBuffer, 
	int outSize);

bool ShrinkWs();
bool SRSChoice(PBOOL pbQuit);
bool SystemRangeSubmenu();
bool UnloadSysRegDrv();
bool UnlockPageableDrvTest();
bool VirtAllocTest(PVOID address, SIZE_T size, DWORD allocationType,
	DWORD protect, BOOL explicitNumaNode, DWORD numaNode,
	PVOID* ppStart,
	PVOID* ppEnd);
bool VirtAllocTestInterface();
bool VirtProtTestInterface();
bool WriteFileWr(
	HANDLE hFile,
	LPVOID buffer,
	DWORD count
);

