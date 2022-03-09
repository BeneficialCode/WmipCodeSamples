#pragma once
/*


=======================================================================

Kernel memory allocation test driver

Companion test program to What Makes It Page?

Copyright (c), 2012 by Enrico Martignetti - All rights reserved.



=======================================================================



*/

#define DRIVER_PREFIX "[KernelAllocs]: "

#define MEMTEST_DEVICE 0x8000

#define DRIVER_TAG 'KATS'

#define IOCTL_MEMTEST_MDL_FOR_USER_BUFFER CTL_CODE(MEMTEST_DEVICE,\
	0x800,METHOD_BUFFERED,FILE_ANY_ACCESS)

#define IOCTL_MEMTEST_ALLOCATEMDL CTL_CODE(MEMTEST_DEVICE,\
	0x801,METHOD_BUFFERED,FILE_ANY_ACCESS)

#define IOCTL_MEMTEST_FREEMDL CTL_CODE(MEMTEST_DEVICE,\
	0x802,METHOD_BUFFERED,FILE_ANY_ACCESS)

#define IOCTL_MEMTEST_ALLOCMAPADDR CTL_CODE(MEMTEST_DEVICE,\
	0x803,METHOD_BUFFERED,FILE_ANY_ACCESS)

#define IOCTL_MEMTEST_FREEMAPADDR CTL_CODE(MEMTEST_DEVICE,\
	0x804,METHOD_BUFFERED,FILE_ANY_ACCESS)

#define IOCTL_MEMTEST_PROBEANDLOCK CTL_CODE(MEMTEST_DEVICE,\
	0x805,METHOD_BUFFERED,FILE_ANY_ACCESS)

#define IOCTL_MEMTEST_UNLOCKPAGES CTL_CODE(MEMTEST_DEVICE,\
	0x806,METHOD_BUFFERED,FILE_ANY_ACCESS)

#define IOCTL_MEMTEST_ALLOCPAGESMDL CTL_CODE(MEMTEST_DEVICE,\
	0x807,METHOD_BUFFERED,FILE_ANY_ACCESS)

#define IOCTL_MEMTEST_FREEPAGESMDL CTL_CODE(MEMTEST_DEVICE,\
	0x808,METHOD_BUFFERED,FILE_ANY_ACCESS)

#define IOCTL_MEMTEST_MAPLPAGESRESMAP CTL_CODE(MEMTEST_DEVICE,\
	0x809,METHOD_BUFFERED,FILE_ANY_ACCESS)

#define IOCTL_MEMTEST_UNMAPRESMAP CTL_CODE(MEMTEST_DEVICE,\
	0x80A,METHOD_BUFFERED,FILE_ANY_ACCESS)

#define IOCTL_MEMTEST_KMEMTOUCH CTL_CODE(MEMTEST_DEVICE,\
	0x80B,METHOD_BUFFERED,FILE_ANY_ACCESS)

#define IOCTL_MEMTEST_CALLPAGEABLE CTL_CODE(MEMTEST_DEVICE,\
	0x80C,METHOD_BUFFERED,FILE_ANY_ACCESS)

#define IOCTL_MEMTEST_LOCKPAGEABLE CTL_CODE(MEMTEST_DEVICE,\
	0x80D,METHOD_BUFFERED,FILE_ANY_ACCESS)

#define IOCTL_MEMTEST_UNLOCKPAGEABLE CTL_CODE(MEMTEST_DEVICE,\
	0x80E,METHOD_BUFFERED,FILE_ANY_ACCESS)

#define IOCTL_MEMTEST_MAPLOCKPAGES CTL_CODE(MEMTEST_DEVICE,\
	0x80F,METHOD_BUFFERED,FILE_ANY_ACCESS)

#define IOCTL_MEMTEST_UNMAPLOCKPAG CTL_CODE(MEMTEST_DEVICE,\
	0x810,METHOD_BUFFERED,FILE_ANY_ACCESS)

enum class AccessType{
	ATRead,
	ATWrite
};

enum class AccessMode {
	AMKernel,
	AmUser
};

enum class CacheType {
	CTNonCached,
	CTCahced,
	CTWriteCombined
};

struct AllocaMdl {
	PVOID VirtualAddress;
	ULONG Length;
};

struct AllMapAddr {
	SIZE_T Size;
	PVOID Address;
};

struct AllPagesForMdl {
	PVOID LowAddress;
	PVOID HighAddress;
	ULONGLONG SkipBytes;
	SIZE_T TotalBytes;
	ULONG CacheType;
	ULONG Flags;
};

struct KmemTouch {
	PVOID Start;
	SIZE_T Length;
	AccessType AccessType;
};

struct MapLockPages {
	PVOID Mdl;
	ULONG AccessMode;
	ULONG CacheType;
	PVOID BaseAddress;
};

struct MdlForUserBuffer {
	PVOID Buffer;
	ULONG BufSize;
	AccessType AccessType;
	AccessMode AccessMode;
	CacheType CacheType;
};

struct ProbeAndLock {
	PVOID Mdl;
	AccessMode AccessMode;
	AccessType Operation;
};

struct UnmapLockPag {
	PVOID BaseAddress;
	PVOID Mdl;
};

struct UnmapResMap {
	PVOID BaseAddress;
	PVOID Mdl;
};

struct ZwMapViewOfSec {
	WCHAR ProcName[256];
	PVOID SectionHandle;
	PVOID BaseAddress;
	ULONGLONG ZeroBits;
	ULONGLONG CommitSize;
	ULONGLONG SectionOffset;
	ULONGLONG ViewSize;
	ULONG Win32Protect;
};

struct ZwOpenSec {
	WCHAR SecName[256];
	ULONG AccessMask;
};


