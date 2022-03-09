# WmipCodeSamples

《What makes it page？》 code samples

**MemColls**

MemColls is a program to test in-paging collisions. It is meant to be used together with the WrkEvent driver, to cause collisions and analyze them. See Chapter 35 of the book.
The source files for this program are located in the MemColls subdirectory of the package.

**MemTests and KrnlAllocs**

MemTests can be used to perform a number of test calls to memory management APIs and has been used for many experiments described in the book.
This program also allows to experiment (at one's own risk) with kernel mode DDIs for memory management, by means of the companion KrnlAllocs kernel mode driver. The System range tests submenu includes options to load and unload the driver and to call DDIs through it.
The source files for these programs are located under the MemTests directory of the package. MemTests\Memtests contains the program source and MemTests\KrnlAllocs the driver one.

**WrkEvent and WrkEvClient**

WrkEvent is a kernel mode driver which allocates synchronization objects used in the in-paging collision tests. It is meant to be used in conjunction with MemColls to experiment on the concepts explained in Chapter 35 of the book.
WrkEvClient is a user mode program used to load/unload the driver and call its functions.
The source files for these programs can be found in the WorkEvent\Driver and WorkEvent\Client directories.
