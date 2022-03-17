// WrkEvClient.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include "WrkEvClient.h"

int main(){
	wprintf(L"\nWrkEvent client,compiled %S %S\n\n", __DATE__, __TIME__);
	bool bEndLoop = false;
	DWORD error = ERROR_SUCCESS;
	WCHAR cmd;

	wprintf(L"\n\nCAUTION!!!\n");
	wprintf(L"\nThis program is about to load the WrkEvent.sys driver,\
		which works ONLY");
	wprintf(L"\non Windows 7 x64 RTM (pre-SP1).");
	wprintf(L"\n\nThis driver WILL CRASH THE SYSTEM on any\
		other version of Windows.");
	do
	{
		wprintf(L"\n\nContinue (y/n)?");
		cmd = getwchar();
		wprintf(L"%c", cmd);
		if (cmd == 'y') break;
		if (cmd == 'n') return ERROR_CANCELLED;
	} while ((cmd != L'y') && (cmd != L'n'));

	wprintf(L"\nLoading the driver...");
	if (!LoadDriver()) {
		error = GetLastError();
		wprintf(L"\nDriver load failed,attempting cleanup...");
		if (!UnloadDriver()) {
			wprintf(L"\nCleanup failed");
		}
		else {
			wprintf(L"\nCleanup succeeded");
		}
		return error;
	}
	wprintf(L"\nDriver load succeeded");
	do
	{
		PrintFunctions();
		cmd = getwchar();
		switch (cmd)
		{
		case CLTFUN_CLEAR_EVENT:
			ClearEvent();
			break;
		case CLTFUN_PRINT_ADDRESSES:
			PrintObjAddresses();
			break;
		case CLTFUN_SIGNAL_EVENT:
			SignalEvent();
			break;
		case CLTFUN_SIGNAL_GATE:
			SignalGate();
			break;
		case CLTFUN_QUIT:
			bEndLoop = TRUE;
			break;
		default:
			wprintf(L"\nInvalid command: %c", cmd);
			break;
		}
	} while (!bEndLoop);

	wprintf(L"\nUnloading the driver...");
	if (!UnloadDriver())
		return GetLastError();
	wprintf(L"\nDriver unload succeeded");
	return ERROR_SUCCESS;
}

int ClearEvent() {
	DWORD error;
	HANDLE hDevice = INVALID_HANDLE_VALUE;

	int index;
	wprintf(L"\nEnter event index: ");
	if (!wscanf_s(L"%u", &index)) {
		wprintf(L"\nInvalid index");
		// drain the standard input
		while (getwc(stdin) != L'\n'){}
		return ERROR_INVALID_PARAMETER;
	}
	wprintf(L"\nClearing event: %d", index);
	hDevice = OpenWeDevice();
	if (hDevice == INVALID_HANDLE_VALUE)
		return GetLastError();
	do
	{
		if (!SendIoCtl(hDevice,
			IOCTL_WRKEVENT_CLEAR_EVENT,
			&index,
			sizeof index,
			nullptr,
			0)) {
			error = GetLastError();
			break;
		}
		wprintf(L"\nEvent cleared");
		error = ERROR_SUCCESS;
	} while (false);
	
	if (hDevice != INVALID_HANDLE_VALUE)
		::CloseHandle(hDevice);
	return error;
}

bool LoadDriver() {
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
		DWORD nameLen = GetFullPathName(DRIVER_NAME, len,
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

HANDLE OpenWeDevice() {
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

void PrintFunctions() {
	wprintf(L"\n\n");
	wprintf(L"\n%c - Print objects addresses", CLTFUN_PRINT_ADDRESSES);
	wprintf(L"\n%c - Set event", CLTFUN_SIGNAL_EVENT);
	wprintf(L"\n%c - Clear event", CLTFUN_CLEAR_EVENT);
	wprintf(L"\n%c - Signal gate", CLTFUN_SIGNAL_GATE);
	wprintf(L"\n%c - Quit", CLTFUN_QUIT);
	wprintf(L"\n\n");
}

int PrintObjAddresses() {
	DWORD error;
	HANDLE hDevice = INVALID_HANDLE_VALUE;

	hDevice = OpenWeDevice();
	if (hDevice == INVALID_HANDLE_VALUE)
		return GetLastError();

	do
	{
		if (!SendIoCtl(
			hDevice,
			IOCTL_WRKEVENT_PRINT_OBJ_ADDRS,
			nullptr,0,
			nullptr,0
		)) {
			error = GetLastError();
			break;
		}
		wprintf(L"\nAddress printed to the debugger console");
		error = ERROR_SUCCESS;
	} while (false);
	
	if (hDevice != INVALID_HANDLE_VALUE)
		::CloseHandle(hDevice);
	return error;
}

int SignalEvent() {
	DWORD error;
	HANDLE hDevice = INVALID_HANDLE_VALUE;

	int index = 0;
	wprintf(L"\nEnter event index: ");
	if (!wscanf_s(L"%u", &index)) {
		wprintf(L"\nInvalid index");

		while(getwc(stdin)!=L'\n'){}
		return ERROR_INVALID_PARAMETER;
	}
	wprintf(L"\nSignaling event %d", index);
	hDevice = OpenWeDevice();
	if (hDevice == INVALID_HANDLE_VALUE) {
		error = GetLastError();
		wprintf(L"\nSignalEvent(): device open failed");
		return error;
	}
	do
	{
		if (!SendIoCtl(hDevice,
			IOCTL_WRKEVENT_SIGNAL_EVENT,
			&index,
			sizeof index,
			nullptr,
			0)) {
			error = GetLastError();
			wprintf(L"\nSignalEvent(): device ioctl failed");
			break;
		}
		wprintf(L"\nEvent signaled");
		error = ERROR_SUCCESS;
	} while (false);

	if (hDevice != INVALID_HANDLE_VALUE)
		::CloseHandle(hDevice);
	return error;
}

int SignalGate() {
	DWORD error;
	HANDLE hDevice = INVALID_HANDLE_VALUE;

	wprintf(L"\nSignaling the gate");
	hDevice = OpenWeDevice();
	if (hDevice == INVALID_HANDLE_VALUE) {
		error = GetLastError();
		wprintf(L"\nSignalGate(): device open failed");
		return error;
	}
	do
	{
		if (!SendIoCtl(hDevice,
			IOCTL_WRKEVENT_SIGNAL_GATE,
			nullptr, 0, nullptr, 0)) {
			error = GetLastError();
			wprintf(L"\nSignalGate(): device ioctl failed");
			break;
		}
		wprintf(L"\nGate signaled");
		error = ERROR_SUCCESS;
	} while (false);

	if (hDevice != INVALID_HANDLE_VALUE)
		::CloseHandle(hDevice);
	return error;
}

bool UnloadDriver() {
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

bool SendIoCtl(HANDLE hDevice, int code, LPVOID inBuffer,
	int inSize, LPVOID outBuffer, int outSize) {
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