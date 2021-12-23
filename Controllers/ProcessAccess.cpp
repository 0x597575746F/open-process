#include "../stdafx.h"
struct HandleInformation{
};

auto ProcessAccess::EnumerateCSRSSProcess() -> std::vector<HANDLE>{
	std::vector<HANDLE> ret;
	HANDLE hProcessSnap;
	PROCESSENTRY32 pe32;

	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE)
		return ret;

	pe32.dwSize = sizeof(PROCESSENTRY32);
	if (!Process32First(hProcessSnap, &pe32)){
		CloseHandle(hProcessSnap);
		return ret;
	}

	do{
		if (wcsicmp(pe32.szExeFile, L"csrss.exe") == 0) {
			HANDLE hProc = ntapi->NtOpenProcess(pe32.th32ProcessID, FALSE, PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION);
			ret.push_back(hProc);
		}

	} while (Process32Next(hProcessSnap, &pe32));

	CloseHandle(hProcessSnap);
	return ret;
}

auto ProcessAccess::EnumerateSystemHandles(G::OBJECT_TYPE_NUMBER type, const std::vector<HANDLE>& srcproc_filter) -> std::vector<G::SYSTEM_HANDLE> {
	std::vector<G::SYSTEM_HANDLE> ret;
	ULONG SystemHandleSize = 0x15000;
	CHAR* SystemHandleBuffer = 0;
	G::NTSTATUS ntRet = 0;

	do {
		if (SystemHandleBuffer) {
			delete[] SystemHandleBuffer;
			SystemHandleBuffer = 0;
		}

		SystemHandleBuffer = new char[SystemHandleSize];
		ntRet = ntapi->NtQuerySystemInformation(G::SystemHandleInformation, SystemHandleBuffer, SystemHandleSize, &SystemHandleSize);
	} while (ntRet == G::STATUS_INFO_LENGTH_MISMATCH);

	auto* handles = reinterpret_cast<G::SYSTEM_HANDLE_INFORMATION*>(SystemHandleBuffer)->Handles;
	auto count = reinterpret_cast<G::SYSTEM_HANDLE_INFORMATION*>(SystemHandleBuffer)->HandleCount;

	for (ULONG i = 0; i < count; i++) {
		for (auto process : srcproc_filter)
		if (handles[i].ObjectTypeNumber == type && handles[i].ProcessId == GetProcessId(process))
			ret.push_back(handles[i]);
	}

	delete[] SystemHandleBuffer;
	return ret;
}

auto ProcessAccess::FindProcessHandles(DWORD process_id) -> HANDLE{
	if (CsrssHandles.empty())
		CsrssHandles = EnumerateCSRSSProcess();


	auto handles = EnumerateSystemHandles(G::OBJECT_TYPE_Process, CsrssHandles);
	auto dup = (HANDLE)nullptr;

	for (auto handle : handles) {
		for (auto csrss : CsrssHandles) {
			if (DuplicateHandle(csrss, (HANDLE)handle.Handle, GetCurrentProcess(), &dup, PROCESS_ALL_ACCESS, 0, 0)) {
				if (GetProcessId(dup) == process_id) {
					return dup;
				}
				CloseHandle(dup);
			}
		}
	}
	return 0;
}

auto ProcessAccess::FindThreadHandles(DWORD thread_id) -> HANDLE{
	if (CsrssHandles.empty())
		CsrssHandles = EnumerateCSRSSProcess();

	auto handles = EnumerateSystemHandles(G::OBJECT_TYPE_Thread, CsrssHandles);
	auto dup = (HANDLE)nullptr;

	for (auto handle : handles) {
		for (auto csrss : CsrssHandles) {
			if (DuplicateHandle(csrss, (HANDLE)handle.Handle, GetCurrentProcess(), &dup, THREAD_ALL_ACCESS, 0, 0)) {
				if (GetThreadId(dup) == thread_id) {
					return dup;
				}
				CloseHandle(dup);
			}
		}
	}
	return 0;
}

HANDLE WINAPI ProcessAccess::CopyProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId) {
	return GetInstance()->FindProcessHandles(dwProcessId);
}

HANDLE ProcessAccess::CopyThread(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwThreadId){
	return GetInstance()->FindThreadHandles(dwThreadId);
}

auto ProcessAccess::GetInstance() -> ProcessAccess * {
	static auto instance = new ProcessAccess();
	return instance;
}

void ProcessAccess::Attach(){
	CloseHandle(CreateThread(0, 0, [](LPVOID)->DWORD {
		auto _this = GetInstance();
		_this->OldOpenProcess = OpenProcess;
		_this->OldOpenThread = OpenThread;

		(VOID)DetourTransactionBegin();
		(VOID)DetourUpdateThread(GetCurrentThread());

		(VOID)DetourAttach(&(PVOID&)_this->OldOpenProcess, CopyProcess);
		(VOID)DetourAttach(&(PVOID&)_this->OldOpenThread, CopyThread);

		(VOID)DetourTransactionCommit();
		return 0;
	}, 0, 0, 0));
}

