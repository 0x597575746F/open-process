#pragma once
class NtApi {
	auto RtlOffsetToPointer(HMODULE Module, uintptr_t Pointer)->uintptr_t;
	auto Hash(PCHAR Input)->uint32_t;
	auto GetPEB()->G::PPEB;
	auto GetLDREntry(DWORD hash)->G::PLDR_DATA_TABLE_ENTRY;

	HMODULE hModule = nullptr;
public:
	NtApi();
	static auto GetInstance()->NtApi*;
	auto GetProcAddress(uint32_t Hash, uint32_t DataDirectory = 0)->uintptr_t;

	G::NTSTATUS NtQuerySystemInformation(DWORD SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
	G::NTSTATUS NtQueryObject(HANDLE ObjectHandle, DWORD ObjectInformationClass, PVOID ObjectInformation, ULONG Length, PULONG ResultLength);
	G::NTSTATUS NtDuplicateObject(HANDLE SourceProcessHandle, HANDLE SourceHandle, HANDLE TargetProcessHandle, PHANDLE TargetHandle, ACCESS_MASK DesiredAccess, BOOLEAN InheritHandle, ULONG Options);
	HANDLE NtOpenProcess(DWORD ProcessId, BOOL InheritHandle, DWORD AccessRights);
};