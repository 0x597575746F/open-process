#include "../stdafx.h"

NtApi::NtApi() {
	this->hModule = (HMODULE)GetLDREntry(G::NtDll)->DllBase;
}

auto NtApi::GetInstance() -> NtApi * {
	static auto instance = new NtApi();
	return instance;
}

G::PPEB NtApi::GetPEB() {
#ifdef _WIN64
	auto peb = (G::PPEB)__readgsqword(0x60);

#else
	G::PPEB peb = (G::PPEB)__readfsdword(0x30);
#endif

	return peb;
}

G::PLDR_DATA_TABLE_ENTRY NtApi::GetLDREntry(DWORD hash) {
	G::LDR_DATA_TABLE_ENTRY *ldr = NULL;

	G::PPEB peb = GetPEB();
	LIST_ENTRY head = peb->Ldr->InMemoryOrderModuleList;
	LIST_ENTRY curr = head;

	while (curr.Flink != head.Blink) {
		G::LDR_DATA_TABLE_ENTRY *mod = (G::LDR_DATA_TABLE_ENTRY *)CONTAINING_RECORD(curr.Flink, G::LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
		if (mod->FullDllName.Buffer) {

			auto temp = std::wstring((wchar_t*)mod->BaseDllName.Buffer, mod->BaseDllName.Length);
			auto name = std::string(CW2A(temp.c_str()));

			if (hash == Hash((PCHAR)name.c_str())) {
				ldr = mod;
				break;
			}
		}
		curr = *curr.Flink;
	}
	return ldr;
}

auto NtApi::GetProcAddress(uint32_t Hash, uint32_t DataDirectory) -> uintptr_t {
	PIMAGE_DOS_HEADER ImageDosHeader = PIMAGE_DOS_HEADER(hModule);
	if (ImageDosHeader->e_magic == IMAGE_DOS_SIGNATURE) {
		PIMAGE_NT_HEADERS pNtHeaders = PIMAGE_NT_HEADERS(RtlOffsetToPointer(hModule, ImageDosHeader->e_lfanew));
		if (pNtHeaders->Signature == IMAGE_NT_SIGNATURE) {
			if (pNtHeaders->OptionalHeader.DataDirectory[DataDirectory].VirtualAddress && DataDirectory < pNtHeaders->OptionalHeader.NumberOfRvaAndSizes) {
				PIMAGE_EXPORT_DIRECTORY pImageExport = PIMAGE_EXPORT_DIRECTORY(PBYTE(RtlOffsetToPointer(hModule, pNtHeaders->OptionalHeader.DataDirectory[DataDirectory].VirtualAddress)));
				if (pImageExport != ERROR) {
					PDWORD pAddrOfNames = PDWORD(RtlOffsetToPointer(hModule, pImageExport->AddressOfNames));
					for (DWORD n = NULL; n < pImageExport->NumberOfNames; ++n) {
						LPSTR Function = LPSTR(RtlOffsetToPointer(hModule, pAddrOfNames[n]));
						if (this->Hash(Function) == Hash) {
							PDWORD AddrOfFunction = PDWORD(RtlOffsetToPointer(hModule, pImageExport->AddressOfFunctions));
							PWORD AddrOfOrdinal = PWORD(RtlOffsetToPointer(hModule, pImageExport->AddressOfNameOrdinals));
							return RtlOffsetToPointer(hModule, AddrOfFunction[AddrOfOrdinal[n]]);
						}
					}
				}
			}
		}
	}
	return ERROR;
}

G::NTSTATUS NtApi::NtQuerySystemInformation(DWORD SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength) {
	static G::fnNtQuerySystemInformation function = reinterpret_cast<G::fnNtQuerySystemInformation>(GetProcAddress(G::NtQuerySystemInformation));
	return function(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
}

G::NTSTATUS NtApi::NtQueryObject(HANDLE ObjectHandle, DWORD ObjectInformationClass, PVOID ObjectInformation, ULONG Length, PULONG ResultLength) {
	static G::fnNtQueryObject function = reinterpret_cast<G::fnNtQueryObject>(GetProcAddress(G::NtQueryObject));
	return function(ObjectHandle, ObjectInformationClass, ObjectInformation, Length, ResultLength);
}

G::NTSTATUS NtApi::NtDuplicateObject(HANDLE SourceProcessHandle, HANDLE SourceHandle, HANDLE TargetProcessHandle, PHANDLE TargetHandle, ACCESS_MASK DesiredAccess, BOOLEAN InheritHandle, ULONG Options) {
	static G::fnNtDuplicateObject function = reinterpret_cast<G::fnNtDuplicateObject>(GetProcAddress(G::NtDuplicateObject));
	return function(SourceProcessHandle, SourceHandle, TargetProcessHandle, TargetHandle, DesiredAccess, InheritHandle, Options);
}

HANDLE NtApi::NtOpenProcess(DWORD ProcessId, BOOL InheritHandle, DWORD AccessRights){
	static G::fnNtOpenProcess function = reinterpret_cast<G::fnNtOpenProcess>(GetProcAddress(G::NtOpenProcess));
	HANDLE hProcess = NULL;
	DWORD dwProcessId = ProcessId;

	G::OBJECT_ATTRIBUTES object_attributes = { 0 };
	object_attributes.Length = sizeof(object_attributes);
	object_attributes.Attributes = InheritHandle ? G::OBJ_INHERIT : 0;

	G::CLIENT_ID client_id = { 0 };
	client_id.UniqueProcess = (PVOID)ProcessId;

	G::NTSTATUS result = function(&hProcess, AccessRights, &object_attributes, &client_id);

	if (NT_SUCCESS(result))
		return hProcess;
	else
		return NULL;
}

auto NtApi::RtlOffsetToPointer(HMODULE Module, uintptr_t Pointer) -> uintptr_t {
	return uintptr_t(Module) + Pointer;
}

auto NtApi::Hash(PCHAR Input) -> uint32_t {
	INT Counter = NULL;
	UINT Hash = 0, N = 0;
	while ((Counter = *Input++)) {
		Hash ^= ((N++ & 1) == NULL) ? ((Hash << 5) ^ Counter ^ (Hash >> 1)) : (~((Hash << 9) ^ Counter ^ (Hash >> 3)));
	}
	return (Hash & 0x7FFFFFFF);
}