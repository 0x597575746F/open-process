#pragma once
namespace G {
	typedef LONG NTSTATUS;

	typedef NTSTATUS(NTAPI* fnNtQuerySystemInformation)(DWORD SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
	typedef NTSTATUS(NTAPI* fnNtQueryObject)(HANDLE ObjectHandle, DWORD ObjectInformationClass, PVOID ObjectInformation, ULONG Length, PULONG ResultLength);
	typedef NTSTATUS(NTAPI* fnNtDuplicateObject)(HANDLE SourceProcessHandle, HANDLE SourceHandle, HANDLE TargetProcessHandle, PHANDLE TargetHandle, ACCESS_MASK DesiredAccess, BOOLEAN InheritHandle, ULONG Options);
	typedef NTSTATUS(NTAPI* fnNtOpenProcess)(PHANDLE ProcessHandle, ACCESS_MASK AccessMask, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ProcessId);
}
#ifndef NT_FAIL
#define NT_FAIL(status) (status < 0)
#endif

#ifndef NT_SUCCESS
#define NT_SUCCESS(status) (status >= 0)
#endif
