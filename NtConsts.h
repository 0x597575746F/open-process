#pragma once
namespace G {
	static const uint32_t NtDll = 0x16E0FFAF;
	enum NtApiHash : uint32_t {
		NtReadVirtualMemory = 0x916FC82,
		NtWriteVirtualMemory = 0x685A225D,
		NtTerminateProcess = 0x676A7ABE,
		RtlAddVectoredExceptionHandler = 0x6FDBAF38,
		RtlAddVectoredContinueHandler = 0x1352820,
		RtlRemoveVectoredExceptionHandler = 0x1E84C167,
		NtOpenProcess = 0x7BF19EC8,
		NtQuerySystemInformation = 0x46ADCD47,
		NtQueryObject = 0x2634829,
		NtDuplicateObject = 0x4CD6864E,
	};
	
	constexpr uint32_t STATUS_INFO_LENGTH_MISMATCH = 0xc0000004;
	constexpr uint32_t SystemHandleInformation = 16;
	constexpr uint32_t ObjectNameInformation = 1;
	constexpr uint32_t ObjectTypeInformation = 2;
}