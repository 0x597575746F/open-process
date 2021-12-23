#pragma once
namespace G {
	typedef struct _UNICODE_STRING
	{
		WORD Length;
		WORD MaximumLength;
		WORD * Buffer;
	} UNICODE_STRING, *PUNICODE_STRING;

	typedef struct _PEB_LDR_DATA{
		ULONG Length;
		BOOLEAN Initialized;
		HANDLE SsHandle;
		LIST_ENTRY InLoadOrderModuleList;
		LIST_ENTRY InMemoryOrderModuleList;
		LIST_ENTRY InInitializationOrderModuleList;
		PVOID EntryInProgress;
		BOOLEAN ShutdownInProgress;
		HANDLE ShutdownThreadId;
	} PEB_LDR_DATA, *PPEB_LDR_DATA;

	typedef struct _RTL_DRIVE_LETTER_CURDIR{
		USHORT Flags;
		USHORT Length;
		ULONG TimeStamp;
		UNICODE_STRING DosPath;
	} RTL_DRIVE_LETTER_CURDIR, *PRTL_DRIVE_LETTER_CURDIR;

	typedef struct _CURDIR{
		UNICODE_STRING DosPath;
		HANDLE Handle;
	} CURDIR, *PCURDIR;

	typedef struct _RTL_USER_PROCESS_PARAMETERS{
		ULONG MaximumLength;
		ULONG Length;

		ULONG Flags;
		ULONG DebugFlags;

		HANDLE ConsoleHandle;
		ULONG ConsoleFlags;
		HANDLE StandardInput;
		HANDLE StandardOutput;
		HANDLE StandardError;

		CURDIR CurrentDirectory;
		UNICODE_STRING DllPath;
		UNICODE_STRING ImagePathName;
		UNICODE_STRING CommandLine;
		PWCHAR Environment;

		ULONG StartingX;
		ULONG StartingY;
		ULONG CountX;
		ULONG CountY;
		ULONG CountCharsX;
		ULONG CountCharsY;
		ULONG FillAttribute;

		ULONG WindowFlags;
		ULONG ShowWindowFlags;
		UNICODE_STRING WindowTitle;
		UNICODE_STRING DesktopInfo;
		UNICODE_STRING ShellInfo;
		UNICODE_STRING RuntimeData;
		RTL_DRIVE_LETTER_CURDIR CurrentDirectories[32];

		ULONG_PTR EnvironmentSize;
		ULONG_PTR EnvironmentVersion;
		PVOID PackageDependencyData;
		ULONG ProcessGroupId;
		ULONG LoaderThreads;
	} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

	typedef ULONG GDI_HANDLE_BUFFER32[34];
	typedef ULONG GDI_HANDLE_BUFFER64[60];
#ifndef _WIN64
	typedef ULONG GDI_HANDLE_BUFFER[34];
#else
	typedef ULONG GDI_HANDLE_BUFFER[60];
#endif

	typedef struct _PEB{
		BOOLEAN InheritedAddressSpace;
		BOOLEAN ReadImageFileExecOptions;
		BOOLEAN BeingDebugged;
		union
		{
			BOOLEAN BitField;
			struct
			{
				BOOLEAN ImageUsesLargePages : 1;
				BOOLEAN IsProtectedProcess : 1;
				BOOLEAN IsImageDynamicallyRelocated : 1;
				BOOLEAN SkipPatchingUser32Forwarders : 1;
				BOOLEAN IsPackagedProcess : 1;
				BOOLEAN IsAppContainer : 1;
				BOOLEAN IsProtectedProcessLight : 1;
				BOOLEAN IsLongPathAwareProcess : 1;
			} s1;
		} u1;

		HANDLE Mutant;

		PVOID ImageBaseAddress;
		PPEB_LDR_DATA Ldr;
		PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
		PVOID SubSystemData;
		PVOID ProcessHeap;
		PRTL_CRITICAL_SECTION FastPebLock;
		PVOID AtlThunkSListPtr;
		PVOID IFEOKey;
		union
		{
			ULONG CrossProcessFlags;
			struct
			{
				ULONG ProcessInJob : 1;
				ULONG ProcessInitializing : 1;
				ULONG ProcessUsingVEH : 1;
				ULONG ProcessUsingVCH : 1;
				ULONG ProcessUsingFTH : 1;
				ULONG ProcessPreviouslyThrottled : 1;
				ULONG ProcessCurrentlyThrottled : 1;
				ULONG ReservedBits0 : 25;
			} s2;
		} u2;
		union
		{
			PVOID KernelCallbackTable;
			PVOID UserSharedInfoPtr;
		} u3;
		ULONG SystemReserved[1];
		ULONG AtlThunkSListPtr32;
		PVOID ApiSetMap;
		ULONG TlsExpansionCounter;
		PVOID TlsBitmap;
		ULONG TlsBitmapBits[2];

		PVOID ReadOnlySharedMemoryBase;
		PVOID SharedData; // HotpatchInformation
		PVOID* ReadOnlyStaticServerData;

		PVOID AnsiCodePageData; // PCPTABLEINFO
		PVOID OemCodePageData; // PCPTABLEINFO
		PVOID UnicodeCaseTableData; // PNLSTABLEINFO

		ULONG NumberOfProcessors;
		ULONG NtGlobalFlag;

		LARGE_INTEGER CriticalSectionTimeout;
		SIZE_T HeapSegmentReserve;
		SIZE_T HeapSegmentCommit;
		SIZE_T HeapDeCommitTotalFreeThreshold;
		SIZE_T HeapDeCommitFreeBlockThreshold;

		ULONG NumberOfHeaps;
		ULONG MaximumNumberOfHeaps;
		PVOID* ProcessHeaps; // PHEAP

		PVOID GdiSharedHandleTable;
		PVOID ProcessStarterHelper;
		ULONG GdiDCAttributeList;

		PRTL_CRITICAL_SECTION LoaderLock;

		ULONG OSMajorVersion;
		ULONG OSMinorVersion;
		USHORT OSBuildNumber;
		USHORT OSCSDVersion;
		ULONG OSPlatformId;
		ULONG ImageSubsystem;
		ULONG ImageSubsystemMajorVersion;
		ULONG ImageSubsystemMinorVersion;
		ULONG_PTR ActiveProcessAffinityMask;
		GDI_HANDLE_BUFFER GdiHandleBuffer;
		PVOID PostProcessInitRoutine;

		PVOID TlsExpansionBitmap;
		ULONG TlsExpansionBitmapBits[32];

		ULONG SessionId;

		ULARGE_INTEGER AppCompatFlags;
		ULARGE_INTEGER AppCompatFlagsUser;
		PVOID pShimData;
		PVOID AppCompatInfo; // APPCOMPAT_EXE_DATA

		UNICODE_STRING CSDVersion;

		PVOID ActivationContextData; // ACTIVATION_CONTEXT_DATA
		PVOID ProcessAssemblyStorageMap; // ASSEMBLY_STORAGE_MAP
		PVOID SystemDefaultActivationContextData; // ACTIVATION_CONTEXT_DATA
		PVOID SystemAssemblyStorageMap; // ASSEMBLY_STORAGE_MAP

		SIZE_T MinimumStackCommit;

		PVOID* FlsCallback;
		LIST_ENTRY FlsListHead;
		PVOID FlsBitmap;
		ULONG FlsBitmapBits[FLS_MAXIMUM_AVAILABLE / (sizeof(ULONG) * 8)];
		ULONG FlsHighIndex;

		PVOID WerRegistrationData;
		PVOID WerShipAssertPtr;
		PVOID pUnused; // pContextData
		PVOID pImageHeaderHash;
		union
		{
			ULONG TracingFlags;
			struct
			{
				ULONG HeapTracingEnabled : 1;
				ULONG CritSecTracingEnabled : 1;
				ULONG LibLoaderTracingEnabled : 1;
				ULONG SpareTracingBits : 29;
			} s3;
		} u4;
		ULONGLONG CsrServerReadOnlySharedMemoryBase;
		PVOID TppWorkerpListLock;
		LIST_ENTRY TppWorkerpList;
		PVOID WaitOnAddressHashTable[128];
		PVOID TelemetryCoverageHeader; // REDSTONE3
		ULONG CloudFileFlags;
	} PEB, *PPEB;

	typedef struct _RTL_BALANCED_NODE{
		union{
			struct _RTL_BALANCED_NODE* Children[2];
			struct{
				struct _RTL_BALANCED_NODE* Left;
				struct _RTL_BALANCED_NODE* Right;
			} s;
		};
		union{
			UCHAR Red : 1;
			UCHAR Balance : 2;
			ULONG_PTR ParentValue;
		} u;
	} RTL_BALANCED_NODE, *PRTL_BALANCED_NODE;

	typedef struct _LDR_SERVICE_TAG_RECORD{
		struct _LDR_SERVICE_TAG_RECORD* Next;
		ULONG ServiceTag;
	} LDR_SERVICE_TAG_RECORD, *PLDR_SERVICE_TAG_RECORD;

	typedef struct _LDRP_CSLIST {
		PSINGLE_LIST_ENTRY Tail;
	} LDRP_CSLIST, *PLDRP_CSLIST;

	typedef struct _LDR_DDAG_NODE {
		LIST_ENTRY Modules;
		PLDR_SERVICE_TAG_RECORD ServiceTagList;
		ULONG LoadCount;
		ULONG LoadWhileUnloadingCount;
		ULONG LowestLink;
		union
		{
			LDRP_CSLIST Dependencies;
			SINGLE_LIST_ENTRY RemovalLink;
		};
		LDRP_CSLIST IncomingDependencies;
		LDR_DDAG_STATE State;
		SINGLE_LIST_ENTRY CondenseLink;
		ULONG PreorderNumber;
	} LDR_DDAG_NODE, *PLDR_DDAG_NODE;

	typedef struct _LDR_DATA_TABLE_ENTRY {
		LIST_ENTRY InLoadOrderLinks;
		LIST_ENTRY InMemoryOrderLinks;
		union {
			LIST_ENTRY InInitializationOrderLinks;
			LIST_ENTRY InProgressLinks;
		};
		PVOID DllBase;
		PVOID EntryPoint;
		ULONG SizeOfImage;
		UNICODE_STRING FullDllName;
		UNICODE_STRING BaseDllName;
		union{
			UCHAR FlagGroup[4];
			ULONG Flags;
			struct{
				ULONG PackagedBinary : 1;
				ULONG MarkedForRemoval : 1;
				ULONG ImageDll : 1;
				ULONG LoadNotificationsSent : 1;
				ULONG TelemetryEntryProcessed : 1;
				ULONG ProcessStaticImport : 1;
				ULONG InLegacyLists : 1;
				ULONG InIndexes : 1;
				ULONG ShimDll : 1;
				ULONG InExceptionTable : 1;
				ULONG ReservedFlags1 : 2;
				ULONG LoadInProgress : 1;
				ULONG LoadConfigProcessed : 1;
				ULONG EntryProcessed : 1;
				ULONG ProtectDelayLoad : 1;
				ULONG ReservedFlags3 : 2;
				ULONG DontCallForThreads : 1;
				ULONG ProcessAttachCalled : 1;
				ULONG ProcessAttachFailed : 1;
				ULONG CorDeferredValidate : 1;
				ULONG CorImage : 1;
				ULONG DontRelocate : 1;
				ULONG CorILOnly : 1;
				ULONG ReservedFlags5 : 3;
				ULONG Redirected : 1;
				ULONG ReservedFlags6 : 2;
				ULONG CompatDatabaseProcessed : 1;
			} s;
		} u;
		USHORT ObsoleteLoadCount;
		USHORT TlsIndex;
		LIST_ENTRY HashLinks;
		ULONG TimeDateStamp;
		struct _ACTIVATION_CONTEXT* EntryPointActivationContext;
		PVOID Lock;
		PLDR_DDAG_NODE DdagNode;
		LIST_ENTRY NodeModuleLink;
		struct _LDRP_LOAD_CONTEXT* LoadContext;
		PVOID ParentDllBase;
		PVOID SwitchBackContext;
		RTL_BALANCED_NODE BaseAddressIndexNode;
		RTL_BALANCED_NODE MappingInfoIndexNode;
		ULONG_PTR OriginalBase;
		LARGE_INTEGER LoadTime;
		ULONG BaseNameHashValue;
		LDR_DLL_LOAD_REASON LoadReason;
		ULONG ImplicitPathOptions;
		ULONG ReferenceCount;
		ULONG DependentLoadFlags;
		UCHAR SigningLevel;
	} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

	typedef struct _SYSTEM_HANDLE{
		ULONG ProcessId;
		BYTE ObjectTypeNumber;
		BYTE Flags;
		USHORT Handle;
		PVOID Object;
		ACCESS_MASK GrantedAccess;
	} SYSTEM_HANDLE, *PSYSTEM_HANDLE;

	typedef struct _SYSTEM_HANDLE_INFORMATION{
		ULONG HandleCount;
		SYSTEM_HANDLE Handles[1];
	} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

	typedef struct _OBJECT_TYPE_INFORMATION{
		UNICODE_STRING Name;
		ULONG TotalNumberOfObjects;
		ULONG TotalNumberOfHandles;
		ULONG TotalPagedPoolUsage;
		ULONG TotalNonPagedPoolUsage;
		ULONG TotalNamePoolUsage;
		ULONG TotalHandleTableUsage;
		ULONG HighWaterNumberOfObjects;
		ULONG HighWaterNumberOfHandles;
		ULONG HighWaterPagedPoolUsage;
		ULONG HighWaterNonPagedPoolUsage;
		ULONG HighWaterNamePoolUsage;
		ULONG HighWaterHandleTableUsage;
		ULONG InvalidAttributes;
		GENERIC_MAPPING GenericMapping;
		ULONG ValidAccess;
		BOOLEAN SecurityRequired;
		BOOLEAN MaintainHandleCount;
		USHORT MaintainTypeList;
		POOL_TYPE PoolType;
		ULONG PagedPoolUsage;
		ULONG NonPagedPoolUsage;
	} OBJECT_TYPE_INFORMATION, *POBJECT_TYPE_INFORMATION;

	typedef struct _OBJECT_ATTRIBUTES {
		ULONG           Length;
		HANDLE          RootDirectory;
		PUNICODE_STRING ObjectName;
		ULONG           Attributes;
		PVOID           SecurityDescriptor;
		PVOID           SecurityQualityOfService;
	} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

	typedef struct _CLIENT_ID {
		PVOID UniqueProcess;
		PVOID UniqueThread;
	} CLIENT_ID, *PCLIENT_ID;
}