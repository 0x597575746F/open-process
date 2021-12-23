#pragma once
namespace G {
	typedef enum _LDR_DLL_LOAD_REASON {
		LoadReasonStaticDependency,
		LoadReasonStaticForwarderDependency,
		LoadReasonDynamicForwarderDependency,
		LoadReasonDelayloadDependency,
		LoadReasonDynamicLoad,
		LoadReasonAsImageLoad,
		LoadReasonAsDataLoad,
		LoadReasonUnknown = -1
	} LDR_DLL_LOAD_REASON, *PLDR_DLL_LOAD_REASON;

	typedef enum _LDR_DDAG_STATE {
		LdrModulesMerged = -5,
		LdrModulesInitError = -4,
		LdrModulesSnapError = -3,
		LdrModulesUnloaded = -2,
		LdrModulesUnloading = -1,
		LdrModulesPlaceHolder = 0,
		LdrModulesMapping = 1,
		LdrModulesMapped = 2,
		LdrModulesWaitingForDependencies = 3,
		LdrModulesSnapping = 4,
		LdrModulesSnapped = 5,
		LdrModulesCondensed = 6,
		LdrModulesReadyToInit = 7,
		LdrModulesInitializing = 8,
		LdrModulesReadyToRun = 9
	} LDR_DDAG_STATE, *PLDR_DDAG_STATE;

	typedef enum _POOL_TYPE{
		NonPagedPool,
		PagedPool,
		NonPagedPoolMustSucceed,
		DontUseThisType,
		NonPagedPoolCacheAligned,
		PagedPoolCacheAligned,
		NonPagedPoolCacheAlignedMustS
	} POOL_TYPE, *PPOOL_TYPE;

	typedef enum _OBJECT_TYPE_NUMBER{
		OBJECT_TYPE_Process = 0x07,
		OBJECT_TYPE_Thread = 0x08,
		OBJECT_TYPE_Mutant = 0x11,
	} OBJECT_TYPE_NUMBER;

	typedef enum _OBJECT_ATTRIBUTE_ATTRIBUTE {
		OBJ_INHERIT = 0x00000002L,
		OBJ_PERMANENT = 0x00000010L,
		OBJ_EXCLUSIVE = 0x00000020L,
		OBJ_CASE_INSENSITIVE = 0x00000040L,
		OBJ_OPENIF = 0x00000080L,
		OBJ_OPENLINK = 0x00000100L,
		OBJ_VALID_ATTRIBUTES = 0x000001F2L,
	} OBJECT_ATTRIBUTE_ATTRIBUTE, *POBJECT_ATTRIBUTE_ATTRIBUTE;


}