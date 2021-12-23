#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <string>
#include <vector>
#include <atlstr.h>
#include <Psapi.h>
#include <TlHelp32.h>

#include "detours.h"
#include "NtConsts.h"
#include "NtEnums.h"
#include "NtStructs.h"
#include "NtTypedefs.h"
#include "Controllers\\NativeAPI.h"
#include "Controllers\\ProcessAccess.h"

#ifdef _WIN64
#pragma comment(lib, "lib\\detours.x64.lib")
#else
#pragma comment(lib, "lib\\detours.x32.lib")
#endif

static auto ntapi = NtApi::GetInstance();
static auto access = ProcessAccess::GetInstance();