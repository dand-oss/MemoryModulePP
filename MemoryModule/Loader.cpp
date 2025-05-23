#include "stdafx.h"
#include <cmath>
#include <iostream>
#include <format>

// NEW: Include for resource usage
#include <psapi.h>

NTSTATUS NTAPI LdrMapDllMemory(
	_In_ HMEMORYMODULE ViewBase,
	_In_ DWORD dwFlags,
	_In_opt_ PCWSTR DllName,
	_In_opt_ PCWSTR lpFullDllName,
	_Out_opt_ PLDR_DATA_TABLE_ENTRY* DataTableEntry) {

	UNICODE_STRING FullDllName, BaseDllName;
	PIMAGE_NT_HEADERS NtHeaders;
	PLDR_DATA_TABLE_ENTRY LdrEntry;
	HANDLE heap = NtCurrentPeb()->ProcessHeap;

	if (!(NtHeaders = RtlImageNtHeader(ViewBase))) return STATUS_INVALID_IMAGE_FORMAT;

	if (!(LdrEntry = RtlAllocateDataTableEntry(ViewBase))) return STATUS_NO_MEMORY;

	if (!NT_SUCCESS(RtlResolveDllNameUnicodeString(DllName, lpFullDllName, &BaseDllName, &FullDllName))) {
		RtlFreeHeap(heap, 0, LdrEntry);
		return STATUS_NO_MEMORY;
	}

	if (!RtlInitializeLdrDataTableEntry(LdrEntry, dwFlags, ViewBase, BaseDllName, FullDllName)) {
		RtlFreeHeap(heap, 0, LdrEntry);
		RtlFreeHeap(heap, 0, BaseDllName.Buffer);
		RtlFreeHeap(heap, 0, FullDllName.Buffer);
		return STATUS_UNSUCCESSFUL;
	}

	RtlInsertMemoryTableEntry(LdrEntry);
	if (DataTableEntry) *DataTableEntry = LdrEntry;
	return STATUS_SUCCESS;
}

// NEW: Log with timestamp
static void LogWithTimestamp(const std::wstring& message) {
    SYSTEMTIME st;
    GetSystemTime(&st);
    std::wcerr << std::format(L"[{:%Y-%m-%d %H:%M:%S}.{:03}] {}\n",
                              st, st.wMilliseconds, message);
}

// NEW: Log resource usage
static void LogResourceUsage(const std::wstring& dllName, size_t bufferSize, HMEMORYMODULE baseAddress) {
    MEMORYSTATUSEX memStatus = { sizeof(memStatus) };
    GlobalMemoryStatusEx(&memStatus);
    PROCESS_MEMORY_COUNTERS pmc = { sizeof(pmc) };
    GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc));
    
    LogWithTimestamp(std::format(L"Resource usage for {}:", dllName));
    LogWithTimestamp(std::format(L"  Buffer Size: {} bytes", bufferSize));
    LogWithTimestamp(std::format(L"  Base Address: {:#x}", reinterpret_cast<uintptr_t>(baseAddress)));
    LogWithTimestamp(std::format(L"  Available Virtual Memory: {} MB", memStatus.ullAvailVirtual / (1024 * 1024)));
    LogWithTimestamp(std::format(L"  Process Working Set: {} MB", pmc.WorkingSetSize / (1024 * 1024)));
}

// Helper function to perform SEH-protected checks without C++ unwinding
static NTSTATUS CheckImageAndGlobalData(
    _In_ LPVOID BufferAddress,
    _Inout_ size_t* BufferSize,
    _In_ DWORD dwFlags,
    _In_ PMMP_GLOBAL_DATA MmpGlobalDataPtr,
    _Out_ HMEMORYMODULE* BaseAddress,
    _Out_opt_ PVOID* LdrEntry) {
    NTSTATUS status = STATUS_SUCCESS;

    __try {
        *BaseAddress = nullptr;
        if (LdrEntry) *LdrEntry = nullptr;

        if (!RtlIsValidImageBuffer(BufferAddress, BufferSize) && !(dwFlags & LOAD_FLAGS_PASS_IMAGE_CHECK)) {
            status = STATUS_INVALID_IMAGE_FORMAT;
        }
        else if (MmpGlobalDataPtr == nullptr) {
            status = STATUS_INVALID_PARAMETER;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }

    return status;
}

extern "C" NTSTATUS NTAPI LdrLoadDllMemoryExW(
	_Out_ HMEMORYMODULE* BaseAddress,
	_Out_opt_ PVOID* LdrEntry,
	_In_ DWORD dwFlags,
	_In_ LPVOID BufferAddress,
	_In_ size_t BufferSize,
	_In_opt_ LPCWSTR DllName,
	_In_opt_ LPCWSTR DllFullName) {
	PMEMORYMODULE module = nullptr;
	NTSTATUS status = STATUS_SUCCESS;
	PLDR_DATA_TABLE_ENTRY ModuleEntry = nullptr;
	PIMAGE_NT_HEADERS headers = nullptr;

	std::wstring logDllName = DllName ? DllName : L"unknown";
	LogWithTimestamp(std::format(L"Starting LdrLoadDllMemoryExW for {}", logDllName));

	// Skip TLS handling for dstng_firebird_d.dll to test
	if (DllName && wcscmp(DllName, L"dstng_firebird_d.dll") == 0) {
		dwFlags |= LOAD_FLAGS_NOT_HANDLE_TLS;
		LogWithTimestamp(std::format(L"Skipping TLS handling for {}", DllName));
	}

	if (!BufferSize) {
		LogWithTimestamp(std::format(L"Invalid BufferSize for {}", logDllName));
		return STATUS_INVALID_PARAMETER_5;
	}

	// Perform SEH-protected checks in helper function
	status = CheckImageAndGlobalData(BufferAddress, &BufferSize, dwFlags, MmpGlobalDataPtr, BaseAddress, LdrEntry);
	if (!NT_SUCCESS(status)) {
		LogWithTimestamp(std::format(L"Initial checks failed for {} (Status: {:#x})", logDllName, status));
		return status;
	}

	if (dwFlags & LOAD_FLAGS_NOT_MAP_DLL) {
		dwFlags &= LOAD_FLAGS_NOT_MAP_DLL;
		DllName = DllFullName = nullptr;
		logDllName = L"unknown";
	}
	if (dwFlags & LOAD_FLAGS_USE_DLL_NAME && (!DllName || !DllFullName)) {
		LogWithTimestamp(std::format(L"Invalid DLL name parameters for {}", logDllName));
		return STATUS_INVALID_PARAMETER_3;
	}

	if (DllName) {
		int length = static_cast<int>(wcslen(DllName));
		PLIST_ENTRY ListHead = &NtCurrentPeb()->Ldr->InLoadOrderModuleList, ListEntry = ListHead->Flink;
		PIMAGE_NT_HEADERS h1 = RtlImageNtHeader(BufferAddress), h2 = nullptr;
		if (!h1) {
			LogWithTimestamp(std::format(L"Invalid image format for {}", logDllName));
			return STATUS_INVALID_IMAGE_FORMAT;
		}
		
		while (ListEntry != ListHead) {
			PLDR_DATA_TABLE_ENTRY CurEntry = CONTAINING_RECORD(ListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
			ListEntry = ListEntry->Flink;

			if (!CurEntry->InMemoryOrderLinks.Flink) continue;

			auto dist = (CurEntry->BaseDllName.Length / sizeof(wchar_t)) - length;
			bool equal = false;
			if (!(dist == 0 || dist == 4)) continue;
			equal = !_wcsnicmp(DllName, CurEntry->BaseDllName.Buffer, length);
			
			if (equal) {
				if (!(h2 = RtlImageNtHeader(CurEntry->DllBase))) continue;
				if (!(module = MapMemoryModuleHandle(static_cast<HMEMORYMODULE>(CurEntry->DllBase)))) continue;
				if ((h1->OptionalHeader.SizeOfCode == h2->OptionalHeader.SizeOfCode) &&
					(h1->OptionalHeader.SizeOfHeaders == h2->OptionalHeader.SizeOfHeaders)) {
					if (!module->UseReferenceCount || dwFlags & LOAD_FLAGS_NOT_USE_REFERENCE_COUNT) {
						LogWithTimestamp(std::format(L"Reference count error for {}", logDllName));
						return STATUS_INVALID_PARAMETER_3;
					}
					
					RtlUpdateReferenceCount(module, FLAG_REFERENCE);
					*BaseAddress = static_cast<HMEMORYMODULE>(CurEntry->DllBase);
					if (LdrEntry) *LdrEntry = CurEntry;
					LogWithTimestamp(std::format(L"Found existing module for {} at {:#x}", logDllName, reinterpret_cast<uintptr_t>(*BaseAddress)));
					return STATUS_SUCCESS;
				}
			}
		}
	}

	LogWithTimestamp(std::format(L"Calling MemoryLoadLibrary for {}", logDllName));
	// NEW: Log input and output addresses
	HMEMORYMODULE prevBaseAddress = *BaseAddress;
	status = MemoryLoadLibrary(BaseAddress, BufferAddress, static_cast<DWORD>(BufferSize));
	if (!NT_SUCCESS(status) || status == STATUS_IMAGE_MACHINE_TYPE_MISMATCH) {
		LogWithTimestamp(std::format(L"MemoryLoadLibrary failed for {} (Status: {:#x})", logDllName, status));
		LogResourceUsage(logDllName, BufferSize, *BaseAddress);
		return status;
	}
	if (prevBaseAddress != *BaseAddress) {
		LogWithTimestamp(std::format(L"MemoryLoadLibrary relocated {} from {:#x} to {:#x}", 
			logDllName, reinterpret_cast<uintptr_t>(prevBaseAddress), reinterpret_cast<uintptr_t>(*BaseAddress)));
	}

	if (!(module = MapMemoryModuleHandle(*BaseAddress))) {
		LogWithTimestamp(std::format(L"Failed to map memory module for {}", logDllName));
		__fastfail(FAST_FAIL_FATAL_APP_EXIT);
		DebugBreak();
		ExitProcess(STATUS_INVALID_ADDRESS);
		TerminateProcess(NtCurrentProcess(), STATUS_INVALID_ADDRESS);
	}
	module->loadFromLdrLoadDllMemory = true;

	headers = RtlImageNtHeader(*BaseAddress);
	if (headers->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NO_SEH) dwFlags |= LOAD_FLAGS_NOT_ADD_INVERTED_FUNCTION;

	if (dwFlags & LOAD_FLAGS_NOT_MAP_DLL) {
		do {
			LogWithTimestamp(std::format(L"Resolving imports for {}", logDllName));
			status = MemoryResolveImportTable(reinterpret_cast<LPBYTE>(*BaseAddress), headers, module);
			if (!NT_SUCCESS(status)) {
				LogWithTimestamp(std::format(L"MemoryResolveImportTable failed for {} (Status: {:#x})", logDllName, status));
				break;
			}

			LogWithTimestamp(std::format(L"Setting section protection for {}", logDllName));
			status = MemorySetSectionProtection(reinterpret_cast<LPBYTE>(*BaseAddress), headers);
			if (!NT_SUCCESS(status)) {
				LogWithTimestamp(std::format(L"MemorySetSectionProtection failed for {} (Status: {:#x})", logDllName, status));
				break;
			}

			LogWithTimestamp(std::format(L"Executing TLS for {}", logDllName));
			if (!LdrpExecuteTLS(module)) {
				status = STATUS_DLL_INIT_FAILED;
				LogWithTimestamp(std::format(L"LdrpExecuteTLS failed for {} (Status: {:#x})", logDllName, status));
				if (headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) {
					LogWithTimestamp(std::format(L"TLS directory size: {}", headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size));
				} else {
					LogWithTimestamp(L"No TLS directory present"));
				}
				break;
			}

			LogWithTimestamp(std::format(L"Calling initializers for {}", logDllName));
			if (!LdrpCallInitializers(module, DLL_PROCESS_ATTACH)) {
				status = STATUS_DLL_INIT_FAILED;
				LogWithTimestamp(std::format(L"LdrpCallInitializers failed for {} (Status: {:#x})", logDllName, status));
				if (headers->OptionalHeader.AddressOfEntryPoint) {
					LogWithTimestamp(std::format(L"Entry point present at: {:#x}", headers->OptionalHeader.AddressOfEntryPoint));
				} else {
					LogWithTimestamp(L"No entry point (DllMain) present"));
				}
				break;
			}
		} while (false);

		if (!NT_SUCCESS(status)) {
			MemoryFreeLibrary(*BaseAddress);
			LogWithTimestamp(std::format(L"Failed to load {}, freeing memory", logDllName));
		}

		return status;
	}

	do {
		LogWithTimestamp(std::format(L"Mapping DLL for {}", logDllName));
		status = LdrMapDllMemory(*BaseAddress, dwFlags, DllName, DllFullName, &ModuleEntry);
		if (!NT_SUCCESS(status)) {
			LogWithTimestamp(std::format(L"LdrMapDllMemory failed for {} (Status: {:#x})", logDllName, status));
			break;
		}

		module->MappedDll = true;
		module->LdrEntry = ModuleEntry;

		LogWithTimestamp(std::format(L"Resolving imports for {}", logDllName));
		status = MemoryResolveImportTable(reinterpret_cast<LPBYTE>(*BaseAddress), headers, module);
		if (!NT_SUCCESS(status)) {
			LogWithTimestamp(std::format(L"MemoryResolveImportTable failed for {} (Status: {:#x})", logDllName, status));
			break;
		}

		LogWithTimestamp(std::format(L"Setting section protection for {}", logDllName));
		status = MemorySetSectionProtection(reinterpret_cast<LPBYTE>(*BaseAddress), headers);
		if (!NT_SUCCESS(status)) {
			LogWithTimestamp(std::format(L"MemorySetSectionProtection failed for {} (Status: {:#x})", logDllName, status));
			break;
		}

		if (!(dwFlags & LOAD_FLAGS_NOT_USE_REFERENCE_COUNT)) module->UseReferenceCount = true;

		if (!(dwFlags & LOAD_FLAGS_NOT_ADD_INVERTED_FUNCTION)) {
			LogWithTimestamp(std::format(L"Inserting inverted function table for {}", logDllName));
			status = RtlInsertInvertedFunctionTable(static_cast<PVOID>(module->codeBase), headers->OptionalHeader.SizeOfImage);
			if (!NT_SUCCESS(status)) {
				LogWithTimestamp(std::format(L"RtlInsertInvertedFunctionTable failed for {} (Status: {:#x})", logDllName, status));
				break;
			}
			module->InsertInvertedFunctionTableEntry = true;
		}

		if (!(dwFlags & LOAD_FLAGS_NOT_HANDLE_TLS)) {
			LogWithTimestamp(std::format(L"Handling TLS data for {}", logDllName));
			status = MmpGlobalDataPtr->MmpFunctions->_MmpHandleTlsData(ModuleEntry);
			if (!NT_SUCCESS(status)) {
				LogWithTimestamp(std::format(L"_MmpHandleTlsData failed for {} (Status: {:#x})", logDllName, status));
				if (dwFlags & LOAD_FLAGS_NOT_FAIL_IF_HANDLE_TLS) status = 0x7fffffff;
				if (!NT_SUCCESS(status)) break;
			} else {
				module->TlsHandled = true;
			}
		}

		if (dwFlags & LOAD_FLAGS_HOOK_DOT_NET) {
			LogWithTimestamp(std::format(L"Pre-initializing .NET hooks for {}", logDllName));
			MmpPreInitializeHooksForDotNet();
		}

		LogWithTimestamp(std::format(L"Executing TLS for {}", logDllName));
		if (!LdrpExecuteTLS(module)) {
			status = STATUS_DLL_INIT_FAILED;
			LogWithTimestamp(std::format(L"LdrpExecuteTLS failed for {} (Status: {:#x})", logDllName, status));
			if (headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) {
				LogWithTimestamp(std::format(L"TLS directory size: {}", headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size));
			} else {
				LogWithTimestamp(L"No TLS directory present"));
			}
			break;
		}

		LogWithTimestamp(std::format(L"Calling initializers for {}", logDllName));
		if (!LdrpCallInitializers(module, DLL_PROCESS_ATTACH)) {
			status = STATUS_DLL_INIT_FAILED;
			LogWithTimestamp(std::format(L"LdrpCallInitializers failed for {} (Status: {:#x})", logDllName, status));
			if (headers->OptionalHeader.AddressOfEntryPoint) {
				LogWithTimestamp(std::format(L"Entry point present at: {:#x}", headers->OptionalHeader.AddressOfEntryPoint));
			} else {
				LogWithTimestamp(L"No entry point (DllMain) present"));
			}
			break;
		}

		if (dwFlags & LOAD_FLAGS_HOOK_DOT_NET) {
			LogWithTimestamp(std::format(L"Initializing .NET hooks for {}", logDllName));
			MmpInitializeHooksForDotNet();
		}
	} while (false);

	if (NT_SUCCESS(status)) {
		if (LdrEntry) *LdrEntry = ModuleEntry;
		LogWithTimestamp(std::format(L"Successfully loaded {} at {:#x}", logDllName, reinterpret_cast<uintptr_t>(*BaseAddress)));
	} else {
		LogWithTimestamp(std::format(L"Unloading due to failure for {}", logDllName));
		LdrUnloadDllMemory(*BaseAddress);
		*BaseAddress = nullptr;
	}

	return status;
}

extern "C" NTSTATUS NTAPI LdrUnloadDllMemory(_In_ HMEMORYMODULE BaseAddress) {
	PLDR_DATA_TABLE_ENTRY CurEntry;
	ULONG count = 0;
	NTSTATUS status = STATUS_SUCCESS;
	PMEMORYMODULE module = MapMemoryModuleHandle(BaseAddress);
	PIMAGE_NT_HEADERS headers = RtlImageNtHeader(BaseAddress);

	WCHAR modulePath[MAX_PATH] = { 0 };
	std::wstring logDllName = L"unknown";
	if (GetModuleFileNameW(BaseAddress, modulePath, MAX_PATH)) {
		logDllName = modulePath;
	}
	LogWithTimestamp(std::format(L"Starting LdrUnloadDllMemory for address {:#x} ({})", reinterpret_cast<uintptr_t>(BaseAddress), logDllName));

	if (logDllName.find(L"\\Windows\\") != std::wstring::npos) {
		LogWithTimestamp(std::format(L"Skipping unload of system DLL at {:#x} ({})", reinterpret_cast<uintptr_t>(BaseAddress), logDllName));
		return STATUS_INVALID_PARAMETER;
	}

	if (!module || !headers) {
		LogWithTimestamp(std::format(L"Invalid module or headers for address {:#x} ({})", reinterpret_cast<uintptr_t>(BaseAddress), logDllName));
		return STATUS_INVALID_PARAMETER;
	}

	do {
		if (!module->loadFromLdrLoadDllMemory) {
			status = STATUS_INVALID_HANDLE;
			LogWithTimestamp(std::format(L"Not a memory module loaded via LdrLoadDllMemory for {} (Status: {:#x})", logDllName, status));
			break;
		}

		if (MmpGlobalDataPtr == nullptr) {
			status = STATUS_INVALID_PARAMETER;
			LogWithTimestamp(std::format(L"Invalid MmpGlobalDataPtr for {} (Status: {:#x})", logDllName, status));
			break;
		}

		if (!module->MappedDll) {
			module->underUnload = true;
			status = (MemoryFreeLibrary(BaseAddress) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL);
			LogWithTimestamp(std::format(L"Non-mapped DLL, freeing memory for {} (Status: {:#x})", logDllName, status));
			break;
		}

		CurEntry = static_cast<PLDR_DATA_TABLE_ENTRY>(module->LdrEntry);

		if (headers->OptionalHeader.SizeOfImage != CurEntry->SizeOfImage) {
			LogWithTimestamp(L"Image size mismatch in LdrUnloadDllMemory");
			__fastfail(FAST_FAIL_FATAL_APP_EXIT);
		}

		if (module->UseReferenceCount) {
			status = RtlGetReferenceCount(module, &count);
			if (!NT_SUCCESS(status)) {
				LogWithTimestamp(std::format(L"RtlGetReferenceCount failed for {} (Status: {:#x})", logDllName, status));
				break;
			}
		}

		if (count & ~1) {
			status = RtlUpdateReferenceCount(module, FLAG_DEREFERENCE);
			LogWithTimestamp(std::format(L"Module still referenced, decrementing count for {} (Status: {:#x})", logDllName, status));
			break;
		}

		module->underUnload = true;
		if (module->initialized) {
			if (headers->OptionalHeader.AddressOfEntryPoint) {
				LogWithTimestamp(std::format(L"Calling DllMain for DLL_PROCESS_DETACH for {}", logDllName));
				PLDR_INIT_ROUTINE(static_cast<LPVOID>(module->codeBase + headers->OptionalHeader.AddressOfEntryPoint))(
					reinterpret_cast<HINSTANCE>(module->codeBase),
					DLL_PROCESS_DETACH,
					0
				);
			} else {
				LogWithTimestamp(std::format(L"No DllMain to call for DLL_PROCESS_DETACH for {}", logDllName));
			}
		}

		if (module->MappedDll) {
			if (module->InsertInvertedFunctionTableEntry) {
				LogWithTimestamp(std::format(L"Removing inverted function table for {}", logDllName));
				status = RtlRemoveInvertedFunctionTable(BaseAddress);
				if (!NT_SUCCESS(status)) {
					LogWithTimestamp(std::format(L"RtlRemoveInvertedFunctionTable failed for {} (Status: {:#x})", logDllName, status));
					__fastfail(FAST_FAIL_CORRUPT_LIST_ENTRY);
				}
			}

			if (module->TlsHandled) {
				LogWithTimestamp(std::format(L"Releasing TLS entry for {}", logDllName));
				status = MmpGlobalDataPtr->MmpFunctions->_MmpReleaseTlsEntry(CurEntry);
				if (!NT_SUCCESS(status)) {
					LogWithTimestamp(std::format(L"_MmpReleaseTlsEntry failed for {} (Status: {:#x})", logDllName, status));
					__fastfail(FAST_FAIL_FATAL_APP_EXIT);
				}
			}

			LogWithTimestamp(std::format(L"Freeing LDR data table entry for {}", logDllName));
			if (!RtlFreeLdrDataTableEntry(CurEntry)) {
				LogWithTimestamp(std::format(L"RtlFreeLdrDataTableEntry failed for {}", logDllName));
				__fastfail(FAST_FAIL_FATAL_APP_EXIT);
			}
		}

		LogWithTimestamp(std::format(L"Freeing memory for module {}", logDllName));
		if (!MemoryFreeLibrary(BaseAddress)) {
			LogWithTimestamp(std::format(L"MemoryFreeLibrary failed for {}", logDllName));
			__fastfail(FAST_FAIL_FATAL_APP_EXIT);
		}
	} while (false);

	LogWithTimestamp(std::format(L"LdrUnloadDllMemory completed with status {:#x} for {}", status, logDllName));
	return status;
}

extern "C" DECLSPEC_NORETURN VOID NTAPI LdrUnloadDllMemoryAndExitThread(
	_In_ HMEMORYMODULE BaseAddress,
	_In_ DWORD dwExitCode) {
	WCHAR modulePath[MAX_PATH] = { 0 };
	std::wstring logDllName = L"unknown";
	if (GetModuleFileNameW(BaseAddress, modulePath, MAX_PATH)) {
		logDllName = modulePath;
	}
	LogWithTimestamp(std::format(L"Unloading DLL and exiting thread for address {:#x} ({})", reinterpret_cast<uintptr_t>(BaseAddress), logDllName));
	LdrUnloadDllMemory(BaseAddress);
	RtlExitUserThread(dwExitCode);
}

extern "C" NTSTATUS NTAPI LdrQuerySystemMemoryModuleFeatures(_Out_ PDWORD pFeatures) {
	NTSTATUS status = STATUS_SUCCESS;
	__try {
		*pFeatures = MmpGlobalDataPtr->MmpFeatures;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		status = GetExceptionCode();
	}
	return status;
}