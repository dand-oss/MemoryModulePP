#include "stdafx.h"
#include <cmath>
#include <iostream>

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
	if (DataTableEntry)*DataTableEntry = LdrEntry;
	return STATUS_SUCCESS;
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

    std::wcerr << L"Starting LdrLoadDllMemoryExW for " << (DllName ? DllName : L"null") << std::endl;

	// Skip TLS handling for dstng_firebird_d.dll to test
	if (DllName && wcscmp(DllName, L"dstng_firebird_d.dll") == 0) {
		dwFlags |= LOAD_FLAGS_NOT_HANDLE_TLS;
		std::wcerr << L"Skipping TLS handling for dstng_firebird_d.dll" << std::endl;
	}

	if (BufferSize)return STATUS_INVALID_PARAMETER_5;
	__try {
		*BaseAddress = nullptr;
		if (LdrEntry)*LdrEntry = nullptr;

		if (!RtlIsValidImageBuffer(BufferAddress, &BufferSize) && !(dwFlags & LOAD_FLAGS_PASS_IMAGE_CHECK)) {
			status = STATUS_INVALID_IMAGE_FORMAT;
            std::wcerr << L"Invalid image buffer for " << (DllName ? DllName : L"null") << L" (Status: " << status << L")" << std::endl;
		}

		if (MmpGlobalDataPtr == nullptr) {
			status = STATUS_INVALID_PARAMETER;
            std::wcerr << L"Invalid MmpGlobalDataPtr for " << (DllName ? DllName : L"null") << L" (Status: " << status << L")" << std::endl;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		status = GetExceptionCode();
        std::wcerr << L"Exception in initial checks for " << (DllName ? DllName : L"null") << L" (Status: " << status << L")" << std::endl;
	}
	if (!NT_SUCCESS(status))return status;

	if (dwFlags & LOAD_FLAGS_NOT_MAP_DLL) {
		dwFlags &= LOAD_FLAGS_NOT_MAP_DLL;
		DllName = DllFullName = nullptr;
	}
	if (dwFlags & LOAD_FLAGS_USE_DLL_NAME && (!DllName || !DllFullName))return STATUS_INVALID_PARAMETER_3;

	if (DllName) {
		int length = static_cast<int>(wcslen(DllName));
		PLIST_ENTRY ListHead = &NtCurrentPeb()->Ldr->InLoadOrderModuleList, ListEntry = ListHead->Flink;
		PIMAGE_NT_HEADERS h1 = RtlImageNtHeader(BufferAddress), h2 = nullptr;
		if (!h1)return STATUS_INVALID_IMAGE_FORMAT;
		
		while (ListEntry != ListHead) {
			PLDR_DATA_TABLE_ENTRY CurEntry = CONTAINING_RECORD(ListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
			ListEntry = ListEntry->Flink;

			/* Check if it's being unloaded */
			if (!CurEntry->InMemoryOrderLinks.Flink) continue;

			auto dist = (CurEntry->BaseDllName.Length / sizeof(wchar_t)) - length;
			bool equal = false;
			if (!(dist == 0 || dist == 4)) continue;
			equal = !_wcsnicmp(DllName, CurEntry->BaseDllName.Buffer, length);
			
			/* Check if name matches */
			if (equal) {

				/* Let's compare their headers */
				if (!(h2 = RtlImageNtHeader(CurEntry->DllBase)))continue;
				if (!(module = MapMemoryModuleHandle(static_cast<HMEMORYMODULE>(CurEntry->DllBase))))continue;
				if ((h1->OptionalHeader.SizeOfCode == h2->OptionalHeader.SizeOfCode) &&
					(h1->OptionalHeader.SizeOfHeaders == h2->OptionalHeader.SizeOfHeaders)) {
				
					/* This is our entry!, update load count and return success */
					if (!module->UseReferenceCount || dwFlags & LOAD_FLAGS_NOT_USE_REFERENCE_COUNT)return STATUS_INVALID_PARAMETER_3;
					
					RtlUpdateReferenceCount(module, FLAG_REFERENCE);
					*BaseAddress = static_cast<HMEMORYMODULE>(CurEntry->DllBase);
					if (LdrEntry)*LdrEntry = CurEntry;
                    std::wcerr << L"Found existing module for " << DllName << L" at " << *BaseAddress << std::endl;
					return STATUS_SUCCESS;
				}
			}
		}
	}

    std::wcerr << L"Calling MemoryLoadLibrary for " << (DllName ? DllName : L"null") << std::endl;
	status = MemoryLoadLibrary(BaseAddress, BufferAddress, static_cast<DWORD>(BufferSize));
	if (!NT_SUCCESS(status) || status == STATUS_IMAGE_MACHINE_TYPE_MISMATCH) {
        std::wcerr << L"MemoryLoadLibrary failed for " << (DllName ? DllName : L"null") << L" (Status: " << status << L")" << std::endl;
        return status;
    }

	if (!(module = MapMemoryModuleHandle(*BaseAddress))) {
		__fastfail(FAST_FAIL_FATAL_APP_EXIT);
		DebugBreak();
		ExitProcess(STATUS_INVALID_ADDRESS);
		TerminateProcess(NtCurrentProcess(), STATUS_INVALID_ADDRESS);
	}
	module->loadFromLdrLoadDllMemory = true;

	headers = RtlImageNtHeader(*BaseAddress);
	if (headers->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NO_SEH)dwFlags |= LOAD_FLAGS_NOT_ADD_INVERTED_FUNCTION;

	if (dwFlags & LOAD_FLAGS_NOT_MAP_DLL) {

		do {
			std::wcerr << L"Resolving imports for " << (DllName ? DllName : L"null") << std::endl;
			status = MemoryResolveImportTable(reinterpret_cast<LPBYTE>(*BaseAddress), headers, module);
			if (!NT_SUCCESS(status)) {
                std::wcerr << L"MemoryResolveImportTable failed for " << (DllName ? DllName : L"null") << L" (Status: " << status << L")" << std::endl;
                break;
            }

			std::wcerr << L"Setting section protection for " << (DllName ? DllName : L"null") << std::endl;
			status = MemorySetSectionProtection(reinterpret_cast<LPBYTE>(*BaseAddress), headers);
			if (!NT_SUCCESS(status)) {
                std::wcerr << L"MemorySetSectionProtection failed for " << (DllName ? DllName : L"null") << L" (Status: " << status << L")" << std::endl;
                break;
            }

			std::wcerr << L"Executing TLS for " << (DllName ? DllName : L"null") << std::endl;
			if (!LdrpExecuteTLS(module)) {
				status = STATUS_DLL_INIT_FAILED;
				std::wcerr << L"LdrpExecuteTLS failed for " << (DllName ? DllName : L"null") << L" (Status: " << status << L")" << std::endl;
				if (headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) {
					std::wcerr << L"TLS directory size: " << headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size << std::endl;
				} else {
					std::wcerr << L"No TLS directory present" << std::endl;
				}
				break;
			}

			std::wcerr << L"Calling initializers for " << (DllName ? DllName : L"null") << std::endl;
			if (!LdrpCallInitializers(module, DLL_PROCESS_ATTACH)) {
				status = STATUS_DLL_INIT_FAILED;
				std::wcerr << L"LdrpCallInitializers failed for " << (DllName ? DllName : L"null") << L" (Status: " << status << L")" << std::endl;
				if (headers->OptionalHeader.AddressOfEntryPoint) {
					std::wcerr << L"Entry point present at: " << headers->OptionalHeader.AddressOfEntryPoint << std::endl;
				} else {
					std::wcerr << L"No entry point (DllMain) present" << std::endl;
				}
				break;
			}

		} while (false);

		if (!NT_SUCCESS(status)) {
			MemoryFreeLibrary(*BaseAddress);
            std::wcerr << L"Failed to load " << (DllName ? DllName : L"null") << L", freeing memory" << std::endl;
		}

		return status;
	}

	do {

		std::wcerr << L"Mapping DLL for " << (DllName ? DllName : L"null") << std::endl;
		status = LdrMapDllMemory(*BaseAddress, dwFlags, DllName, DllFullName, &ModuleEntry);
		if (!NT_SUCCESS(status)) {
            std::wcerr << L"LdrMapDllMemory failed for " << (DllName ? DllName : L"null") << L" (Status: " << status << L")" << std::endl;
            break;
        }

		module->MappedDll = true;
		module->LdrEntry = ModuleEntry;

		std::wcerr << L"Resolving imports for " << (DllName ? DllName : L"null") << std::endl;
		status = MemoryResolveImportTable(reinterpret_cast<LPBYTE>(*BaseAddress), headers, module);
		if (!NT_SUCCESS(status)) {
            std::wcerr << L"MemoryResolveImportTable failed for " << (DllName ? DllName : L"null") << L" (Status: " << status << L")" << std::endl;
            break;
        }

		std::wcerr << L"Setting section protection for " << (DllName ? DllName : L"null") << std::endl;
		status = MemorySetSectionProtection(reinterpret_cast<LPBYTE>(*BaseAddress), headers);
		if (!NT_SUCCESS(status)) {
            std::wcerr << L"MemorySetSectionProtection failed for " << (DllName ? DllName : L"null") << L" (Status: " << status << L")" << std::endl;
            break;
        }

		if (!(dwFlags & LOAD_FLAGS_NOT_USE_REFERENCE_COUNT))module->UseReferenceCount = true;

		if (!(dwFlags & LOAD_FLAGS_NOT_ADD_INVERTED_FUNCTION)) {
			std::wcerr << L"Inserting inverted function table for " << (DllName ? DllName : L"null") << std::endl;
			status = RtlInsertInvertedFunctionTable(static_cast<PVOID>(module->codeBase), headers->OptionalHeader.SizeOfImage);
			if (!NT_SUCCESS(status)) {
                std::wcerr << L"RtlInsertInvertedFunctionTable failed for " << (DllName ? DllName : L"null") << L" (Status: " << status << L")" << std::endl;
                break;
            }

			module->InsertInvertedFunctionTableEntry = true;
		}

		if (!(dwFlags & LOAD_FLAGS_NOT_HANDLE_TLS)) {
			std::wcerr << L"Handling TLS data for " << (DllName ? DllName : L"null") << std::endl;
			status = MmpGlobalDataPtr->MmpFunctions->_MmpHandleTlsData(ModuleEntry);
			if (!NT_SUCCESS(status)) {
				std::wcerr << L"_MmpHandleTlsData failed for " << (DllName ? DllName : L"null") << L" (Status: " << status << L")" << std::endl;
				if (dwFlags & LOAD_FLAGS_NOT_FAIL_IF_HANDLE_TLS) status = 0x7fffffff;
				if (!NT_SUCCESS(status))break;
			}
			else {
				module->TlsHandled = true;
			}
		}

		if (dwFlags & LOAD_FLAGS_HOOK_DOT_NET) {
			std::wcerr << L"Pre-initializing .NET hooks for " << (DllName ? DllName : L"null") << std::endl;
			MmpPreInitializeHooksForDotNet();
		}

		std::wcerr << L"Executing TLS for " << (DllName ? DllName : L"null") << std::endl;
		if (!LdrpExecuteTLS(module)) {
			status = STATUS_DLL_INIT_FAILED;
			std::wcerr << L"LdrpExecuteTLS failed for " << (DllName ? DllName : L"null") << L" (Status: " << status << L")" << std::endl;
			if (headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) {
				std::wcerr << L"TLS directory size: " << headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size << std::endl;
			} else {
				std::wcerr << L"No TLS directory present" << std::endl;
			}
			break;
		}

		std::wcerr << L"Calling initializers for " << (DllName ? DllName : L"null") << std::endl;
		if (!LdrpCallInitializers(module, DLL_PROCESS_ATTACH)) {
			status = STATUS_DLL_INIT_FAILED;
			std::wcerr << L"LdrpCallInitializers failed for " << (DllName ? DllName : L"null") << L" (Status: " << status << L")" << std::endl;
			if (headers->OptionalHeader.AddressOfEntryPoint) {
				std::wcerr << L"Entry point present at: " << headers->OptionalHeader.AddressOfEntryPoint << std::endl;
			} else {
				std::wcerr << L"No entry point (DllMain) present" << std::endl;
			}
			break;
		}

		if (dwFlags & LOAD_FLAGS_HOOK_DOT_NET) {
			std::wcerr << L"Initializing .NET hooks for " << (DllName ? DllName : L"null") << std::endl;
			MmpInitializeHooksForDotNet();
		}

	} while (false);

	if (NT_SUCCESS(status)) {
		if (LdrEntry)*LdrEntry = ModuleEntry;
        std::wcerr << L"Successfully loaded " << (DllName ? DllName : L"null") << L" at " << *BaseAddress << std::endl;
	}
	else {
        std::wcerr << L"Unloading due to failure for " << (DllName ? DllName : L"null") << std::endl;
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

	std::wcerr << L"Starting LdrUnloadDllMemory for address " << BaseAddress << std::endl;

	if (!module || !headers) {
		std::wcerr << L"Invalid module or headers in LdrUnloadDllMemory for address " << BaseAddress << std::endl;
		return STATUS_INVALID_PARAMETER;
	}

	do {

		//Not a memory module loaded via LdrLoadDllMemory
		if (!module->loadFromLdrLoadDllMemory) {
			status = STATUS_INVALID_HANDLE;
			std::wcerr << L"Not a memory module loaded via LdrLoadDllMemory (Status: " << status << L")" << std::endl;
			break;
		}

		if (MmpGlobalDataPtr == nullptr) {
			status = STATUS_INVALID_PARAMETER;
			std::wcerr << L"Invalid MmpGlobalDataPtr in LdrUnloadDllMemory (Status: " << status << L")" << std::endl;
			break;
		}

		//Mapping dll failed
		if (!module->MappedDll) {
			module->underUnload = true;
			status = (MemoryFreeLibrary(BaseAddress) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL);
			std::wcerr << L"Non-mapped DLL, freeing memory (Status: " << status << L")" << std::endl;
			break;
		}

		CurEntry = static_cast<PLDR_DATA_TABLE_ENTRY>(module->LdrEntry);

		if (headers->OptionalHeader.SizeOfImage != CurEntry->SizeOfImage) {
			std::wcerr << L"Image size mismatch in LdrUnloadDllMemory" << std::endl;
			__fastfail(FAST_FAIL_FATAL_APP_EXIT);
		}

		if (module->UseReferenceCount) {
			status = RtlGetReferenceCount(module, &count);
			if (!NT_SUCCESS(status)) {
				std::wcerr << L"RtlGetReferenceCount failed (Status: " << status << L")" << std::endl;
				break;
			}
		}

		if (count & ~1) {
			status = RtlUpdateReferenceCount(module, FLAG_DEREFERENCE);
			std::wcerr << L"Module still referenced, decrementing count (Status: " << status << L")" << std::endl;
			break;
		}

		module->underUnload = true;
		if (module->initialized) {
			if (headers->OptionalHeader.AddressOfEntryPoint) {
				std::wcerr << L"Calling DllMain for DLL_PROCESS_DETACH" << std::endl;
				PLDR_INIT_ROUTINE(static_cast<LPVOID>(module->codeBase + headers->OptionalHeader.AddressOfEntryPoint))(
					reinterpret_cast<HINSTANCE>(module->codeBase),
					DLL_PROCESS_DETACH,
					0
				);
			} else {
				std::wcerr << L"No DllMain to call for DLL_PROCESS_DETACH" << std::endl;
			}
		}

		if (module->MappedDll) {
			if (module->InsertInvertedFunctionTableEntry) {
				std::wcerr << L"Removing inverted function table" << std::endl;
				status = RtlRemoveInvertedFunctionTable(BaseAddress);
				if (!NT_SUCCESS(status)) {
					std::wcerr << L"RtlRemoveInvertedFunctionTable failed (Status: " << status << L")" << std::endl;
					__fastfail(FAST_FAIL_CORRUPT_LIST_ENTRY);
				}
			}

			if (module->TlsHandled) {
				std::wcerr << L"Releasing TLS entry" << std::endl;
				status = MmpGlobalDataPtr->MmpFunctions->_MmpReleaseTlsEntry(CurEntry);
				if (!NT_SUCCESS(status)) {
					std::wcerr << L"_MmpReleaseTlsEntry failed (Status: " << status << L")" << std::endl;
					__fastfail(FAST_FAIL_FATAL_APP_EXIT);
				}
			}

			std::wcerr << L"Freeing LDR data table entry" << std::endl;
			if (!RtlFreeLdrDataTableEntry(CurEntry)) {
				std::wcerr << L"RtlFreeLdrDataTableEntry failed" << std::endl;
				__fastfail(FAST_FAIL_FATAL_APP_EXIT);
			}
		}

		std::wcerr << L"Freeing memory for module" << std::endl;
		if (!MemoryFreeLibrary(BaseAddress)) {
			std::wcerr << L"MemoryFreeLibrary failed" << std::endl;
			__fastfail(FAST_FAIL_FATAL_APP_EXIT);
		}

	} while (false);

	std::wcerr << L"LdrUnloadDllMemory completed with status " << status << std::endl;
	return status;
}

extern "C"
DECLSPEC_NORETURN
VOID NTAPI LdrUnloadDllMemoryAndExitThread(_In_ HMEMORYMODULE BaseAddress, _In_ DWORD dwExitCode) {
	std::wcerr << L"Unloading DLL and exiting thread for address " << BaseAddress << std::endl;
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