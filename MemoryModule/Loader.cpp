#include "stdafx.h"
#include <cmath>
#include <iostream>
#include <format>

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

	std::wcerr << std::format(L"Starting LdrLoadDllMemoryExW for {}", DllName ? DllName : L"null") << std::endl;

	if (BufferSize) return STATUS_INVALID_PARAMETER_5;

	// Perform SEH-protected checks in helper function
	status = CheckImageAndGlobalData(BufferAddress, &BufferSize, dwFlags, MmpGlobalDataPtr, BaseAddress, LdrEntry);
	if (!NT_SUCCESS(status)) {
		std::wcerr << std::format(L"Initial checks failed for {} (Status: {:#x})", DllName ? DllName : L"null", status) << std::endl;
		return status;
	}

	if (dwFlags & LOAD_FLAGS_NOT_MAP_DLL) {
		dwFlags &= LOAD_FLAGS_NOT_MAP_DLL;
		DllName = DllFullName = nullptr;
	}
	if (dwFlags & LOAD_FLAGS_USE_DLL_NAME && (!DllName || !DllFullName)) return STATUS_INVALID_PARAMETER_3;

	if (DllName) {
		int length = static_cast<int>(wcslen(DllName));
		PLIST_ENTRY ListHead = &NtCurrentPeb()->Ldr->InLoadOrderModuleList, ListEntry = ListHead->Flink;
		PIMAGE_NT_HEADERS h1 = RtlImageNtHeader(BufferAddress), h2 = nullptr;
		if (!h1) return STATUS_INVALID_IMAGE_FORMAT;
		
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
					if (!module->UseReferenceCount || dwFlags & LOAD_FLAGS_NOT_USE_REFERENCE_COUNT) return STATUS_INVALID_PARAMETER_3;
					
					RtlUpdateReferenceCount(module, FLAG_REFERENCE);
					*BaseAddress = static_cast<HMEMORYMODULE>(CurEntry->DllBase);
					if (LdrEntry) *LdrEntry = CurEntry;
					std::wcerr << std::format(L"Found existing module for {} at {:#x}", DllName, reinterpret_cast<uintptr_t>(*BaseAddress)) << std::endl;
					return STATUS_SUCCESS;
				}
			}
		}
	}

	std::wcerr << std::format(L"Calling MemoryLoadLibrary for {} with size {}", DllName ? DllName : L"null", BufferSize) << std::endl;
	status = MemoryLoadLibrary(BaseAddress, BufferAddress, static_cast<DWORD>(BufferSize));
	if (!NT_SUCCESS(status) || status == STATUS_IMAGE_MACHINE_TYPE_MISMATCH) {
		std::wcerr << std::format(L"MemoryLoadLibrary failed for {} (Status: {:#x})", DllName ? DllName : L"null", status) << std::endl;
		return status;
	}
	std::wcerr << std::format(L"MemoryLoadLibrary allocated at {:#x} for {} with protection PAGE_EXECUTE_READWRITE", reinterpret_cast<uintptr_t>(*BaseAddress), DllName ? DllName : L"null") << std::endl;

	if (!(module = MapMemoryModuleHandle(*BaseAddress))) {
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
			std::wcerr << std::format(L"Resolving imports for {}", DllName ? DllName : L"null") << std::endl;
			status = MemoryResolveImportTable(reinterpret_cast<LPBYTE>(*BaseAddress), headers, module);
			if (!NT_SUCCESS(status)) {
				std::wcerr << std::format(L"MemoryResolveImportTable failed for {} (Status: {:#x})", DllName ? DllName : L"null", status) << std::endl;
				break;
			}

			std::wcerr << std::format(L"Setting section protection for {}", DllName ? DllName : L"null") << std::endl;
			status = MemorySetSectionProtection(reinterpret_cast<LPBYTE>(*BaseAddress), headers);
			if (!NT_SUCCESS(status)) {
				std::wcerr << std::format(L"MemorySetSectionProtection failed for {} (Status: {:#x})", DllName ? DllName : L"null", status) << std::endl;
				break;
			}

			std::wcerr << std::format(L"Executing TLS for {}", DllName ? DllName : L"null") << std::endl;
			if (!LdrpExecuteTLS(module)) {
				status = STATUS_DLL_INIT_FAILED;
				std::wcerr << std::format(L"LdrpExecuteTLS failed for {} (Status: {:#x})", DllName ? DllName : L"null", status) << std::endl;
				if (headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) {
					std::wcerr << std::format(L"TLS directory size: {}", headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) << std::endl;
				} else {
					std::wcerr << L"No TLS directory present" << std::endl;
				}
				break;
			}

			std::wcerr << std::format(L"Calling initializers for {}", DllName ? DllName : L"null") << std::endl;
			if (!LdrpCallInitializers(module, DLL_PROCESS_ATTACH)) {
				status = STATUS_DLL_INIT_FAILED;
				std::wcerr << std::format(L"LdrpCallInitializers failed for {} (Status: {:#x})", DllName ? DllName : L"null", status) << std::endl;
				if (headers->OptionalHeader.AddressOfEntryPoint) {
					std::wcerr << std::format(L"Entry point present at: {:#x}", headers->OptionalHeader.AddressOfEntryPoint) << std::endl;
				} else {
					std::wcerr << L"No entry point (DllMain) present" << std::endl;
				}
				break;
			}
		} while (false);

		if (!NT_SUCCESS(status)) {
			MemoryFreeLibrary(*BaseAddress);
			std::wcerr << std::format(L"Failed to load {}, freeing memory", DllName ? DllName : L"null") << std::endl;
		}

		return status;
	}

	do {
		std::wcerr << std::format(L"Mapping DLL for {} instantaneously", DllName ? DllName : L"null") << std::endl;
		status = LdrMapDllMemory(*BaseAddress, dwFlags, DllName, DllFullName, &ModuleEntry);
		if (!NT_SUCCESS(status)) {
			std::wcerr << std::format(L"LdrMapDllMemory failed for {} (Status: {:#x})", DllName ? DllName : L"null", status) << std::endl;
			break;
		}

		module->MappedDll = true;
		module->LdrEntry = ModuleEntry;

		std::wcerr << std::format(L"Resolving imports for {}", DllName ? DllName : L"null") << std::endl;
		status = MemoryResolveImportTable(reinterpret_cast<LPBYTE>(*BaseAddress), headers, module);
		if (!NT_SUCCESS(status)) {
			std::wcerr << std::format(L"MemoryResolveImportTable failed for {} (Status: {:#x})", DllName ? DllName : L"null", status) << std::endl;
			break;
		}

		std::wcerr << std::format(L"Setting section protection for {}", DllName ? DllName : L"null") << std::endl;
		status = MemorySetSectionProtection(reinterpret_cast<LPBYTE>(*BaseAddress), headers);
		if (!NT_SUCCESS(status)) {
			std::wcerr << std::format(L"MemorySetSectionProtection failed for {} (Status: {:#x})", DllName ? DllName : L"null", status) << std::endl;
			break;
		}

		if (!(dwFlags & LOAD_FLAGS_NOT_USE_REFERENCE_COUNT)) module->UseReferenceCount = true;

		if (!(dwFlags & LOAD_FLAGS_NOT_ADD_INVERTED_FUNCTION)) {
			std::wcerr << std::format(L"Inserting inverted function table for {}", DllName ? DllName : L"null") << std::endl;
			status = RtlInsertInvertedFunctionTable(static_cast<PVOID>(module->codeBase), headers->OptionalHeader.SizeOfImage);
			if (!NT_SUCCESS(status)) {
				std::wcerr << std::format(L"RtlInsertInvertedFunctionTable failed for {} (Status: {:#x})", DllName ? DllName : L"null", status) << std::endl;
				break;
			}
			module->InsertInvertedFunctionTableEntry = true;
		}

		if (!(dwFlags & LOAD_FLAGS_NOT_HANDLE_TLS)) {
			std::wcerr << std::format(L"Handling TLS data for {}", DllName ? DllName : L"null") << std::endl;
			status = MmpGlobalDataPtr->MmpFunctions->_MmpHandleTlsData(ModuleEntry);
			if (!NT_SUCCESS(status)) {
				std::wcerr << std::format(L"_MmpHandleTlsData failed for {} (Status: {:#x})", DllName ? DllName : L"null", status) << std::endl;
				if (headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) {
					PIMAGE_TLS_DIRECTORY tlsDir = reinterpret_cast<PIMAGE_TLS_DIRECTORY>(
						RtlImageRvaToVa(headers, *BaseAddress, headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress, nullptr)
					);
					if (tlsDir) {
						std::wcerr << std::format(L"TLS Directory: StartAddressOfRawData=0x{:x}, EndAddressOfRawData=0x{:x}, AddressOfIndex=0x{:x}, AddressOfCallBacks=0x{:x}, SizeOfZeroFill={}",
							tlsDir->StartAddressOfRawData, tlsDir->EndAddressOfRawData, tlsDir->AddressOfIndex, tlsDir->AddressOfCallBacks, tlsDir->SizeOfZeroFill) << std::endl;
					} else {
						std::wcerr << L"Failed to resolve TLS directory" << std::endl;
					}
				} else {
					std::wcerr << L"No TLS directory present" << std::endl;
				}
				if (dwFlags & LOAD_FLAGS_NOT_FAIL_IF_HANDLE_TLS) status = 0x7fffffff;
				if (!NT_SUCCESS(status)) break;
			} else {
				module->TlsHandled = true;
			}
		}

		if (dwFlags & LOAD_FLAGS_HOOK_DOT_NET) {
			std::wcerr << std::format(L"Pre-initializing .NET hooks for {}", DllName ? DllName : L"null") << std::endl;
			MmpPreInitializeHooksForDotNet();
		}

		std::wcerr << std::format(L"Executing TLS for {}", DllName ? DllName : L"null") << std::endl;
		if (!LdrpExecuteTLS(module)) {
			std::wcerr << std::format(L"LdrpExecuteTLS failed for {} (Status: {:#x})", DllName ? DllName : L"null", status) << std::endl;
			if (headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) {
				std::wcerr << std::format(L"TLS directory size: {}", headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) << std::endl;
			} else {
				std::wcerr << L"No TLS directory present" << std::endl;
			}
			break;
		}

		std::wcerr << std::format(L"Calling initializers for {}", DllName ? DllName : L"null") << std::endl;
		if (!LdrpCallInitializers(module, DLL_PROCESS_ATTACH)) {
			std::wcerr << std::format(L"LdrpCallInitializers failed for {} (Status: {:#x})", DllName ? DllName : L"null", status) << std::endl;
			if (headers->OptionalHeader.AddressOfEntryPoint) {
				std::wcerr << std::format(L"Entry point present at: {:#x}", headers->OptionalHeader.AddressOfEntryPoint) << std::endl;
			} else {
				std::wcerr << L"No entry point (DllMain) present" << std::endl;
			}
			break;
		}

		if (dwFlags & LOAD_FLAGS_HOOK_DOT_NET) {
			std::wcerr << std::format(L"Initializing .NET hooks for {}", DllName ? DllName : L"null") << std::endl;
			MmpInitializeHooksForDotNet();
		}
	} while (false);

	if (NT_SUCCESS(status)) {
		if (LdrEntry) *LdrEntry = ModuleEntry;
		std::wcerr << std::format(L"Successfully loaded {} at {:#x}", DllName ? DllName : L"null", reinterpret_cast<uintptr_t>(*BaseAddress)) << std::endl;
	} else {
		std::wcerr << std::format(L"Unloading due to failure for {}", DllName ? DllName : L"null") << std::endl;
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

	std::wcerr << std::format(L"Starting LdrUnloadDllMemory for address {:#x}", reinterpret_cast<uintptr_t>(BaseAddress)) << std::endl;

	if (!module || !headers) {
		std::wcerr << std::format(L"Invalid module or headers for address {:#x}", reinterpret_cast<uintptr_t>(BaseAddress)) << std::endl;
		return STATUS_INVALID_PARAMETER;
	}

	do {
		if (!module->loadFromLdrLoadDllMemory) {
			status = STATUS_INVALID_HANDLE;
			std::wcerr << std::format(L"Not a memory module loaded via LdrLoadDllMemory (Status: {:#x})", status) << std::endl;
			break;
		}

		if (MmpGlobalDataPtr == nullptr) {
			status = STATUS_INVALID_PARAMETER;
			std::wcerr << std::format(L"Invalid MmpGlobalDataPtr (Status: {:#x})", status) << std::endl;
			break;
		}

		if (!module->MappedDll) {
			module->underUnload = true;
			status = (MemoryFreeLibrary(BaseAddress) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL);
			std::wcerr << std::format(L"Non-mapped DLL, freeing memory (Status: {:#x})", status) << std::endl;
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
				std::wcerr << std::format(L"RtlGetReferenceCount failed (Status: {:#x})", status) << std::endl;
				break;
			}
		}

		if (count & ~1) {
			status = RtlUpdateReferenceCount(module, FLAG_DEREFERENCE);
			std::wcerr << std::format(L"Module still referenced, decrementing count (Status: {:#x})", status) << std::endl;
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
					std::wcerr << std::format(L"RtlRemoveInvertedFunctionTable failed (Status: {:#x})", status) << std::endl;
					__fastfail(FAST_FAIL_CORRUPT_LIST_ENTRY);
				}
			}

			if (module->TlsHandled) {
				std::wcerr << L"Releasing TLS entry" << std::endl;
				status = MmpGlobalDataPtr->MmpFunctions->_MmpReleaseTlsEntry(CurEntry);
				if (!NT_SUCCESS(status)) {
					std::wcerr << std::format(L"_MmpReleaseTlsEntry failed (Status: {:#x})", status) << std::endl;
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

	std::wcerr << std::format(L"LdrUnloadDllMemory completed with status {:#x}", status) << std::endl;
	return status;
}

extern "C" DECLSPEC_NORETURN VOID NTAPI LdrUnloadDllMemoryAndExitThread(
	_In_ HMEMORYMODULE BaseAddress,
	_In_ DWORD dwExitCode) {
	std::wcerr << std::format(L"Unloading DLL and exiting thread for address {:#x}", reinterpret_cast<uintptr_t>(BaseAddress)) << std::endl;
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
