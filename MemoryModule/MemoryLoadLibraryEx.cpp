#include "stdafx.h"
#include <string>
#include <algorithm>
#include <iostream>
#include "Utils.h" // Include for LdrpCallInitializers
#include "MemoryModule.h" // PMEMORYMODULE
#include "LoadDllMemoryApi.h" // CustomLoadLibraryFunc, CustomAllocFunc, CustomFreeFunc, CustomGetProcAddressFunc, CustomFreeLibraryFunc

// Define _MMP_IAT_HANDLE (matches ImportTable.cpp)
struct _MMP_IAT_HANDLE {
    HMODULE hModule;
    PMM_IAT_RESOLVER lpResolver;
};
using PMMP_IAT_HANDLE = _MMP_IAT_HANDLE*;

namespace {
    // Default allocation function using VirtualAlloc
    LPVOID WINAPI DefaultAlloc(LPVOID address, SIZE_T size, DWORD allocationType, DWORD protect, void* userdata) {
        return VirtualAlloc(address, size, allocationType, protect);
    }

    // Default free function using VirtualFree
    BOOL WINAPI DefaultFree(LPVOID address, SIZE_T size, DWORD freeType, void* userdata) {
        return VirtualFree(address, size, freeType);
    }
}

static NTSTATUS MemoryResolveImportTableCustom(
    IN LPBYTE base,
    IN PIMAGE_NT_HEADERS lpNtHeaders,
    IN PMEMORYMODULE hMemoryModule,
    IN CustomLoadLibraryFunc loadLibrary,
    IN void* userdata) {
    auto status = STATUS_SUCCESS;
    PIMAGE_IMPORT_DESCRIPTOR importDesc = nullptr;
    auto count = DWORD{0};

    // Compute count
    const auto dir = &lpNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    PIMAGE_IMPORT_DESCRIPTOR iat = nullptr;

    if (dir && dir->Size) {
        iat = importDesc = PIMAGE_IMPORT_DESCRIPTOR(base + dir->VirtualAddress);
    }

    if (iat) {
        while (iat->Name) {
            ++count;
            ++iat;
        }
    }

    if (!importDesc || !count) {
        return STATUS_SUCCESS;
    }

    // Allocate handles
    const auto handles = static_cast<PMMP_IAT_HANDLE>(
        HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(_MMP_IAT_HANDLE) * count));
    if (!handles) {
        return STATUS_NO_MEMORY;
    }
    hMemoryModule->hModulesList = handles;
    hMemoryModule->dwModulesCount = count;

    // Process imports
    for (auto i = DWORD{0}; i < count; ++i, ++importDesc) {
        const auto dllName = reinterpret_cast<LPCSTR>(base + importDesc->Name);
        auto dllNameLower = std::string(dllName);
        std::transform(dllNameLower.begin(), dllNameLower.end(), dllNameLower.begin(), ::tolower);

        // Use the loadLibrary callback to load the dependency
        const auto handle = loadLibrary(dllName, userdata);
        if (!handle) {
            status = STATUS_DLL_NOT_FOUND;
            break;
        }

        static_cast<PMMP_IAT_HANDLE>(hMemoryModule->hModulesList)[i].hModule = handle;
        static_cast<PMMP_IAT_HANDLE>(hMemoryModule->hModulesList)[i].lpResolver = nullptr;

        // Patch IAT with manual validation
        if (!importDesc->OriginalFirstThunk && !importDesc->FirstThunk) {
            status = STATUS_INVALID_ADDRESS;
            break;
        }

        uintptr_t* thunkRef;
        FARPROC* funcRef;
        if (importDesc->OriginalFirstThunk) {
            thunkRef = reinterpret_cast<uintptr_t*>(base + importDesc->OriginalFirstThunk);
            funcRef = reinterpret_cast<FARPROC*>(base + importDesc->FirstThunk);
        } else {
            thunkRef = reinterpret_cast<uintptr_t*>(base + importDesc->FirstThunk);
            funcRef = reinterpret_cast<FARPROC*>(base + importDesc->FirstThunk);
        }

        auto mbi = MEMORY_BASIC_INFORMATION{};
        for (; ; ++thunkRef, ++funcRef) {
            if (VirtualQuery(thunkRef, &mbi, sizeof(mbi)) != sizeof(mbi) || 
                VirtualQuery(funcRef, &mbi, sizeof(mbi)) != sizeof(mbi)) {
                status = STATUS_ACCESS_VIOLATION;
                break;
            }
            if (!*thunkRef) break;

            if (IMAGE_SNAP_BY_ORDINAL(*thunkRef)) {
                *funcRef = reinterpret_cast<FARPROC>(
                    GetProcAddress(reinterpret_cast<HMODULE>(handle), reinterpret_cast<LPCSTR>(IMAGE_ORDINAL(*thunkRef))));
            } else {
                const auto thunkData = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(base + (*thunkRef));
                if (VirtualQuery(thunkData, &mbi, sizeof(mbi)) != sizeof(mbi)) {
                    status = STATUS_ACCESS_VIOLATION;
                    break;
                }
                *funcRef = reinterpret_cast<FARPROC>(
                    GetProcAddress(reinterpret_cast<HMODULE>(handle), reinterpret_cast<LPCSTR>(&thunkData->Name)));
            }
            if (!*funcRef) {
                status = STATUS_PROCEDURE_NOT_FOUND;
                break;
            }
        }

        if (!NT_SUCCESS(status)) {
            break;
        }
    }

    if (!NT_SUCCESS(status) && hMemoryModule->hModulesList) {
        HeapFree(GetProcessHeap(), 0, hMemoryModule->hModulesList);
        hMemoryModule->hModulesList = nullptr;
        hMemoryModule->dwModulesCount = 0;
    }

    return status;
}

extern "C" HMEMORYMODULE WINAPI MemoryLoadLibraryEx(
    const void* data,
    size_t size,
    CustomAllocFunc allocMemory,
    CustomFreeFunc freeMemory,
    CustomLoadLibraryFunc loadLibrary,
    CustomGetProcAddressFunc getProcAddress,
    CustomFreeLibraryFunc freeLibrary,
    void* userdata)
{
    // Use default allocation/free functions if nullptr is passed
    CustomAllocFunc allocFunc = allocMemory ? allocMemory : DefaultAlloc;
    CustomFreeFunc freeFunc = freeMemory ? freeMemory : DefaultFree;

    auto status = STATUS_SUCCESS;
    HMEMORYMODULE memoryModule = nullptr;
    PIMAGE_NT_HEADERS headers = nullptr;

    // Validate and extract headers without SEH
    const auto dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(const_cast<void*>(data));
    if (IsBadReadPtr(dos_header, sizeof(IMAGE_DOS_HEADER)) || dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
        return nullptr; // Invalid image format
    }

    const auto headerOffset = static_cast<const BYTE*>(data) + dos_header->e_lfanew;
    if (IsBadReadPtr(headerOffset, sizeof(IMAGE_NT_HEADERS))) {
        return nullptr; // Access violation
    }

    headers = reinterpret_cast<PIMAGE_NT_HEADERS>(const_cast<BYTE*>(headerOffset));
    if (headers->Signature != IMAGE_NT_SIGNATURE) {
        return nullptr; // Invalid image format
    }

    // Map image using MemoryLoadLibrary
    status = MemoryLoadLibrary(&memoryModule, data, static_cast<DWORD>(size));
    if (!NT_SUCCESS(status)) {
        return nullptr;
    }

    // Resolve imports using callbacks
    status = MemoryResolveImportTableCustom(
        reinterpret_cast<LPBYTE>(memoryModule),
        headers,
        reinterpret_cast<PMEMORYMODULE>(memoryModule),
        loadLibrary,
        userdata);
    if (!NT_SUCCESS(status)) {
        MemoryFreeLibrary(memoryModule);
        return nullptr;
    }

    // Set section protections
    status = MemorySetSectionProtection(
        reinterpret_cast<LPBYTE>(memoryModule),
        headers);
    if (!NT_SUCCESS(status)) {
        MemoryFreeLibrary(memoryModule);
        return nullptr;
    }

    // Call DLL entry point using LdrpCallInitializers
	const auto module = reinterpret_cast<PMEMORYMODULE>(memoryModule);
    if (!LdrpExecuteTLS(module) || !LdrpCallInitializers(module, DLL_PROCESS_ATTACH)) {
        std::cerr << "Warning: LdrpCallInitializers failed for module at " << memoryModule 
                  << " with error " << GetLastError() << ". Load aborted.\n";
        MemoryFreeLibrary(memoryModule);
        return nullptr;
    }

    return memoryModule;
}
