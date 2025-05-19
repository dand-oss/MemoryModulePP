#pragma once
#include <Windows.h>

using HMEMORYMODULE = HMODULE;
using HCUSTOMMODULE = HMODULE;

// Callback type definitions (required for MemoryLoadLibraryEx)
typedef void* (WINAPI *CustomAllocFunc)(LPVOID, SIZE_T, DWORD, DWORD, void*);
typedef BOOL (WINAPI *CustomFreeFunc)(LPVOID, SIZE_T, DWORD, void*);
typedef HCUSTOMMODULE (WINAPI *CustomLoadLibraryFunc)(LPCSTR, void*);
typedef FARPROC (WINAPI *CustomGetProcAddressFunc)(HCUSTOMMODULE, LPCSTR, void*);
typedef void (WINAPI *CustomFreeLibraryFunc)(HCUSTOMMODULE, void*);

#include "Loader.h"
#include "Initialize.h"

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

extern "C" {

HMEMORYMODULE WINAPI LoadLibraryMemory(
    _In_ PVOID BufferAddress
);

HMEMORYMODULE WINAPI LoadLibraryMemoryExA(
    _In_ PVOID BufferAddress,
    _In_ size_t Reserved,
    _In_opt_ LPCSTR DllBaseName,
    _In_opt_ LPCSTR DllFullName,
    _In_ DWORD Flags
);

HMEMORYMODULE WINAPI LoadLibraryMemoryExW(
    _In_ PVOID BufferAddress,
    _In_ size_t Reserved,
    _In_opt_ LPCWSTR DllBaseName,
    _In_opt_ LPCWSTR DllFullName,
    _In_ DWORD Flags
);

BOOL WINAPI FreeLibraryMemory(
    _In_ HMEMORYMODULE hMemoryModule
);

HMEMORYMODULE WINAPI MemoryLoadLibraryEx(
    const void* data,
    size_t size,
    CustomAllocFunc allocMemory,
    CustomFreeFunc freeMemory,
    CustomLoadLibraryFunc loadLibrary,
    CustomGetProcAddressFunc getProcAddress,
    CustomFreeLibraryFunc freeLibrary,
    void* userdata) ;

#define NtLoadDllMemory LdrLoadDllMemory
#define NtLoadDllMemoryExA LdrLoadDllMemoryExA
#define NtLoadDllMemoryExW LdrLoadDllMemoryExW
#define NtUnloadDllMemory LdrUnloadDllMemory
#define NtUnloadDllMemoryAndExitThread LdrUnloadDllMemoryAndExitThread
#define FreeLibraryMemoryAndExitThread LdrUnloadDllMemoryAndExitThread
#define NtQuerySystemMemoryModuleFeatures LdrQuerySystemMemoryModuleFeatures

#ifdef UNICODE
#define LdrLoadDllMemoryEx LdrLoadDllMemoryExW
#define LoadLibraryMemoryEx LoadLibraryMemoryExW
#else
#define LdrLoadDllMemoryEx LdrLoadDllMemoryExA
#define LoadLibraryMemoryEx LoadLibraryMemoryExA
#endif
#define NtLoadDllMemoryEx LdrLoadDllMemoryEx

}