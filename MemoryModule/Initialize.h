#pragma once

NTSTATUS NTAPI MmInitialize();
NTSTATUS NTAPI MmCleanup();

//
// This function is available only if the MMPP is compiled as a DLL.
//
#ifdef _USRDLL
extern "C" __declspec(dllexport) BOOL WINAPI ReflectiveMapDll(HMODULE hModule) ;
#endif
