#include "stdafx.h"
#include <3rdparty/Detours/detours.h>

typedef struct _MMP_FAKE_HANDLE_LIST_ENTRY {
    LIST_ENTRY InMmpFakeHandleList;
    HANDLE hObject;
    PVOID value;
    BOOL bImageMapping;
}MMP_FAKE_HANDLE_LIST_ENTRY, * PMMP_FAKE_HANDLE_LIST_ENTRY;

BOOL MmpIsMemoryModuleFileName(
    _In_ LPCWSTR lpFileName,
    _Out_opt_ PLDR_DATA_TABLE_ENTRY *LdrEntry) {

    __try {
        if (LdrEntry)*LdrEntry = nullptr;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }

    BOOL result = FALSE;

    EnterCriticalSection(NtCurrentPeb()->LoaderLock);
    for (auto entry = NtCurrentPeb()->Ldr->InLoadOrderModuleList.Flink;
        entry != &NtCurrentPeb()->Ldr->InLoadOrderModuleList;
        entry = entry->Flink) {

        PLDR_DATA_TABLE_ENTRY CurEntry = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, LDR_DATA_TABLE_ENTRY::InLoadOrderLinks);
        if (!wcsncmp(CurEntry->FullDllName.Buffer, lpFileName, CurEntry->FullDllName.Length) &&
            wcslen(lpFileName) * 2 == CurEntry->FullDllName.Length) {
            result = IsValidMemoryModuleHandle(static_cast<HMODULE>(CurEntry->DllBase));
            if (result) {
                if (LdrEntry) {
                    __try {
                        *LdrEntry = CurEntry;
                    }
                    __except (EXCEPTION_EXECUTE_HANDLER) {
                        ;
                    }
                }
            }

            break;
        }

    }
    LeaveCriticalSection(NtCurrentPeb()->LoaderLock);

    return result;
}

VOID MmpInsertHandleEntry(
    _In_ HANDLE hObject,
    _In_ PVOID value,
    _In_ BOOL bImageMapping = FALSE) {
    auto entry = static_cast<PMMP_FAKE_HANDLE_LIST_ENTRY>(RtlAllocateHeap(RtlProcessHeap(), HEAP_ZERO_MEMORY, sizeof(MMP_FAKE_HANDLE_LIST_ENTRY)));
    entry->hObject = hObject;
    entry->value = value;
    entry->bImageMapping = bImageMapping;

    EnterCriticalSection(&GetMmpGlobalDataPtr()->MmpDotNet->MmpFakeHandleListLock);
    InsertTailList(&GetMmpGlobalDataPtr()->MmpDotNet->MmpFakeHandleListHead, &entry->InMmpFakeHandleList);
    LeaveCriticalSection(&GetMmpGlobalDataPtr()->MmpDotNet->MmpFakeHandleListLock);
}

PMMP_FAKE_HANDLE_LIST_ENTRY MmpFindHandleEntry(HANDLE hObject) {

    PMMP_FAKE_HANDLE_LIST_ENTRY result = nullptr;
    EnterCriticalSection(&GetMmpGlobalDataPtr()->MmpDotNet->MmpFakeHandleListLock);

    for (auto entry = GetMmpGlobalDataPtr()->MmpDotNet->MmpFakeHandleListHead.Flink; entry != &GetMmpGlobalDataPtr()->MmpDotNet->MmpFakeHandleListHead; entry = entry->Flink) {
        auto CurEntry = CONTAINING_RECORD(entry, MMP_FAKE_HANDLE_LIST_ENTRY, MMP_FAKE_HANDLE_LIST_ENTRY::InMmpFakeHandleList);

        if (CurEntry->hObject == hObject) {
            result = CurEntry;
            break;
        }

    }

    LeaveCriticalSection(&GetMmpGlobalDataPtr()->MmpDotNet->MmpFakeHandleListLock);
    return result;
}

VOID MmpFreeHandleEntry(PMMP_FAKE_HANDLE_LIST_ENTRY lpHandleEntry) {
    EnterCriticalSection(&GetMmpGlobalDataPtr()->MmpDotNet->MmpFakeHandleListLock);
    RemoveEntryList(&lpHandleEntry->InMmpFakeHandleList);
    RtlFreeHeap(RtlProcessHeap(), 0, lpHandleEntry);
    LeaveCriticalSection(&GetMmpGlobalDataPtr()->MmpDotNet->MmpFakeHandleListLock);
}

HANDLE WINAPI HookCreateFileW(
    _In_ LPCWSTR lpFileName,
    _In_ DWORD dwDesiredAccess,
    _In_ DWORD dwShareMode,
    _In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    _In_ DWORD dwCreationDisposition,
    _In_ DWORD dwFlagsAndAttributes,
    _In_opt_ HANDLE hTemplateFile) {

    PLDR_DATA_TABLE_ENTRY entry;
    if (MmpIsMemoryModuleFileName(lpFileName, &entry)) {
        HANDLE hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);

        MmpInsertHandleEntry(hEvent, entry);
        return hEvent;
    }

    return GetMmpGlobalDataPtr()->MmpDotNet->Hooks.OriginCreateFileW(
        lpFileName,
        dwDesiredAccess,
        dwShareMode,
        lpSecurityAttributes,
        dwCreationDisposition,
        dwFlagsAndAttributes,
        hTemplateFile
    );
}

BOOL WINAPI HookGetFileInformationByHandle(
    _In_ HANDLE hFile,
    _Out_ LPBY_HANDLE_FILE_INFORMATION lpFileInformation) {
    auto iter = MmpFindHandleEntry(hFile);
    if (iter) {
        RtlZeroMemory(lpFileInformation, sizeof(BY_HANDLE_FILE_INFORMATION));

        auto entry = (PLDR_DATA_TABLE_ENTRY)iter->value;
        auto module = MapMemoryModuleHandle(static_cast<HMEMORYMODULE>(entry->DllBase));

        lpFileInformation->ftCreationTime = lpFileInformation->ftLastAccessTime = lpFileInformation->ftLastWriteTime = GetMmpGlobalDataPtr()->MmpDotNet->AssemblyTimes;
        lpFileInformation->nFileSizeLow = module->dwImageFileSize;

        return TRUE;
    }
    else {
        return GetMmpGlobalDataPtr()->MmpDotNet->Hooks.OriginGetFileInformationByHandle(
            hFile,
            lpFileInformation
        );
    }
}

BOOL WINAPI HookGetFileAttributesExW(
    _In_ LPCWSTR lpFileName,
    _In_ GET_FILEEX_INFO_LEVELS fInfoLevelId,
    _Out_writes_bytes_(static_cast<sizeof>(WIN32_FILE_ATTRIBUTE_DATA)) LPVOID lpFileInformation) {

    PLDR_DATA_TABLE_ENTRY entry;
    if (MmpIsMemoryModuleFileName(lpFileName, &entry)) {
        __try {
            RtlZeroMemory(
                lpFileInformation,
                sizeof(WIN32_FILE_ATTRIBUTE_DATA)
            );

            LPWIN32_FILE_ATTRIBUTE_DATA data = static_cast<LPWIN32_FILE_ATTRIBUTE_DATA>(lpFileInformation);
            auto module = MapMemoryModuleHandle(static_cast<HMEMORYMODULE>(entry->DllBase));

            data->ftCreationTime = data->ftLastAccessTime = data->ftLastWriteTime = GetMmpGlobalDataPtr()->MmpDotNet->AssemblyTimes;
            data->nFileSizeLow = module->dwImageFileSize;
            return TRUE;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return FALSE;
        }
    }

    return GetMmpGlobalDataPtr()->MmpDotNet->Hooks.OriginGetFileAttributesExW(
        lpFileName,
        fInfoLevelId,
        lpFileInformation
    );
}

DWORD WINAPI HookGetFileSize(
    _In_ HANDLE hFile,
    _Out_opt_ LPDWORD lpFileSizeHigh) {

    auto iter = MmpFindHandleEntry(hFile);
    if (iter) {
        if (lpFileSizeHigh)*lpFileSizeHigh = 0;

        auto entry = static_cast<PLDR_DATA_TABLE_ENTRY>(iter->value);
        auto module = MapMemoryModuleHandle(static_cast<HMEMORYMODULE>(entry->DllBase));

        return module->dwImageFileSize;
    }
    else {
        return GetMmpGlobalDataPtr()->MmpDotNet->Hooks.OriginGetFileSize(
            hFile,
            lpFileSizeHigh
        );
    }

}

BOOL WINAPI HookGetFileSizeEx(
    _In_ HANDLE hFile,
    _Out_ PLARGE_INTEGER lpFileSize) {

    auto iter = MmpFindHandleEntry(hFile);
    if (iter) {
        auto entry = static_cast<PLDR_DATA_TABLE_ENTRY>(iter->value);
        auto module = MapMemoryModuleHandle(static_cast<HMEMORYMODULE>(entry->DllBase));

        lpFileSize->QuadPart = module->dwImageFileSize;
        return TRUE;
    }
    else {
        return GetMmpGlobalDataPtr()->MmpDotNet->Hooks.OriginGetFileSizeEx(
            hFile,
            lpFileSize
        );
    }

}

HANDLE WINAPI HookCreateFileMappingW(
    _In_     HANDLE hFile,
    _In_opt_ LPSECURITY_ATTRIBUTES lpFileMappingAttributes,
    _In_     DWORD flProtect,
    _In_     DWORD dwMaximumSizeHigh,
    _In_     DWORD dwMaximumSizeLow,
    _In_opt_ LPCWSTR lpName) {

    auto iter = MmpFindHandleEntry(hFile);
    if (iter) {
        HANDLE hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        
        MmpInsertHandleEntry(hEvent, iter->value, !!(flProtect & SEC_IMAGE));
        return hEvent;
    }

    return GetMmpGlobalDataPtr()->MmpDotNet->Hooks.OriginCreateFileMappingW(
        hFile,
        lpFileMappingAttributes,
        flProtect,
        dwMaximumSizeHigh,
        dwMaximumSizeLow,
        lpName
    );
}

LPVOID WINAPI HookMapViewOfFileEx(
    _In_ HANDLE hFileMappingObject,
    _In_ DWORD dwDesiredAccess,
    _In_ DWORD dwFileOffsetHigh,
    _In_ DWORD dwFileOffsetLow,
    _In_ SIZE_T dwNumberOfBytesToMap,
    _In_opt_ LPVOID lpBaseAddress) {

    auto iter = MmpFindHandleEntry(hFileMappingObject);
    if (iter) {
        HMEMORYMODULE hModule = nullptr;
        auto entry = (PLDR_DATA_TABLE_ENTRY)iter->value;
        auto pModule = MapMemoryModuleHandle(static_cast<HMEMORYMODULE>(entry->DllBase));
        if (pModule) {
            if (iter->bImageMapping) {
                MemoryLoadLibrary(&hModule, pModule->lpReserved, pModule->dwImageFileSize);
                if (hModule) MmpInsertHandleEntry(hModule, hModule);
            }
            else {
                return pModule->lpReserved;
            }
        }

        return hModule;
    }

    return GetMmpGlobalDataPtr()->MmpDotNet->Hooks.OriginMapViewOfFileEx(
        hFileMappingObject,
        dwDesiredAccess,
        dwFileOffsetHigh,
        dwFileOffsetLow,
        dwNumberOfBytesToMap,
        lpBaseAddress
    );
}

LPVOID WINAPI HookMapViewOfFile(
    _In_ HANDLE hFileMappingObject,
    _In_ DWORD dwDesiredAccess,
    _In_ DWORD dwFileOffsetHigh,
    _In_ DWORD dwFileOffsetLow,
    _In_ SIZE_T dwNumberOfBytesToMap) {

    return HookMapViewOfFileEx(
        hFileMappingObject,
        dwDesiredAccess,
        dwFileOffsetHigh,
        dwFileOffsetLow,
        dwNumberOfBytesToMap,
        nullptr
    );

}

BOOL WINAPI HookUnmapViewOfFile(_In_ LPCVOID lpBaseAddress) {
    auto iter = MmpFindHandleEntry((HANDLE)lpBaseAddress);
    if (iter) {
        MemoryFreeLibrary((HMEMORYMODULE)lpBaseAddress);
        MmpFreeHandleEntry(iter);
        return TRUE;
    }

    return GetMmpGlobalDataPtr()->MmpDotNet->Hooks.OriginUnmapViewOfFile(lpBaseAddress);
}

BOOL WINAPI HookCloseHandle(_In_ _Post_ptr_invalid_ HANDLE hObject) {
    auto iter = MmpFindHandleEntry(hObject);
    if (iter)MmpFreeHandleEntry(iter);

    return GetMmpGlobalDataPtr()->MmpDotNet->Hooks.OriginCloseHandle(hObject);
}

HRESULT WINAPI HookGetFileVersion(
    LPCWSTR szFilename,
    LPWSTR szBuffer,
    DWORD cchBuffer,
    DWORD* dwLength) {

    typedef struct _COR20_METADATA {
        DWORD Signature;
        WORD MajorVersion;
        WORD MinorVersion;
        DWORD Reserved;
        DWORD VersionLength;
        CHAR VersionString[ANYSIZE_ARRAY];
    }COR20_METADATA, * PCOR20_METADATA;

    PLDR_DATA_TABLE_ENTRY entry = nullptr;

    if (MmpIsMemoryModuleFileName(szFilename, &entry)) {

        __try {
            PIMAGE_NT_HEADERS headers = RtlImageNtHeader(entry->DllBase);
            auto dir = headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR];
            if (!dir.Size || !dir.VirtualAddress)__leave;

            PIMAGE_COR20_HEADER cor2 = PIMAGE_COR20_HEADER(static_cast<LPBYTE>(entry->DllBase) + dir.VirtualAddress);
            if (!cor2->MetaData.Size || !cor2->MetaData.VirtualAddress) __leave;

            PCOR20_METADATA meta = PCOR20_METADATA(static_cast<LPBYTE>(entry->DllBase) + cor2->MetaData.VirtualAddress);
            if (dwLength)*dwLength = meta->VersionLength;
            if (cchBuffer < meta->VersionLength)return 0x8007007A;
            
            MultiByteToWideChar(CP_ACP, 0, meta->VersionString, meta->VersionLength, szBuffer, cchBuffer);
            return 0;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            ;
        }

    }

    return GetMmpGlobalDataPtr()->MmpDotNet->Hooks.OriginGetFileVersion1(
        szFilename,
        szBuffer,
        cchBuffer,
        dwLength
    );
}

BOOL WINAPI MmpPreInitializeHooksForDotNet() {

    EnterCriticalSection(NtCurrentPeb()->FastPebLock);

    if (!GetMmpGlobalDataPtr()->MmpDotNet->PreHooked) {
        HMODULE hModule = LoadLibraryW(L"mscoree.dll");
        if (hModule) {
            GetMmpGlobalDataPtr()->MmpDotNet->Hooks.OriginGetFileVersion2 = (GetFileVersion_T)GetProcAddress(hModule, "GetFileVersion");
            if (GetMmpGlobalDataPtr()->MmpDotNet->Hooks.OriginGetFileVersion2) {

                GetSystemTimeAsFileTime(&GetMmpGlobalDataPtr()->MmpDotNet->AssemblyTimes);

                InitializeCriticalSection(&GetMmpGlobalDataPtr()->MmpDotNet->MmpFakeHandleListLock);
                InitializeListHead(&GetMmpGlobalDataPtr()->MmpDotNet->MmpFakeHandleListHead);

                GetMmpGlobalDataPtr()->MmpDotNet->Hooks.OriginCreateFileW = CreateFileW;
                GetMmpGlobalDataPtr()->MmpDotNet->Hooks.OriginGetFileInformationByHandle = GetFileInformationByHandle;
                GetMmpGlobalDataPtr()->MmpDotNet->Hooks.OriginGetFileAttributesExW = GetFileAttributesExW;
                GetMmpGlobalDataPtr()->MmpDotNet->Hooks.OriginGetFileSize = GetFileSize;
                GetMmpGlobalDataPtr()->MmpDotNet->Hooks.OriginGetFileSizeEx = GetFileSizeEx;
                GetMmpGlobalDataPtr()->MmpDotNet->Hooks.OriginCreateFileMappingW = CreateFileMappingW;
                GetMmpGlobalDataPtr()->MmpDotNet->Hooks.OriginMapViewOfFileEx = MapViewOfFileEx;
                GetMmpGlobalDataPtr()->MmpDotNet->Hooks.OriginMapViewOfFile = MapViewOfFile;
                GetMmpGlobalDataPtr()->MmpDotNet->Hooks.OriginUnmapViewOfFile = UnmapViewOfFile;
                GetMmpGlobalDataPtr()->MmpDotNet->Hooks.OriginCloseHandle = CloseHandle;

                DetourTransactionBegin();
                DetourUpdateThread(NtCurrentThread());

                DetourAttach((PVOID*)&GetMmpGlobalDataPtr()->MmpDotNet->Hooks.OriginCreateFileW, HookCreateFileW);
                DetourAttach((PVOID*)&GetMmpGlobalDataPtr()->MmpDotNet->Hooks.OriginGetFileInformationByHandle, HookGetFileInformationByHandle);
                DetourAttach((PVOID*)&GetMmpGlobalDataPtr()->MmpDotNet->Hooks.OriginGetFileAttributesExW, HookGetFileAttributesExW);
                DetourAttach((PVOID*)&GetMmpGlobalDataPtr()->MmpDotNet->Hooks.OriginGetFileSize, HookGetFileSize);
                DetourAttach((PVOID*)&GetMmpGlobalDataPtr()->MmpDotNet->Hooks.OriginGetFileSizeEx, HookGetFileSizeEx);
                DetourAttach((PVOID*)&GetMmpGlobalDataPtr()->MmpDotNet->Hooks.OriginCreateFileMappingW, HookCreateFileMappingW);
                DetourAttach((PVOID*)&GetMmpGlobalDataPtr()->MmpDotNet->Hooks.OriginMapViewOfFileEx, HookMapViewOfFileEx);
                DetourAttach((PVOID*)&GetMmpGlobalDataPtr()->MmpDotNet->Hooks.OriginMapViewOfFile, HookMapViewOfFile);
                DetourAttach((PVOID*)&GetMmpGlobalDataPtr()->MmpDotNet->Hooks.OriginUnmapViewOfFile, HookUnmapViewOfFile);
                DetourAttach((PVOID*)&GetMmpGlobalDataPtr()->MmpDotNet->Hooks.OriginCloseHandle, HookCloseHandle);
                DetourAttach((PVOID*)&GetMmpGlobalDataPtr()->MmpDotNet->Hooks.OriginGetFileVersion2, HookGetFileVersion);

                DetourTransactionCommit();

                GetMmpGlobalDataPtr()->MmpDotNet->PreHooked = TRUE;
            }
        }
    }

    LeaveCriticalSection(NtCurrentPeb()->FastPebLock);

    return GetMmpGlobalDataPtr()->MmpDotNet->PreHooked;
}

BOOL WINAPI MmpInitializeHooksForDotNet() {
    HMODULE hModule = GetModuleHandleW(L"mscoreei.dll");
    if (hModule) {
        GetMmpGlobalDataPtr()->MmpDotNet->Hooks.OriginGetFileVersion1 = (GetFileVersion_T)GetProcAddress(hModule, "GetFileVersion");
        if (GetMmpGlobalDataPtr()->MmpDotNet->Hooks.OriginGetFileVersion1) {

            EnterCriticalSection(NtCurrentPeb()->FastPebLock);

            if (!GetMmpGlobalDataPtr()->MmpDotNet->PreHooked) {
                LeaveCriticalSection(NtCurrentPeb()->FastPebLock);
                return FALSE;
            }

            if (!GetMmpGlobalDataPtr()->MmpDotNet->Initialized) {
                DetourTransactionBegin();
                DetourUpdateThread(NtCurrentThread());
                DetourAttach((PVOID*)&GetMmpGlobalDataPtr()->MmpDotNet->Hooks.OriginGetFileVersion1, HookGetFileVersion);
                DetourTransactionCommit();
                GetMmpGlobalDataPtr()->MmpDotNet->Initialized = TRUE;
            }

            LeaveCriticalSection(NtCurrentPeb()->FastPebLock);
            return TRUE;
        }
    }

    return FALSE;
}

VOID WINAPI MmpCleanupDotNetHooks() {
    EnterCriticalSection(NtCurrentPeb()->FastPebLock);

    if (GetMmpGlobalDataPtr()->MmpDotNet->PreHooked) {
        DetourTransactionBegin();
        DetourUpdateThread(NtCurrentThread());

        DetourDetach((PVOID*)&GetMmpGlobalDataPtr()->MmpDotNet->Hooks.OriginCreateFileW, HookCreateFileW);
        DetourDetach((PVOID*)&GetMmpGlobalDataPtr()->MmpDotNet->Hooks.OriginGetFileInformationByHandle, HookGetFileInformationByHandle);
        DetourDetach((PVOID*)&GetMmpGlobalDataPtr()->MmpDotNet->Hooks.OriginGetFileAttributesExW, HookGetFileAttributesExW);
        DetourDetach((PVOID*)&GetMmpGlobalDataPtr()->MmpDotNet->Hooks.OriginGetFileSize, HookGetFileSize);
        DetourDetach((PVOID*)&GetMmpGlobalDataPtr()->MmpDotNet->Hooks.OriginGetFileSizeEx, HookGetFileSizeEx);
        DetourDetach((PVOID*)&GetMmpGlobalDataPtr()->MmpDotNet->Hooks.OriginCreateFileMappingW, HookCreateFileMappingW);
        DetourDetach((PVOID*)&GetMmpGlobalDataPtr()->MmpDotNet->Hooks.OriginMapViewOfFileEx, HookMapViewOfFileEx);
        DetourDetach((PVOID*)&GetMmpGlobalDataPtr()->MmpDotNet->Hooks.OriginMapViewOfFile, HookMapViewOfFile);
        DetourDetach((PVOID*)&GetMmpGlobalDataPtr()->MmpDotNet->Hooks.OriginUnmapViewOfFile, HookUnmapViewOfFile);
        DetourDetach((PVOID*)&GetMmpGlobalDataPtr()->MmpDotNet->Hooks.OriginCloseHandle, HookCloseHandle);
        DetourDetach((PVOID*)&GetMmpGlobalDataPtr()->MmpDotNet->Hooks.OriginGetFileVersion2, HookGetFileVersion);

        DetourTransactionCommit();

        GetMmpGlobalDataPtr()->MmpDotNet->PreHooked = FALSE;
    }

    if (GetMmpGlobalDataPtr()->MmpDotNet->Initialized) {
        DetourTransactionBegin();
        DetourUpdateThread(NtCurrentThread());
        DetourDetach((PVOID*)&GetMmpGlobalDataPtr()->MmpDotNet->Hooks.OriginGetFileVersion1, HookGetFileVersion);
        DetourTransactionCommit();
        GetMmpGlobalDataPtr()->MmpDotNet->Initialized = FALSE;
    }

    LeaveCriticalSection(NtCurrentPeb()->FastPebLock);
}
