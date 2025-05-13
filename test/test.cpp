#include "../MemoryModule/stdafx.h"
#include "../MemoryModule/LoadDllMemoryApi.h"
#include <cstdio>
#include <string>
#pragma comment(lib,"ntdll.lib")

static void DisplayStatus() {
    printf(
        "\
MemoryModulePP [Version %d.%d%s]\n\n\t\
MmpFeatures = %08X\n\n\t\
LdrpModuleBaseAddressIndex = %p\n\t\
NtdllLdrEntry = %p\n\t\
RtlRbInsertNodeEx = %p\n\t\
RtlRbRemoveNode = %p\n\n\t\
LdrpInvertedFunctionTable = %p\n\n\t\
LdrpHashTable = %p\n\n\
",
        MmpGlobalDataPtr->MajorVersion,
        MEMORY_MODULE_GET_MINOR_VERSION(MmpGlobalDataPtr->MinorVersion),
        MEMORY_MODULE_IS_PREVIEW(MmpGlobalDataPtr->MinorVersion) ? " Preview" : "",
        MmpGlobalDataPtr->MmpFeatures,
        MmpGlobalDataPtr->MmpBaseAddressIndex->LdrpModuleBaseAddressIndex,
        MmpGlobalDataPtr->MmpBaseAddressIndex->NtdllLdrEntry,
        MmpGlobalDataPtr->MmpBaseAddressIndex->_RtlRbInsertNodeEx,
        MmpGlobalDataPtr->MmpBaseAddressIndex->_RtlRbRemoveNode,
        MmpGlobalDataPtr->MmpInvertedFunctionTable->LdrpInvertedFunctionTable,
        MmpGlobalDataPtr->MmpLdrEntry->LdrpHashTable
    );
}

static PVOID ReadDllFile(const std::string& FilePath) {
    LPVOID buffer;
    size_t size;
    FILE* f;
    fopen_s(&f, FilePath.c_str(), "rb");
    if (!f)return 0;
    _fseeki64(f, 0, SEEK_END);
    if (!(size = _ftelli64(f))) {
        fclose(f);
        return 0;
    }
    _fseeki64(f, 0, SEEK_SET);

    buffer = VirtualAlloc(0, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    fread(buffer, 1, size, f);
    fclose(f);
    return buffer;
}

static std::string ResolveWithModulePath(const std::string& dll_path)
{
    std::string rc(dll_path) ;

    // expect default dll in module directory
    CHAR path[MAX_PATH + 4];
    const auto len = GetModuleFileNameA(nullptr, path, sizeof(path));

    if (len) {
        const std::string mod_path(path);
        const auto last_slash = mod_path.find_last_of("/\\") ;
        rc = mod_path.substr(0, last_slash + 1) + dll_path;
    }

    return rc ;
}

int test(const std::string& dll_path) {

    HMODULE hModule = nullptr;
    FARPROC pfn = nullptr;

    typedef int(*_exception)(int code);
    _exception exception = nullptr;
    HRSRC hRsrc;
    DWORD SizeofRes;
    HGLOBAL gRes;
    char str[10];

    LPVOID buffer = ReadDllFile(dll_path);
    if ( !buffer ) {
        printf("failed to find %s.\n", dll_path.c_str());
        goto end;
    }
    printf("%s read into memory.\n", dll_path.c_str());

    if (!NT_SUCCESS(LdrLoadDllMemoryExW(&hModule, nullptr, 0, buffer, 0, L"kernel64", nullptr))) {
        printf("LdrLoadDllMemoryExW failed.\n");
        goto end;
    }

    //forward export
    pfn = (decltype(pfn))(GetProcAddress(hModule, "Socket")); //ws2_32.WSASocketW
    pfn = (decltype(pfn))(GetProcAddress(hModule, "VerifyTruse")); //wintrust.WinVerifyTrust

    //exception
    exception = (_exception)GetProcAddress(hModule, "exception");
    if (exception) {
        for (int i = 0; i < 5; ++i)exception(i);
    }

    //tls
    pfn = GetProcAddress(hModule, "thread");
    if (pfn && pfn()) {
        printf("thread test failed.\n");
    }

    //resource
    if (!LoadStringA(hModule, 101, str, 10)) {
        printf("load string failed.\n");
    }
    else {
        printf("%s\n", str);
    }
    if (!(hRsrc = FindResourceA(hModule, MAKEINTRESOURCEA(102), "BINARY"))) {
        printf("find binary resource failed.\n");
    }
    else {
        if ((SizeofRes = SizeofResource(hModule, hRsrc)) != 0x10) {
            printf("invalid res size.\n");
        }
        else {
            if (!(gRes = LoadResource(hModule, hRsrc))) {
                printf("load res failed.\n");
            }
            else {
                if (!LockResource(gRes))printf("lock res failed.\n");
                else {
                    printf("resource test success.\n");
                }
            }
        }
    }

end:
    LdrUnloadDllMemory(hModule);
    VirtualFree(buffer, 0, MEM_RELEASE);
    return 0;
}

int main(int argc, char* argv[]) {

    DisplayStatus();

    std::string dll_path("a.dll"); // default
    dll_path = argc > 1 ?  argv[1] : ResolveWithModulePath(dll_path);

    test(dll_path);

    return 0;
}
