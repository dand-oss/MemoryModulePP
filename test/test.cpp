#include "stdafx.h"
#include "LoadDllMemoryApi.h"
#include <cstdio>
#include <string>
#pragma comment(lib,"ntdll.lib")

static int DisplayStatus() {
    const auto gdp = GetMmpGlobalDataPtr();
    if ( !gdp ) {
        printf("failed GetMmpGlobalDataPtr().\n");
        return -1 ;
    }
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
        gdp->MajorVersion,
        MEMORY_MODULE_GET_MINOR_VERSION(gdp->MinorVersion),
        MEMORY_MODULE_IS_PREVIEW(gdp->MinorVersion) ? " Preview" : "",
        gdp->MmpFeatures,
        (PVOID)gdp->MmpBaseAddressIndex->LdrpModuleBaseAddressIndex,
        (PVOID)gdp->MmpBaseAddressIndex->NtdllLdrEntry,
        gdp->MmpBaseAddressIndex->_RtlRbInsertNodeEx,
        gdp->MmpBaseAddressIndex->_RtlRbRemoveNode,
        gdp->MmpInvertedFunctionTable->LdrpInvertedFunctionTable,
        (PVOID)gdp->MmpLdrEntry->LdrpHashTable
    );
    return 0 ;
}

static PVOID ReadDllFile(const std::string& FilePath) {
    size_t size;
    FILE* f;
    fopen_s(&f, FilePath.c_str(), "rb");
    if (!f) return nullptr;
    _fseeki64(f, 0, SEEK_END);
    if (!(size = _ftelli64(f))) {
        fclose(f);
        return nullptr;
    }
    _fseeki64(f, 0, SEEK_SET);

    auto buffer = VirtualAlloc(0, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

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

static void test_fwd_export(HMODULE hModule)
{
    FARPROC pfn;
    pfn = (decltype(pfn))(GetProcAddress(hModule, "Socket")); //ws2_32.WSASocketW
    pfn = (decltype(pfn))(GetProcAddress(hModule, "VerifyTruse")); //wintrust.WinVerifyTrust
}

static void test_exception(HMODULE hModule)
{
    using _exception = int(*)(int code);
    _exception exception = nullptr;

    exception = (_exception)GetProcAddress(hModule, "exception");
    if (exception) {
        for (int i = 0; i < 5; ++i) {
            exception(i);
        }
    }
}

static void test_tls(HMODULE hModule)
{
    auto pfn = GetProcAddress(hModule, "thread");
    if (pfn && pfn()) {
        printf("thread test failed.\n");
    }
}

static void test_resource(HMODULE hModule)
{
    char str[10];
    if (!LoadStringA(hModule, 101, str, 10)) {
        printf("load string failed.\n");
    }
    else {
        printf("%s\n", str);
    }

    HRSRC hRsrc;
    if (!(hRsrc = FindResourceA(hModule, MAKEINTRESOURCEA(102), "BINARY"))) {
        printf("find binary resource failed.\n");
    }
    else {
        DWORD SizeofRes;
        if ((SizeofRes = SizeofResource(hModule, hRsrc)) != 0x10) {
            printf("invalid res size.\n");
        }
        else {
            HGLOBAL gRes;
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
}

static void test_ref_count(HMODULE hModule, const std::string& dll_path)
{
    // print the reference count
    const auto init_refcount = MemoryRefCount(hModule) ;
    printf("%d reference for %s after LoadLibraryMemory()\n",
        init_refcount, dll_path.c_str() );

    // load the same dll via windows
    // which should increase reference count each time
    const auto num_loads = 10 ;
    for ( auto ii = num_loads ; ii-- ; ) {
        const auto mod = LoadLibraryA(dll_path.c_str());
        if (!mod) {
            printf("LoadLibraryA() failed\n");
            break;
        }
    }

    // report reference result
    const auto final_refs = MemoryRefCount(hModule);
    const auto expected_refs = num_loads + init_refcount ;
    if ( final_refs != expected_refs) {
        printf("ERROR LoadLibraryA() ignored: final_refs(%d) != expected_refs(%d)\n",
            final_refs, expected_refs);
    }
    else {
        printf("Hey DLL reference counting started working!\n");
    }

    // have windows let go..
    /*
    for ( auto ii = num_loads ; ii-- ; ) {
        FreeLibrary(hModule);
    }
    */
}

int test(const std::string& dll_path) {

    HMODULE hModule = nullptr;
    FARPROC pfn = nullptr;

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

    test_fwd_export(hModule) ;
    test_exception(hModule) ;
    test_tls(hModule) ;
    test_resource(hModule) ;
    test_ref_count(hModule, dll_path);

end:
    LdrUnloadDllMemory(hModule);
    VirtualFree(buffer, 0, MEM_RELEASE);
    return 0;
}

int main(int argc, char* argv[]) {

    // check MemoryModulePP initialization
    if ( DisplayStatus() ) {
        return -1 ;
    }

    std::string dll_path("a.dll"); // default
    dll_path = argc > 1 ?  argv[1] : ResolveWithModulePath(dll_path);

    test(dll_path);

    return 0;
}
