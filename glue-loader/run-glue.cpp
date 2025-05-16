#include "../MemoryModule/stdafx.h"
#include "../MemoryModule/LoadDllMemoryApi.h"
#include "hfbfuncs.hpp"
#include "run-glue.hpp"
#include <iostream> // std::cerr
#include <cstdio>
#pragma comment(lib,"ntdll.lib")


#pragma comment(lib, "ntdll.lib")

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

// Helper to resolve "asv.hfb" into full path if needed
std::string resolve_hfb_path(const std::string& inputPath) {
    if (inputPath != "asv.hfb") {
        return inputPath;  // user gave a full/relative path
    }

    wchar_t buffer[MAX_PATH];
    DWORD len = GetCurrentDirectoryW(MAX_PATH, buffer);
    if (len == 0 || len >= MAX_PATH) {
        MessageBoxW(nullptr, L"Failed to get current directory.", L"Fatal Error", MB_ICONERROR);
        return inputPath; // fallback, may still work
    }

    std::wstring fullPath = buffer;
    fullPath += L"\\asv.hfb";
    return std::string(fullPath.begin(), fullPath.end());  // convert to UTF-8
}

HMODULE LoadAllDllsAndReturnGlueApp(const std::string& dbPathInput) {
    const std::string zone = "HFB";
    const std::string vfs = "crypto";
    const std::string dbPath = resolve_hfb_path(dbPathInput);

    // This is critical, the DLLs will not load if order is wrong
    const std::vector<std::string> dllLoadOrder = {
        "I77.dll",
        "Qt5CoreASVd.dll",
        "audit_customize.dll",
        "ibpp.dll",
        "nlopt.dll",
        "ntools.dll",
        "qhttpserver.dll",
        "rttr_core.dll",
        "rwtool.dll",
        "xlsx.dll",
        "yaml-cpp.dll",
        "F77.dll",
        "Qt5GuiASVd.dll",
        "Qt5NetworkASVd.dll",
        "Qt5XmlASVd.dll",
        "apptools.dll",
        "athread.dll",
        "tools.dll",
        "Qt5WidgetsASVd.dll",
        "Wt2.dll",
        "dynalift.dll",
        "oilcore1.dll",
        "ole.dll",
        "twophase.dll",
        "win31.dll",
        "Qt5PrintSupportASVd.dll",
        "Qt5SvgASVd.dll",
        "gtools.dll",
        "winhelp.dll",
        "oilcore2.dll",
        "glsupdll1.dll",
        "piapi.dll",
        "oilrunt.dll",
        "otools.dll",
        "glsupdll2.dll",
        "piapi_oil.dll",
        "asirpc.dll",
        "oilapi.dll",
        "oilapp.dll",
        "oilcomp.dll",
        "oilole.dll",
        "qtoil.dll",
        "Wt2_Oil.dll",
        "calc.dll",
        "dstng.dll",
        "glsuplib1.dll",
        "oildll.dll",
        "qtxlsx.dll",
        "network.dll",
        "glsuplib2.dll",
        "gluecomlib.dll",
        "dbobj.dll",
        "dstng_odbc.dll",
        "dstng_oracle.dll",
        "dstng_firebird.dll",
        "dstng_vanilla.dll",
        "gui.dll",
        "graphds.dll",
        "asv-settings-app.dll",
        "glueapp.dll",
    };
    HMODULE glueappModule = nullptr;

    for (const auto& dllName : dllLoadOrder) {
        auto buffer = load_member_with_objstore(dbPath, vfs, zone, dllName);
        if (buffer.empty()) {
            std::wstring msg = L"Failed to load " + std::wstring(dllName.begin(), dllName.end());
            MessageBoxW(nullptr, msg.c_str(), L"Load Error", MB_ICONERROR);
            continue;
        }

        HMODULE hMod = nullptr;
        std::wstring wideName(dllName.begin(), dllName.end());

//#define USE_MEMLOAD
#ifdef USE_MEMLOAD
        // MemoryLoadLibrary loads all DLLs but when glue-launch is called,
        // WinGLUE fails to open glueapp.dll error code 126.
        // Try LoadLibraryMemory,  but will not link. Postpone this until rebase with master.
        hMod = LoadLibraryMemory(buffer.data());

        if ( hMod == nullptr) {
            wchar_t msg[512];
            swprintf_s(msg, L"Failed to load %s", wideName.c_str());
#else
        // This call works.  Loads all DLLs then glue-launch successfully opens WinGLUE. 
        NTSTATUS status = LdrLoadDllMemoryExW(
            &hMod, nullptr, 0,
            buffer.data(), 0,
            wideName.c_str(), nullptr
        );

        if (status != 0 || hMod == nullptr) {
            wchar_t msg[512];
            swprintf_s(msg, L"Failed to load %s\nNTSTATUS: 0x%08X", wideName.c_str(), static_cast<unsigned int>(status));
#endif
            MessageBoxW(nullptr, msg, L"Load Error", MB_ICONERROR);
        }
        else if (dllName == "glueapp.dll") {
            glueappModule = hMod;
        }
    }

    return glueappModule;
}

extern "C" __declspec(dllexport)
int run_glue(int argc, const char* argv[], HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmdLine, int nCmdShow) {
    try {
        return launch_main(argc, argv, hInst, hPrev, lpCmdLine, nCmdShow);
    }
    catch (const std::exception& ex) {
        MessageBoxA(nullptr, ex.what(), "Unhandled Exception", MB_ICONERROR);
        return -1;
    }
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
    switch (fdwReason) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hinstDLL); // Optional: disables thread notifications
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}