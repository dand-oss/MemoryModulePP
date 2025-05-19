// ========================================================================== //
// Copyright (c) 2017 by AppSmiths Software LLC.  All Rights Reserved.        //
// -------------------------------------------------------------------------- //
// All material is proprietary to AppSmiths Software LLC and may be used only //
// pursuant to license rights granted by AppSmiths Software LLC.  Other       //
// reproduction, distribution, or use is strictly prohibited.                 //
// ========================================================================== //

#undef WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "api-set.hpp"
#include <sqlite3pp.h>
#include <LoadDllMemoryApi.h> // LoadLibraryMemoryExA, NTSTATUS
#include <MemoryModule.h> // needed for ImportTable.h
#include <ImportTable.h> // MmRegisterImportTableResolver
#include <iostream>
#include <filesystem>
#include <expected>
#include <format>
#include <map>
#include <set>

// #include <ntstatus.h>
#define STATUS_SUCCESS                   ((NTSTATUS)0x00000000L)
#define STATUS_NOT_SUPPORTED             ((NTSTATUS)0xC00000BBL)

/*

DLL ReferenceCount is claimed to be stored in

LDR_DATA_TABLE_ENTRY
https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/ntldr/ldr_data_table_entry.htm

ULONG ReferenceCount;
10.0 and higher
32: 0x9C
64: 0x0114

LdrEntry.h
ULONG ReferenceCount;                                                     //0x114

However,

// load a dll in mmpp
LdrLoadDllMemoryExW(my_dll_name)

LDR.ReferenceCount == 1

// load same dll in MMP
LoadLibary(my_dll_name)

LDR.ReferenceCount == 1

> LDR.ReferenceCount observed in MMPP is not changed

 */

namespace fs = std::filesystem;

struct DllInfo {
    std::string name;
    fs::path path_name;
    HMODULE module = nullptr;
    size_t size = 0;
    bool success = false;
    bool failLoadLibraryMemory = false;
    bool failLoadLibraryA = false;
    std::string error_message;
    bool skipped = false;
    bool skippedApiSet = false;
    bool skippedAlreadyLoaded = false;
    bool skippedNotOurs = false;

    std::string module_str() const {
        return std::format("{:p}", static_cast<void*>(module));
    }
};

// Global vector to track all DLL loading attempts
static std::vector<DllInfo> dllLoadLog;

// Static variable to store the database path for preloadDllImportFromDb
static std::string g_dbPath;

// handle of our resolver in MemoryModulePP resolver list
static HANDLE g_resolverHandle;

// control printing
static bool g_verbose;

// holds the dll handles we loaded
static std::map<HMODULE, DllInfo> db_dlls ;

// Function to convert bytes to MB
static double toMB(size_t bytes) {
    return static_cast<double>(bytes) / 1024.0 / 1024.0;
}

// Portable logging wrappers using std::format_string
template<typename... Args>
void logInfo(std::format_string<Args...> fmt, Args&&... args) {
    if (g_verbose) {
        std::cout << std::format(fmt, std::forward<Args>(args)...) << std::endl;
    }
}

template<typename... Args>
void logError(std::format_string<Args...> fmt, Args&&... args) {
    std::cerr << std::format(fmt, std::forward<Args>(args)...) << std::endl;
}

// Normalize DLL name by appending .dll if missing
static std::string normalizeDllName(const std::string& dllName) {
    fs::path path(dllName);
    if (path.extension() == ".dll" || path.extension() == ".DLL") {
        return dllName;
    }
    return std::format("{}.dll", dllName);
}

static std::string get_file_name(HMODULE module)
{
    std::string rc("null-module");
    if ( module) {
        std::vector<char> buffer(MAX_PATH);
        // get module name
        const auto len = GetModuleFileNameA(
            module,
            buffer.data(),
            buffer.size());

        if (!len || len >= buffer.size()) {
            logError("GetModuleFilename({:p}) failed {}",
                static_cast<void*>(module),
                GetLastError());
            rc = "error-module";
        }
        else {
            rc = buffer.data();
        }
    }
    return rc;
}

// Perform the actual DLL loading
[[nodiscard]]
static std::expected<HMODULE, std::string> loadLibraryMemory(
    std::vector<unsigned char> buffer,
    const std::string& dllName,
    const fs::path& dllPath)
{
    logInfo("-> LibraryMemoryExA({})", dllName);
    std::expected<HMODULE, std::string> rc ;
    const auto module = LoadLibraryMemoryExA(
        buffer.data(),
        buffer.size(),
        dllName.c_str(),
        dllPath.string().c_str(),
        0);
    if (module) {
        // success
        rc = module ;
    }
    else {
        // return failure
        const auto& error = std::format(
            "FAILED: LoadLibraryMemoryExA({}) {}",
            dllName,
            GetLastError());
        logError("{}", error);
        rc = std::unexpected(error);
    }
    logInfo("<- LibraryMemoryExA({}) {:p}", dllName, static_cast<void*>(module));
    return rc;
}

// Read DLL data from database
[[nodiscard]]
static std::expected<
    std::pair<std::vector<unsigned char>, std::string>,
    std::string>
readFromDatabase(
    const std::string& dbPath,
    const std::string& dllName)
{
    try {
        // open the database
        sqlite3pp::database db(dbPath.c_str(), SQLITE_OPEN_READONLY);

        // get dll info
        sqlite3pp::query qry(db, "SELECT data, full_path FROM dlls WHERE name = ? COLLATE NOCASE");
        qry.bind(1, dllName, sqlite3pp::copy);
        const auto& it = qry.begin();
        if (it == qry.end()) {
            // logInfo("{} not found in database", dllName);
            return std::unexpected(std::format("{} not found in database", dllName));
        }

        // check size
        const auto blobSize = (*it).column_bytes(0);
        if (blobSize > SIZE_MAX) {
            logError("Error: SQLite blobSize {} too large for DLL {}", blobSize, dllName);
            return std::unexpected(std::format("SQLite blobSize {} too large for DLL {}", blobSize, dllName));
        }

        // copy the data out
        const auto buf_size = static_cast<size_t>(blobSize);
        const auto blob = static_cast<const char*>((*it).get<const void*>(0));
        const auto& full_path = (*it).get<std::string>(1);
        return std::pair<std::vector<unsigned char>, std::string>(
            std::vector<unsigned char>(blob, blob + buf_size),
            full_path) ;

    } catch (const sqlite3pp::database_error& e) {

        // nope
        logError("Error: Database error for DLL {}: {}", dllName, e.what());
        return std::unexpected(std::format("Database error for DLL {}: {}", dllName, e.what()));
    }
}

// Common logic to load DLL data
static HMODULE loadDllFromDb(
    const std::string& dllName,
    const std::string& dbPath)
{
    DllInfo dllInfo{.name = dllName};

    // Check if DLL is an API set
    if (dllInfo.name.find("api-ms-win-") == 0 || IsApiSetDllByNamespace(dllInfo.name))
    {
        // api set is not a file or db, record skipped
        dllInfo.skipped = true;
        dllInfo.skippedApiSet = true;
        dllInfo.success = true;

    // Check if already loaded
    } else if (const auto existingHandle = GetModuleHandleA(dllName.c_str()))
    {
        // record skipped
        dllInfo.skipped = true;
        dllInfo.skippedAlreadyLoaded = true;
        dllInfo.success = true;

        // loaded by us?
        if ( db_dlls.contains(existingHandle) ) {

            // not give to windows
            dllInfo.module = existingHandle;

            // good to track refs
            logInfo("before AddRef({}) ",
                 MemoryRefCount(dllInfo.module),
                 dllInfo.name,
                 dllInfo.module_str());

            // update our/memorymodulepp bookkeeping
            MemoryAddRef(dllInfo.module);
        }
    }
    else {
        // Try loading from database
        std::vector<unsigned char> buffer;

        if (const auto& dbResult = readFromDatabase(dbPath, dllName)) {
            buffer = std::move((*dbResult).first);

            // Store buffer size before moving
            dllInfo.size = buffer.size();

            // we will keep path name around
            dllInfo.path_name = (*dbResult).second;

            // Attempt to load the DLL from database
            if (const auto& loadResult = loadLibraryMemory(
                std::move(buffer),
                dllName,
                dllInfo.path_name))
            {
                // record successful side load
                dllInfo.success = true;

                // not give to windows
                dllInfo.module = *loadResult;

                // record our load set
                db_dlls[dllInfo.module] = dllInfo;
            }
            else {
                // record side load failed
                dllInfo.failLoadLibraryMemory = true;
                dllInfo.error_message = loadResult.error();
                logError("FAILED: LoadLibraryMemory({}) {}",
                    dllInfo.name,
                    dllInfo.error_message
                );
            }
        }
    } // loading from DB

    // not resolved?
    if (!dllInfo.module) {

        // let Windows handle anything we didn't handle
        logInfo("-> LoadLibraryA({}, {})", dllName, dllInfo.module_str());
        dllInfo.module = LoadLibraryA(dllName.c_str());

        if (!dllInfo.module) {
            // record failure of windows
            dllInfo.failLoadLibraryA = true;
            dllInfo.error_message = std::format(
                 "FAILED: LoadLibraryA({}) (windows) {}",
                 dllName,
                 GetLastError());
            logError("{}", dllInfo.error_message);
        }
        else{
            // record success
            dllInfo.skipped = true;
            logInfo("-> LoadLibraryA({}) {}", dllName, dllInfo.module_str());
        }
    }

    // log it
    dllLoadLog.emplace_back(dllInfo);

    return dllInfo.module;
}

// called back from MemoryModulePP resolver
static HMODULE WINAPI loadLibraryCB(LPCSTR lpModuleName) {
    // Import table entries do not need normalization
    const std::string dllName(lpModuleName);

    // load import entry from db
    return loadDllFromDb(dllName, g_dbPath);
}

// called back from MemoryModulePP resolver
static BOOL WINAPI freeLibraryCB(_In_ HMEMORYMODULE hMemoryModule)
{
    BOOL rc;
    logInfo("-> freeLibraryCb({:p})", static_cast<void*>(hMemoryModule));

    if (const auto it = db_dlls.find(hMemoryModule); it != db_dlls.end()) {
        const auto& dllInfo = it->second;
        if (g_verbose) {
            logInfo("    FreeLibraryMemory({:p}) {} ref={}",
                static_cast<void*>(hMemoryModule),
                dllInfo.name,
                MemoryRefCount(hMemoryModule),
                rc );
        }
        rc = FreeLibraryMemory(hMemoryModule);
    } else {
        const auto& mod_name = get_file_name(hMemoryModule);
        if (g_verbose) {
            logInfo("    windows({:p}) {}",
                static_cast<void*>(hMemoryModule),
                mod_name);
        }
        rc = FreeLibrary(hMemoryModule);
    }

    logInfo("<- freeLibraryCb({:p})", static_cast<void*>(hMemoryModule));
    return rc;
}

// Initialize the import table resolver
[[nodiscard]]
static HANDLE initializeResolver(const std::string& dbPath) {
    g_dbPath = dbPath; // Store dbPath for loadLibraryCB
    // register our callbacks to MemoryModulePP
    const auto use_append = 0;
    const auto resolverHandle = MmRegisterImportTableResolver(
        loadLibraryCB,
        freeLibraryCB,
        use_append);
    if (!resolverHandle) {
        throw std::runtime_error("Failed to register import table resolver");
    }
    return resolverHandle;
}

static void print_dll_result()
{
    size_t totalMemory = 0, loadCount = 0, skipCount = 0;
    size_t failCount = 0, failLoadLibraryMemoryCount = 0, failLoadLibraryACount = 0;
    size_t skipApiSetCount = 0, skipAlreadyLoadedCount = 0, skipNotOursCount = 0;
    std::set<std::string> uniqueApiSetDlls, uniqueAlreadyLoadedDlls, uniqueNotOursDlls, uniqueFailLoadLibraryMemory, uniqueFailLoadLibraryA;

    // print the log
    logInfo("\nDLL Detail:");
    for (size_t ii = 0; ii < dllLoadLog.size(); ++ii) {
        const auto& dll = dllLoadLog[ii];
        if (dll.skipped) {
            logInfo("  {}. {}: {}",
                ii + 1,
                dll.name,
                dll.skippedApiSet ? "API set" : "already loaded");
            ++skipCount;
            if (dll.skippedApiSet) {
                ++skipApiSetCount;
                uniqueApiSetDlls.insert(dll.name);
            } else if ( dll.skippedAlreadyLoaded) {
                ++skipAlreadyLoadedCount;
                uniqueAlreadyLoadedDlls.insert(dll.name);
            } else {
                ++skipNotOursCount;
                uniqueNotOursDlls.insert(dll.name);
            }
        } else if (dll.success) {
            const auto memoryMb = toMB(dll.size);
            logInfo("  {}. {}: {:.3f} MB",
                ii + 1,
                dll.name,
                memoryMb);
            totalMemory += dll.size;
            ++loadCount;
        } else {
            logInfo("  {}. {}: Failed ({})",
                ii + 1,
                dll.name,
                dll.error_message);
            ++failCount;
            if (dll.failLoadLibraryMemory) {
                ++failLoadLibraryMemoryCount;
                uniqueFailLoadLibraryMemory.insert(dll.name);
            }
            else {
                ++failLoadLibraryACount;
                uniqueFailLoadLibraryA.insert(dll.name);
            }
        }
    }  // for

    // Print Summary
    const auto totalMemoryMb = toMB(totalMemory);
    logInfo("\nLogged:");
    logInfo("   {} failures", failCount);
    logInfo("       {} failed LoadLibraryMemory", failLoadLibraryMemoryCount);
    logInfo("       {} failed LoadLibraryA", failLoadLibraryACount);
    logInfo("   {} skips", skipCount);
    logInfo("       {} API set", skipApiSetCount);
    logInfo("       {} already loaded", skipAlreadyLoadedCount);
    logInfo("       {} not ours", skipNotOursCount);

    logInfo("\nUnique:");
    if (failCount) {
        logInfo("   {} failed", uniqueFailLoadLibraryMemory.size() + uniqueFailLoadLibraryA.size());
        logInfo("   {} failed LoadLibraryMemory", uniqueFailLoadLibraryMemory.size());
        logInfo("   {} failed LoadLibraryA", uniqueFailLoadLibraryA.size());
    }
    logInfo("   {} skips", uniqueApiSetDlls.size()+ uniqueAlreadyLoadedDlls.size() + uniqueNotOursDlls.size());
    logInfo("       {} API set", uniqueApiSetDlls.size());
    logInfo("       {} already loaded", uniqueAlreadyLoadedDlls.size());
    logInfo("       {} not ours", uniqueNotOursDlls.size());

    logInfo("\nSummary:");
    logInfo("   {} DLLs", loadCount + skipNotOursCount);
    logInfo("       {} from database", loadCount);
    logInfo("       {} not ours", skipNotOursCount);
    logInfo("   Total memory allocated: {:.3f} MB", totalMemoryMb);
    logInfo("   {}", failCount
            ? std::format("All DLLs loaded successfully")
            : std::format("{} loading failures", failCount));
}

int load_dlls(
    const std::string& dbPath,
    const std::vector<std::string>& dllNames,
    bool verbose)
{
    logInfo("Loading dlls");
    g_verbose = verbose;
    auto rc = 0 ;

    try {
        // hook up our DLL resolver
        g_resolverHandle = initializeResolver(dbPath);

        // roll the dll names
        for (const auto& dllName : dllNames) {
            // fix dll names, as passed on path can skip
            const auto& inputDllName = normalizeDllName(dllName);
            logInfo("\nloadDllFromDb {}", dllName);
            // load the dll
            loadDllFromDb(inputDllName, dbPath);
        }

        if (verbose) {
            print_dll_result();
        }

    } catch (const std::exception& e) {
        logError("Error: {}", e.what());
        rc = 1;
    }

    return rc ;
}

void unload_dll_list(
    const std::vector<std::string>& dllNames,
    bool verbose)
{
    logInfo("Loading dlls");
    g_verbose = verbose;
    auto rc = 0 ;

    // roll the dll names
    for (const auto& dllName : dllNames) {

        // fix dll names, as passed on path can skip
        const auto& inputDllName = normalizeDllName(dllName);
        const auto moduleHandle = GetModuleHandleA(dllName.c_str());

        freeLibraryCB(moduleHandle);
    } // for
}

void unload_dlls()
{
    logInfo("Unloading {} DLLs", dllLoadLog.size());

    // Process in reverse load order
    for (auto ii = dllLoadLog.size(); ii-- ; ) {

        const auto& dll = dllLoadLog[ii];
        const auto& dll_name = dll.name; // for debugging

        // only successful and not skipped DLLs
        if (dll.success && !dll.skipped) {

            // Verify the module is still loaded
            const auto moduleHandle = GetModuleHandleA(dll_name.c_str());

            if (moduleHandle && moduleHandle == dll.module) {
                logInfo("Freeing: {} ({} at {})",
                    dll_name,
                    ii + 1,
                    dll.module_str());

                // unload it!
                // MemoryModulePP has its own ref count
                FreeLibraryMemory(dll.module);
            } else {
                logInfo("Skipping unload: {} ({} at {}) - module not loaded",
                    dll_name,
                    ii + 1,
                    dll.module_str());
            }
        }
    } // for

    // cleanup resolver
}

bool Cleanup_Resolver()
{
    return MmRemoveImportTableResolver(g_resolverHandle);
}

int MmpCleanup()
{
    auto rc = MmCleanup();

    // ignore bad ref counts coming from Initialize.cpp::CleanupLockHeld()
    if ( rc == STATUS_NOT_SUPPORTED ) {
        rc = STATUS_SUCCESS;
    }
    return rc;
}
