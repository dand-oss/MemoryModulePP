#define NOMINMAX
#include <windows.h>
#include <ntstatus.h>
#include <string>
#include <iostream>
#include <format>
#include <algorithm>
#include <array>
#include <filesystem>
#include <expected>
#include <system_error>
#include <vector>
#include <shlwapi.h>
#include <sqlite3pp.h>
#include "api-set.hpp"
#include <../MemoryModule/MemoryModule.h>
#include <../MemoryModule/LoadDllMemoryApi.h>
#include <../MemoryModule/ImportTable.h>
#include <cppcrc.h>

// NEW: Include for resource usage logging
#include <psapi.h>

namespace fs = std::filesystem;

// Fallback definition for NT_SUCCESS
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

// NEW: Log with timestamp
static void LogWithTimestamp(const std::string& message) {
    SYSTEMTIME st;
    GetSystemTime(&st);
    std::cout << std::format("[{:%Y-%m-%d %H:%M:%S}.{:03}] {}\n",
                             st, st.wMilliseconds, message);
}

// NEW: Log resource usage with allocation details
static void LogResourceUsage(const std::string& dllName, size_t size, void* buffer, void* preferredAddress = nullptr, bool isFailure = false) {
    MEMORYSTATUSEX memStatus = { sizeof(memStatus) };
    GlobalMemoryStatusEx(&memStatus);
    PROCESS_MEMORY_COUNTERS pmc = { sizeof(pmc) };
    GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc));
    
    LogWithTimestamp(std::format("Resource usage for {} ({}):", dllName, isFailure ? "failure" : "info"));
    LogWithTimestamp(std::format("  DLL Size: {} bytes", size));
    LogWithTimestamp(std::format("  Buffer Address: {:#x}", reinterpret_cast<uintptr_t>(buffer)));
    if (preferredAddress) {
        LogWithTimestamp(std::format("  Preferred Address: {:#x}", reinterpret_cast<uintptr_t>(preferredAddress)));
    }
    LogWithTimestamp(std::format("  Available Virtual Memory: {} MB", memStatus.ullAvailVirtual / (1024 * 1024)));
    LogWithTimestamp(std::format("  Process Working Set: {} MB", pmc.WorkingSetSize / (1024 * 1024)));
    
    // NEW: Log memory region details
    if (buffer) {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery(buffer, &mbi, sizeof(mbi))) {
            LogWithTimestamp(std::format("  Memory Region: State={}, Type={}, Size={} bytes",
                mbi.State == MEM_COMMIT ? "Committed" : mbi.State == MEM_RESERVE ? "Reserved" : "Free",
                mbi.Type == MEM_IMAGE ? "Image" : mbi.Type == MEM_MAPPED ? "Mapped" : "Private",
                mbi.RegionSize));
        } else {
            LogWithTimestamp(std::format("  Failed to query memory region at {:#x}: Error {}", 
                reinterpret_cast<uintptr_t>(buffer), GetLastError()));
        }
    }
}

// Reads a DLL file into a VirtualAlloc buffer
static std::expected<std::pair<LPVOID, size_t>, std::error_code> readDllFromFile(const fs::path& path) {
    FILE* filePtr;
    if (fopen_s(&filePtr, path.string().c_str(), "rb") != 0 || !filePtr) {
        return std::unexpected(std::make_error_code(std::errc::no_such_file_or_directory));
    }
    _fseeki64(filePtr, 0, SEEK_END);
    const auto fileISize = _ftelli64(filePtr);
    if (fileISize <= 0) {
        fclose(filePtr);
        return std::unexpected(std::make_error_code(std::errc::no_such_file_or_directory));
    }
    if (fileISize > SIZE_MAX) {
        fclose(filePtr);
        return std::unexpected(std::make_error_code(std::errc::file_too_large));
    }
    const auto fileSize = static_cast<const size_t>(fileISize);
    _fseeki64(filePtr, 0, SEEK_SET);

    auto buffer = VirtualAlloc(nullptr, static_cast<size_t>(fileSize), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!buffer) {
        fclose(filePtr);
        return std::unexpected(std::make_error_code(std::errc::not_enough_memory));
    }

    size_t totalRead = 0;
    constexpr size_t chunkSize = 1024 * 1024; // 1 MB chunks
    char* ptr = static_cast<char*>(buffer);
    while (totalRead < fileSize) {
        const auto toRead = std::min(chunkSize, fileSize - totalRead);
        const auto bytesRead = fread(ptr, 1, toRead, filePtr);

        // read fail
        if (bytesRead != toRead) {
            VirtualFree(buffer, 0, MEM_RELEASE);
            fclose(filePtr);
            return std::unexpected(std::make_error_code(std::errc::io_error));
        }
        totalRead += bytesRead;
        ptr += bytesRead;
    }

    fclose(filePtr);

    return std::make_pair(buffer, fileSize);
}

// Parses command-line arguments for database path and list of DLL names
static std::pair<std::string, std::vector<std::string>> parseArguments(int argc, char* argv[]) {
    std::string dbPath("dlls.db"); // Default database path
    std::vector<std::string> dllNames;

    for (auto ii = 1; ii < argc; ++ii) {
        std::string arg(argv[ii]);
        if (arg == "--db" && ii + 1 < argc) {
            dbPath = argv[++ii];
            continue;
        }
        dllNames.emplace_back(arg);
    }

    return {dbPath, dllNames};
}

class DllLoader {
private:
    static std::string dbPath; // Static member to store database path
    HANDLE resolverHandle;

    // NEW: Track recursion depth
    static thread_local int recursionDepth;

    // MODIFIED: Common logic to load DLL data from database or filesystem
    static std::expected<std::pair<HMODULE, bool>, std::string> loadDllData(
        const std::string& dllName,
        const std::string& dbPath,
        const std::string& logPrefix)
    {
        // NEW: Increment and log recursion depth
        recursionDepth++;
        if (recursionDepth > 50) {
            LogWithTimestamp(std::format("WARNING: High recursion depth ({}) for {}", recursionDepth, dllName));
        }
        LogWithTimestamp(std::format("Depth {}: {}", recursionDepth, logPrefix));

        std::string lowerName = toLowerCase(dllName);
        bool dllInDb = false;
        LPVOID buffer = nullptr;
        size_t size = 0;

        // Check if module is already loaded
        const auto existingHandle = GetModuleHandleA(lowerName.c_str());
        if (existingHandle) {
            LogWithTimestamp(std::format("Depth {}: <--- {} already loaded at {:#x}", 
                recursionDepth, logPrefix, reinterpret_cast<uintptr_t>(existingHandle)));
            recursionDepth--; // NEW: Decrement depth
            return std::make_pair(existingHandle, dllInDb);
        }

        // Try database
        try {
            sqlite3pp::database db(dbPath.c_str(), SQLITE_OPEN_READONLY);
            LogWithTimestamp(std::format("Depth {}:     {} query for {}", recursionDepth, dbPath, lowerName));

            sqlite3pp::query qry(db, "SELECT data, crc32 FROM dlls WHERE name = ?");
            qry.bind(1, lowerName, sqlite3pp::copy);
            const auto& it = qry.begin();
            if (it != qry.end()) {
                const auto blob = (*it).get<const void*>(0);
                const auto blobSize = (*it).column_bytes(0);
                const auto storedCrc32 = (*it).get<long long>(1);
                if (blobSize > SIZE_MAX) {
                    LogWithTimestamp(std::format("Depth {}: <--- {} Failed: SQLite blobSize {} ({:#x}) too large for size_t (max: {})", 
                        recursionDepth, logPrefix, blobSize, blobSize, SIZE_MAX));
                    recursionDepth--; // NEW: Decrement depth
                    return std::unexpected(std::format("SQLite blobSize {} too large for {}", blobSize, lowerName));
                }

                size = static_cast<size_t>(blobSize);
                // Verify CRC32 using cppcrc
                CRC32::CRC32 crc32;
                uint32_t computedCrc32 = crc32.calc(
                    static_cast<const unsigned char*>(blob),
                    size,
                    crc32.null_crc);
                if (computedCrc32 != static_cast<uint32_t>(storedCrc32)) {
                    LogWithTimestamp(std::format("Depth {}: <--- {} Failed: CRC32 mismatch for {} (stored: {:#x}, computed: {:#x})", 
                                             recursionDepth, logPrefix, lowerName, storedCrc32, computedCrc32));
                    recursionDepth--; // NEW: Decrement depth
                    return std::unexpected(std::format("CRC32 mismatch for {}", lowerName));
                }

                // NEW: Log VirtualAlloc details
                void* preferredAddress = nullptr; // No preferred address specified
                buffer = VirtualAlloc(preferredAddress, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                if (!buffer) {
                    LogWithTimestamp(std::format("Depth {}: <--- {} Failed: VirtualAlloc() for {} bytes", 
                        recursionDepth, logPrefix, size));
                    LogResourceUsage(lowerName, size, nullptr, preferredAddress, true);
                    recursionDepth--; // NEW: Decrement depth
                    return std::unexpected(std::format("Failed to VirtualAlloc() memory for {}", lowerName));
                }
                LogWithTimestamp(std::format("Depth {}:     VirtualAlloc: Preferred={:#x}, Allocated={:#x}, Size={} bytes, Protection=PAGE_EXECUTE_READWRITE", 
                    recursionDepth, reinterpret_cast<uintptr_t>(preferredAddress), reinterpret_cast<uintptr_t>(buffer), size));
                LogResourceUsage(lowerName, size, buffer, preferredAddress);

                std::memcpy(buffer, blob, size);
                dllInDb = true;
                LogWithTimestamp(std::format("Depth {}:     Loaded {} bytes from database for {} (crc32: {:#x})", 
                    recursionDepth, size, lowerName, storedCrc32));
            } else {
                LogWithTimestamp(std::format("Depth {}:     {} not found in database", recursionDepth, lowerName));
            }
        } catch (const sqlite3pp::database_error& e) {
            LogWithTimestamp(std::format("Depth {}:     {} Database error in load: {}", recursionDepth, lowerName, e.what()));
        }

        // Fallback to filesystem
        if (!buffer) {
            LogWithTimestamp(std::format("Depth {}:     {} falling back to filesystem", recursionDepth, lowerName));

            std::string inputPath(lowerName);
            if (fs::path(inputPath).extension() != ".dll" && fs::path(inputPath).extension() != ".DLL") {
                inputPath = std::format("{}.dll", lowerName);
            }

            fs::path path(inputPath);
            if (fs::exists(path)) {
                LogWithTimestamp(std::format("Depth {}:     {} found: {}", recursionDepth, lowerName, path.string()));
            } else {
                LogWithTimestamp(std::format("Depth {}:     {} full path failed, searching PATH", recursionDepth, path.string()));
                path = FindDllInPath(inputPath);
                if (path.empty()) {
                    LogWithTimestamp(std::format("Depth {}: <--- {} Failed: {} not found in system path", recursionDepth, logPrefix, lowerName));
                    recursionDepth--; // NEW: Decrement depth
                    return std::unexpected(std::format("{} not found in system path", lowerName));
                }
                LogWithTimestamp(std::format("Depth {}:     {} found in system path: {}", recursionDepth, lowerName, path.string()));
            }

            const auto dllDataResult = readDllFromFile(path);
            if (!dllDataResult) {
                LogWithTimestamp(std::format("Depth {}: <--- {} Failed: reading file {}: {}", 
                    recursionDepth, logPrefix, path.string(), dllDataResult.error().message()));
                recursionDepth--; // NEW: Decrement depth
                return std::unexpected(std::format("Failed to read DLL data for {}: {}", path.string(), dllDataResult.error().message()));
            }
            buffer = dllDataResult->first;
            size = dllDataResult->second;
            // NEW: Log VirtualAlloc details for filesystem
            void* preferredAddress = nullptr;
            LogWithTimestamp(std::format("Depth {}:     VirtualAlloc: Preferred={:#x}, Allocated={:#x}, Size={} bytes, Protection=PAGE_EXECUTE_READWRITE", 
                recursionDepth, reinterpret_cast<uintptr_t>(preferredAddress), reinterpret_cast<uintptr_t>(buffer), size));
            LogResourceUsage(lowerName, size, buffer, preferredAddress);
            LogWithTimestamp(std::format("Depth {}:     Read {} bytes for file {}", recursionDepth, size, path.string()));
        }

        LogWithTimestamp(std::format("Depth {}:     {} calling LoadLibraryMemory({:#x}) - may recurse", 
            recursionDepth, lowerName, reinterpret_cast<uintptr_t>(buffer)));
        const auto handle = LoadLibraryMemory(buffer, lowerName.c_str());
        if (!handle) {
            DWORD error = GetLastError();
            LogWithTimestamp(std::format("Depth {}: <--- {} Failed: LoadLibraryMemory handle == 0 (Error: {})", 
                recursionDepth, logPrefix, error));
            LogResourceUsage(lowerName, size, buffer, nullptr, true);
            VirtualFree(buffer, 0, MEM_RELEASE);
            recursionDepth--; // NEW: Decrement depth
            return std::unexpected(std::format("LoadLibraryMemory failed for {} (Error: {})", lowerName, error));
        }

        // Memory is managed by LoadLibraryMemory on success
        LogWithTimestamp(std::format("Depth {}: <--- {} Successfully loaded from {} at {:#x}", 
            recursionDepth, logPrefix, dllInDb ? "database" : "filesystem", reinterpret_cast<uintptr_t>(handle)));
        recursionDepth--; // NEW: Decrement depth
        return std::make_pair(handle, dllInDb);
    }

public:
    DllLoader(const std::string& dbPath) {
        DllLoader::dbPath = dbPath;
        resolverHandle = nullptr ;
        LogWithTimestamp(std::format("DllLoader initialized with database path: {}", dbPath));
        /*
        resolverHandle = MmRegisterImportTableResolver(loadDependency, FreeLibraryCallback, 0);
        if (!resolverHandle) {
            throw std::runtime_error("Failed to register import table resolver");
        }
        */
    }

    ~DllLoader() {
        if (resolverHandle) {
            MmRemoveImportTableResolver(resolverHandle);
        }
    }

    // Loads a DLL from memory using the database or filesystem
    static HMODULE load(const std::string& dllName) {
        const std::string lowerName(toLowerCase(dllName));
        const std::string func_spec(std::format("load:{}", lowerName));

        LogWithTimestamp(std::format("---> {}", func_spec));

        const auto result = loadDllData(dllName, dbPath, func_spec);
        if (!result) {
            LogWithTimestamp(std::format("<--- {} Failed: {}", func_spec, result.error()));
            return nullptr;
        }

        LogWithTimestamp(std::format("<--- {} Successfully loaded from {} at {:#x}",
            func_spec, result->second ? "database" : "filesystem", reinterpret_cast<uintptr_t>(result->first)));
        return result->first;
    }

    // Loads a dependency from the database or filesystem
    static HMODULE WINAPI loadDependency(LPCSTR lpModuleName) {
        const std::string dllName(toLowerCase(lpModuleName));
        const std::string func_spec(std::format("loadDependency:{}", dllName));

        LogWithTimestamp(std::format("---> {}", func_spec));

        // Quick API set check
        if (dllName.find("api-ms-win-") == 0 || IsApiSetDllByNamespace(dllName)) {
            LogWithTimestamp(std::format("    Skipping API set DLL {}, deferring to default resolver", dllName));
            return nullptr;
        }

        const auto result = loadDllData(dllName, dbPath, func_spec);
        if (!result) {
            LogWithTimestamp(std::format("<--- {} Failed: {}", func_spec, result.error()));
            return nullptr;
        }

        LogWithTimestamp(std::format("<--- {} Successfully loaded from {} at {:#x}",
            func_spec, result->second ? "database" : "filesystem", reinterpret_cast<uintptr_t>(result->first)));
        return result->first;
    }

    // Frees a loaded library
    static BOOL WINAPI FreeLibraryCallback(HMODULE hModule) {
        if (hModule) {
            WCHAR modulePath[MAX_PATH];
            if (GetModuleFileNameW(hModule, modulePath, MAX_PATH)) {
                std::wstring path(modulePath);
                if (path.find(L"\\Windows\\") != std::wstring::npos) {
                    LogWithTimestamp(std::format("Skipping unload of system DLL at {:#x} ({})", 
                        reinterpret_cast<uintptr_t>(hModule), modulePath));
                    return FALSE;
                }
            }
            BOOL result = FreeLibraryMemory(hModule);
            LogWithTimestamp(std::format("FreeLibraryMemory for {:#x} returned {}", 
                reinterpret_cast<uintptr_t>(hModule), result ? "TRUE" : "FALSE"));
            return result;
        }
        LogWithTimestamp("FreeLibraryCallback: Invalid module handle");
        return FALSE;
    }
};

// Define static member
std::string DllLoader::dbPath;

// NEW: Initialize recursion depth
thread_local int DllLoader::recursionDepth = 0;

int main(int argc, char* argv[]) {
    // Parse arguments
    const auto [dbPath, dllNames] = parseArguments(argc, argv);
    if (dllNames.empty()) {
        LogWithTimestamp(std::format("Usage: {} [--db <database_path>] <dll_name> [<dll_name> ...]", argv[0]));
        return 1;
    }
    LogWithTimestamp(std::format("\nStarting with database path: {}, DLLs: {}", dbPath, dllNames.size()));

    try {
        DllLoader loader(dbPath);
        bool allLoaded = true;
        std::vector<HMODULE> loadedModules;

        for (const auto& dllName : dllNames) {
            std::string inputDllName(dllName);
            if (fs::path(inputDllName).extension() != ".dll" && fs::path(inputDllName).extension() != ".DLL") {
                inputDllName = std::format("{}.dll", dllName);
            }
            const auto hModule = loader.load(inputDllName);
            if (!hModule) {
                LogWithTimestamp(std::format("Failed to load DLL: {}", inputDllName));
                allLoaded = false;
                continue;
            }
            LogWithTimestamp(std::format("FINAL Successfully loaded DLL: {}", inputDllName));
            loadedModules.push_back(hModule);
        }

        // Free all loaded modules
        for (const auto module : loadedModules) {
            FreeLibraryCallback(module);
        }

        return allLoaded ? 0 : 1;
    } catch (const std::exception& e) {
        LogWithTimestamp(std::format("Error: {}", e.what()));
        return 1;
    }
}