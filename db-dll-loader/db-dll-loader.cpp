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

namespace fs = std::filesystem;

// Fallback definition for NT_SUCCESS
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

// Converts a string to lowercase
static std::string toLowerCase(const std::string& input) {
    std::string result(input);
    std::transform(result.begin(), result.end(), result.begin(), ::tolower);
    return result;
}

// Find DLL in system path, returning std::filesystem::path
[[nodiscard]] static std::filesystem::path FindDllInPath(const std::string& dllName) noexcept {
    std::array<char, MAX_PATH> fullPath{};
    return dllName.size() < fullPath.size()
        && strcpy_s(fullPath.data(), fullPath.size(), dllName.c_str()) == 0
        && PathFindOnPathA(fullPath.data(), nullptr)
        ? std::filesystem::path(fullPath.data())
        : std::filesystem::path{};
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

    // Common logic to load DLL data from database or filesystem
    static std::expected<std::pair<HMODULE, bool>, std::string> loadDllData(
        const std::string& dllName,
        const std::string& dbPath,
        const std::string& logPrefix)
    {
        std::string lowerName = toLowerCase(dllName);
        bool dllInDb = false;
        LPVOID buffer = nullptr;
        size_t size = 0;

        // Check if module is already loaded
        const auto existingHandle = GetModuleHandleA(lowerName.c_str());
        if (existingHandle) {
            std::cout << std::format("<--- {} already loaded at {:#x}\n\n",
                logPrefix, reinterpret_cast<uintptr_t>(existingHandle));
            return std::make_pair(existingHandle, dllInDb);
        }

        // Try database
        try {
            sqlite3pp::database db(dbPath.c_str(), SQLITE_OPEN_READONLY);
            std::cout << std::format("    {} query for {}\n", dbPath, lowerName);

            sqlite3pp::query qry(db, "SELECT data, crc32 FROM dlls WHERE name = ?");
            qry.bind(1, lowerName, sqlite3pp::copy);
            const auto& it = qry.begin();
            if (it != qry.end()) {
                const auto blob = (*it).get<const void*>(0);
                const auto blobSize = (*it).column_bytes(0);
                const auto storedCrc32 = (*it).get<long long>(1);
                if (blobSize > SIZE_MAX) {
                    std::cerr << std::format("<--- {} Failed: SQLite blobSize {} ({:#x}) too large for size_t (max: {})\n\n", 
                        logPrefix, blobSize, blobSize, SIZE_MAX);
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
                    std::cerr << std::format("<--- {} Failed: CRC32 mismatch for {} (stored: {:#x}, computed: {:#x})\n\n", 
                                             logPrefix, lowerName, storedCrc32, computedCrc32);
                    return std::unexpected(std::format("CRC32 mismatch for {}", lowerName));
                }


                buffer = VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                if (!buffer) {
                    std::cerr << std::format("<--- {} Failed: VirtualAlloc()\n\n", logPrefix);
                    return std::unexpected(std::format("Failed to VirtualAlloc() memory for {}", lowerName));
                }
                std::memcpy(buffer, blob, size);
                dllInDb = true;
                std::cout << std::format("    Loaded {} bytes from database for {} (crc32: {:#x})\n", size, lowerName, storedCrc32);
            } else {
                std::cout << std::format("    {} not found in database\n", lowerName);
            }
        } catch (const sqlite3pp::database_error& e) {
            std::cerr << std::format("    {} Database error in load: {}\n", lowerName, e.what());
        }

        // Fallback to filesystem
        if (!buffer) {
            std::cout << std::format("    {} falling back to filesystem\n", lowerName);

            std::string inputPath(lowerName);
            if (fs::path(inputPath).extension() != ".dll" && fs::path(inputPath).extension() != ".DLL") {
                inputPath = std::format("{}.dll", lowerName);
            }

            fs::path path(inputPath);
            if (fs::exists(path)) {
                std::cout << std::format("    {} found: {}\n", lowerName, path.string());
            } else {
                std::cout << std::format("    {} full path failed, searching PATH\n", path.string());
                path = FindDllInPath(inputPath);
                if (path.empty()) {
                    std::cerr << std::format("<--- {} Failed: {} not found in system path\n\n", logPrefix, lowerName);
                    return std::unexpected(std::format("{} not found in system path", lowerName));
                }
                std::cout << std::format("    {} found in system path: {}\n", lowerName, path.string());
            }

            const auto dllDataResult = readDllFromFile(path);
            if (!dllDataResult) {
                std::cerr << std::format("<--- {} Failed: reading fil {}: {}\n\n", logPrefix, path.string(), dllDataResult.error().message());
                return std::unexpected(std::format("Failed to read DLL data for {}: {}", path.string(), dllDataResult.error().message()));
            }
            buffer = dllDataResult->first;
            size = dllDataResult->second;
            std::cout << std::format("    Read {} bytes for file {}\n", size, path.string());
        }

        std::cout << std::format("    {} calling LoadLibraryMemory({}) - may recurse\n", lowerName, buffer);
        const auto handle = LoadLibraryMemory(buffer);
        if (!handle) {
            std::cerr << std::format("<--- {} Failed: LoadLibraryMemory handle == 0 (Error: {})\n\n", logPrefix, GetLastError());
            VirtualFree(buffer, 0, MEM_RELEASE);
        }

        // Memory is managed by LoadLibraryMemory on success
        return std::make_pair(handle, dllInDb);
    }

public:
    DllLoader(const std::string& dbPath) {
        DllLoader::dbPath = dbPath;
        std::cout << std::format("DllLoader initialized with database path: {}\n", dbPath);
        resolverHandle = MmRegisterImportTableResolver(loadDependency, FreeLibraryCallback, 0);
        if (!resolverHandle) {
            throw std::runtime_error("Failed to register import table resolver");
        }
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

        std::cout << std::format("---> {}\n", func_spec);

        const auto result = loadDllData(dllName, dbPath, func_spec);
        if (!result) {
            std::cerr << std::format("<--- {} Failed: {}\n\n", func_spec, result.error());
            return nullptr;
        }

        std::cout << std::format("<--- {} Successfully loaded from {} at {:#x}\n\n",
            func_spec, result->second ? "database" : "filesystem", reinterpret_cast<uintptr_t>(result->first));
        return result->first;
    }

    // Loads a dependency from the database or filesystem
    static HMODULE WINAPI loadDependency(LPCSTR lpModuleName) {
        const std::string dllName(toLowerCase(lpModuleName));
        const std::string func_spec(std::format("loadDependency:{}", dllName));

        std::cout << std::format("---> {}\n", func_spec);

        // Quick API set check
        if (dllName.find("api-ms-win-") == 0 || IsApiSetDllByNamespace(dllName)) {
            std::cout << std::format("    Skipping API set DLL {}, deferring to default resolver\n", dllName);
            return nullptr;
        }

        const auto result = loadDllData(dllName, dbPath, func_spec);
        if (!result) {
            std::cerr << std::format("<--- {} Failed: {}\n\n", func_spec, result.error());
            return nullptr;
        }

        std::cout << std::format("<--- {} Successfully loaded from {} at {:#x}\n\n",
            func_spec, result->second ? "database" : "filesystem", reinterpret_cast<uintptr_t>(result->first));
        return result->first;
    }

    // Frees a loaded library
    static BOOL WINAPI FreeLibraryCallback(HMODULE hModule) {
        if (hModule) {
            return FreeLibraryMemory(hModule);
        }
        return FALSE;
    }
};

// Define static member
std::string DllLoader::dbPath;

int main(int argc, char* argv[]) {
    // Parse arguments
    const auto [dbPath, dllNames] = parseArguments(argc, argv);
    if (dllNames.empty()) {
        std::cerr << std::format("Usage: {} [--db <database_path>] <dll_name> [<dll_name> ...]\n", argv[0]);
        return 1;
    }
    std::cout << std::format("\nStarting with database path: {}, DLLs: {}\n\n", dbPath, dllNames.size());

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
                std::cerr << std::format("Failed to load DLL: {}\n", inputDllName);
                allLoaded = false;
                continue;
            }
            std::cout << std::format("FINAL Successfully loaded DLL: {}\n", inputDllName);
            loadedModules.push_back(hModule);
        }

        // Free all loaded modules
        for (const auto module : loadedModules) {
            FreeLibraryMemory(module);
        }

        return allLoaded ? 0 : 1;
    } catch (const std::exception& e) {
        std::cerr << std::format("Error: {}\n", e.what());
        return 1;
    }
}
