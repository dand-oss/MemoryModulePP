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
#include <../MemoryModule/MemoryModule.h>
#include <../MemoryModule/LoadDllMemoryApi.h>
#include <../MemoryModule/ImportTable.h>

namespace fs = std::filesystem;

// Fallback definition for NT_SUCCESS
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

// Converts a string to lowercase
static std::string toLowerCase(const std::string& input) {
    std::string result(input);
    std::transform(
        result.begin(),
        result.end(),
        result.begin(),
        ::tolower);
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

    if (fread(buffer, 1, fileSize, filePtr) != fileSize) {
        VirtualFree(buffer, 0, MEM_RELEASE);
        fclose(filePtr);
        return std::unexpected(std::make_error_code(std::errc::io_error));
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

public:
    DllLoader(const std::string& dbPath) {
        DllLoader::dbPath = dbPath;
        std::cout << std::format("DllLoader initialized with database path: {}\n", dbPath);
        // Register the resolver with loadDependency and FreeLibraryCallback
        MmClearImportTableResolvers();
        resolverHandle = MmRegisterImportTableResolver(loadDependency, FreeLibraryCallback);
        if (!resolverHandle) {
            throw std::runtime_error("Failed to register import table resolver");
        }
    }

    ~DllLoader() {
        if (resolverHandle) {
            MmRemoveImportTableResolver(resolverHandle);
        }
    }

    // Loads a DLL from memory using the database
    static HMODULE load(const std::string& dllName) {
        std::string lowerName = toLowerCase(dllName);
        std::cout << std::format("Attempting to load DLL: {}\n", lowerName);

        LPVOID buffer = nullptr;
        size_t size = 0;
        try {
            sqlite3pp::database db(DllLoader::dbPath.c_str(), SQLITE_OPEN_READONLY);
            std::cout << std::format("Database opened for load: {}\n", lowerName);

            sqlite3pp::query qry(db, "SELECT data FROM dlls WHERE name = ?");
            qry.bind(1, lowerName, sqlite3pp::copy);
            const auto& it = qry.begin();
            if (it == qry.end()) {
                std::cerr << std::format("DLL not found in database: {}\n", lowerName);
                return nullptr;
            }
            const auto blob = (*it).get<const void*>(0);
            const auto blobSize = (*it).column_bytes(0);
            if (blobSize > SIZE_MAX) {
                std::cerr << std::format("Error: SQLite data for {} too large for size_t\n", lowerName);
                return nullptr;
            }
            size = static_cast<size_t>(blobSize);
            buffer = VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (!buffer) {
                std::cerr << std::format("Error: Failed to allocate memory for {}\n", lowerName);
                return nullptr;
            }
            std::memcpy(buffer, blob, size);
            std::cout << std::format("Loaded {} bytes from database for {}\n", size, lowerName);
        } catch (const sqlite3pp::database_error& e) {
            std::cerr << std::format("Database error in load: {}\n", e.what());
            return nullptr;
        }

        const auto hModule = LoadLibraryMemory(buffer);
        if (!hModule) {
            std::cerr << std::format("Failed to load DLL: {} (Error: {})\n", lowerName, GetLastError());
            VirtualFree(buffer, 0, MEM_RELEASE);
            return nullptr;
        }
        std::cout << std::format("Successfully loaded DLL: {}\n", lowerName);
        return hModule;
    }

    // Loads a dependency from the database or filesystem
    static HMODULE WINAPI loadDependency(LPCSTR lpModuleName) {
        std::string dllName = toLowerCase(lpModuleName);
        std::cout << std::format("Attempting to load dependency: {}\n", dllName);

        const auto existingHandle = GetModuleHandleA(dllName.c_str());
        if (existingHandle) {
            std::cout << std::format("DLL {} already loaded at {:#x}\n", dllName, reinterpret_cast<uintptr_t>(existingHandle));
            return existingHandle;
        }

        LPVOID buffer = nullptr;
        size_t size = 0;
        bool dllInDb = false;
        try {
            sqlite3pp::database db(DllLoader::dbPath.c_str(), SQLITE_OPEN_READONLY);
            std::cout << std::format("Database opened for loadDependency: {}\n", dllName);

            sqlite3pp::query qry(db, "SELECT data FROM dlls WHERE name = ?");
            qry.bind(1, dllName, sqlite3pp::copy);
            const auto& it = qry.begin();
            if (it != qry.end()) {
                const auto blob = (*it).get<const void*>(0);
                const auto blobSize = (*it).column_bytes(0);
                if (blobSize > SIZE_MAX) {
                    std::cerr << std::format("Error: SQLite data for {} too large for size_t\n", dllName);
                    return nullptr;
                }
                size = static_cast<size_t>(blobSize);
                buffer = VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                if (!buffer) {
                    std::cerr << std::format("Error: Failed to allocate memory for {}\n", dllName);
                    return nullptr;
                }
                std::memcpy(buffer, blob, size);
                dllInDb = true;
                std::cout << std::format("Loaded {} bytes from database for {}\n", size, dllName);
            } else {
                std::cout << std::format("DLL {} not found in database, falling back to filesystem\n", dllName);
            }
        } catch (const sqlite3pp::database_error& e) {
            std::cerr << std::format("Database error in loadDependency: {}\n", e.what());
        }

        // Fallback to filesystem if not found in database or database error
        if (!buffer) {
            std::string inputPath(dllName);
            if (fs::path(inputPath).extension() != ".dll" && fs::path(inputPath).extension() != ".DLL") {
                inputPath = std::format("{}.dll", dllName);
            }

            fs::path path = inputPath;
            if (fs::exists(path)) {
                std::cout << std::format("DLL {} found at local path: {}\n", dllName, path.string());
            } else {
                path = FindDllInPath(inputPath);
                if (path.empty()) {
                    std::cerr << std::format("Error: DLL {} not found in system path\n", dllName);
                    return nullptr;
                }
                std::cout << std::format("DLL {} found in system path: {}\n", dllName, path.string());
            }

            const auto dllDataResult = readDllFromFile(path);
            if (!dllDataResult) {
                std::cerr << std::format("Error: Failed to read DLL data for {}: {}\n", path.string(), dllDataResult.error().message());
                return nullptr;
            }
            buffer = dllDataResult->first;
            size = dllDataResult->second;
            std::cout << std::format("Read {} bytes from filesystem for {}\n", size, path.string());
        }

        const auto handle = LoadLibraryMemory(buffer);
        if (handle) {
            std::cout << std::format("Successfully loaded {} from {} at {:#x}\n", dllName, dllInDb ? "database" : "filesystem", reinterpret_cast<uintptr_t>(handle));
        } else {
            std::cerr << std::format("Failed to load {} (Error: {})\n", dllName, GetLastError());
            VirtualFree(buffer, 0, MEM_RELEASE);
            return nullptr;
        }
        return handle;
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
    std::cout << std::format("Starting with database path: {}, DLLs: {}\n", dbPath, dllNames.size());

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
            std::cout << std::format("Successfully loaded DLL: {}\n", inputDllName);
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