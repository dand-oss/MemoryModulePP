#include <windows.h>
#include <ntstatus.h>
#include <string>
#include <iostream>
#include <format>
#include <algorithm>
#include <filesystem>
#include <expected>
#include <system_error>
#include <sqlite3pp.h>
#include <../MemoryModule/MemoryModule.h>
#include <../MemoryModule/LoadDllMemoryApi.h>
#include <../MemoryModule/ImportTable.h>

namespace fs = std::filesystem;

// Fallback definition for NT_SUCCESS
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

// Reads a DLL file into a VirtualAlloc buffer
static std::expected<std::pair<LPVOID, size_t>, std::error_code> readDllFromFile(
    const fs::path& path) {
    FILE* filePtr;
    if (fopen_s(&filePtr, path.string().c_str(), "rb") != 0 || !filePtr) {
        return std::unexpected(std::make_error_code(std::errc::no_such_file_or_directory));
    }
    _fseeki64(filePtr, 0, SEEK_END);
    const auto fileSize = _ftelli64(filePtr);
    if (fileSize <= 0) {
        fclose(filePtr);
        return std::unexpected(std::make_error_code(std::errc::no_such_file_or_directory));
    }
    if (fileSize > SIZE_MAX) {
        fclose(filePtr);
        return std::unexpected(std::make_error_code(std::errc::file_too_large));
    }
    _fseeki64(filePtr, 0, SEEK_SET);

    LPVOID buffer = VirtualAlloc(nullptr, static_cast<size_t>(fileSize), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!buffer) {
        fclose(filePtr);
        return std::unexpected(std::make_error_code(std::errc::not_enough_memory));
    }

    if (fread(buffer, 1, static_cast<size_t>(fileSize), filePtr) != static_cast<size_t>(fileSize)) {
        VirtualFree(buffer, 0, MEM_RELEASE);
        fclose(filePtr);
        return std::unexpected(std::make_error_code(std::errc::io_error));
    }
    fclose(filePtr);

    return std::make_pair(buffer, static_cast<size_t>(fileSize));
}

// Parses command-line arguments for database path and DLL name
static std::pair<std::string, std::string> parseArguments(int argc, char* argv[]) {
    std::string dbPath = "dlls.db"; // Default database path
    std::string dllName;

    for (int ii = 1; ii < argc; ++ii) {
        std::string arg(argv[ii]);
        if (arg == "--db" && ii + 1 < argc) {
            dbPath = argv[++ii];
            continue;
        }
        dllName = arg;
    }

    return {dbPath, dllName};
}

class DllLoader {
private:
    sqlite3pp::database db;
    HANDLE resolverHandle;

    // Checks if a DLL exists in SQLite and allocates memory
    bool hasDllInSqlite(const std::string& name, LPVOID& buffer, size_t& size) {
        try {
            sqlite3pp::query qry(db, "SELECT data FROM dlls WHERE name = ?");
            qry.bind(1, name, sqlite3pp::copy);
            auto it = qry.begin();
            if (it == qry.end()) return false;
            auto blob = (*it).get<const void*>(0);
            const auto blobSize = (*it).column_bytes(0);
            if (blobSize > SIZE_MAX) {
                std::cerr << std::format("Error: SQLite data for {} too large for size_t\n", name);
                return false;
            }
            size = static_cast<size_t>(blobSize);
            buffer = VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (!buffer) {
                std::cerr << std::format("Error: Failed to allocate memory for {}\n", name);
                return false;
            }
            std::memcpy(buffer, blob, size);
            return true;
        } catch (const sqlite3pp::database_error& e) {
            std::cerr << std::format("SQLite error: {}\n", e.what());
            return false;
        }
    }

    // Loads a dependency from the database or filesystem
    static HMODULE WINAPI loadDependency(LPCSTR lpModuleName) {
        DllLoader* loader = reinterpret_cast<DllLoader*>(GetModuleHandle(NULL)); // Simplified instance access
        std::string dllName(lpModuleName);
        std::transform(dllName.begin(), dllName.end(), dllName.begin(), ::tolower);
        std::cout << std::format("Attempting to load dependency: {}\n", dllName);

        // Check if already loaded
        HMODULE existingHandle = GetModuleHandleA(dllName.c_str());
        if (existingHandle) {
            std::cout << std::format("DLL {} already loaded at {:#x}\n", dllName, reinterpret_cast<uintptr_t>(existingHandle));
            return existingHandle;
        }

        // Load DLL data
        LPVOID buffer = nullptr;
        size_t size = 0;
        bool dllInDb = loader->hasDllInSqlite(dllName, buffer, size);
        const char* loadFrom = dllInDb ? "SQLite" : "filesystem";
        fs::path path;
        if (!dllInDb) {
            std::cout << std::format("Reading {} from filesystem\n", dllName);
            std::string inputPath = dllName;
            if (fs::path(inputPath).extension() != ".dll" && fs::path(inputPath).extension() != ".DLL") {
                inputPath = std::format("{}.dll", dllName);
            }
            path = fs::path(inputPath);
            auto dllDataResult = readDllFromFile(path);
            if (!dllDataResult) {
                std::cerr << std::format("Error: Failed to read DLL data for {}: {}\n", path.string(), dllDataResult.error().message());
                return nullptr;
            }
            buffer = dllDataResult->first;
            size = dllDataResult->second;
            std::cout << std::format("Read {} bytes from {}\n", size, path.string());
        } else {
            std::cout << std::format("Loading {} from SQLite (memory)\n", dllName);
        }

        // Load DLL
        HMEMORYMODULE handle = LoadLibraryMemory(buffer);
        if (handle) {
            std::cout << std::format("Successfully loaded {} from {} at {:#x}\n", dllName, loadFrom, reinterpret_cast<uintptr_t>(handle));
        } else {
            std::cerr << std::format("Failed to load {} from {} (Error: {})\n", dllName, loadFrom, GetLastError());
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

public:
    DllLoader(const std::string& dbPath) : db(dbPath.c_str(), SQLITE_OPEN_READWRITE)  {
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

    // Loads a DLL from memory using the registered resolver
    HMODULE load(const std::string& dllName) {
        std::string lowerName(dllName);
        std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);

        LPVOID buffer = nullptr;
        size_t size = 0;
        if (!hasDllInSqlite(lowerName, buffer, size)) {
            std::cerr << std::format("DLL not found in database: {}\n", dllName);
            return nullptr;
        }

        HMEMORYMODULE hModule = LoadLibraryMemory(buffer);
        if (!hModule) {
            std::cerr << std::format("Failed to load DLL: {} (Error: {})\n", dllName, GetLastError());
            VirtualFree(buffer, 0, MEM_RELEASE);
            return nullptr;
        }
        return hModule;
    }
};

int main(int argc, char* argv[]) {
    // Parse arguments
    auto [dbPath, dllName] = parseArguments(argc, argv);
    if (dllName.empty()) {
        std::cerr << std::format("Usage: {} [--db <database_path>] <dll_name>\n", argv[0]);
        return 1;
    }

    try {
        DllLoader loader(dbPath);
        std::string inputDllName = dllName;
        if (fs::path(inputDllName).extension() != ".dll" && fs::path(inputDllName).extension() != ".DLL") {
            inputDllName = std::format("{}.dll", dllName);
        }
        HMODULE hModule = loader.load(inputDllName);
        if (!hModule) {
            std::cerr << std::format("Failed to load DLL: {}\n", inputDllName);
            return 1;
        }
        std::cout << std::format("Successfully loaded DLL: {}\n", inputDllName);
        FreeLibraryMemory(hModule);
    } catch (const std::exception& e) {
        std::cerr << std::format("Error: {}\n", e.what());
        return 1;
    }

    return 0;
}
