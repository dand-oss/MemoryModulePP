#include <windows.h>
#include <shlwapi.h>
#include <vector>
#include <string>
#include <unordered_map>
#include <set>
#include <filesystem>
#include <iostream>
#include <format>
#include <algorithm>
#include <expected>
#include <system_error>
#include <fstream>
#include <sqlite3pp.h>
#include "LoadDllMemoryApi.h"
#include "MemoryModule.h"

#pragma comment(lib, "shlwapi.lib")

// Ensure C++20 is enabled for std::expected and std::format
// Project settings: /std:c++20

namespace fs = std::filesystem;

// Custom formatter for HMODULE
template <>
struct std::formatter<HMODULE> {
    constexpr auto parse(std::format_parse_context& ctx) { return ctx.begin(); }
    auto format(const HMODULE& handle, std::format_context& ctx) const {
        return std::format_to(ctx.out(), "0x{:016x}", reinterpret_cast<std::uintptr_t>(handle));
    }
};

// Reads a DLL file into a VirtualAlloc buffer
static std::expected<std::pair<LPVOID, size_t>, std::error_code> readDllFromFile(
    const fs::path& path) {
    FILE* f;
    if (fopen_s(&f, path.string().c_str(), "rb") != 0 || !f) {
        return std::unexpected(std::make_error_code(std::errc::no_such_file_or_directory));
    }
    _fseeki64(f, 0, SEEK_END);
    const auto fileSize = _ftelli64(f);
    if (fileSize <= 0) {
        fclose(f);
        return std::unexpected(std::make_error_code(std::errc::no_such_file_or_directory));
    }
    if (fileSize > SIZE_MAX) {
        fclose(f);
        return std::unexpected(std::make_error_code(std::errc::file_too_large));
    }
    _fseeki64(f, 0, SEEK_SET);

    LPVOID buffer = VirtualAlloc(nullptr, static_cast<size_t>(fileSize), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!buffer) {
        fclose(f);
        return std::unexpected(std::make_error_code(std::errc::not_enough_memory));
    }

    if (fread(buffer, 1, static_cast<size_t>(fileSize), f) != static_cast<size_t>(fileSize)) {
        VirtualFree(buffer, 0, MEM_RELEASE);
        fclose(f);
        return std::unexpected(std::make_error_code(std::errc::io_error));
    }
    fclose(f);

    return std::make_pair(buffer, static_cast<size_t>(fileSize));
}

class DllLoader {
public:
    explicit DllLoader(sqlite3pp::database& db)
        : db_(db), dllListLoaded_(false), dllNames_(loadDllNamesFromDb()) {}

    ~DllLoader() { unloadAll(); }

    // Load a DLL from memory data with its name
    HMEMORYMODULE loadDll(
        LPVOID buffer,
        size_t size,
        const std::string& dllName) {
        if (std::find(loadOrder_.begin(), loadOrder_.end(), dllName) == loadOrder_.end()) {
            loadOrder_.push_back(dllName);
        }
        auto handle = MemoryLoadLibraryEx(
            buffer,
            size,
            nullptr,
            nullptr,
            LoadDependencyCallback,
            GetProcAddressCallback,
            FreeLibraryCallback,
            this
        );
        if (handle) {
            loadedModules_[handle] = true;
        } else {
            VirtualFree(buffer, 0, MEM_RELEASE);
        }
        return handle;
    }

    // Unload all loaded modules
    void unloadAll() {
        for (const auto& [module, isMemoryLoaded] : loadedModules_) {
            FreeLibraryMemory(static_cast<HMEMORYMODULE>(module));
        }
        loadedModules_.clear();
        loadOrder_.clear();
    }

    // Check if a DLL exists in SQLite
    bool hasDllInSqlite(
        const std::string& name,
        LPVOID& buffer,
        size_t& size) {
        if (dllNames_.find(name) == dllNames_.end()) return false;

        try {
            sqlite3pp::query qry(db_, "SELECT data FROM dlls WHERE name = ?");
            qry.bind(1, name, sqlite3pp::copy);
            auto it = qry.begin();
            if (it == qry.end()) return false;
            auto blob = (*it).get<const void*>(0);
            const auto blobSize = (*it).column_bytes(0);
            if (blobSize > SIZE_MAX) {
                std::cout << std::format("Error: SQLite data for {} too large for size_t\n", name);
                return false;
            }
            size = static_cast<size_t>(blobSize);
            buffer = VirtualAlloc(nullptr, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
            if (!buffer) {
                std::cout << std::format("Error: Failed to allocate memory for {}\n", name);
                return false;
            }
            std::memcpy(buffer, blob, size);
            return true;
        } catch (const sqlite3pp::database_error& e) {
            std::cout << std::format("SQLite error: {}\n", e.what());
            return false;
        }
    }

    // Get the load order of DLLs
    const std::vector<std::string>& getLoadOrder() const { return loadOrder_; }

    // Load a dependency
    HCUSTOMMODULE loadDependency(const char* name) {
        const std::string dllName(name);
        std::string lowerName(dllName);
        std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);
        std::cout << std::format("Attempting to load dependency: {}\n", lowerName);

        // Check if already loaded
        auto existingHandle = GetModuleHandleA(lowerName.c_str());
        if (existingHandle) {
            if (loadedModules_.find(existingHandle) == loadedModules_.end()) {
                loadedModules_[existingHandle] = false;
                if (std::find(loadOrder_.begin(), loadOrder_.end(), lowerName) == loadOrder_.end()) {
                    loadOrder_.push_back(lowerName);
                }
            }
            std::cout << std::format("DLL {} already loaded at {}\n", lowerName, existingHandle);
            return existingHandle;
        }

        // Load DLL data
        LPVOID buffer = nullptr;
        size_t size = 0;
        const bool dllInDb = hasDllInSqlite(lowerName, buffer, size);
        fs::path path;
        if (!dllInDb) {
            std::cout << std::format("Loading {} from filesystem\n", lowerName);
            char fullPath[MAX_PATH];
            strcpy_s(fullPath, lowerName.c_str());
            bool found = PathFindOnPathA(fullPath, nullptr) != 0;
            if (!found) {
                std::cout << std::format("Error: Could not find {} in PATH\n", lowerName);
                return nullptr;
            }
            path = fs::path(fullPath);
            std::cout << std::format("Resolved {} to {}\n", lowerName, path.string());

            auto dllDataResult = readDllFromFile(path);
            if (!dllDataResult) {
                std::cout << std::format("Error: Failed to load DLL data for {}: {}\n", path.string(), dllDataResult.error().message());
                return nullptr;
            }
            buffer = dllDataResult->first;
            size = dllDataResult->second;
        } else {
            std::cout << std::format("Loading {} from SQLite (memory)\n", lowerName);
        }

        // Load DLL
        auto handle = MemoryLoadLibraryEx(
            buffer,
            size,
            nullptr,
            nullptr,
            LoadDependencyCallback,
            GetProcAddressCallback,
            FreeLibraryCallback,
            this
        );

        const char* loadFrom = dllInDb ? "SQLite" : "filesystem";
        if (handle) {
            loadedModules_[handle] = true;
            if (std::find(loadOrder_.begin(), loadOrder_.end(), lowerName) == loadOrder_.end()) {
                loadOrder_.push_back(lowerName);
            }
            std::cout << std::format("Successfully loaded {} from {} at {}\n", lowerName, loadFrom, handle);
        } else {
            std::cout << std::format("Failed to load {} from {}\n", lowerName, loadFrom);
            VirtualFree(buffer, 0, MEM_RELEASE);
        }
        return handle;
    }

    // Static callback functions for MemoryLoadLibraryEx
    static HCUSTOMMODULE WINAPI LoadDependencyCallback(
        LPCSTR name,
        void* userdata) {
        return static_cast<DllLoader*>(userdata)->loadDependency(name);
    }

    static FARPROC WINAPI GetProcAddressCallback(
        HCUSTOMMODULE module,
        LPCSTR name,
        void* userdata) {
        return GetProcAddress(static_cast<HMODULE>(module), name);
    }

    static void WINAPI FreeLibraryCallback(
        HCUSTOMMODULE module,
        void* userdata) {
        auto loader = static_cast<DllLoader*>(userdata);
        auto it = loader->loadedModules_.find(module);
        if (it == loader->loadedModules_.end()) return;
        FreeLibraryMemory(static_cast<HMEMORYMODULE>(module));
        loader->loadedModules_.erase(it);
    }

    // Load all DLLs from SQLite database
    void loadAllDllsFromDb() {
        if (dllListLoaded_) return; // Avoid reloading
        dllListLoaded_ = true;

        try {
            sqlite3pp::query qry(db_, "SELECT name FROM dlls");
            for (auto it = qry.begin(); it != qry.end(); ++it) {
                const std::string dllName((*it).get<std::string>(0));
                LPVOID buffer = nullptr;
                size_t size = 0;
                if (hasDllInSqlite(dllName, buffer, size)) {
                    std::cout << std::format("Loading {} from SQLite\n", dllName);
                    const auto handle = loadDll(buffer, size, dllName);
                    if (handle) {
                        std::cout << std::format("DLL {} loaded from SQLite at {}\n", dllName, handle);
                    } else {
                        std::cout << std::format("Error: Failed to load DLL {} from SQLite (Error: {})\n", dllName, GetLastError());
                        VirtualFree(buffer, 0, MEM_RELEASE);
                    }
                }
            }
        } catch (const sqlite3pp::database_error& e) {
            std::cout << std::format("SQLite error: {}\n", e.what());
        }
    }

private:
    // Load DLL names from database into a set
    std::set<std::string> loadDllNamesFromDb() {
        std::set<std::string> names;
        try {
            sqlite3pp::query qry(db_, "SELECT name FROM dlls");
            for (auto it = qry.begin(); it != qry.end(); ++it) {
                names.emplace((*it).get<std::string>(0));
            }
        } catch (const sqlite3pp::database_error& e) {
            std::cout << std::format("SQLite error while loading DLL names: {}\n", e.what());
        }
        return names;
    }

    sqlite3pp::database& db_;
    std::unordered_map<HCUSTOMMODULE, bool> loadedModules_;
    std::vector<std::string> loadOrder_;
    bool dllListLoaded_;
    const std::set<std::string> dllNames_;
};

// Loads a DLL, checking SQLite first, then filesystem
static HMEMORYMODULE loadDll(const fs::path& path, DllLoader& loader) {
    const std::string dllName(path.filename().string());
    std::string lowerName(dllName);
    std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);

    // Check SQLite database first
    LPVOID buffer = nullptr;
    size_t size = 0;
    if (loader.hasDllInSqlite(lowerName, buffer, size)) {
        std::cout << std::format("Loading {} from SQLite (memory)\n", lowerName);
        auto handle = loader.loadDll(buffer, size, lowerName);
        if (handle) {
            std::cout << std::format("Successfully loaded {} from SQLite at {}\n", lowerName, handle);
            return handle;
        } else {
            std::cout << std::format("Error: Failed to load DLL {} from SQLite (Error: {})\n", lowerName, GetLastError());
            VirtualFree(buffer, 0, MEM_RELEASE);
        }
    }

    // Fallback to filesystem
    auto dllDataResult = readDllFromFile(path);
    if (!dllDataResult) {
        std::cout << std::format("Error: Failed to load DLL data for {}: {}\n", path.string(), dllDataResult.error().message());
        return nullptr;
    }

    std::cout << std::format("Loaded {} bytes from {}\n", dllDataResult->second, path.string());
    auto handle = loader.loadDll(dllDataResult->first, dllDataResult->second, lowerName);
    if (!handle) {
        std::cout << std::format("Error: Failed to load DLL {} (Error: {})\n", path.string(), GetLastError());
        VirtualFree(dllDataResult->first, 0, MEM_RELEASE);
    }
    return handle;
}

// Parses command-line arguments and returns DLL paths and database path
static std::pair<std::vector<fs::path>, std::string> parseArguments(int argc, char* argv[]) {
    std::vector<fs::path> dllPaths;
    std::string dbPath = "dlls.db"; // Default database path

    for (int i = 1; i < argc; ++i) {
        const std::string arg(argv[i]);
        if (arg == "--db" && i + 1 < argc) {
            dbPath = argv[++i];
            continue;
        }
        std::string inputPath(arg);
        if (!(fs::path(inputPath).extension() == ".dll" || fs::path(inputPath).extension() == ".DLL")) {
            inputPath += ".dll";
        }
        auto path = fs::path(inputPath);
        bool isFilename = !path.has_parent_path();
        if (isFilename) {
            char fullPath[MAX_PATH];
            strcpy_s(fullPath, inputPath.c_str());
            bool found = PathFindOnPathA(fullPath, nullptr) != 0;
            if (found) {
                path = fs::path(fullPath);
                std::cout << std::format("Resolved {} to {}\n", inputPath, path.string());
            } else {
                std::cout << std::format("Error: Could not find {} in PATH\n", inputPath);
                continue;
            }
        }
        dllPaths.push_back(path);
    }

    return {dllPaths, dbPath};
}

// Loads DLLs from command-line arguments
static void loadDllsFromArgs(const std::vector<fs::path>& dllPaths, DllLoader& loader) {
    for (const auto& path : dllPaths) {
        std::cout << std::format("Processing DLL: {}\n", path.string());
        const auto handle = loadDll(path, loader);
        if (handle) {
            std::cout << std::format("DLL {} loaded successfully at {}\n", path.string(), handle);
        }
    }
}

// Reports the DLL load order
static void reportLoadOrder(const DllLoader& loader) {
    const auto& loadOrder = loader.getLoadOrder();
    std::cout << "DLL load order (via import table resolution):\n";
    for (const auto& dll : loadOrder) {
        std::cout << std::format("  {}\n", dll);
    }
}

int main(int argc, char* argv[])
{
    // Parse command-line arguments
    const auto [dllPaths, dbPath] = parseArguments(argc, argv);

    // Check for valid input
    if (dllPaths.empty()) {
        std::cout << std::format("Usage: {} [--db <database_path>] <dll_path> [dll_path...]\n", argv[0]);
        return 1;
    }

    // Initialize SQLite database
    try {
        sqlite3pp::database db(dbPath.c_str(), SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);

        // Initialize DLL loader and load from database
        DllLoader loader(db);
        loader.loadAllDllsFromDb();

        // Load DLLs from command-line arguments
        loadDllsFromArgs(dllPaths, loader);

        // Report load order
        reportLoadOrder(loader);
    } catch (const sqlite3pp::database_error& e) {
        std::cout << std::format("SQLite error: {}\n", e.what());
        return 1;
    }

    return 0;
}
</xArtifact>

### Build Instructions
1. **Project Settings**:
   - C++20: Project Properties > C/C++ > Language > `/std:c++20` (required for `std::format` and `std::expected`).
   - Link `shlwapi.lib`: Project Properties > Linker > Input > Additional Dependencies.
   - Include paths: Ensure `sqlite3pp.h` (`I:\af\ports\vs17-32\include`), `LoadDllMemoryApi.h`, `MemoryModule.h`, and `Utils.h` (for `LdrpCallInitializers`) are accessible.
   - Compiler: MSVC 14.44.35207 (per your build log).
2. **Build**:
   - Rebuild `db-dll-import.vcxproj` (unchanged, should succeed as before).
   - Rebuild `dll-order.vcxproj` (previously succeeded; `std::format` reintroduction should not cause issues if C++20 is enabled).
3. **Verify**:
   - Confirm no compilation errors related to `std::format` (requires C++20).
   - Check console output formatting in `dll-order.exe` to ensure `std::format` is applied consistently.

### Testing
- **db-dll-import.cpp** (Unchanged):
  - Run: `db-dll-import.exe --db my_dlls.db dll1.dll dll2.dll`
  - Test cases:
    - Valid DLLs in PATH.
    - Missing DLLs for error messages.
    - DLL names without `.dll` for extension appending.
    - Custom database path (`--db test.db`).
  - Verify `my_dlls.db` has the `dlls` table with correct data.
- **dll-order.cpp**:
  - Run: `dll-order.exe --db my_dlls.db path/to/dll1.dll`
  - Test cases:
    - DLLs in `my_dlls.db` for database loading.
    - Filesystem DLLs for fallback.
    - Invalid paths for error handling.
    - Custom database path (`--db test.db`).
  - Verify console output uses `std::format` style (e.g., clean, formatted strings like `Successfully loaded kernel32.dll from SQLite at 0x00007fff12345678`).
- **Integration**:
  - Import: `db-dll-import.exe --db test.db dll1.dll`
  - Load: `dll-order.exe --db test.db dll1.dll`
  - Confirm database consistency and formatted output.

### Notes
- **std::format in dll-order.cpp**: Restored for all console output, matching the style in `db-dll-import.cpp`. The `HMODULE` formatter ensures consistent handle formatting.
- **No Functional Changes**: Only output formatting changed in `dll-order.cpp`; logic is identical to the previous version.
- **C++20 Dependency**: `std::format` requires C++20. Your previous successful build of `dll-order.cpp` suggests C++20 is enabled, but if errors occur, confirm `/std:c++20` in project settings. If C++17 is needed, I can rewrite using `sprintf_s` or `std::stringstream`.
- **MemoryLoadLibraryEx**: Assumes `LdrpCallInitializers` integration. Ensure `Utils.h`/`Utils.cpp` are linked.
- **db-dll-import.cpp**: Included unchanged for completeness. If you want to modify its formatting or add features, let me know.

If you encounter build issues (e.g., `std::format` not found) or want further tweaks (e.g., aligning `db-dll-import.cpp` formatting, C++17 compatibility), please share the build log or details. Thanks for specifying your preference for `std::format`!