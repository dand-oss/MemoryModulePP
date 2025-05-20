#include <windows.h>
#include <shlwapi.h>
#include <vector>
#include <string>
#include <unordered_map>
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

namespace fs = std::filesystem;

// Custom formatter for HMODULE
template <>
struct std::formatter<HMODULE> {
    constexpr auto parse(std::format_parse_context& ctx) { return ctx.begin(); }
    auto format(const HMODULE& handle, std::format_context& ctx) const {
        return std::format_to(ctx.out(), "0x{:016x}", reinterpret_cast<std::uintptr_t>(handle));
    }
};

// Predefined list of DLLs to load with --load
const std::vector<std::string> dllLoadOrder = {
    "I77_d.dll",
    "Qt5CoreASVd_d.dll",
    "audit_customize_d.dll",
    "ibpp_d.dll",
    "nlopt_d.dll",
    "ntools_d.dll",
    "qhttpserver_d.dll",
    "rttr_core_d.dll",
    "rwtool_d.dll",
    "xlsx_d.dll",
    "yaml-cpp_d.dll",
    "F77_d.dll",
    "Qt5GuiASVd_d.dll",
    "Qt5NetworkASVd_d.dll",
    "Qt5XmlASVd_d.dll",
    "apptools_d.dll",
    "athread_d.dll",
    "tools_d.dll",
    "Qt5WidgetsASVd_d.dll",
    "Wt2_d.dll",
    "dynalift_d.dll",
    "oilcore1_d.dll",
    "ole_d.dll",
    "twophase_d.dll",
    "win31_d.dll",
    "Qt5PrintSupportASVd_d.dll",
    "Qt5SvgASVd_d.dll",
    "gtools_d.dll",
    "winhelp_d.dll",
    "oilcore2_d.dll",
    "glsupdll1_d.dll",
    "piapi_d.dll",
    "oilrunt_d.dll",
    "otools_d.dll",
    "glsupdll2_d.dll",
    "piapi_oil_d.dll",
    "asirpc_d.dll",
    "oilapi_d.dll",
    "oilapp_d.dll",
    "oilcomp_d.dll",
    "oilole_d.dll",
    "qtoil_d.dll",
    "Wt2_Oil_d.dll",
    "calc_d.dll",
    "dstng_d.dll",
    "glsuplib1_d.dll",
    "oildll_d.dll",
    "qtxlsx_d.dll",
    "network_d.dll",
    "glsuplib2_d.dll",
    "gluecomlib_d.dll",
    "dbobj_d.dll",
    "dstng_odbc_d.dll",
    "dstng_oracle_d.dll",
    "dstng_firebird_d.dll",
    "dstng_vanilla_d.dll",
    "gui_d.dll",
    "graphds_d.dll",
    "asv-settings-app_d.dll",
    "glueapp_d.dll"
};

// Reads a DLL file into a byte vector
static std::expected<std::vector<unsigned char>, std::error_code> readDllFromFile(
    const fs::path& path) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) return std::unexpected(std::make_error_code(std::errc::no_such_file_or_directory));
    const auto fileSize = file.tellg();
    if (fileSize <= 0) return std::unexpected(std::make_error_code(std::errc::no_such_file_or_directory));
    std::vector<unsigned char> dllData(static_cast<size_t>(fileSize));
    file.seekg(0, std::ios::beg);
    return file.read(reinterpret_cast<char*>(dllData.data()), fileSize)
        ? std::expected<std::vector<unsigned char>, std::error_code>{dllData}
        : std::unexpected(std::make_error_code(std::errc::io_error));
}

// Populates SQLite database with DLL data
static bool populateSqliteDb(
    sqlite3pp::database& db,
    const std::vector<fs::path>& dllPaths) {
    try {
        db.execute("CREATE TABLE IF NOT EXISTS dlls (name TEXT PRIMARY KEY, data BLOB)");
        sqlite3pp::command cmd(db, "INSERT OR REPLACE INTO dlls (name, data) VALUES (?, ?)");
        for (const auto& path : dllPaths) {
            auto dllData = readDllFromFile(path);
            if (!dllData) {
                std::cout << std::format(
                    "Error: Failed to read {}: {}\n",
                    path.string(),
                    dllData.error().message());
                continue;
            }
            std::string dllName = path.filename().string();
            std::transform(dllName.begin(), dllName.end(), dllName.begin(), ::tolower);
            cmd.bind(1, dllName, sqlite3pp::copy);
            cmd.bind(2, dllData->data(), static_cast<int>(dllData->size()), sqlite3pp::nocopy);
            cmd.execute();
            cmd.reset();
            std::cout << std::format("Added {} to SQLite database\n", dllName);
        }
        return true;
    } catch (const sqlite3pp::database_error& e) {
        std::cout << std::format("SQLite error: {}\n", e.what());
        return false;
    }
}

class DllLoader {
public:
    explicit DllLoader(sqlite3pp::database& db) : db_(db), dllListLoaded_(false) {}

    ~DllLoader() { unloadAll(); }

    // Load a DLL from memory data with its name
    HMEMORYMODULE loadDll(
        const std::vector<unsigned char>& dllData,
        const std::string& dllName) {
        if (std::find(loadOrder_.begin(), loadOrder_.end(), dllName) == loadOrder_.end()) {
            loadOrder_.push_back(dllName);
        }
        auto handle = MemoryLoadLibraryEx(
            dllData.data(),
            dllData.size(),
            nullptr,
            nullptr,
            LoadDependencyCallback,
            GetProcAddressCallback,
            FreeLibraryCallback,
            this
        );
        if (handle) loadedModules_[handle] = true;
        return handle;
    }

    // Unload all loaded modules
    void unloadAll() {
        for (const auto& [module, isMemoryLoaded] : loadedModules_) {
            isMemoryLoaded ? FreeLibraryMemory(static_cast<HMEMORYMODULE>(module)) : FreeLibrary(static_cast<HMODULE>(module));
        }
        loadedModules_.clear();
        loadOrder_.clear();
    }

    // Check if a DLL exists in SQLite
    bool hasDllInSqlite(
        const std::string& name,
        std::vector<unsigned char>& data) {
        try {
            sqlite3pp::query qry(db_, "SELECT data FROM dlls WHERE name = ?");
            qry.bind(1, name, sqlite3pp::copy);
            auto it = qry.begin();
            if (it == qry.end()) return false;
            auto blob = (*it).get<const void*>(0);
            const auto size = (*it).column_bytes(0);
            data.assign(static_cast<const unsigned char*>(blob),
                        static_cast<const unsigned char*>(blob) + size);
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
        std::string dllName(name);
        std::transform(dllName.begin(), dllName.end(), dllName.begin(), ::tolower);
        std::cout << std::format("Attempting to load dependency: {}\n", dllName);

        auto existingHandle = GetModuleHandleA(dllName.c_str());
        if (existingHandle) {
            if (loadedModules_.find(existingHandle) == loadedModules_.end()) {
                loadedModules_[existingHandle] = false;
                if (std::find(loadOrder_.begin(), loadOrder_.end(), dllName) == loadOrder_.end()) {
                    loadOrder_.push_back(dllName);
                }
            }
            std::cout << std::format("DLL {} already loaded at {}\n", dllName, existingHandle);
            return existingHandle;
        }

        std::vector<unsigned char> dllData;
        if (hasDllInSqlite(dllName, dllData)) {
            std::cout << std::format("Loading {} from SQLite (memory)\n", dllName);
            auto handle = MemoryLoadLibraryEx(
                dllData.data(),
                dllData.size(),
                nullptr,
                nullptr,
                LoadDependencyCallback,
                GetProcAddressCallback,
                FreeLibraryCallback,
                this
            );
            if (handle) {
                loadedModules_[handle] = true;
                if (std::find(loadOrder_.begin(), loadOrder_.end(), dllName) == loadOrder_.end()) {
                    loadOrder_.push_back(dllName);
                }
                std::cout << std::format("Successfully loaded {} from SQLite at {}\n", dllName, handle);
            } else {
                std::cout << std::format("Failed to load {} from SQLite\n", dllName);
            }
            return handle;
        }

        std::cout << std::format("Loading {} from filesystem\n", dllName);
        auto handle = LoadLibraryA(dllName.c_str());
        if (handle) {
            loadedModules_[handle] = false;
            if (std::find(loadOrder_.begin(), loadOrder_.end(), dllName) == loadOrder_.end()) {
                loadOrder_.push_back(dllName);
            }
            std::cout << std::format("Successfully loaded {} from filesystem at {}\n", dllName, handle);
        } else {
            std::cout << std::format("Failed to load {} from filesystem\n", dllName);
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
        it->second ? FreeLibraryMemory(static_cast<HMEMORYMODULE>(module)) : FreeLibrary(static_cast<HMODULE>(module));
        loader->loadedModules_.erase(it);
    }

    // Load all DLLs from SQLite database
    void loadAllDllsFromDb() {
        if (dllListLoaded_) return; // Avoid reloading
        dllListLoaded_ = true;

        try {
            sqlite3pp::query qry(db_, "SELECT name FROM dlls");
            for (auto it = qry.begin(); it != qry.end(); ++it) {
                std::string dllName = (*it).get<std::string>(0);
                std::vector<unsigned char> dllData;
                if (hasDllInSqlite(dllName, dllData)) {
                    std::cout << std::format("Loading {} from SQLite\n", dllName);
                    const auto handle = loadDll(dllData, dllName);
                    if (handle) {
                        std::cout << std::format("DLL {} loaded from SQLite at {}\n", dllName, handle);
                    } else {
                        std::cout << std::format("Error: Failed to load DLL {} from SQLite (Error: {})\n", dllName, GetLastError());
                    }
                }
            }
        } catch (const sqlite3pp::database_error& e) {
            std::cout << std::format("SQLite error: {}\n", e.what());
        }
    }

private:
    sqlite3pp::database& db_;
    std::unordered_map<HCUSTOMMODULE, bool> loadedModules_;
    std::vector<std::string> loadOrder_;
    bool dllListLoaded_; // Flag to track if DLL list has been loaded
};

// Loads a DLL, checking SQLite first, then filesystem
static HMEMORYMODULE loadDll(const fs::path& path, DllLoader& loader) {
    std::string dllName = path.filename().string();
    std::transform(dllName.begin(), dllName.end(), dllName.begin(), ::tolower);

    // Check SQLite database first
    std::vector<unsigned char> dllData;
    if (loader.hasDllInSqlite(dllName, dllData)) {
        std::cout << std::format("Loading {} from SQLite (memory)\n", dllName);
        auto handle = loader.loadDll(dllData, dllName);
        if (handle) {
            std::cout << std::format("Successfully loaded {} from SQLite at {}\n", dllName, handle);
            return handle;
        } else {
            std::cout << std::format("Error: Failed to load DLL {} from SQLite (Error: {})\n", dllName, GetLastError());
        }
    }

    // Fallback to filesystem
    auto dllDataResult = readDllFromFile(path);
    if (!dllDataResult) {
        std::cout << std::format("Error: Failed to load DLL data for {}: {}\n", path.string(), dllDataResult.error().message());
        return nullptr;
    }

    std::cout << std::format("Loaded {} bytes from {}\n", dllDataResult->size(), path.string());
    auto handle = loader.loadDll(*dllDataResult, dllName);
    if (!handle) {
        std::cout << std::format("Error: Failed to load DLL {} (Error: {})\n", path.string(), GetLastError());
    }
    return handle;
}

int main(int argc, char* argv[])
{
    bool loadPredefined = false;
    std::vector<fs::path> dllPaths;

    // Parse command-line arguments
    for (int ii = 1; ii < argc; ++ii) {
        std::string arg(argv[ii]);
        if (arg == "--load") {
            loadPredefined = true;
            continue;
        }
        auto inputPath = arg;
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

    // Check for valid input
    if (!loadPredefined && dllPaths.empty()) {
        std::cout << std::format(
            "Usage: {} [--load] <dll_path> [dll_path...]\n",
            argv[0]);
        return 1;
    }

    sqlite3pp::database db(
         "dlls.db",
         SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);

    // Load predefined DLLs if --load is specified
    if (loadPredefined) {
        std::vector<fs::path> predefinedPaths;
        for (const auto& dllName : dllLoadOrder) {
            char fullPath[MAX_PATH];
            strcpy_s(fullPath, dllName.c_str());
            bool found = PathFindOnPathA(fullPath, nullptr) != 0;
            if (found) {
                fs::path path(fullPath);
                predefinedPaths.push_back(path);
                std::cout << std::format(
                    "Resolved predefined DLL {} to {}\n",
                    dllName,
                    path.string());
            } else {
                std::cout << std::format(
                    "Error: Could not find predefined DLL {} in PATH\n",
                    dllName);
            }
        }
        if (!predefinedPaths.empty()) {
            populateSqliteDb(db, predefinedPaths);
        }
        exit(0);
    }

    DllLoader loader(db);

    // Load all DLLs from SQLite database on first access
    loader.loadAllDllsFromDb();

    // Load DLLs from command-line arguments
    for (const auto& path : dllPaths) {
        std::cout << std::format("Processing DLL: {}\n", path.string());
        const auto handle = loadDll(path, loader);
        if (handle) {
            std::cout << std::format("DLL {} loaded successfully at {}\n", path.string(), handle);
        }
    }

    // Report load order
    const auto& loadOrder = loader.getLoadOrder();
    std::cout << "DLL load order (via import table resolution):\n";
    for (const auto& dll : loadOrder) {
        std::cout << std::format("  {}\n", dll);
    }

    return 0;
}