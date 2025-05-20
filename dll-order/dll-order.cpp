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

namespace fs = std::filesystem;

// Custom formatter for HMODULE
template <>
struct std::formatter<HMODULE> {
    constexpr auto parse(std::format_parse_context& ctx) { return ctx.begin(); }
    auto format(const HMODULE& handle, std::format_context& ctx) const {
        return std::format_to(ctx.out(), "0x{:016x}", reinterpret_cast<std::uintptr_t>(handle));
    }
};

// Predefined list of DLLs to import with --import
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
            const std::string dllName(path.filename().string());
            std::string lowerName(dllName);
            std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);
            cmd.bind(1, lowerName, sqlite3pp::copy);
            cmd.bind(2, dllData->data(), static_cast<int>(dllData->size()), sqlite3pp::nocopy);
            cmd.execute();
            cmd.reset();
            std::cout << std::format("Added {} to SQLite database\n", lowerName);
        }
        return true;
    } catch (const sqlite3pp::database_error& e) {
        std::cout << std::format("SQLite error: {}\n", e.what());
        return false;
    }
}

class DllLoader {
public:
    explicit DllLoader(sqlite3pp::database& db)
        : db_(db), dllListLoaded_(false), dllNames_(loadDllNamesFromDb()) {}

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
            FreeLibraryMemory(static_cast<HMEMORYMODULE>(module));
        }
        loadedModules_.clear();
        loadOrder_.clear();
    }

    // Check if a DLL exists in SQLite
    bool hasDllInSqlite(
        const std::string& name,
        std::vector<unsigned char>& data) {
        if (dllNames_.find(name) == dllNames_.end()) return false;

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
        const std::string dllName(name);
        std::string lowerName(dllName);
        std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);
        std::cout << std::format("Attempting to load dependency: {}\n", lowerName);

        // check loaded
        auto existingHandle = GetModuleHandleA(lowerName.c_str());
        if (existingHandle) {

            // need to keep?
            if (loadedModules_.find(existingHandle) == loadedModules_.end()) {
                loadedModules_[existingHandle] = false;
                if (std::find(loadOrder_.begin(), loadOrder_.end(), lowerName) == loadOrder_.end()) {
                    loadOrder_.push_back(lowerName);
                }
            }

            // report
            std::cout << std::format("DLL {} already loaded at {}\n", lowerName, existingHandle);
            // done
            return existingHandle;
        }

        std::vector<unsigned char> dllData;

        // in db?
        const auto dll_in_db(hasDllInSqlite(lowerName, dllData)) ;

        LPVOID dll_data ;
        size_t dll_size ;
        if (dll_in_db) {
            std::cout << std::format("Loading {} from SQLite (memory)\n", lowerName);
            dll_data = dllData.data() ;
            dll_size = dllData.size() ;
        }
        else {
            std::cout << std::format("Loading {} from filesystem\n", lowerName);
            char fullPath[MAX_PATH];
            strcpy_s(fullPath, lowerName.c_str());
            bool found = PathFindOnPathA(fullPath, nullptr) != 0;
            fs::path path;
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
            dll_data = dllDataResult->data() ;
            dll_size = dllDataResult->size() ;
        }

        //
        auto handle = MemoryLoadLibraryEx(
            dll_data,
            dll_size,
            nullptr,
            nullptr,
            LoadDependencyCallback,
            GetProcAddressCallback,
            FreeLibraryCallback,
            this
        );

        if (handle) {
            // mark it
            loadedModules_[handle] = true;

            const char* loadfrom = !dll_in_db ? "filesystem" : "SQLite" ;
            // not recorded
            if (std::find(loadOrder_.begin(), loadOrder_.end(), lowerName) == loadOrder_.end()) {
                loadOrder_.push_back(lowerName);
            }
            std::cout << std::format("Successfully loaded {} from {} at {}\n", lowerName, dll_in_db, handle);
        } else {
                std::cout << std::format("Failed to load {} from {}\n", lowerName, dll_in_db);
            }
            return handle;
        }
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
    std::vector<unsigned char> dllData;
    if (loader.hasDllInSqlite(lowerName, dllData)) {
        std::cout << std::format("Loading {} from SQLite (memory)\n", lowerName);
        auto handle = loader.loadDll(dllData, lowerName);
        if (handle) {
            std::cout << std::format("Successfully loaded {} from SQLite at {}\n", lowerName, handle);
            return handle;
        } else {
            std::cout << std::format("Error: Failed to load DLL {} from SQLite (Error: {})\n", lowerName, GetLastError());
        }
    }

    // Fallback to filesystem
    auto dllDataResult = readDllFromFile(path);
    if (!dllDataResult) {
        std::cout << std::format("Error: Failed to load DLL data for {}: {}\n", path.string(), dllDataResult.error().message());
        return nullptr;
    }

    std::cout << std::format("Loaded {} bytes from {}\n", dllDataResult->size(), path.string());
    auto handle = loader.loadDll(*dllDataResult, lowerName);
    if (!handle) {
        std::cout << std::format("Error: Failed to load DLL {} (Error: {})\n", path.string(), GetLastError());
    }
    return handle;
}

// Parses command-line arguments and returns DLL paths and import flag
static std::pair<std::vector<fs::path>, bool> parseArguments(int argc, char* argv[]) {
    std::vector<fs::path> dllPaths;
    bool importPredefined = false;

    for (int ii = 1; ii < argc; ++ii) {
        const std::string arg(argv[ii]);
        if (arg == "--import") {
            importPredefined = true;
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

    return {dllPaths, importPredefined};
}

// Populates SQLite database with predefined DLLs and exits
static void populatePredefinedDlls(sqlite3pp::database& db) {
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
    const auto [dllPaths, importPredefined] = parseArguments(argc, argv);

    // Check for valid input
    if (!importPredefined && dllPaths.empty()) {
        std::cout << std::format("Usage: {} [--import] <dll_path> [dll_path...]\n", argv[0]);
        return 1;
    }

    // Initialize SQLite database
    sqlite3pp::database db("dlls.db", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);

    // Handle --import option
    if (importPredefined) {
        populatePredefinedDlls(db);
    }

    // Initialize DLL loader and load from database
    DllLoader loader(db);
    loader.loadAllDllsFromDb();

    // Load DLLs from command-line arguments
    loadDllsFromArgs(dllPaths, loader);

    // Report load order
    reportLoadOrder(loader);

    return 0;
}
