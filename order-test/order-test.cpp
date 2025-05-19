#include <dll-order-min.h>
#include <iostream>
#include <filesystem>
#include <sqlite3pp.h>
#include <format>

namespace fs = std::filesystem;

// Portable logging wrappers using std::format_string
template<typename... Args>
void logResult(std::format_string<Args...> fmt, Args&&... args) {
    std::cout << std::format(fmt, std::forward<Args>(args)...) << std::endl;
}

template<typename... Args>
void logInfo(std::format_string<Args...> fmt, Args&&... args) {
    std::cout << std::format(fmt, std::forward<Args>(args)...) << std::endl;
}

template<typename... Args>
void logError(std::format_string<Args...> fmt, Args&&... args) {
    std::cerr << std::format(fmt, std::forward<Args>(args)...) << std::endl;
}

// Parses command-line arguments for database path
static std::string parseDbPath(int argc, char* argv[]) {
    std::string dbPath = "dlls.db";
    for (int i = 1; i < argc; ++i) {
        if (std::string(argv[i]) == "--db" && i + 1 < argc) {
            dbPath = argv[++i];
        }
    } // for
    return dbPath;
}

// Loads DLL data from database
std::expected<std::map<std::string, std::vector<char>>, std::string>
loadDllData(const std::string& dbPath)
{
    std::map<std::string, std::vector<char>> dllDataMap;
    try {
        sqlite3pp::database db(dbPath.c_str(), SQLITE_OPEN_READONLY);
        sqlite3pp::query dllQuery(db, "SELECT name, data FROM dlls");
        for (const auto& row : dllQuery) {
            std::string name = row.get<std::string>(0);
            const char* blob = static_cast<const char*>(row.get<const void*>(1));
            int size = row.column_bytes(1);
            dllDataMap[name] = std::vector<char>(blob, blob + size);
        }
    } catch (const sqlite3pp::database_error& e) {
        return std::unexpected("Database error: " + std::string(e.what()));
    }
    return dllDataMap;
}

// Stub for extractDependencies
std::vector<std::string> extractDependencies(
    const char* data,
    size_t size)
{
    return std::vector<std::string>{}; // Stub: returns empty vector
}

// Prints dependency list
void printDependencyList(
    const std::vector<std::tuple<std::string,
    const char*, size_t>>& loadOrder)
{
    logResult("DLL Load Order and Dependencies:");
    for (size_t i = 0; i < loadOrder.size(); ++i) {
        const auto& [name, data, size] = loadOrder[i];
        auto deps = extractDependencies(data, size);
        if (deps.empty()) {
            logResult("{}. {}: none", i + 1, name);
        } else {
            std::string depList;
            bool first = true;
            for (const auto& dep : deps) {
                if (!first) depList += ", ";
                depList += dep;
                first = false;
            }
            logResult("{}. {}: {}", i + 1, name, depList);
        }
    }
}

int main(int argc, char* argv[]) {

    // Parse database path
    std::string dbPath = parseDbPath(argc, argv);
    if (!fs::exists(dbPath)) {
        logError("Error: Database file {} does not exist", dbPath);
        return 1;
    }

    // Load DLL data from database
    auto dllDataResult = loadDllData(dbPath);
    if (!dllDataResult) {
        logError("{}", dllDataResult.error());
        return 1;
    }
    auto dllDataMap = *dllDataResult;

    if (dllDataMap.empty()) {
        logError("Error: No DLLs found in database");
        return 1;
    }

    // Compute load order
    auto loadOrderResult = computeLoadOrder(dllDataMap);
    if (!loadOrderResult) {
        logError("Error: {}", loadOrderResult.error());
        return 1;
    }

    // Print dependency list
    printDependencyList(*loadOrderResult);

    return 0;
}
