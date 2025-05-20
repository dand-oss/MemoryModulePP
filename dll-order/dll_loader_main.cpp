#include <windows.h>
#include <shlwapi.h>
#include <vector>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <filesystem>
#include <iostream>
#include <format>
#include <algorithm>
#include <expected>
#include <system_error>
#include <queue>
#include <SQLiteCpp/SQLiteCpp.h>
#include "DllLoader.h"

namespace fs = std::filesystem;

// Custom formatter for HMODULE
template <>
struct std::formatter<HMODULE> {
    constexpr auto parse(std::format_parse_context& ctx) {
        return ctx.begin();
    }
    auto format(const HMODULE& handle, std::format_context& ctx) const {
        return std::format_to(ctx.out(), "0x{:016x}", reinterpret_cast<std::uintptr_t>(handle));
    }
};

// Reads a DLL file into a byte vector
static std::expected<std::vector<unsigned char>, std::error_code> readDllFromFile(const fs::path& path) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        return std::unexpected(std::make_error_code(std::errc::no_such_file_or_directory));
    }
    const auto fileSize = file.tellg();
    if (fileSize <= 0) {
        return std::unexpected(std::make_error_code(std::errc::no_such_file_or_directory));
    }
    std::vector<unsigned char> dllData(static_cast<size_t>(fileSize));
    file.seekg(0, std::ios::beg);
    if (!file.read(reinterpret_cast<char*>(dllData.data()), fileSize)) {
        return std::unexpected(std::make_error_code(std::errc::io_error));
    }
    return dllData;
}

// Populates SQLite database with DLL data (for testing)
static void populateSqliteDb(SQLite::Database& db, const std::vector<fs::path>& dllPaths) {
    db.exec("CREATE TABLE IF NOT EXISTS dlls (name TEXT PRIMARY KEY, data BLOB)");
    SQLite::Statement insert(db, "INSERT OR REPLACE INTO dlls (name, data) VALUES (?, ?)");
    for (const auto& path : dllPaths) {
        auto dllData = readDllFromFile(path);
        if (!dllData) {
            std::cout << std::format("Error: Failed to read {}: {}\n", path.string(), dllData.error().message());
            continue;
        }
        std::string dllName = path.filename().string();
        std::transform(dllName.begin(), dllName.end(), dllName.begin(), ::tolower);
        insert.bind(1, dllName);
        insert.bind(2, dllData->data(), static_cast<int>(dllData->size()));
        insert.exec();
        insert.reset();
        std::cout << std::format("Added {} to SQLite database\n", dllName);
    }
}

// Dependency graph for topological sort using Kahn's algorithm
class DependencyGraph {
public:
    void addEdge(const std::string& from, const std::string& to) {
        // Add edge from -> to
        graph_[from].insert(to);
        // Ensure 'to' is in the graph even if it has no outgoing edges
        graph_[to];
        // Increment in-degree of 'to'
        inDegree_[to]++;
    }

    std::vector<std::string> topologicalSort() {
        std::vector<std::string> result;
        std::queue<std::string> queue;
        std::unordered_map<std::string, int> inDegree = inDegree_;

        // Initialize queue with nodes having in-degree 0
        for (const auto& [node, _] : graph_) {
            if (inDegree[node] == 0) {
                queue.push(node);
            }
        }

        // Process nodes
        while (!queue.empty()) {
            auto node = queue.front();
            queue.pop();
            result.push_back(node);

            // Decrease in-degree for all neighbors
            for (const auto& neighbor : graph_[node]) {
                if (--inDegree[neighbor] == 0) {
                    queue.push(neighbor);
                }
            }
        }

        // Check for cycles
        if (result.size() != graph_.size()) {
            std::cout << "Error: Dependency cycle detected in the graph\n";
            // Return partial order or empty list
            return {};
        }

        return result;
    }

private:
    // Adjacency list: node -> set of neighbors
    std::unordered_map<std::string, std::unordered_set<std::string>> graph_;
    // In-degree for each node
    std::unordered_map<std::string, int> inDegree_;
};

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << std::format("Usage: {} <dll_path> [dll_path...]\n", argv[0]);
        return 1;
    }

    // Initialize SQLite database
    SQLite::Database db("dlls.db", SQLite::OPEN_READWRITE | SQLite::OPEN_CREATE);
    
    // Process command-line arguments
    std::vector<fs::path> dllPaths;
    for (int i = 1; i < argc; ++i) {
        std::string inputPath = argv[i];
        if (fs::path(inputPath).extension() != ".dll" && fs::path(inputPath).extension() != ".DLL") {
            inputPath += ".dll";
        }
        fs::path path = inputPath;
        if (!path.has_parent_path()) {
            char fullPath[MAX_PATH];
            strcpy_s(fullPath, inputPath.c_str());
            if (PathFindOnPathA(fullPath, nullptr)) {
                path = fs::path(fullPath);
                std::cout << std::format("Resolved {} to {}\n", inputPath, path.string());
            } else {
                std::cout << std::format("Error: Could not find {} in PATH\n", inputPath);
                continue;
            }
        }
        dllPaths.push_back(path);
    }

    if (dllPaths.empty()) {
        std::cout << "Error: No valid DLL paths provided\n";
        return 1;
    }

    // Populate SQLite database with example DLLs (for testing)
    populateSqliteDb(db, dllPaths);

    // Initialize DllLoader with SQLite database
    DllLoader loader(db);

    // Load DLLs and collect dependencies
    for (const auto& path : dllPaths) {
        std::string dllName = path.filename().string();
        std::transform(dllName.begin(), dllName.end(), dllName.begin(), ::tolower);
        auto dllData = readDllFromFile(path);
        if (!dllData) {
            std::cout << std::format("Error: Failed to load DLL data for {}: {}\n", path.string(), dllData.error().message());
            continue;
        }
        loader.setCurrentDll(dllName); // Track current DLL for dependency logging
        auto handle = loader.loadDll(*dllData);
        loader.setCurrentDll(""); // Reset after loading
        if (handle) {
            std::cout << std::format("DLL {} loaded successfully at {}\n", path.string(), handle);
        } else {
            std::cout << std::format("Error: Failed to load DLL {} (Error: {})\n", path.string(), GetLastError());
        }
    }

    // Get topological sort order
    auto loadOrder = loader.getDependencyGraph().topologicalSort();
    std::cout << "Loading order (postorder topological sort via Kahn's algorithm):\n";
    for (const auto& dll : loadOrder) {
        std::cout << std::format("  {}\n", dll);
    }

    // Unload all loaded DLLs
    loader.unloadAll();

    return 0;
}