#define NOMINMAX
#include <iostream>
#include <format>
#include <string>
#include <vector>
#include <set>
#include <map>
#include <algorithm>
#include <sqlite3pp.h>
#include <filesystem>
#include <windows.h>
#include <winnt.h>
#include <numeric>
#include "../3rdparty/phnt/include/phnt_windows.h"
#include "../3rdparty/phnt/include/phnt.h"

namespace fs = std::filesystem;

// Global verbose flag
static bool verbose = false;

// Function to convert bytes to MB
static double toMB(size_t bytes) {
    return static_cast<double>(bytes) / (1024.0 * 1024.0);
}

// Portable logging wrappers using std::format_string
template<typename... Args>
void logResult(std::format_string<Args...> fmt, Args&&... args) {
    std::cout << std::format(fmt, std::forward<Args>(args)...) << std::endl;
}

template<typename... Args>
void logInfo(std::format_string<Args...> fmt, Args&&... args) {
    if (verbose) {
        std::cout << std::format(fmt, std::forward<Args>(args)...) << std::endl;
    }
}

template<typename... Args>
void logError(std::format_string<Args...> fmt, Args&&... args) {
    std::cerr << std::format(fmt, std::forward<Args>(args)...) << std::endl;
}

// Converts a string to lowercase
static std::string toLowerCase(const std::string& input) {
    std::string result(input);
    std::transform(result.begin(), result.end(), result.begin(), ::tolower);
    return result;
}

// Checks if a file is a valid PE DLL
static bool isValidPeDll(const std::vector<char>& data) {
    if (data.size() < sizeof(IMAGE_DOS_HEADER)) {
        logError("Error: Insufficient size for DOS header");
        return false;
    }
    const auto* dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(data.data());
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        logError("Error: Invalid DOS signature ({:#x})", dosHeader->e_magic);
        return false;
    }
    if (data.size() < dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS)) {
        logError("Error: Insufficient size for NT headers");
        return false;
    }
    const auto* ntHeader = reinterpret_cast<const IMAGE_NT_HEADERS*>(
        data.data() + dosHeader->e_lfanew);
    if (ntHeader->Signature != IMAGE_NT_SIGNATURE) {
        logError("Error: Invalid NT signature ({:#x})", ntHeader->Signature);
        return false;
    }
    return (ntHeader->FileHeader.Characteristics & IMAGE_FILE_DLL) != 0;
}

// Converts an RVA to a file offset using the section table
static size_t rvaToFileOffset(
    const void* dllData,
    size_t dllSize,
    DWORD rva
) {
    size_t result = 0;

    if (dllSize >= sizeof(IMAGE_DOS_HEADER)) {
        const auto* dosHeader = static_cast<const IMAGE_DOS_HEADER*>(dllData);
        if (dosHeader->e_magic == IMAGE_DOS_SIGNATURE &&
            dosHeader->e_lfanew >= sizeof(IMAGE_DOS_HEADER) &&
            static_cast<size_t>(dosHeader->e_lfanew) + sizeof(IMAGE_NT_HEADERS) <= dllSize) {
            const auto* ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS*>(
                static_cast<const char*>(dllData) + dosHeader->e_lfanew);
            if (ntHeaders->Signature == IMAGE_NT_SIGNATURE) {
                const auto* sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
                const auto numberOfSections = ntHeaders->FileHeader.NumberOfSections;
                for (size_t ii = 0; ii < numberOfSections; ++ii) {
                    const auto& section = sectionHeader[ii];
                    if (rva >= section.VirtualAddress && rva < section.VirtualAddress + section.SizeOfRawData) {
                        result = rva - section.VirtualAddress + section.PointerToRawData;
                        break;
                    }
                }
            }
        }
    }

    return result;
}

// Struct to hold command-line arguments
struct Arguments {
    std::string dbPath;
    bool verbose;
};

// Parses command-line arguments for database path and verbose flag
static Arguments parseArguments(
    int argc,
    char* argv[]
) {
    Arguments args;
    args.dbPath = "dlls.db";
    args.verbose = false;

    for (int ii = 1; ii < argc; ++ii) {
        const std::string arg(argv[ii]);
        if (arg == "--db" && ii + 1 < argc) {
            args.dbPath = argv[++ii];
        } else if (arg == "--verbose") {
            args.verbose = true;
        }
    }

    return args;
}

// Extracts dependencies from the DLL's import table with PE header validation
static std::set<std::string> extractDependencies(
    const void* dllData,
    size_t dllSize,
    const std::string& dllName
) {
    std::set<std::string> dependencies;

    if (dllSize < sizeof(IMAGE_DOS_HEADER)) {
        logError(
            "Warning: {} has insufficient size ({}) for DOS header",
            dllName,
            dllSize
        );
    } else {
        const auto* dosHeader = static_cast<const IMAGE_DOS_HEADER*>(dllData);
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            logError(
                "Warning: {} has invalid DOS signature ({:#x})",
                dllName,
                dosHeader->e_magic
            );
        } else if (dosHeader->e_lfanew < sizeof(IMAGE_DOS_HEADER) ||
                   static_cast<size_t>(dosHeader->e_lfanew) + sizeof(IMAGE_NT_HEADERS) > dllSize) {
            logError(
                "Warning: {} has invalid NT header offset ({:#x})",
                dllName,
                dosHeader->e_lfanew
            );
        } else {
            const auto* ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS*>(
                static_cast<const char*>(dllData) + dosHeader->e_lfanew);
            if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
                logError(
                    "Warning: {} has invalid NT signature ({:#x})",
                    dllName,
                    ntHeaders->Signature
                );
            } else if (ntHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC &&
                       ntHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
                logError("Warning: {} has invalid optional header magic ({:#x})",
                    dllName,
                    ntHeaders->OptionalHeader.Magic
                );
            } else {
                const auto* importDir = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
                if (importDir->Size == 0 || importDir->VirtualAddress == 0) {
                    logInfo("Info: {} has no import directory", dllName);
                } else {
                    const auto importDirOffset = rvaToFileOffset(dllData, dllSize, importDir->VirtualAddress);
                    if (importDirOffset == 0 || importDirOffset + importDir->Size > dllSize) {
                        logError(
                            "Warning: {} has invalid import directory offset {:#x}",
                            dllName,
                            importDirOffset
                        );
                    } else {
                        const auto* importDesc = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(
                            static_cast<const char*>(dllData) + importDirOffset);
                        while (importDesc->Name) {
                            const auto nameOffset = rvaToFileOffset(dllData, dllSize, importDesc->Name);
                            if (nameOffset == 0 || nameOffset >= dllSize) {
                                logError(
                                    "Warning: {} has invalid import descriptor name offset {:#x}",
                                    dllName,
                                    importDesc->Name
                                );
                                break;
                            }
                            const auto* depName = static_cast<const char*>(dllData) + nameOffset;
                            dependencies.insert(toLowerCase(depName));
                            ++importDesc;
                        }
                    }
                }
            }
        }
    }

    return dependencies;
}

// Loads DLL data from the database
static bool loadDllData(
    const std::string& dbPath,
    std::map<std::string, size_t>& dllSizes,
    std::map<std::string, std::set<std::string>>& graph,
    std::map<std::string, int>& inDegree
) {
    bool success = true;

    try {
        sqlite3pp::database db(dbPath.c_str(), SQLITE_OPEN_READONLY);
        logInfo("Opened database: {}", dbPath);

        sqlite3pp::query dllQuery(db, "SELECT name, data FROM dlls");
        for (const auto& row : dllQuery) {
            const auto& name = toLowerCase(row.get<std::string>(0));
            const auto* blob = static_cast<const void*>(row.get<const void*>(1));
            const auto size = static_cast<size_t>(row.column_bytes(1));

            dllSizes[name] = size;
            graph[name];
            inDegree[name] = 0;

            const auto& deps = extractDependencies(blob, size, name);
            for (const auto& dep : deps) {
                if (dllSizes.count(dep)) {
                    graph[name].insert(dep);
                    inDegree[dep]++;
                } else {
                    logInfo(
                        "Info: Dependency {} for {} assumed external",
                        dep,
                        name
                    );
                }
            }
        }
    } catch (const sqlite3pp::database_error& e) {
        logError("Database error: {}", e.what());
        success = false;
    }

    return success;
}

// Builds the dependency graph
static bool buildDependencyGraph(
    const std::map<std::string, size_t>& dllSizes,
    const std::map<std::string, std::set<std::string>>& graph,
    std::map<std::string, int>& inDegree,
    std::set<std::string>& zeroInDegree
) {
    bool success = true;

    logInfo("Verifying graph consistency...");
    for (const auto& [node, _] : graph) {
        if (!dllSizes.count(node)) {
            logError("Error: Node {} in graph but not in dllSizes", node);
            success = false;
        }
    }

    if (success) {
        logInfo("Initializing zero in-degree set...");
        for (const auto& [name, degree] : inDegree) {
            logInfo("Node {} has in-degree {}", name, degree);
            if (degree == 0) {
                zeroInDegree.insert(name);
            }
        }
        if (verbose) {
            logInfo("Checking for nodes with dependencies...");
            for (const auto& [name, degree] : inDegree) {
                if (degree > 0) {
                    logInfo("Warning: Node {} has in-degree {}, depends on:", name, degree);
                    for (const auto& [src, deps] : graph) {
                        if (deps.count(name)) {
                            logInfo("    {}", src);
                        }
                    }
                }
            }
        }
    }

    return success;
}

// Performs DFS to detect cycles in the dependency graph
static void detectCycles(
    const std::map<std::string, std::set<std::string>>& graph,
    const std::string& node,
    std::set<std::string>& visited,
    std::set<std::string>& recStack,
    std::vector<std::string>& cycle,
    bool& cycleDetected
) {
    visited.insert(node);
    recStack.insert(node);
    cycle.push_back(node);

    for (const auto& neighbor : graph.at(node)) {
        if (!visited.count(neighbor)) {
            detectCycles(graph, neighbor, visited, recStack, cycle, cycleDetected);
        } else if (recStack.count(neighbor)) {
            cycleDetected = true;
            while (!cycle.empty() && cycle.front() != neighbor) {
                cycle.erase(cycle.begin());
            }
        }
        if (cycleDetected) {
            break;
        }
    }

    if (!cycleDetected) {
        cycle.clear();
    }
    recStack.erase(node);
}

// Performs topological sort using Kahn's algorithm
static std::vector<std::pair<std::string, size_t>> performTopologicalSort(
    const std::map<std::string, size_t>& dllSizes,
    std::map<std::string, std::set<std::string>>& graph,
    std::map<std::string, int>& inDegree,
    std::set<std::string>& zeroInDegree
) {
    std::vector<std::pair<std::string, size_t>> loadOrder;

    logInfo("Starting topological sort...");
    while (!zeroInDegree.empty()) {
        const auto it = zeroInDegree.begin();
        const std::string current = *it;
        logInfo("Processing node {}", current);
        zeroInDegree.erase(it);

        if (!dllSizes.count(current)) {
            logError(
                "Error: Node {} not found in dllSizes during topological sort",
                current
            );
            loadOrder.clear();
            break;
        }

        loadOrder.emplace_back(current, dllSizes.at(current));

        const std::vector<std::string> neighbors(graph[current].begin(), graph[current].end());
        for (const auto& neighbor : neighbors) {
            inDegree[neighbor]--;
            logInfo(
                "Updated in-degree of {} to {}",
                neighbor,
                inDegree[neighbor]
            );
            if (inDegree[neighbor] == 0) {
                zeroInDegree.insert(neighbor);
            }
        }
        graph[current].clear();
    }

    if (loadOrder.size() != dllSizes.size()) {
        logError(
            "Error: Incomplete processing. Only {} of {} DLLs processed.",
            loadOrder.size(),
            dllSizes.size()
        );
        if (verbose) {
            logInfo("Remaining nodes with dependencies:");
            for (const auto& [name, degree] : inDegree) {
                if (degree > 0) {
                    logInfo("Node {} has in-degree {}, depends on:", name, degree);
                    for (const auto& [src, deps] : graph) {
                        if (deps.count(name)) {
                            logInfo("    {}", src);
                        }
                    }
                }
            }
        }
        loadOrder.clear();
    }

    return loadOrder;
}

// Computes topological sort of DLLs with cycle detection
static std::vector<std::pair<std::string, size_t>> computeLoadOrder(
    const std::string& dbPath
) {
    std::vector<std::pair<std::string, size_t>> loadOrder;
    std::map<std::string, size_t> dllSizes;
    std::map<std::string, std::set<std::string>> graph;
    std::map<std::string, int> inDegree;
    std::set<std::string> zeroInDegree;

    if (loadDllData(dbPath, dllSizes, graph, inDegree)) {
        if (buildDependencyGraph(dllSizes, graph, inDegree, zeroInDegree)) {
            logInfo("Checking for cycles...");
            std::set<std::string> visited;
            std::set<std::string> recStack;
            std::vector<std::string> cycle;
            bool cycleDetected = false;
            for (const auto& [node, _] : graph) {
                if (!visited.count(node)) {
                    detectCycles(graph, node, visited, recStack, cycle, cycleDetected);
                    if (cycleDetected) {
                        std::string cyclePath;
                        for (size_t ii = 0; ii < cycle.size(); ++ii) {
                            cyclePath += cycle[ii];
                            if (ii < cycle.size() - 1) {
                                cyclePath += " -> ";
                            }
                        }
                        logError(
                            "Error: Detected cycle in dependency graph: {}",
                            cyclePath
                        );
                        loadOrder.clear();
                        break;
                    }
                }
            }
            if (!cycleDetected) {
                loadOrder = performTopologicalSort(
                    dllSizes,
                    graph,
                    inDegree,
                    zeroInDegree);
            }
        }
    }

    return loadOrder;
}

// Main function
int main(
    int argc,
    char* argv[]
) {
    const auto args = parseArguments(argc, argv);
    verbose = args.verbose;
    if (!fs::exists(args.dbPath)) {
        logError(
            "Error: Database file {} does not exist",
            args.dbPath
        );
        return 1;
    }

    logResult(
        "\nComputing DLL load order for database: {}\n",
        args.dbPath
    );

    std::map<std::string, size_t> dllSizes;
    std::map<std::string, std::set<std::string>> graph;
    std::map<std::string, int> inDegree;
    std::set<std::string> zeroInDegree;
    if (loadDllData(args.dbPath, dllSizes, graph, inDegree)) {
        // Save a copy of inDegree before topological sort modifies it
        std::map<std::string, int> originalInDegree = inDegree;

        if (buildDependencyGraph(dllSizes, graph, inDegree, zeroInDegree)) {
            logInfo("Checking for cycles...");
            std::set<std::string> visited;
            std::set<std::string> recStack;
            std::vector<std::string> cycle;
            bool cycleDetected = false;
            for (const auto& [node, _] : graph) {
                if (!visited.count(node)) {
                    detectCycles(graph, node, visited, recStack, cycle, cycleDetected);
                    if (cycleDetected) {
                        std::string cyclePath;
                        for (size_t ii = 0; ii < cycle.size(); ++ii) {
                            cyclePath += cycle[ii];
                            if (ii < cycle.size() - 1) {
                                cyclePath += " -> ";
                            }
                        }
                        logError("Error: Detected cycle in dependency graph: {}", cyclePath);
                        return 1;
                    }
                }
            }
            if (!cycleDetected) {
                auto loadOrder = performTopologicalSort(dllSizes, graph, inDegree, zeroInDegree);
                if (loadOrder.empty()) {
                    logError("Failed to compute load order");
                    return 1;
                }

                size_t totalSize = 0;
                logResult("DLL Load Order (Leaf to Root):");
                for (size_t ii = 0; ii < loadOrder.size(); ++ii) {
                    const auto& [name, size] = loadOrder[ii];
                    totalSize += size;
                    logResult("  {}. {}: {:.2f} MB, In-Degree: {}", 
                              ii + 1, name, toMB(size), originalInDegree[name]);
                }

                logResult("\nDependency Order Summary:");
                logResult("  Total DLLs: {}", loadOrder.size());
                logResult("  Total memory: {:.2f} MB", toMB(totalSize));
            }
        }
    } else {
        logError("Failed to compute load order");
        return 1;
    }

    return 0;
}
