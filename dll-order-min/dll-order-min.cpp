#include "dll-order-min.h"
#include <set>
#include <algorithm>
#include <windows.h>
#include <winnt.h>

// Converts a string to lowercase for case-insensitive DLL name comparisons.
// @param input The input string to convert.
// @return A new string with all characters in lowercase.
static std::string toLowerCase(const std::string& input) {
    std::string result(input);
    std::transform(result.begin(), result.end(), result.begin(), ::tolower);
    return result;
}

// Converts a Relative Virtual Address (RVA) to a file offset in a DLL's binary data.
// Used to locate import table and dependency names in the PE file structure.
// @param dllData Pointer to the DLL's binary data.
// @param dllSize Size of the DLL data in bytes.
// @param rva The Relative Virtual Address to convert.
// @return The file offset corresponding to the RVA, or 0 if invalid.
static size_t rvaToFileOffset(
    const void* dllData,
    size_t dllSize, DWORD rva)
{
    size_t result = 0;
    // Ensure enough data for DOS header
    if (dllSize >= sizeof(IMAGE_DOS_HEADER)) {
        const auto* dosHeader = static_cast<const IMAGE_DOS_HEADER*>(dllData);
        // Verify DOS signature and NT header offset
        if (dosHeader->e_magic == IMAGE_DOS_SIGNATURE &&
            static_cast<size_t>(dosHeader->e_lfanew) + sizeof(IMAGE_NT_HEADERS) <= dllSize) {
            const auto* ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS*>(
                static_cast<const char*>(dllData) + dosHeader->e_lfanew);
            // Verify NT signature
            if (ntHeaders->Signature == IMAGE_NT_SIGNATURE) {
                // Iterate through section headers to find the section containing the RVA
                const auto* sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
                for (size_t i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i) {
                    const auto& section = sectionHeader[i];
                    if (rva >= section.VirtualAddress && 
                        rva < section.VirtualAddress + section.SizeOfRawData) {
                        // Calculate file offset: RVA - section's virtual address + section's file offset
                        result = rva - section.VirtualAddress + section.PointerToRawData;
                        break;
                    }
                }
            }
        }
    }
    return result;
}

// Extracts dependency DLL names from a DLL's import table.
// Assumes the input is a valid PE file; invalid files yield no dependencies.
// @param dllData Pointer to the DLL's binary data.
// @param dllSize Size of the DLL data in bytes.
// @return A set of lowercase dependency DLL names.
static std::set<std::string>
extractDependencies(
    const void* dllData,
    size_t dllSize)
{
    std::set<std::string> dep_name_set;
    // Check for minimum size to contain DOS header
    if (dllSize >= sizeof(IMAGE_DOS_HEADER)) {
        const auto* dosHeader = static_cast<const IMAGE_DOS_HEADER*>(dllData);
        // Verify DOS signature and NT header offset
        if (dosHeader->e_magic == IMAGE_DOS_SIGNATURE &&
            static_cast<size_t>(dosHeader->e_lfanew) + sizeof(IMAGE_NT_HEADERS) <= dllSize) {
            const auto* ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS*>(
                static_cast<const char*>(dllData) + dosHeader->e_lfanew);
            // Verify NT signature
            if (ntHeaders->Signature == IMAGE_NT_SIGNATURE) {
                // Locate the import directory
                const auto& importDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
                if (importDir.Size != 0 && importDir.VirtualAddress != 0) {
                    // Convert import directory RVA to file offset
                    const auto offset = rvaToFileOffset(dllData, dllSize, importDir.VirtualAddress);
                    if (offset != 0 && offset + importDir.Size <= dllSize) {
                        // Iterate through import descriptors
                        const auto* importDesc = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(
                            static_cast<const char*>(dllData) + offset);
                        while (importDesc->Name) {
                            // Convert dependency name RVA to file offset
                            const auto nameOffset = rvaToFileOffset(dllData, dllSize, importDesc->Name);
                            if (nameOffset != 0 && nameOffset < dllSize) {
                                // Extract and normalize dependency name
                                const auto* depName = static_cast<const char*>(dllData) + nameOffset;
                                dep_name_set.insert(toLowerCase(depName));
                            }
                            ++importDesc;
                        }
                    }
                }
            }
        }
    }

    return dep_name_set;
}

// Computes the load order for a set of DLLs based on their dependencies.
// Uses topological sort (Kahn's algorithm) to order DLLs from leaf nodes (no dependents)
// to root nodes (depend on others). Returns an empty result with an error message
// if a cycle is detected in the dependency graph.
// @param dllDataMap Map of DLL names to their binary data (std::vector<char>).
// @return std::expected containing either the ordered list of (name, data pointer, size)
//         tuples or an error message if a cycle is detected.
std::expected<std::vector<std::tuple<std::string, const char*, size_t>>, std::string>
computeLoadOrder(
    const std::map<std::string,
    std::vector<char>>& dllDataMap)
{
    // Map lowercase DLL names to original names and data pointers for case-insensitive comparisons
    std::map<std::string, std::pair<std::string, const std::vector<char>*>> dllInfo;
    for (const auto& [name, data] : dllDataMap) {
        dllInfo[toLowerCase(name)] = {name, &data};
    }

    // Build dependency graph (edges from DLL to its dependencies) and in-degree map
    std::map<std::string, std::set<std::string>> graph;
    std::map<std::string, int> inDegree;
    for (const auto& [lcName, info] : dllInfo) {

        // Extract dependencies from the DLL's import table
        auto deps = extractDependencies(info.second->data(), info.second->size());
        for (const auto& dep : deps) {
            // Only include dependencies present in the input map (ignore external dependencies)
            if (dllInfo.count(dep)) {
                graph[lcName].insert(dep);
                inDegree[dep]++;
            }
        }

        // Ensure every DLL is in the graph and in-degree map, even if it has no dependencies
        if (!graph.count(lcName)) graph[lcName] = {};
        if (!inDegree.count(lcName)) inDegree[lcName] = 0;
    } // for

    // Perform topological sort using Kahn's algorithm
    std::vector<std::tuple<std::string, const char*, size_t>> result;
    std::set<std::string> zeroInDegree;
    // Initialize queue with nodes that have no dependents (in-degree 0)
    for (const auto& [node, deg] : inDegree) {
        if (deg == 0) zeroInDegree.insert(node);
    } // for

    // Process nodes in topological order
    while (!zeroInDegree.empty()) {
        // Take a node with no dependents
        auto node = *zeroInDegree.begin();
        zeroInDegree.erase(node);
        // Add node to result with its original name, data pointer, and size
        const auto& info = dllInfo[node];
        result.emplace_back(info.first, info.second->data(), info.second->size());
        // Update in-degrees of dependencies
        for (const auto& dep : graph[node]) {
            if (--inDegree[dep] == 0) {
                // If a dependency now has no dependents, add it to the queue
                zeroInDegree.insert(dep);
            }
        }
    } // while

    // Check for cycles: if not all nodes were processed, a cycle exists
    if (result.size() != graph.size()) {
        return std::unexpected("Cycle detected in dependency graph");
    }

    // Return the ordered list of DLLs
    return result;
}
