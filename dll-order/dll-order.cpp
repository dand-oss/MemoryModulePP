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
#include "LoadDllMemoryApi.h"

namespace fs = std::filesystem;

// Custom formatter for HMODULE to handle std::format
template <>
struct std::formatter<HMODULE> {
    constexpr auto parse(
        std::format_parse_context& ctx
    ) {
        return ctx.begin();
    }

    auto format(
        const HMODULE& handle,
        std::format_context& ctx
    ) const {
        return std::format_to(
            ctx.out(),
            "0x{:016x}",
            reinterpret_cast<std::uintptr_t>(handle)
        );
    }
};

// Reads a DLL file into a byte vector using VirtualAlloc
static std::expected<std::vector<BYTE>, std::error_code> readDllFromFile(
    const fs::path& path
) {
    std::expected<std::vector<BYTE>, std::error_code> result
        = std::unexpected(
            std::make_error_code(
                std::errc::invalid_argument));

    // Open the file in binary mode with RAII
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (file.is_open()) {
        // Get file size
        const auto fileSize = file.tellg();
        if (fileSize > 0) {
            // Allocate executable buffer
            const auto buffer = VirtualAlloc(
                nullptr,
                static_cast<size_t>(fileSize),
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE);
            if (buffer) {
                // Reset to beginning of file
                file.seekg(0, std::ios::beg);
                // Read file directly into allocated buffer
                if (file.read(static_cast<char*>(buffer), fileSize)) {
                    // Copy buffer to vector
                    std::vector<BYTE> dllData(static_cast<BYTE*>(buffer), static_cast<BYTE*>(buffer) + fileSize);
                    VirtualFree(buffer, 0, MEM_RELEASE); // Free VirtualAlloc memory
                    result = std::move(dllData);
                }
                else {
                    VirtualFree(buffer, 0, MEM_RELEASE);
                    result = std::unexpected(
                        std::make_error_code(
                            std::errc::io_error));
                }
            }
            else {
                result = std::unexpected(
                    std::make_error_code(
                        std::errc::no_buffer_space));
            }
        }
        else {
            result = std::unexpected(
                std::make_error_code(
                    std::errc::no_such_file_or_directory));
        }
    }
    else {
        result = std::unexpected(
            std::make_error_code(
                std::errc::no_such_file_or_directory));
    }
    return result;
}

class DllLoader {
public:
    // Constructor: Initialize with side-load DLLs
    DllLoader(
        const std::unordered_map<std::string, std::vector<BYTE>>& sideLoadDlls
    ) : sideLoadDlls_(sideLoadDlls) {}

    // Callback to load dependencies
    HMODULE loadDependency(
        const char* name
    ) {
        auto dllName = std::string(name);
        std::transform(
            dllName.begin(),
            dllName.end(),
            dllName.begin(),
            ::tolower
        );
        std::cout << std::format(
            "Attempting to load dependency: {}\n",
            dllName
        );

        // Check if already loaded
        const auto existingHandle = GetModuleHandleA(dllName.c_str());
        const auto isLoaded = existingHandle != nullptr;
        if (isLoaded) {
            std::cout << std::format(
                "DLL {} already loaded at {}\n",
                dllName,
                existingHandle
            );
            return existingHandle;
        }

        // Check if in side-load list
        const auto it = sideLoadDlls_.find(dllName);
        const auto inSideLoad = it != sideLoadDlls_.end();
        if (inSideLoad) {
            std::cout << std::format(
                "Loading {} from memory (side-load)\n",
                dllName
            );
            const auto handle = MemoryLoadLibraryEx(
                it->second.data(),
                it->second.size(),
                LoadDependencyCallback,
                GetProcAddressCallback,
                FreeLibraryCallback,
                this
            );
            const auto isSuccess = handle != nullptr;
            std::cout << (isSuccess
                ? std::format(
                    "Successfully loaded {} from memory at {}\n",
                    dllName,
                    handle
                )
                : std::format(
                    "Failed to load {} from memory\n",
                    dllName
                )
            );
            return isSuccess ? handle : nullptr;
        }

        // Load from file system
        const auto dllPath = fs::path(dllName);
        std::cout << std::format(
            "Loading {} from file system\n",
            dllName
        );
        const auto handle = LoadLibraryA(dllPath.string().c_str());
        const auto isSuccess = handle != nullptr;
        std::cout << (isSuccess
            ? std::format(
                "Successfully loaded {} from file system at {}\n",
                dllName,
                handle
            )
            : std::format(
                "Failed to load {} from file system\n",
                dllName
            )
        );
        return isSuccess ? handle : nullptr;
    }

    // Static callback functions for MemoryLoadLibraryEx
    static HCUSTOMMODULE LoadDependencyCallback(
        LPCSTR name,
        void* userdata
    ) {
        const auto loader = static_cast<DllLoader*>(userdata);
        return loader->loadDependency(name);
    }

    static FARPROC GetProcAddressCallback(
        HCUSTOMMODULE module,
        LPCSTR name,
        void* userdata
    ) {
        return MemoryGetProcAddressEx(
            static_cast<HMEMORYMODULE>(module),
            name
        );
    }

    static void FreeLibraryCallback(
        HCUSTOMMODULE module,
        void* userdata
    ) {
        MemoryFreeLibraryEx(
            static_cast<HMEMORYMODULE>(module)
        );
    }

private:
    std::unordered_map<std::string, std::vector<BYTE>> sideLoadDlls_;
};

// Loads a DLL using MemoryLoadLibraryEx
static HMEMORYMODULE loadDll(
    const fs::path& path,
    DllLoader& loader
) {
    const auto dllDataResult = readDllFromFile(path);
    if (!dllDataResult) {
        std::cout << std::format(
            "Error: Failed to load DLL data for {}: {}\n",
            path.string(),
            dllDataResult.error().message()
        );
        return nullptr;
    }

    const auto& dllData = *dllDataResult;
    const auto isEmpty = dllData.empty();
    if (isEmpty) {
        std::cout << std::format(
            "Error: No data loaded for DLL {}\n",
            path.string()
        );
        return nullptr;
    }

    std::cout << std::format(
        "Loaded {} bytes from {}\n",
        dllData.size(),
        path.string()
    );

    const auto handle = MemoryLoadLibraryEx(
        dllData.data(),
        dllData.size(),
        DllLoader::LoadDependencyCallback,
        DllLoader::GetProcAddressCallback,
        DllLoader::FreeLibraryCallback,
        &loader
    );
    const auto isSuccess = handle != nullptr;
    if (!isSuccess) {
        std::cout << std::format(
            "Error: Failed to load DLL {} (Error: {})\n",
            path.string(),
            GetLastError()
        );
    }
    return handle;
}

int main(int argc, char* argv[]) {
    const auto hasArgs = argc >= 2;
    if (!hasArgs) {
        std::cout << std::format(
            "Usage: {} <dll_path> [dll_path...]\n",
            argv[0]
        );
        return 1;
    }

    // Process list of DLL paths/names
    auto dllPaths = std::vector<fs::path>();
    for (auto ii = 1; ii < argc; ++ii) {
        // Check and append .dll extension if missing
        auto inputPath = std::string(argv[ii]);
        const auto hasDllExtension = fs::path(inputPath).extension() == ".dll" ||
                                     fs::path(inputPath).extension() == ".DLL";
        if (!hasDllExtension) {
            inputPath += ".dll";
        }

        auto path = fs::path(inputPath);
        const auto isFilename = !path.has_parent_path();
        if (isFilename) {
            char fullPath[MAX_PATH];
            strcpy_s(fullPath, inputPath.c_str());
            const auto found = PathFindOnPathA(fullPath, nullptr) != 0;
            if (found) {
                path = fs::path(fullPath);
                std::cout << std::format(
                    "Resolved {} to {}\n",
                    inputPath,
                    path.string()
                );
            }
            else {
                std::cout << std::format(
                    "Error: Could not find {} in PATH\n",
                    inputPath
                );
                continue;
            }
        }
        dllPaths.push_back(path);
    }

    const auto hasPaths = !dllPaths.empty();
    if (!hasPaths) {
        std::cout << "Error: No valid DLL paths provided\n";
        return 1;
    }

    // Example side-load DLLs (simulating SQLite data)
    auto sideLoadDlls = std::unordered_map<std::string, std::vector<BYTE>>();
    DllLoader loader(sideLoadDlls);

    // Load and unload each DLL
    for (const auto& path : dllPaths) {
        std::cout << std::format(
            "Processing DLL: {}\n",
            path.string()
        );
        const auto handle = loadDll(path, loader);
        const auto isLoaded = handle != nullptr;
        if (isLoaded) {
            std::cout << std::format(
                "DLL {} loaded successfully at {}\n",
                path.string(),
                handle
            );
            const auto freed = MemoryFreeLibraryEx(handle);
            std::cout << (freed
                ? std::format(
                    "DLL {} unloaded\n",
                    path.string()
                )
                : std::format(
                    "Error: Failed to unload DLL {}\n",
                    path.string()
                )
            );
        }
    }

    return 0;
}