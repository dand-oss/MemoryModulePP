#include <expected>
#include <filesystem>
#include <system_error>
#include <windows.h>
#include <fstream>
#include <print>
#include <format>
#include <array>
#include <shlwapi.h>
#include <iostream>  // For std::wcout, std::wcerr

// Returns a pointer to the allocated memory containing the DLL data or an error code
[[nodiscard]] std::expected<LPVOID, std::error_code> 
ReadDllToMemory(const std::filesystem::path& filePath) noexcept {
    std::expected<LPVOID, std::error_code> result
        = std::unexpected(
            std::make_error_code(
                std::errc::invalid_argument));

    // Open the file in binary mode with RAII
    std::ifstream file(filePath, std::ios::binary | std::ios::ate);
    if (file.is_open()) {

        // Get file size
        const std::streampos fileSize = file.tellg();

        if (fileSize > 0) {

            // Allocate executable memory
            const LPVOID memory = VirtualAlloc(
                nullptr,
                static_cast<size_t>(fileSize), 
                MEM_COMMIT | MEM_RESERVE, 
                PAGE_EXECUTE_READWRITE);

            if (memory) {

                // Reset to beginning of file
                file.seekg(0, std::ios::beg);

                // Read file directly into allocated memory
                if (file.read(static_cast<char*>(memory), fileSize)) {
                    result = memory;
                } else {
                    result = std::unexpected(
                        std::make_error_code(
                            std::errc::io_error));
                }

            } else {
                result = std::unexpected(std::make_error_code(std::errc::not_enough_memory));
            }
        }
        // No cleanup needed; file is closed by RAII
    } else {
        result = std::unexpected(
            std::make_error_code(
                std::errc::no_such_file_or_directory));
    }

    return result;
}

// Find DLL in system path, returning std::filesystem::path with single return
[[nodiscard]] std::filesystem::path FindDllInPath(const std::wstring& dllName) noexcept
{
    std::array<wchar_t, MAX_PATH> fullPath{};

    return dllName.size() < fullPath.size()
        && wcscpy_s(fullPath.data(), fullPath.size(), dllName.c_str()) == 0
        && PathFindOnPathW(fullPath.data(), nullptr)
           ? std::filesystem::path(fullPath.data())
           : std::filesystem::path{};
}

int test( const std::filesystem::path& dllFullPath )
{
    // Read DLL directly into executable memory
    const auto& result = ReadDllToMemory(dllFullPath);
    LPVOID memory = nullptr; // Track memory for cleanup
    if (!result) {
        const auto& errorMsg = std::system_category().message(result.error().value());
        const std::wstring wErrorMsg(errorMsg.begin(), errorMsg.end()); // Simple narrow-to-wide conversion
        std::wcout << std::format(L"Failed to load DLL: {}\n", wErrorMsg);
        return -1;
    }

    memory = *result; // Store for cleanup
    std::wcout << std::format(L"Successfully loaded {} into memory at: {:#x}\n", 
        dllFullPath.wstring(),
        reinterpret_cast<std::uintptr_t>(memory));

    // Standardized cleanup
    VirtualFree(memory, 0, MEM_RELEASE);
    return 0;
}

// Example usage
int main( int argc, char* argv[]) {

    std::wstring dll_name(L"winhttp.dll");

    const std::filesystem::path dllPath{dll_name};

    // Find DLL in system path
    const auto& dllFullPath = FindDllInPath(dll_name);
    if (dllFullPath.empty()) {
        std::wcout << std::format(L"DLL not found: {}\n", dll_name);
        return 1;
    }

    std::wcout << std::format(L"Found {} for {}\n", dllFullPath.wstring(), dll_name);

    test(dllFullPath);

    return 0;
}
