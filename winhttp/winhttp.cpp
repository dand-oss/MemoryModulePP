#include <expected>
#include <filesystem>
#include <system_error>
#include <windows.h>
#include <fstream>
#include <print>
#include <format>
#include <array>
#include <shlwapi.h>
#include <iostream>
#include <winhttp.h>
#include <vector>
#include <../MemoryModule/LoadDllMemoryApi.h>

// declare winhttp functions we use
typedef HINTERNET(WINAPI* MSVC$WinHttpOpen)(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD);
typedef HINTERNET(WINAPI* MSVC$WinHttpConnect)(HINTERNET, LPCWSTR, INTERNET_PORT, DWORD);
typedef HINTERNET(WINAPI* MSVC$WinHttpOpenRequest)(HINTERNET, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR*, DWORD);
typedef BOOL(WINAPI* MSVC$WinHttpSendRequest)(HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD, DWORD, DWORD_PTR);
typedef BOOL(WINAPI* MSVC$WinHttpReceiveResponse)(HINTERNET, LPVOID);
typedef BOOL(WINAPI* MSVC$WinHttpQueryDataAvailable)(HINTERNET, LPDWORD);
typedef BOOL(WINAPI* MSVC$WinHttpReadData)(HINTERNET, LPVOID, DWORD, LPDWORD);
typedef BOOL(WINAPI* MSVC$WinHttpCloseHandle)(HINTERNET);

template <class TT>
TT GetProcAddress(HMODULE module_handle, LPCSTR proc_name)
{
    return reinterpret_cast<TT>(
        ::GetProcAddress(module_handle, proc_name));
}

// Returns a pointer to the allocated buffer containing the DLL data or an error code
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
            // Allocate executable buffer
            const LPVOID buffer = VirtualAlloc(
                nullptr,
                static_cast<size_t>(fileSize),
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE);
            if (buffer) {
                // Reset to beginning of file
                file.seekg(0, std::ios::beg);
                // Read file directly into allocated buffer
                if (file.read(static_cast<char*>(buffer), fileSize)) {
                    result = buffer;
                }
                else {
                    result = std::unexpected(
                        std::make_error_code(
                            std::errc::io_error));
                }
            }
            else {
                // no buffer
                result = std::unexpected(
                    std::make_error_code(
                        std::errc::no_buffer_space));
            }
        }
    }
    else {
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

int test(const std::filesystem::path& dllFullPath)
{
    // Read DLL directly into executable buffer
    const auto result = ReadDllToMemory(dllFullPath);
    LPVOID buffer = nullptr; // Track buffer for cleanup
    if (!result) {
        const auto errorMsg = std::system_category().message(result.error().value());
        const std::wstring wErrorMsg(errorMsg.begin(), errorMsg.end());
        std::wcout << std::format(L"Failed to load DLL: {}\n", wErrorMsg);
        return -1;
    }

    buffer = *result;
    std::wcout << std::format(L"Successfully loaded {} into buffer at: {:#x}\n",
        dllFullPath.wstring(),
        reinterpret_cast<std::uintptr_t>(buffer));

    HINTERNET hSession = nullptr, hConnect = nullptr, hRequest = nullptr;

    // Load the buffer
    const auto hWinhttp = LoadLibraryMemory(buffer);
    if (!hWinhttp) {
        std::print("LoadLibraryMemory failed.\n");
        VirtualFree(buffer, 0, MEM_RELEASE);
        return -1;
    }

    // Get winhttp functions
    auto win32_WinHttpOpen = GetProcAddress<MSVC$WinHttpOpen>(hWinhttp, "WinHttpOpen");
    auto win32_WinHttpConnect = GetProcAddress<MSVC$WinHttpConnect>(hWinhttp, "WinHttpConnect");
    auto win32_WinHttpOpenRequest = GetProcAddress<MSVC$WinHttpOpenRequest>(hWinhttp, "WinHttpOpenRequest");
    auto win32_WinHttpSendRequest = GetProcAddress<MSVC$WinHttpSendRequest>(hWinhttp, "WinHttpSendRequest");
    auto win32_WinHttpReceiveResponse = GetProcAddress<MSVC$WinHttpReceiveResponse>(hWinhttp, "WinHttpReceiveResponse");
    auto win32_WinHttpQueryDataAvailable = GetProcAddress<MSVC$WinHttpQueryDataAvailable>(hWinhttp, "WinHttpQueryDataAvailable");
    auto win32_WinHttpReadData = GetProcAddress<MSVC$WinHttpReadData>(hWinhttp, "WinHttpReadData");
    auto win32_WinHttpCloseHandle = GetProcAddress<MSVC$WinHttpCloseHandle>(hWinhttp, "WinHttpCloseHandle");

    // Check if function pointers are valid
    if (!win32_WinHttpOpen || !win32_WinHttpConnect || !win32_WinHttpOpenRequest ||
        !win32_WinHttpSendRequest || !win32_WinHttpReceiveResponse ||
        !win32_WinHttpQueryDataAvailable || !win32_WinHttpReadData ||
        !win32_WinHttpCloseHandle) {
        std::print("Failed to get WinHTTP function pointers.\n");
        VirtualFree(buffer, 0, MEM_RELEASE);
        return -1;
    }

    // Clean up lambda defined after function pointers
    const auto cleanup = [hRequest, hConnect, hSession, buffer, win32_WinHttpCloseHandle]() {
        if (hRequest) win32_WinHttpCloseHandle(hRequest);
        if (hConnect) win32_WinHttpCloseHandle(hConnect);
        if (hSession) win32_WinHttpCloseHandle(hSession);
        VirtualFree(buffer, 0, MEM_RELEASE);
    };

    // Initialize WinHTTP session
    hSession = win32_WinHttpOpen(
        L"A WinHTTP Example Program/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0);
    if (!hSession) {
        std::print("Error {} in WinHttpOpen.\n", GetLastError());
        cleanup();
        return -1;
    }

    // Session
    WCHAR serverName[] = L"neverssl.com";
    int serverPort = 80;
    WCHAR objectName[] = L"/";

    // Connect to HTTP server
    hConnect = win32_WinHttpConnect(
        hSession,
        serverName,
        serverPort,
        0);
    if (!hConnect) {
        std::print("Error {} in WinHttpConnect.\n", GetLastError());
        cleanup();
        return -1;
    }

    // Create HTTP GET request
    hRequest = win32_WinHttpOpenRequest(
        hConnect,
        L"GET",
        objectName,
        nullptr,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        0);
    if (!hRequest) {
        std::print("Error {} in WinHttpOpenRequest.\n", GetLastError());
        cleanup();
        return -1;
    }

    // Send HTTP request
    auto bResults = win32_WinHttpSendRequest(
        hRequest,
        WINHTTP_NO_ADDITIONAL_HEADERS,
        0,
        WINHTTP_NO_REQUEST_DATA,
        0,
        0,
        0);
    if (!bResults) {
        std::print("Error {} in WinHttpSendRequest.\n", GetLastError());
        cleanup();
        return -1;
    }

    // End the HTTP request
    bResults = win32_WinHttpReceiveResponse(hRequest, nullptr);
    if (!bResults) {
        std::print("Error {} in WinHttpReceiveResponse.\n", GetLastError());
        cleanup();
        return -1;
    }

    // Allocate memory for the response
    DWORD dwSize = 0;
    do {
        // Check for available data
        dwSize = 0;
        if (!win32_WinHttpQueryDataAvailable(hRequest, &dwSize)) {
            std::print("Error {} in WinHttpQueryDataAvailable.\n", GetLastError());
            cleanup();
            return -1;
        }

        // Allocate memory for the buffer
        std::vector<unsigned char> pszOutBuffer(dwSize + 1);

        // Read the response data
        ZeroMemory(pszOutBuffer.data(), dwSize + 1);
        DWORD dwDownloaded = 0;
        if (!win32_WinHttpReadData(hRequest, pszOutBuffer.data(), dwSize, &dwDownloaded)) {
            std::print("Error {} in WinHttpReadData.\n", GetLastError());
            cleanup();
            return -1;
        }
        else {
            // Convert buffer to string for printing
            std::string response(reinterpret_cast<char*>(pszOutBuffer.data()), dwDownloaded);
            std::print("Response: {}\n", response);
        }
    } while (dwSize > 0);

    cleanup();

    std::print("Press any key to close...\n");
    getchar();

    return 0;
}

// Example usage
int main(int argc, char* argv[]) {
    std::wstring dll_name(L"winhttp.dll");
    const std::filesystem::path dllPath{dll_name};

    // Find DLL in system path
    const auto dllFullPath = FindDllInPath(dll_name);
    if (dllFullPath.empty()) {
        std::wcout << std::format(L"DLL not found: {}\n", dll_name);
        return 1;
    }

    std::wcout << std::format(L"Found {} for {}\n", dllFullPath.wstring(), dll_name);

    return test(dllFullPath);
}

