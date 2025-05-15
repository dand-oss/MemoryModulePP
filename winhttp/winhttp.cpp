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
#include <stdexcept>
#include <../MemoryModule/LoadDllMemoryApi.h>

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

// Struct to manage WinHTTP function pointers with upfront loading
struct WinHttpAPI {
private:
    HMODULE hWinhttp = nullptr; // DLL handle
    LPVOID buffer = nullptr;   // Memory buffer for DLL
    std::filesystem::path dllPath; // Path to DLL

    // Ensure DLL is loaded, returning the module handle
    bool EnsureDllLoaded() {
        if (!hWinhttp) {
            // Load DLL
            auto result = ReadDllToMemory(dllPath);
            if (!result) {
                const auto errorMsg = std::system_category().message(result.error().value());
                const std::wstring wErrorMsg(errorMsg.begin(), errorMsg.end());
                std::wcout << std::format(L"Failed to load DLL: {}\n", wErrorMsg);
                return false;
            }
            buffer = *result;
            hWinhttp = LoadLibraryMemory(buffer);
            if (!hWinhttp) {
                std::print("LoadLibraryMemory failed.\n");
                VirtualFree(buffer, 0, MEM_RELEASE);
                buffer = nullptr;
                return false;
            }
        }
        return true;
    }

    // Template to get function pointer
    template <typename TT>
    TT GetProc(LPCSTR proc_name, TT& cached) {
        if (!EnsureDllLoaded()) {
            return nullptr;
        }
        cached = reinterpret_cast<TT>(::GetProcAddress(hWinhttp, proc_name));
        if (!cached) {
            std::print("Failed to get function: {}\n", proc_name);
        }
        return cached;
    }

    // Load all function pointers
    void LoadFunctions() {
        GetProc("WinHttpOpen", fnWinHttpOpen);
        GetProc("WinHttpConnect", fnWinHttpConnect);
        GetProc("WinHttpOpenRequest", fnWinHttpOpenRequest);
        GetProc("WinHttpSendRequest", fnWinHttpSendRequest);
        GetProc("WinHttpReceiveResponse", fnWinHttpReceiveResponse);
        GetProc("WinHttpQueryDataAvailable", fnWinHttpQueryDataAvailable);
        GetProc("WinHttpReadData", fnWinHttpReadData);
        GetProc("WinHttpCloseHandle", fnWinHttpCloseHandle);

        // Check if all functions were loaded
        if (!fnWinHttpOpen || !fnWinHttpConnect || !fnWinHttpOpenRequest ||
            !fnWinHttpSendRequest || !fnWinHttpReceiveResponse ||
            !fnWinHttpQueryDataAvailable || !fnWinHttpReadData ||
            !fnWinHttpCloseHandle) {
            throw std::runtime_error("Failed to load one or more WinHTTP functions");
        }
    }

public:
    // Instance function pointers
    HINTERNET(WINAPI *fnWinHttpOpen)(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD) = nullptr;
    HINTERNET(WINAPI *fnWinHttpConnect)(HINTERNET, LPCWSTR, INTERNET_PORT, DWORD) = nullptr;
    HINTERNET(WINAPI *fnWinHttpOpenRequest)(HINTERNET, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR*, DWORD) = nullptr;
    BOOL(WINAPI *fnWinHttpSendRequest)(HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD, DWORD, DWORD_PTR) = nullptr;
    BOOL(WINAPI *fnWinHttpReceiveResponse)(HINTERNET, LPVOID) = nullptr;
    BOOL(WINAPI *fnWinHttpQueryDataAvailable)(HINTERNET, LPDWORD) = nullptr;
    BOOL(WINAPI *fnWinHttpReadData)(HINTERNET, LPVOID, DWORD, LPDWORD) = nullptr;
    BOOL(WINAPI *fnWinHttpCloseHandle)(HINTERNET) = nullptr;

    explicit WinHttpAPI(const std::filesystem::path& path) : dllPath(path) {
        LoadFunctions();
    }

    ~WinHttpAPI() {
        if (buffer) {
            VirtualFree(buffer, 0, MEM_RELEASE);
        }
    }
};

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
    std::wcout << std::format(L"Using DLL at: {}\n", dllFullPath.wstring());

    // Initialize API with DLL path
    WinHttpAPI api(dllFullPath);
    try {
        WinHttpAPI api(dllFullPath);
    } catch (const std::runtime_error& e) {
        std::print("Error: {}\n", e.what());
        return -1;
    }

    HINTERNET hSession = nullptr, hConnect = nullptr, hRequest = nullptr;

    // Clean up lambda
    const auto cleanup = [hRequest, hConnect, hSession, &api]() {
        if (hRequest) api.fnWinHttpCloseHandle(hRequest);
        if (hConnect) api.fnWinHttpCloseHandle(hConnect);
        if (hSession) api.fnWinHttpCloseHandle(hSession);
    };

    // Initialize WinHTTP session
    hSession = api.fnWinHttpOpen(
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
    hConnect = api.fnWinHttpConnect(
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
    hRequest = api.fnWinHttpOpenRequest(
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
    auto bResults = api.fnWinHttpSendRequest(
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
    bResults = api.fnWinHttpReceiveResponse(hRequest, nullptr);
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
        if (!api.fnWinHttpQueryDataAvailable(hRequest, &dwSize)) {
            std::print("Error {} in WinHttpQueryDataAvailable.\n", GetLastError());
            cleanup();
            return -1;
        }

        // Allocate memory for the buffer
        std::vector<unsigned char> pszOutBuffer(dwSize + 1);

        // Read the response data
        ZeroMemory(pszOutBuffer.data(), dwSize + 1);
        DWORD dwDownloaded = 0;
        if (!api.fnWinHttpReadData(hRequest, pszOutBuffer.data(), dwSize, &dwDownloaded)) {
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
