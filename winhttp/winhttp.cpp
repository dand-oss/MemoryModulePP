#include <windows.h>
#include <LoadDllMemoryApi.h>
#include <expected>
#include <filesystem>
#include <system_error>
#include <fstream>
#include <print>
#include <format>
#include <array>
#include <shlwapi.h>
#include <iostream>
#include <winhttp.h>
#include <vector>
#include <stdexcept>
#include <memory>

// Function to convert bytes to MB
static double toMB(size_t bytes) {
    return static_cast<double>(bytes) / 1024.0 / 1024.0;
}

// Portable logging wrappers using std::format_string
template<typename... Args>
void logInfo(std::format_string<Args...> fmt, Args&&... args) {
    if (g_verbose) {
        std::cout << std::format(fmt, std::forward<Args>(args)...) << std::endl;
    }
}

template<typename... Args>
void logError(std::format_string<Args...> fmt, Args&&... args) {
    std::cerr << std::format(fmt, std::forward<Args>(args)...) << std::endl;
}

// Find DLL in system path, returning std::filesystem::path with single return
[[nodiscard]]
static std::filesystem::path FindDllInPath(const std::wstring& dllName) noexcept
{
    std::array<wchar_t, MAX_PATH> fullPath{};
    return dllName.size() < fullPath.size()
        && wcscpy_s(fullPath.data(), fullPath.size(), dllName.c_str()) == 0
        && PathFindOnPathW(fullPath.data(), nullptr)
        ? std::filesystem::path(fullPath.data())
        : std::filesystem::path{};
}

// Returns a vector containing the DLL data or an error code
[[nodiscard]]
static std::expected<std::vector<char>, std::error_code>
ReadDllToMemory(const std::filesystem::path& filePath)
{
    std::expected<std::vector<char>, std::error_code> result;

    // Open the file in binary mode with RAII
    std::ifstream dllFile(filePath, std::ios::binary | std::ios::ate);
    if (!dllFile.is_open()) {
        result = std::unexpected(std::make_error_code(std::errc::no_such_file_or_directory));
    } else {
        // Go to end to get size
        const auto streampos = dllFile.tellg();

        // Check size
        if (streampos <= 0) {
            result = std::unexpected(std::make_error_code(std::errc::no_such_file_or_directory));
        } else if (streampos > SIZE_MAX) {
            result = std::unexpected(std::make_error_code(std::errc::file_too_large));
        } else {
            // Report size
            const auto fileSize = static_cast<size_t>(streampos);
            logInfo("    {:.3f} MB for {}\n", toMB(fileSize), filePath.string());

            // Allocate buffer
            std::vector<char> buffer(fileSize);
            if (buffer.empty()) {
                logError("    Failed to allocate {:.3f} MB in std::vector for {}\n", toMB(fileSize), filePath.string());
                result = std::unexpected(std::make_error_code(std::errc::not_enough_memory));
            } else {
                // Reset to beginning of file
                dllFile.seekg(0, std::ios::beg);

                // Read entire file
                result = dllFile.read(buffer.data(), fileSize)
                    ? std::expected<std::vector<char>, std::error_code>(std::move(buffer)) // Success case: assign buffer to result
                    : std::unexpected(std::make_error_code(std::errc::io_error));
            }
        }
    }

    return result;
}

// Struct to manage WinHTTP function pointers with upfront loading
struct EnsureDll {
private:
    HMODULE hWinhttp; // DLL handle
    std::vector<char> buffer; // Memory buffer for DLL

    // Template to get function pointer
    template <typename TT>
    void GetProc(LPCSTR proc_name, TT& target) {
        target = reinterpret_cast<TT>(GetProcAddress(hWinhttp, proc_name));
        if (!target) {
            throw std::runtime_error(std::format("Failed to get function: {}", proc_name));
        }
    }

public:
    // Instance function pointers
    HINTERNET(WINAPI *fnWinHttpOpen)(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD);
    HINTERNET(WINAPI *fnWinHttpConnect)(HINTERNET, LPCWSTR, INTERNET_PORT, DWORD);
    HINTERNET(WINAPI *fnWinHttpOpenRequest)(HINTERNET, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR*, DWORD);
    BOOL(WINAPI *fnWinHttpSendRequest)(HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD, DWORD, DWORD_PTR);
    BOOL(WINAPI *fnWinHttpReceiveResponse)(HINTERNET, LPVOID);
    BOOL(WINAPI *fnWinHttpQueryDataAvailable)(HINTERNET, LPDWORD);
    BOOL(WINAPI *fnWinHttpReadData)(HINTERNET, LPVOID, DWORD, LPDWORD);
    BOOL(WINAPI *fnWinHttpCloseHandle)(HINTERNET);

    explicit EnsureDll(const std::filesystem::path& dllPath) : hWinhttp(nullptr) {

        // Load DLL into memory
        const auto& result = ReadDllToMemory(dllPath);
        if (!result) {
            const auto errorMsg = std::system_category().message(result.error().value());
            throw std::runtime_error(std::format("Failed to load DLL: {}", errorMsg));
        }

        buffer = std::move(*result);

        // Load DLL from memory
        hWinhttp = LoadLibraryMemory(buffer.data());
        if (!hWinhttp) {
            buffer.clear(); // Release memory
            throw std::runtime_error("LoadLibraryMemory failed");
        }

        // Load all function pointers using template
        try {
            GetProc("WinHttpOpen", fnWinHttpOpen);
            GetProc("WinHttpConnect", fnWinHttpConnect);
            GetProc("WinHttpOpenRequest", fnWinHttpOpenRequest);
            GetProc("WinHttpSendRequest", fnWinHttpSendRequest);
            GetProc("WinHttpReceiveResponse", fnWinHttpReceiveResponse);
            GetProc("WinHttpQueryDataAvailable", fnWinHttpQueryDataAvailable);
            GetProc("WinHttpReadData", fnWinHttpReadData);
            GetProc("WinHttpCloseHandle", fnWinHttpCloseHandle);
        }
        catch (...) {
            FreeLibraryMemory(hWinhttp);
            buffer.clear(); // Release memory
            throw;
        }
    }

    ~EnsureDll() {
        if (hWinhttp) {
            FreeLibraryMemory(hWinhttp);
        }
        buffer.clear(); // Memory is managed by vector
    }
};

// Struct to manage HINTERNET handles with RAII
struct WindowHandleManager {
    HINTERNET handle;
    EnsureDll& api;

    WindowHandleManager(HINTERNET h, EnsureDll& a) : handle(h), api(a) {}
    ~WindowHandleManager() {
        if (handle && api.fnWinHttpCloseHandle) {
            api.fnWinHttpCloseHandle(handle);
            handle = nullptr;
        }
    }

    // Access handle
    HINTERNET get() const { return handle; }

    // Prevent copying
    WindowHandleManager(const WindowHandleManager&) = delete;
    WindowHandleManager& operator=(const WindowHandleManager&) = delete;

    // Allow moving
    WindowHandleManager(WindowHandleManager&& other) noexcept : handle(other.handle), api(other.api) {
        other.handle = nullptr;
    }
    WindowHandleManager& operator=(WindowHandleManager&& other) noexcept {
        if (this != &other) {
            if (handle && api.fnWinHttpCloseHandle) {
                api.fnWinHttpCloseHandle(handle);
            }
            handle = other.handle;
            other.handle = nullptr;
        }
        return *this;
    }
};

static int test(
    const std::filesystem::path& dllFullPath,
    const std::wstring& serverName,
    int serverPort,
    const std::wstring& objectName)
{
    logInfo("Using DLL at: {}\n", dllFullPath.string());

    // Initialize API with DLL path
    EnsureDll api(dllFullPath);
    try {
        EnsureDll api(dllFullPath);
    } catch (const std::runtime_error& e) {
        std::print("Error: {}\n", e.what());
        return -1;
    }

    // Session scope
    WindowHandleManager hSession(
        api.fnWinHttpOpen(
            L"A WinHTTP Example Program/1.0",
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            WINHTTP_NO_PROXY_NAME,
            WINHTTP_NO_PROXY_BYPASS,
            0),
        api);
    if (!hSession.get()) {
        std::print("Error {} in WinHttpOpen.\n", GetLastError());
        return -1;
    }

    // Connection scope
    {
        WindowHandleManager hConnect(
            api.fnWinHttpConnect(
                hSession.get(),
                serverName.c_str(),
                static_cast<INTERNET_PORT>(serverPort),
                0),
            api);
        if (!hConnect.get()) {
            std::print("Error {} in WinHttpConnect.\n", GetLastError());
            return -1;
        }

        // Request scope
        {
            WindowHandleManager hRequest(
                api.fnWinHttpOpenRequest(
                    hConnect.get(),
                    L"GET",
                    objectName.c_str(),
                    nullptr,
                    WINHTTP_NO_REFERER,
                    WINHTTP_DEFAULT_ACCEPT_TYPES,
                    0),
                api);
            if (!hRequest.get()) {
                std::print("Error {} in WinHttpOpenRequest.\n", GetLastError());
                return -1;
            }

            // Send HTTP request
            auto bResults = api.fnWinHttpSendRequest(
                hRequest.get(),
                WINHTTP_NO_ADDITIONAL_HEADERS,
                0,
                WINHTTP_NO_REQUEST_DATA,
                0,
                0,
                0);
            if (!bResults) {
                std::print("Error {} in WinHttpSendRequest.\n", GetLastError());
                return -1;
            }

            // End the HTTP request
            bResults = api.fnWinHttpReceiveResponse(hRequest.get(), nullptr);
            if (!bResults) {
                std::print("Error {} in WinHttpReceiveResponse.\n", GetLastError());
                return -1;
            }

            // Allocate memory for the response
            DWORD dwSize = 0;
            do {
                // Check for available data
                dwSize = 0;
                if (!api.fnWinHttpQueryDataAvailable(hRequest.get(), &dwSize)) {
                    std::print("Error {} in WinHttpQueryDataAvailable.\n", GetLastError());
                    return -1;
                }

                // Allocate memory for the buffer
                std::vector<unsigned char> pszOutBuffer(dwSize + 1);

                // Read the response data
                ZeroMemory(pszOutBuffer.data(), dwSize + 1);
                DWORD dwDownloaded = 0;
                if (!api.fnWinHttpReadData(hRequest.get(), pszOutBuffer.data(), dwSize, &dwDownloaded)) {
                    std::print("Error {} in WinHttpReadData.\n", GetLastError());
                    return -1;
                }
                else {
                    // Convert buffer to string for printing
                    std::string response(reinterpret_cast<char*>(pszOutBuffer.data()), dwDownloaded);
                    std::print("Response: {}\n", response);
                }
            } while (dwSize > 0);
        } // hRequest destroyed here
    } // hConnect destroyed here

    std::print("Press any key to close...\n");
    getchar();

    return 0;
} // hSession destroyed here

// Example usage
extern "C" int main(int argc, char* argv[])
{
    std::wstring dll_name(L"winhttp.dll");
    const std::filesystem::path dllPath{dll_name};

    // Find DLL in system path
    const auto dllFullPath = FindDllInPath(dll_name);
    if (dllFullPath.empty()) {
        logInfo("DLL not found: {}\n", dll_name);
        return 1;
    }

    logInfo("Found {} for {}\n", dllFullPath.string(), dll_name);

    // Default values
    std::wstring serverName = L"neverssl.com";
    int serverPort = 80;
    std::wstring objectName = L"/";

    // Parse command-line arguments
    if (argc > 1 && argv[1]) {
        // Convert serverName from char* to wstring
        size_t convertedChars = 0;
        wchar_t wServerName[256];
        mbstowcs_s(&convertedChars, wServerName, argv[1], strlen(argv[1]) + 1);
        if (convertedChars > 0) {
            serverName = wServerName;
        }
    }

    if (argc > 2 && argv[2]) {
        try {
            serverPort = std::stoi(argv[2]);
            if (serverPort <= 0 || serverPort > 65535) {
                std::print("Invalid port: {}. Using default: 80\n", argv[2]);
                serverPort = 80;
            }
        } catch (const std::exception& e) {
            std::print("Invalid port: {}. Using default: 80\n", argv[2]);
            serverPort = 80;
        }
    }

    if (argc > 3 && argv[3]) {
        // Convert objectName from char* to wstring
        size_t convertedChars = 0;
        wchar_t wObjectName[256];
        mbstowcs_s(&convertedChars, wObjectName, argv[3], strlen(argv[3]) + 1);
        if (convertedChars > 0) {
            objectName = wObjectName;
        }
    }

    const auto rc = test(dllFullPath, serverName, serverPort, objectName);

    const auto status = MmCleanup();
    if ( !status ) {
        logError("MmCleanup failed");
    }
    return rc ;
}
