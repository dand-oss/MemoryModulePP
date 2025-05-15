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
#include <codecvt>

// Function to convert bytes to MB
static double toMB(size_t bytes) {
    return static_cast<double>(bytes) / 1024.0 / 1024.0;
}

// Portable logging wrappers using std::format_string
template<typename... Args>
void logInfo(std::format_string<Args...> fmt, Args&&... args) {
    std::cout << std::format(fmt, std::forward<Args>(args)...) << std::endl;
}

template<typename... Args>
void logError(std::format_string<Args...> fmt, Args&&... args) {
    std::cerr << std::format(fmt, std::forward<Args>(args)...) << std::endl;
}

std::string ws2s(const std::wstring& wstr)
{
    // assume ASCII is utf8
    using convert_typeX = std::codecvt_utf8<wchar_t>;
    std::wstring_convert<convert_typeX, wchar_t> converterX;

    return converterX.to_bytes(wstr);
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
        logError("Failed to open DLL file: {}", filePath.string());
        result = std::unexpected(std::make_error_code(std::errc::no_such_file_or_directory));
    } else {
        // Go to end to get size
        const auto streampos = dllFile.tellg();

        // Check size
        if (streampos <= 0) {
            logError("DLL file is empty or invalid: {}", filePath.string());
            result = std::unexpected(std::make_error_code(std::errc::no_such_file_or_directory));
        } else if (streampos > SIZE_MAX) {
            logError("DLL file too large: {:.3f} MB in {}", toMB(streampos), filePath.string());
            result = std::unexpected(std::make_error_code(std::errc::file_too_large));
        } else {
            // Report size
            const auto fileSize = static_cast<size_t>(streampos);
            logInfo("    {:.3f} MB for {}", toMB(fileSize), filePath.string());

            // Allocate buffer
            std::vector<char> buffer(fileSize);
            if (buffer.empty()) {
                logError("    Failed to allocate {:.3f} MB for {}", toMB(fileSize), filePath.string());
                result = std::unexpected(std::make_error_code(std::errc::not_enough_memory));
            } else {
                // Reset to beginning of file
                dllFile.seekg(0, std::ios::beg);

                // Read entire file
                result = dllFile.read(buffer.data(), fileSize)
                    ? std::expected<std::vector<char>, std::error_code>(std::move(buffer)) // Success case: assign buffer to result
                    : std::unexpected(std::make_error_code(std::errc::io_error));
                if (!result) {
                    logError("Failed to read DLL file: {}", filePath.string());
                }
            }
        }
    }

    return result;
}

// Struct to manage WinHTTP function pointers with upfront loading
struct EnsureDll {
private:
    HMODULE _hWinhttp = nullptr; // DLL handle
    std::vector<char> _buffer; // Memory buffer for DLL

    // Structure to hold function name and pointer to member
    struct FuncInfo {
        const char* name;
        void* target;
    };

    // Function to get function pointers
    std::expected<void, std::error_code> GetFunctionPointers(const std::vector<FuncInfo>& functions)
    {
        // Lambda to get function pointers
        auto getProc = [this](LPCSTR proc_name, auto& target) -> std::expected<void, std::error_code> {
            using FuncType = std::decay_t<decltype(target)>;
            target = reinterpret_cast<FuncType>(GetProcAddress(_hWinhttp, proc_name));
            if (!target) {
                auto err = std::error_code(GetLastError(), std::system_category());
                logError("Failed to get function '{}': {}", proc_name, err.message());
                return std::unexpected(err);
            }
            return {};
        };

        // Cleanup lambda
        auto cleanup = [this]() {
            if (_hWinhttp) {
                logInfo("FreeLibraryMemory({:p})", hptr());
                FreeLibraryMemory(_hWinhttp);
                _hWinhttp = nullptr;
            }
            _buffer.clear();
        };

        // Get each function pointer
        for (const auto& func : functions) {
            auto res = getProc(func.name, *static_cast<decltype(fnWinHttpOpen)*>(func.target));
            if (!res) {
                logError("Aborting DLL loading due to failure in function '{}'", func.name);
                cleanup();
                return res;
            }
        }

        return {};
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

    explicit EnsureDll() = default;

    std::expected<void, std::error_code>
    connect(const std::filesystem::path& dllPath)
    {
        // Load DLL into memory
        auto result = ReadDllToMemory(dllPath);
        if (!result) {
            logError("Cannot proceed due to failure in reading DLL: {}", result.error().message());
            return std::unexpected(result.error());
        }
        _buffer = std::move(*result);

        // Load DLL from memory
        logInfo("LoadLibraryMemory {}", dllPath.string());
        _hWinhttp = LoadLibraryMemory(_buffer.data());
        if (!_hWinhttp) {
            auto err = std::error_code(GetLastError(), std::system_category());
            logError("LoadLibraryMemory failed for {}: {}", dllPath.string(), err.message());
            _buffer.clear();
            return std::unexpected(err);
        }
        logInfo("hWinhttp = {:p}", hptr());

        // Macro to define a FuncInfo entry
#define ADD_FUNCTION(func) {#func, &fn##func}

        // Load function pointers
        return GetFunctionPointers({
            ADD_FUNCTION(WinHttpOpen),
            ADD_FUNCTION(WinHttpConnect),
            ADD_FUNCTION(WinHttpOpenRequest),
            ADD_FUNCTION(WinHttpSendRequest),
            ADD_FUNCTION(WinHttpReceiveResponse),
            ADD_FUNCTION(WinHttpQueryDataAvailable),
            ADD_FUNCTION(WinHttpReadData),
            ADD_FUNCTION(WinHttpCloseHandle)
            });
    }

    ~EnsureDll() {
        if (_hWinhttp) {
            logInfo("FreeLibraryMemory({:p})", hptr());
            FreeLibraryMemory(_hWinhttp);
        }
        _buffer.clear(); // Memory is managed by vector
    }
    void* hptr() const { return static_cast<void*>(_hWinhttp); }
};

// Struct to manage HINTERNET handles with RAII
struct WindowHandleManager {
    HINTERNET _handle = nullptr;
    std::string _name = {};
    EnsureDll& _api;

    WindowHandleManager(HINTERNET h, const std::string& name, EnsureDll& a)
        : _handle(h)
        , _name(name)
        , _api(a)
    {
        logInfo("HandleManger {}  {:p}", _name, hptr());
    }
    ~WindowHandleManager() {
        if (_handle && _api.fnWinHttpCloseHandle) {
            logInfo("WinHttpCloseHandle({:p}) {}", hptr(), _name);
            if (! _api.fnWinHttpCloseHandle(_handle)) {
               logError("WinHttpCloseHandle({:p}) {} failed {}", hptr(), _name, GetLastError());
            }
        }
    }

    // Access handle
    HINTERNET get() const { return _handle; }
    void* hptr() const { return static_cast<void*>(_handle); }

    // Prevent copying
    WindowHandleManager(const WindowHandleManager&) = delete;
    WindowHandleManager& operator=(const WindowHandleManager&) = delete;

    // Allow moving
    WindowHandleManager(WindowHandleManager&& other) noexcept
        : _handle(other._handle)
        , _name(std::move(other._name))
        , _api(other._api)
    {
        other._handle = nullptr;
        other._name = "";
    }
    WindowHandleManager& operator=(WindowHandleManager&& other) noexcept {
        if (this != &other) {
            if (_handle && _api.fnWinHttpCloseHandle) {
                _api.fnWinHttpCloseHandle(_handle);
            }
            _handle = other._handle;
            _name = std::move(other._name);
            _api = other._api;
            other._handle = nullptr;
            other._name = "";
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
    logInfo("Using DLL at: {}", dllFullPath.string());

    // RTTI Initialize API with DLL path
    EnsureDll api;
    auto res = api.connect(dllFullPath);
    if (!res) {
        logError("Failed to connect to DLL: {}", res.error().message());
        return -1;
    }

    // Session scope
    logInfo("WinHttpOpen");
    WindowHandleManager hSession(
        api.fnWinHttpOpen(
            L"A WinHTTP Example Program/1.0",
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            WINHTTP_NO_PROXY_NAME,
            WINHTTP_NO_PROXY_BYPASS,
            0),
        "WinHttpOpen",
        api);
    if (!hSession.get()) {
        logError("Error {} in WinHttpOpen.", GetLastError());
        return -1;
    }

    // Connection scope
    {
        logInfo("WinHttpConnect {}:{}", ws2s(serverName), serverPort);
        WindowHandleManager hConnect(
            api.fnWinHttpConnect(
                hSession.get(),
                serverName.c_str(),
                static_cast<INTERNET_PORT>(serverPort),
                0),
           "WinHttpConnect",
            api);
        if (!hConnect.get()) {
            logError("Error {} in WinHttpConnect.", GetLastError());
            return -1;
        }

        // Request scope
        {
            logInfo("WinHttpOpenRequest '{}'", ws2s(objectName));
            WindowHandleManager hRequest(
                api.fnWinHttpOpenRequest(
                    hConnect.get(),
                    L"GET",
                    objectName.c_str(),
                    nullptr,
                    WINHTTP_NO_REFERER,
                    WINHTTP_DEFAULT_ACCEPT_TYPES,
                    0),
                "WinHttpOpenRequest",
                api);
            if (!hRequest.get()) {
                logError("Error {} in WinHttpOpenRequest.", GetLastError());
                return -1;
            }

            // Send HTTP request
            logInfo("WinHttpSendRequest");
            auto bResults = api.fnWinHttpSendRequest(
                hRequest.get(),
                WINHTTP_NO_ADDITIONAL_HEADERS,
                0,
                WINHTTP_NO_REQUEST_DATA,
                0,
                0,
                0);
            if (!bResults) {
                logError("Error {} in WinHttpSendRequest.", GetLastError());
                return -1;
            }

            // End the HTTP request
            logInfo("WinHttpRecieveResponse");
            bResults = api.fnWinHttpReceiveResponse(hRequest.get(), nullptr);
            if (!bResults) {
                logError("Error {} in WinHttpReceiveResponse.", GetLastError());
                return -1;
            }

            // Allocate memory for the response
            DWORD dwSize = 0;
            do {
                // Check for available data
                dwSize = 0;
                if (!api.fnWinHttpQueryDataAvailable(hRequest.get(), &dwSize)) {
                    logError("Error {} in WinHttpQueryDataAvailable.", GetLastError());
                    return -1;
                }

                // Allocate memory for the buffer
                std::vector<unsigned char> pszOutBuffer(dwSize + 1);

                // Read the response data
                ZeroMemory(pszOutBuffer.data(), dwSize + 1);
                DWORD dwDownloaded = 0;
                if (!api.fnWinHttpReadData(hRequest.get(), pszOutBuffer.data(), dwSize, &dwDownloaded)) {
                    logError("Error {} in WinHttpReadData.", GetLastError());
                    return -1;
                }
                else {
                    // Convert buffer to string for printing
                    std::string response(reinterpret_cast<char*>(pszOutBuffer.data()), dwDownloaded);
                    logInfo("Response: {}", response); // Changed to logInfo for consistency
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
        logInfo("DLL not found: {}", ws2s(dll_name));
        return 1;
    }

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
                logError("Invalid port: {}. Using default: 80", argv[2]);
                serverPort = 80;
            }
        } catch (const std::exception& e) {
            logError("Invalid port: {}. Using default: 80", argv[2]);
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

    /*
    const auto status = MmCleanup();
    if ( !status ) {
        logError("MmCleanup failed");
    }
    */
    return rc ;
}
