#include <windows.h>
#include <shlwapi.h>
#include <sqlite3pp.h> // https://github.com/dand-oss/sqlite3pp
#include <cppcrc.h> // https://github.com/dand-oss/cppcrc
#include <vector>
#include <string>
#include <array>
#include <filesystem>
#include <iostream>
#include <format>
#include <expected>
#include <system_error>
#include <fstream>

namespace fs = std::filesystem;

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
static std::expected<bool, std::error_code> isValidPeDll(const std::vector<char>& data) {
    if (data.size() < sizeof(IMAGE_DOS_HEADER)) {
        return std::unexpected(std::make_error_code(std::errc::invalid_argument));
    }
    const auto* dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(data.data());
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return std::unexpected(std::make_error_code(std::errc::invalid_argument));
    }
    if (data.size() < dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS)) {
        return std::unexpected(std::make_error_code(std::errc::invalid_argument));
    }
    const auto* ntHeader = reinterpret_cast<const IMAGE_NT_HEADERS*>(
        data.data() + dosHeader->e_lfanew);
    if (ntHeader->Signature != IMAGE_NT_SIGNATURE) {
        return std::unexpected(std::make_error_code(std::errc::invalid_argument));
    }
    return (ntHeader->FileHeader.Characteristics & IMAGE_FILE_DLL) != 0;
}

// Read DLL data from file, returning only the buffer
[[nodiscard]]
static std::expected<std::vector<char>, std::error_code>
readDllFromFile(const fs::path& filePath)
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
            logInfo("    {:.3f} MB for {}", toMB(fileSize), filePath.string());

            // Allocate buffer
            std::vector<char> buffer(fileSize);
            if (buffer.empty()) {
                logError("    Failed to allocate {:.3f} MB in std::vector for {}", toMB(fileSize), filePath.string());
                result = std::unexpected(std::make_error_code(std::errc::not_enough_memory));
            } else {
                // Reset to beginning of file
                dllFile.seekg(0, std::ios::beg);

                // Read entire file
                if (!dllFile.read(buffer.data(), fileSize)) {
                    result = std::unexpected(std::make_error_code(std::errc::io_error));
                } else {
                    result = std::move(buffer); // Success case: assign buffer to result
                }
            }
        }
    }

    return result;
}

// Reads a DLL file into a vector for import
static std::expected<std::vector<char>, std::error_code>
readDllFromFileForImport(
    const fs::path& filePath) {
    const auto dllResult = readDllFromFile(filePath);
    if (!dllResult) {
        logError("Error: Failed to read DLL file {}: {}", filePath.string(), dllResult.error().message());
        return dllResult; // Propagate the error
    }

    const auto isDll = isValidPeDll(*dllResult);
    if (!isDll || !isDll.value()) {
        logError("Error: File {} is not a valid PE DLL", filePath.string());
        return std::unexpected(std::make_error_code(std::errc::invalid_argument));
    }

    return dllResult; // Success case
}

// Creates the 'dlls' table if it doesn't exist
static bool createDllsTable(sqlite3pp::database& db) {
    try {
        sqlite3pp::query check(db, "SELECT name FROM sqlite_master WHERE type='table' AND name='dlls'");
        if (check.begin() != check.end()) {
            logInfo("Table 'dlls' exists.");
        } else {
            logInfo("Table 'dlls' not found. Creating...");
            if (db.execute("CREATE TABLE dlls (name TEXT PRIMARY KEY, data BLOB, crc32 INTEGER, full_path TEXT)") != SQLITE_OK) {
                logError("Error: Failed to create table: {}", db.error_msg());
                return false;
            }
        }
    } catch (const sqlite3pp::database_error& e) {
        logError("Error: Table check failed: {}", e.what());
        return false;
    }
    return true;
}

// Checks the integrity of the SQLite database
static bool checkDatabaseIntegrity(sqlite3pp::database& db) {
    try {
        sqlite3pp::query integrity(db, "PRAGMA integrity_check");
        auto it = integrity.begin();
        if (it != integrity.end() && std::strcmp((*it).get<char const*>(0), "ok") != 0) {
            logError("Error: Database integrity check failed: {}", (*it).get<char const*>(0));
            return false;
        }
    } catch (const sqlite3pp::database_error& e) {
        logError("Error: Integrity check failed: {}", e.what());
        return false;
    }
    return true;
}

// Upserts DLL data into the database
static bool upsertDllData(
    sqlite3pp::database& db,
    const std::vector<fs::path>& dllPaths,
    size_t& successCount,
    size_t& failureCount,
    size_t& totalSize) {
    const char* upsertSql =
        "INSERT INTO dlls (name, data, crc32, full_path) VALUES (?, ?, ?, ?) ON CONFLICT(name) DO UPDATE SET data = excluded.data, crc32 = excluded.crc32, full_path = excluded.full_path WHERE excluded.crc32 != dlls.crc32";
    logInfo("Preparing SQL: {} (SQLite version: {})", upsertSql, sqlite3_libversion());
    sqlite3pp::command cmd(db, upsertSql);

    for (const auto& dllPath : dllPaths) {
        const auto& dllDataResult = readDllFromFileForImport(dllPath);

        if (!dllDataResult) {
            logError("Error: Failed to read {}: {}", dllPath.string(), dllDataResult.error().message());
            ++failureCount;
            continue;
        }

        const auto& dllName = dllPath.filename().string();
        const auto& lowerName = toLowerCase(dllName);
        const auto& dllData = *dllDataResult;

        CRC32::CRC32 crc32;
        const auto crc32Value = crc32.calc(
            reinterpret_cast<const unsigned char*>(dllData.data()),
            dllData.size(),
            crc32.null_crc);
        logInfo("Computed CRC32 for {}: {:#x}, BLOB size: {:.3f} MB", lowerName, crc32Value, toMB(dllData.size()));

        try {
            cmd.bind(1, lowerName, sqlite3pp::copy);
            cmd.bind(2, dllData.data(), static_cast<int>(dllData.size()), sqlite3pp::nocopy);
            cmd.bind(3, static_cast<const long long>(crc32Value));
            cmd.bind(4, dllPath.string(), sqlite3pp::copy);
            if (cmd.execute() != SQLITE_OK) {
                logError("Error: Failed to upsert {}: {}", lowerName, db.error_msg());
                ++failureCount;
                cmd.reset();
                continue;
            }
            cmd.reset();
            logInfo("Upserted {} (crc32: {:#x}, size: {:.3f} MB)", lowerName, crc32Value, toMB(dllData.size()));
            ++successCount;
            totalSize += dllData.size();
        } catch (const sqlite3pp::database_error& e) {
            logError("Error: Failed to upsert {}: {}", lowerName, e.what());
            ++failureCount;
            cmd.reset();
        }
    }
    return true;
}

// Populates SQLite database with DLL data, tracks success/failure counts
static bool populateSqliteDb(
    sqlite3pp::database& db,
    const std::vector<fs::path>& dllPaths,
    size_t& successCount,
    size_t& failureCount,
    size_t& totalSize) noexcept {
    bool success = true;
    successCount = 0;
    failureCount = 0;
    totalSize = 0;

    if (!createDllsTable(db)) {
        success = false;
    } else if (!checkDatabaseIntegrity(db)) {
        success = false;
    } else {
        try {
            upsertDllData(db, dllPaths, successCount, failureCount, totalSize);
        } catch (const sqlite3pp::database_error& e) {
            logError("Error: Failed to prepare SQL: {} (SQLite version: {})", e.what(), sqlite3_libversion());
            failureCount = dllPaths.size();
            success = false;
        }
    }

    return success;
}

// Find DLL in system path, returning fs::path
[[nodiscard]]
static fs::path FindDllInPath(const std::string& dllName) noexcept {
    std::array<char, MAX_PATH> fullPath{};
    return dllName.size() < fullPath.size()
        && strcpy_s(fullPath.data(), fullPath.size(), dllName.c_str()) == 0
        && PathFindOnPathA(fullPath.data(), nullptr)
        ? fs::path(fullPath.data())
        : fs::path{};
}

// Parses command-line arguments and returns DLL paths, database path, and unresolved count
static std::tuple<std::vector<fs::path>, std::string, size_t>
parseArguments(int argc, char* argv[])
{
    std::vector<fs::path> dllPaths;
    std::string dbPath("dlls.db");
    size_t unresolvedCount = 0;

    for (int i = 1; i < argc; ++i) {
        const std::string arg(argv[i]);

        if (i + 1 < argc && arg == "--db") {
            dbPath = argv[++i];
        } else if (arg == "--verbose") {
            verbose = true;
        } else {
            const auto& lowerName = toLowerCase(arg);

            // resolve dll
            const auto& inputPath = fs::path(lowerName).extension() == ".dll" || fs::path(lowerName).extension() == ".DLL"
                ? lowerName
                : std::format("{}.dll", lowerName);

            const auto& fullPath = fs::exists(inputPath)
                ? fs::absolute(inputPath)
                : FindDllInPath(inputPath);

            if (fullPath.empty()) {
                logError("Error: Could not find {} in PATH", inputPath);
                ++unresolvedCount;
            } else {
                dllPaths.push_back(fullPath);
            }
        }
    }

    return {dllPaths, dbPath, unresolvedCount};
}

extern "C" int main(int argc, char* argv[]) {
    // Parse command-line arguments
    const auto& [dllPaths, dbPath, unresolvedCount] = parseArguments(argc, argv);

    // Check for valid input
    if (dllPaths.empty() && unresolvedCount == 0) {
        logInfo("Usage: {} [--db <database_path>] [--verbose] <dll_name> [dll_name...]", argv[0]);
        return 1;
    }

    // Initialize SQLite database
    size_t successCount = 0;
    size_t failureCount = 0;
    size_t totalSize = 0;
    sqlite3pp::database db;
    try {
        db = sqlite3pp::database(dbPath.c_str(), SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
        if (db.error_code() != SQLITE_OK) {
            logError("Error: Failed to open database {}: {}", dbPath, db.error_msg());
            return 1;
        }
        // Set busy timeout to handle database locks
        db.execute("PRAGMA busy_timeout = 5000");
    } catch (const sqlite3pp::database_error& e) {
        logError("Error: Failed to open database {}: {}", dbPath, e.what());
        return 1;
    }

    // Log SQLite version
    logInfo("Using SQLite version: {}", sqlite3_libversion());

    // Populate database with DLLs
    if (!dllPaths.empty() && !populateSqliteDb(db, dllPaths, successCount, failureCount, totalSize)) {
        logError("Error: Failed to populate SQLite database");
        return 1;
    }

    // Report
    logResult("\nSummary:") ;
    logResult("{} DLLs imported to {} {:.3f} MB", successCount, dbPath, toMB(totalSize));
    if (failureCount) {
        logResult("{} DLLs failed to import.", failureCount);
    }
    if (unresolvedCount) {
        logResult("{} DLLs failed to resolve.", unresolvedCount);
    }

    return 0;
}
