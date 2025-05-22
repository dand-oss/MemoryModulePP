#include <windows.h>
#include <shlwapi.h>
#include <vector>
#include <string>
#include <filesystem>
#include <iostream>
#include <format>
#include <expected>
#include <system_error>
#include <fstream>
#include <sqlite3pp.h>
#include <cppcrc.h>

namespace fs = std::filesystem;

// Checks if a file is a valid PE DLL
static std::expected<bool, std::error_code> isValidPeDll(const std::vector<unsigned char>& data) {
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

// Reads a DLL file into a vector for import
static std::expected<std::vector<unsigned char>, std::error_code> readDllFromFileForImport(
    const fs::path& path) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) return std::unexpected(std::make_error_code(std::errc::no_such_file_or_directory));
    const auto fileSize = file.tellg();
    if (fileSize <= 0) return std::unexpected(std::make_error_code(std::errc::no_such_file_or_directory));
    std::vector<unsigned char> dllData(static_cast<size_t>(fileSize));
    file.seekg(0, std::ios::beg);
    if (!file.read(reinterpret_cast<char*>(dllData.data()), fileSize)) {
        return std::unexpected(std::make_error_code(std::errc::io_error));
    }
    auto isDll = isValidPeDll(dllData);
    if (!isDll || !isDll.value()) {
        return std::unexpected(std::make_error_code(std::errc::invalid_argument));
    }
    return dllData;
}

// Populates SQLite database with DLL data, tracks success/failure counts
static bool populateSqliteDb(
    sqlite3pp::database& db,
    const std::vector<fs::path>& dllPaths,
    size_t& successCount,
    size_t& failureCount) noexcept {
    successCount = 0;
    failureCount = 0;

    if (db.execute("CREATE TABLE IF NOT EXISTS dlls (name TEXT PRIMARY KEY, data BLOB, crc32 INTEGER)") != SQLITE_OK) {
        std::cout << std::format("SQLite error creating table: {}\n", db.error_msg());
        failureCount = dllPaths.size();
        return false;
    }

    sqlite3pp::command cmd(db, "INSERT OR REPLACE INTO dlls (name, data, crc32) VALUES (?, ?, ?)");
    for (const auto& path : dllPaths) {
        auto dllData = readDllFromFileForImport(path);
        if (!dllData) {
            std::cout << std::format("Error: Failed to read {}: {}\n", path.string(), dllData.error().message());
            ++failureCount;
            continue;
        }
        const std::string dllName(path.filename().string());
        std::string lowerName(dllName);
        std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);
        CRC32::CRC32 crc32; // Use cppcrc
        uint32_t crc32Value = crc32.calc(dllData->data(), dllData->size(), crc32.null_crc);
        std::cout << std::format("Computed CRC32 for {}: {:#x}, BLOB size: {} bytes\n", lowerName, crc32Value, dllData->size());
        cmd.bind(1, lowerName, sqlite3pp::copy);
        cmd.bind(2, dllData->data(), static_cast<int>(dllData->size()), sqlite3pp::nocopy);
        cmd.bind(3, static_cast<long long>(crc32Value));
        if (cmd.execute() != SQLITE_OK) {
            std::cout << std::format("Error: Failed to insert {} into database: {}\n", lowerName, db.error_msg());
            ++failureCount;
            cmd.reset();
            continue;
        }
        cmd.reset();
        std::cout << std::format("Imported {} (crc32: {:#x}, size: {} bytes)\n", lowerName, crc32Value, dllData->size());
        ++successCount;
    }
    return true;
}

// Parses command-line arguments and returns DLL paths and database path
static std::pair<std::vector<fs::path>, std::string> parseArguments(int argc, char* argv[]) {
    std::vector<fs::path> dllPaths;
    std::string dbPath = "dlls.db";

    for (int i = 1; i < argc; ++i) {
        const std::string arg(argv[i]);
        if (arg == "--db" && i + 1 < argc) {
            dbPath = argv[++i];
            continue;
        }
        std::string inputPath(arg);
        if (!(fs::path(inputPath).extension() == ".dll" || fs::path(inputPath).extension() == ".DLL")) {
            inputPath += ".dll";
        }
        auto path = fs::path(inputPath);
        bool isFilename = !path.has_parent_path();
        if (isFilename) {
            char fullPath[MAX_PATH];
            strcpy_s(fullPath, inputPath.c_str());
            bool found = PathFindOnPathA(fullPath, nullptr) != 0;
            if (found) {
                path = fs::path(fullPath);
                std::cout << std::format("Resolved {} to {}\n", inputPath, path.string());
            } else {
                std::cout << std::format("Error: Could not find {} in PATH\n", inputPath);
                continue;
            }
        }
        dllPaths.push_back(path);
    }

    return {dllPaths, dbPath};
}

int main(int argc, char* argv[]) {
    // Parse command-line arguments
    const auto [dllPaths, dbPath] = parseArguments(argc, argv);

    // Check for valid input
    if (dllPaths.empty()) {
        std::cout << std::format("Usage: {} [--db <database_path>] <dll_name> [dll_name...]\n", argv[0]);
        return 1;
    }

    // Initialize SQLite database
    size_t successCount = 0;
    size_t failureCount = 0;
    sqlite3pp::database db(dbPath.c_str(), SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
    if (db.error_code() != SQLITE_OK) {
        std::cout << std::format("SQLite error opening database: {}\n", db.error_msg());
        return 1;
    }

    // Populate database with DLLs
    if (!populateSqliteDb(db, dllPaths, successCount, failureCount)) {
        std::cout << std::format("Error: Failed to populate SQLite database\n");
        return 1;
    }

    // Report
    std::cout << std::format("Successfully imported {} DLLs into SQLite database at {}\n", successCount, dbPath);
    if (failureCount) {
        std::cout << std::format("{} DLLs failed.\n", failureCount);
    }

    return 0;
}