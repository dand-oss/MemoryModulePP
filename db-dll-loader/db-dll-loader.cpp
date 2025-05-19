#include "dll-loader.hpp"
#include <string>
#include <vector>
#include <iostream>
#include <expected>
#include <format>

template<typename... Args>
void logError(std::format_string<Args...> fmt, Args&&... args) {
    std::cerr << std::format(fmt, std::forward<Args>(args)...) << std::endl;
}

// Parses command-line arguments
static std::tuple<std::string, std::vector<std::string>> parseArguments(int argc, char* argv[]) {
    std::string dbPath("dlls.db");
    std::vector<std::string> dllNames;
    for (int ii = 1; ii < argc; ++ii) {
        const auto arg = std::string_view(argv[ii]);
        if (arg == "--db" && ii + 1 < argc) {
            dbPath = argv[++ii];
        } else {
            dllNames.emplace_back(arg);
        }
    }
    return {dbPath, dllNames};
}

extern "C" int main(int argc, char* argv[])
{
    const auto [dbPath, dllNames] = parseArguments(argc, argv);
    if (dllNames.empty()) {
        logError("Usage: {} [--db <database_path>] <dll_name> [<dll_name> ...]", argv[0]);
        return 1;
    }
    try {

        // release don't log
        const auto log_info = true ;

        // load 'em
        load_dlls(dbPath, dllNames, log_info);

        return 0;
    } catch (const std::exception& e) {
        logError("Error: {}", e.what());
        return 1;
    }
}
