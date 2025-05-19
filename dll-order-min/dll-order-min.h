#pragma once

#include <vector>
#include <string>
#include <map>
#include <tuple>
#include <expected>

extern std::expected<std::vector<std::tuple<std::string, const char*, size_t>>, std::string> computeLoadOrder(
    const std::map<std::string, std::vector<char>>& dllDataMap) ;
