#pragma once

#include <string>
#include <vector>

class aObjectFileStore;

void show_registered_sqlite_vfs();
void show_zone_members(const aObjectFileStore& os, const std::string& zoneName);
std::vector<unsigned char> load_member_with_objstore(
    const std::string& dbPath,
    const std::string& vfs,
    const std::string& zone,
    const std::string& memberName
);

