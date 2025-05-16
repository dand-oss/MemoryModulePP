#include "hfbfuncs.hpp"

#include <windows.h>
#include <filesystem>
#include <objstore/ObjectStore.hpp>
#include <objstore/ezdb.hpp>
#include <iaiodevice.hpp>
#include <sqlite3.h>

#include <iostream> // std::cerr
#include <fmt/ostream.h>
namespace fs = std::filesystem;

#ifndef FMT_SHARED
#error "FMT_SHARED not defined! You must define this if using fmtd.dll."
#endif

void show_registered_sqlite_vfs() {
    const sqlite3_vfs* vfs = sqlite3_vfs_find(nullptr);
    std::string msg = "Registered SQLite VFS:\n\n";

    while (vfs) {
        msg += " - ";
        msg += vfs->zName;
        msg += "\n";
        vfs = vfs->pNext;
    }

    MessageBoxA(nullptr, msg.c_str(), "Available VFS", MB_OK | MB_ICONINFORMATION);
}

void show_zone_members(const aObjectFileStore& os, const std::string& zoneName) {
    std::string msg = fmt::format("[DEBUG] Zone '{}':\n\n", zoneName);

    for (const auto& name : os.member_name_vec()) {
        msg += "  -> " + name + "\n";
    }

    if (msg.empty() || msg.back() != '\n') {
        msg += "(no members found)\n";
    }

    MessageBoxA(nullptr, msg.c_str(), "Archive Zone Members", MB_OK | MB_ICONINFORMATION);
}

std::vector<unsigned char> load_member_with_objstore(
    const std::string& dbPath,
    const std::string& vfs,
    const std::string& zone,
    const std::string& memberName
) {

    // show_registered_sqlite_vfs();

    EzDb db(std::filesystem::path(dbPath), SQLITE_OPEN_READONLY, vfs.empty() ? nullptr : vfs.c_str());
    aObjectFileStore os(db, zone.c_str());

    // show_zone_members(os, zone);

    if (!os.exists(memberName)) {
        std::string msg = fmt::format("Can't find member '{}'", memberName);
        MessageBoxA(nullptr, msg.c_str(), "ERROR", MB_ICONERROR);
        throw std::runtime_error(msg);
    }

    const auto uuid = os.uuid_of(memberName);
    const size_t want = os.info(uuid).osize;
    std::string want_msg = fmt::format("Expecting {} bytes for '{}'", want, memberName);
    std::vector<unsigned char> data(want);
    const auto& rdev = os.get_read_device(uuid);
    size_t got = rdev->read(data.data(), want);

    if (got != want) {
        std::string msg = fmt::format("Read mismatch: wanted {}, got {}", want, got);
        MessageBoxA(nullptr, msg.c_str(), "ERROR", MB_ICONERROR);
        throw std::runtime_error(msg);
    }

    return data;
}
