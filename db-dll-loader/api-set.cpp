#include "api-set.hpp"
#include <cstdint>
#include <cstring>

// Narrow-string replacement for UNICODE_STRING
typedef struct _STRING {
    uint16_t Length;
    uint16_t MaximumLength;
    char* Buffer;
} STRING, *PSTRING;

// Local structure definitions
struct _PEB {
    uint8_t Reserved1[2];
    uint8_t BeingDebugged;
    uint8_t Reserved2[1];
    void* Reserved3[2];
    void* Ldr;
    void* ProcessParameters;
    uint8_t Reserved4[104];
    void* Reserved5[52];
    void* ApiSetMap; // Simplified to void* to avoid forward declaration issues
};

struct _API_SET_HASH_ENTRY {
    uint32_t Hash;
    uint16_t Index;
    uint16_t Reserved;
};

struct _API_SET_NAMESPACE {
    uint32_t Version;
    uint32_t Size;
    uint32_t Flags;
    uint32_t Count;
    uint32_t EntryOffset;
    uint32_t HashOffset;
    uint32_t HashFactor;
};

struct _API_SET_NAMESPACE_ENTRY {
    STRING Name;
    uint8_t Data[1]; // Variable length
};

// Typedefs
typedef _PEB* PPEB;
typedef _API_SET_NAMESPACE* PAPI_SET_NAMESPACE;
typedef _API_SET_HASH_ENTRY* PAPI_SET_HASH_ENTRY;
typedef _API_SET_NAMESPACE_ENTRY* PAPI_SET_NAMESPACE_ENTRY;

PPEB GetPEB() {
#if defined(_WIN64)
    return reinterpret_cast<PPEB>(__readgsqword(0x60));
#else
    return reinterpret_cast<PPEB>(__readfsdword(0x30));
#endif
}

static uint32_t ComputeApiSetHash(const char* name, uint32_t factor) {
    uint32_t hash = 0;
    for (; *name; ++name) {
        hash = ((hash >> 13) | (hash << 19)) + factor + *name;
    }
    return hash;
}

bool IsApiSetDllByNamespace(const std::string& dllName) {
    const auto peb = GetPEB();
    if (!peb || !peb->ApiSetMap) {
        return false;
    }

    const auto apiSetNamespace = reinterpret_cast<PAPI_SET_NAMESPACE>(peb->ApiSetMap);
    const auto pHashEntries = reinterpret_cast<PAPI_SET_HASH_ENTRY>(
        reinterpret_cast<uint8_t*>(apiSetNamespace) + apiSetNamespace->HashOffset);
    const auto hash = ComputeApiSetHash(dllName.c_str(), apiSetNamespace->HashFactor);
    const auto index = hash % apiSetNamespace->Count;

    for (uint32_t i = 0; i < apiSetNamespace->Count; ++i) {
        const auto pEntry = &pHashEntries[i];
        if (pEntry->Hash == hash && pEntry->Index < apiSetNamespace->Count) {
            const auto pNsEntry = reinterpret_cast<PAPI_SET_NAMESPACE_ENTRY>(
                reinterpret_cast<uint8_t*>(apiSetNamespace) +
                apiSetNamespace->EntryOffset +
                pEntry->Index * sizeof(_API_SET_NAMESPACE_ENTRY));
            if (_strnicmp(pNsEntry->Name.Buffer, dllName.c_str(), pNsEntry->Name.Length / sizeof(char)) == 0) {
                return true;
            }
        }
    }

    return false;
}
