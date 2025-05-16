#include "stdafx.h"

#if defined(_M_ARM64)
#define HOST_MACHINE IMAGE_FILE_MACHINE_ARM64
#elif defined(_M_ARM)
#define HOST_MACHINE IMAGE_FILE_MACHINE_ARM
#elif defined(_WIN64)
#define HOST_MACHINE IMAGE_FILE_MACHINE_AMD64
#else
#define HOST_MACHINE IMAGE_FILE_MACHINE_I386
#endif

#define GET_HEADER_DICTIONARY(headers, idx)  &headers->OptionalHeader.DataDirectory[idx]

#define AlignValueUp(value, alignment) ((static_cast<size_t>(value) + static_cast<size_t>(alignment) - 1) & ~(static_cast<size_t>(alignment) - 1))

#define OffsetPointer(data, offset) reinterpret_cast<LPVOID>(reinterpret_cast<LPBYTE>(data) + ptrdiff_t(offset))

// Protection flags for memory pages (Executable, Readable, Writeable)
static const int ProtectionFlags[2][2][2] = {
	{
		// not executable
		{PAGE_NOACCESS, PAGE_WRITECOPY},
		{PAGE_READONLY, PAGE_READWRITE},
	}, {
		// executable
		{PAGE_EXECUTE, PAGE_EXECUTE_WRITECOPY},
		{PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE},
	},
};

int MmpSizeOfImageHeadersUnsafe(PVOID BaseAddress) {
	PIMAGE_DOS_HEADER dh = static_cast<PIMAGE_DOS_HEADER>(BaseAddress);
	PIMAGE_NT_HEADERS nh = reinterpret_cast<PIMAGE_NT_HEADERS>(static_cast<LPBYTE>(BaseAddress) + dh->e_lfanew);

	//https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_optional_header32
	int sizeOfHeaders = dh->e_lfanew +										// e_lfanew member of IMAGE_DOS_HEADER
		4 +																	// 4 byte signature
		sizeof(IMAGE_FILE_HEADER) +											// size of IMAGE_FILE_HEADER
		sizeof(IMAGE_OPTIONAL_HEADER) +										// size of optional header
		sizeof(IMAGE_SECTION_HEADER) * nh->FileHeader.NumberOfSections;		// size of all section headers
	return sizeOfHeaders;
}

PMEMORYMODULE WINAPI MapMemoryModuleHandle(HMEMORYMODULE hModule) {

	if (!hModule)return nullptr;

	PIMAGE_NT_HEADERS nh = RtlImageNtHeader(hModule);
	if (!nh)return nullptr;

	int sizeOfHeaders = MmpSizeOfImageHeadersUnsafe(hModule);
	PMEMORYMODULE pModule = reinterpret_cast<PMEMORYMODULE>((LPBYTE)hModule + sizeOfHeaders);
	if (pModule->Signature != MEMORY_MODULE_SIGNATURE || pModule->codeBase != reinterpret_cast<LPBYTE>(hModule))return nullptr;
	return pModule;
}

BOOL WINAPI IsValidMemoryModuleHandle(HMEMORYMODULE hModule) {
	return MapMemoryModuleHandle(hModule) != nullptr;
}

NTSTATUS MmpInitializeStructure(DWORD ImageFileSize, LPCVOID ImageFileBuffer, PIMAGE_NT_HEADERS ImageHeaders) {

	if (!ImageHeaders)return STATUS_ACCESS_VIOLATION;

	//
	// Make sure there have enough free space to embed our structure.
	//
	int sizeOfHeaders = MmpSizeOfImageHeadersUnsafe(reinterpret_cast<PVOID>(ImageHeaders->OptionalHeader.ImageBase));
	PIMAGE_SECTION_HEADER pSections = IMAGE_FIRST_SECTION(ImageHeaders);
	for (int i = 0; i < ImageHeaders->FileHeader.NumberOfSections; ++i) {
		if (pSections[i].VirtualAddress < sizeOfHeaders + sizeof(MEMORYMODULE)) {
			return STATUS_NOT_SUPPORTED;
		}
	}

	//
	// Setup MemoryModule structure.
	//
	PMEMORYMODULE hMemoryModule = reinterpret_cast<PMEMORYMODULE>(ImageHeaders->OptionalHeader.ImageBase + sizeOfHeaders);
	RtlZeroMemory(hMemoryModule, sizeof(MEMORYMODULE));
	hMemoryModule->codeBase = reinterpret_cast<PBYTE>(ImageHeaders->OptionalHeader.ImageBase);
	hMemoryModule->dwImageFileSize = ImageFileSize;
	hMemoryModule->Signature = MEMORY_MODULE_SIGNATURE;
	hMemoryModule->SizeofHeaders = ImageHeaders->OptionalHeader.SizeOfHeaders;
	hMemoryModule->lpReserved = const_cast<LPVOID>(ImageFileBuffer);
	hMemoryModule->dwReferenceCount = 1;

	return STATUS_SUCCESS;
}

NTSTATUS MemorySetSectionProtection(
	_In_ LPBYTE base,
	_In_ PIMAGE_NT_HEADERS lpNtHeaders) {
	NTSTATUS status = STATUS_SUCCESS;
	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(lpNtHeaders);

	for (DWORD i = 0; i < lpNtHeaders->FileHeader.NumberOfSections; ++i, ++section) {
		LPVOID address = static_cast<LPBYTE>(base) + section->VirtualAddress;
		SIZE_T size = AlignValueUp(section->Misc.VirtualSize, lpNtHeaders->OptionalHeader.SectionAlignment);

		BOOL executable = (section->Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0,
			readable = (section->Characteristics & IMAGE_SCN_MEM_READ) != 0,
			writeable = (section->Characteristics & IMAGE_SCN_MEM_WRITE) != 0;
		DWORD protect = ProtectionFlags[executable][readable][writeable], oldProtect;

		if (section->Characteristics & IMAGE_SCN_MEM_NOT_CACHED) protect |= PAGE_NOCACHE;

		status = NtProtectVirtualMemory(NtCurrentProcess(), &address, &size, protect, &oldProtect);
		if (!NT_SUCCESS(status))break;
	}

	return status;
}

NTSTATUS MemoryLoadLibrary(
	_Out_ HMEMORYMODULE* MemoryModuleHandle,
	_In_ LPCVOID data,
	_In_ DWORD size) {

	PIMAGE_DOS_HEADER dos_header = nullptr;
	PIMAGE_NT_HEADERS old_header = nullptr;
	BOOLEAN CorImage = FALSE;
	NTSTATUS status = STATUS_SUCCESS;

	//
	// Check parameters
	//
	__try {

		*MemoryModuleHandle = nullptr;

		//
		// Check dos magic
		//
		dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(const_cast<LPVOID>(data));
		if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
			status = STATUS_INVALID_IMAGE_FORMAT;
			__leave;
		}

		//
		// Check nt headers
		//
		old_header = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<size_t>(data) + dos_header->e_lfanew);
		if (old_header->Signature != IMAGE_NT_SIGNATURE ||
			old_header->OptionalHeader.SectionAlignment & 1) {
			status = STATUS_INVALID_IMAGE_FORMAT;
			__leave;
		}

		//
		// Match machine type
		//
		if (old_header->FileHeader.Machine != HOST_MACHINE) {
			status = STATUS_IMAGE_MACHINE_TYPE_MISMATCH;
			__leave;
		}

		//
		// Only dll image support
		//
		if (!(old_header->FileHeader.Characteristics & IMAGE_FILE_DLL)) {
			status = STATUS_NOT_SUPPORTED;
			__leave;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		status = GetExceptionCode();
	}
	if (!NT_SUCCESS(status) || status == STATUS_IMAGE_MACHINE_TYPE_MISMATCH)return status;

	//
	// Reserve the address range of image
	//
	LPBYTE base = nullptr;
	if ((old_header->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) == 0) {
		base = static_cast<LPBYTE>(VirtualAlloc(
			reinterpret_cast<LPVOID>(old_header->OptionalHeader.ImageBase),
			old_header->OptionalHeader.SizeOfImage,
			MEM_RESERVE,
			PAGE_EXECUTE_READWRITE
		));
	}
	if (!base) {
		base = static_cast<LPBYTE>(VirtualAlloc(
			nullptr,
			old_header->OptionalHeader.SizeOfImage,
			MEM_RESERVE,
			PAGE_EXECUTE_READWRITE
		));
		if (!base) status = STATUS_NO_MEMORY;
	}

	if (!NT_SUCCESS(status)) {
		return status;
	}

	//
	// Allocate memory for image headers
	//
	size_t alignedHeadersSize = static_cast<DWORD>(AlignValueUp(old_header->OptionalHeader.SizeOfHeaders + sizeof(MEMORYMODULE), GetMmpGlobalDataPtr()->SystemInfo.dwPageSize));
	if (!VirtualAlloc(base, alignedHeadersSize, MEM_COMMIT, PAGE_READWRITE)) {
		VirtualFree(base, 0, MEM_RELEASE);
		status = STATUS_NO_MEMORY;
		return status;
	}

	//
	// Copy headers
	//
	PIMAGE_DOS_HEADER new_dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
	PIMAGE_NT_HEADERS new_header = reinterpret_cast<PIMAGE_NT_HEADERS>(base + dos_header->e_lfanew);
	RtlCopyMemory(
		new_dos_header,
		dos_header,
		old_header->OptionalHeader.SizeOfHeaders
	);
	new_header->OptionalHeader.ImageBase = reinterpret_cast<size_t>(base);

	do {
		//
		// Setup MEMORYMODULE structure.
		//
		status = MmpInitializeStructure(size, data, new_header);
		if (!NT_SUCCESS(status)) break;

		//
		// Allocate and copy sections
		//
		PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(new_header);
		for (DWORD i = 0; i < new_header->FileHeader.NumberOfSections; ++i, ++section) {

			DWORD size = AlignValueUp(
				section->Misc.VirtualSize,
				new_header->OptionalHeader.SectionAlignment
			);
			if (size < section->SizeOfRawData) {
				status = STATUS_INVALID_IMAGE_FORMAT;
				break;
			}

			LPVOID dest = VirtualAlloc(
				reinterpret_cast<LPSTR>(new_header->OptionalHeader.ImageBase) + section->VirtualAddress,
				size,
				MEM_COMMIT,
				PAGE_READWRITE
			);
			if (!dest) {
				status = STATUS_NO_MEMORY;
				break;
			}

			if (section->SizeOfRawData) {
				RtlCopyMemory(
					dest,
					static_cast<const BYTE*>(data) + section->PointerToRawData,
					section->SizeOfRawData
				);
			}

		}
		if (!NT_SUCCESS(status))break;

		//
		// Rebase image
		//
		auto locationDelta = new_header->OptionalHeader.ImageBase - old_header->OptionalHeader.ImageBase;
		if (locationDelta) {
			typedef struct _REBASE_INFO {
				USHORT Offset : 12;
				USHORT Type : 4;
			}REBASE_INFO, * PREBASE_INFO;
			typedef struct _IMAGE_BASE_RELOCATION_HEADER {
				DWORD VirtualAddress;
				DWORD SizeOfBlock;
				REBASE_INFO TypeOffset[ANYSIZE_ARRAY];

				DWORD TypeOffsetCount()const {
					return (this->SizeOfBlock - 8) / sizeof(_REBASE_INFO);
				}
			}IMAGE_BASE_RELOCATION_HEADER, * PIMAGE_BASE_RELOCATION_HEADER;

			PIMAGE_DATA_DIRECTORY dir = GET_HEADER_DICTIONARY(new_header, IMAGE_DIRECTORY_ENTRY_BASERELOC);
			PIMAGE_BASE_RELOCATION_HEADER relocation = reinterpret_cast<PIMAGE_BASE_RELOCATION_HEADER>(static_cast<LPBYTE>(base) + dir->VirtualAddress);

			if (dir->Size && dir->VirtualAddress) {
				while ((reinterpret_cast<LPBYTE>(relocation) < static_cast<LPBYTE>(base) + dir->VirtualAddress + dir->Size) && relocation->VirtualAddress > 0) {
					auto relInfo = (_REBASE_INFO*)&relocation->TypeOffset;
					for (DWORD i = 0; i < relocation->TypeOffsetCount(); ++i, ++relInfo) {
						switch (relInfo->Type) {
						case IMAGE_REL_BASED_HIGHLOW: *reinterpret_cast<DWORD*>(base + relocation->VirtualAddress + relInfo->Offset) += static_cast<DWORD>(locationDelta); break;
#ifdef _WIN64
						case IMAGE_REL_BASED_DIR64: *reinterpret_cast<ULONGLONG*>(base + relocation->VirtualAddress + relInfo->Offset) += static_cast<ULONGLONG>(locationDelta); break;
#endif
						case IMAGE_REL_BASED_ABSOLUTE:
						default: break;
						}
					}

					// advance to next relocation block
					//relocation->VirtualAddress += module->headers_align;
					relocation = static_cast<decltype(relocation)>(OffsetPointer(relocation, relocation->SizeOfBlock));
				}
			}

		}
		if (!NT_SUCCESS(status))break;

		__try {
			*MemoryModuleHandle = (HMEMORYMODULE)base;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			status = GetExceptionCode();
			break;
		}

		return status;
	} while (false);

	MemoryFreeLibrary((HMEMORYMODULE)base);
	return status;
}

BOOL MemoryFreeLibrary(HMEMORYMODULE mod) {
	PMEMORYMODULE module = MapMemoryModuleHandle(mod);
	PIMAGE_NT_HEADERS headers = RtlImageNtHeader(mod);

	if (!module) return FALSE;
	if (module->loadFromLdrLoadDllMemory && !module->underUnload)return FALSE;
	if (module->hModulesList)MemoryFreeImportTable(module);

	if (module->codeBase) VirtualFree(mod, 0, MEM_RELEASE);
	return TRUE;
}
