#if !(defined(_M_ARM) || defined(_M_ARM64) || !defined(_USRDLL))

//===============================================================================================//
// Copyright (c) 2012, Stephen Fewer of Harmony Security (www.harmonysecurity.com)
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without modification, are permitted 
// provided that the following conditions are met:
// 
//     * Redistributions of source code must retain the above copyright notice, this list of 
// conditions and the following disclaimer.
// 
//     * Redistributions in binary form must reproduce the above copyright notice, this list of 
// conditions and the following disclaimer in the documentation and/or other materials provided 
// with the distribution.
// 
//     * Neither the name of Harmony Security nor the names of its contributors may be used to
// endorse or promote products derived from this software without specific prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR 
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
// FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR 
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR 
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY 
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR 
// OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
// POSSIBILITY OF SUCH DAMAGE.
//===============================================================================================//
#include "ReflectiveLoader.h"
//===============================================================================================//

// This is our position independent reflective DLL loader/injector
DLLEXPORT ULONG_PTR WINAPI ReflectiveLoader(PVOID buffer)
{
	// the functions we need
	LOADLIBRARYA pLoadLibraryA = NULL;
	GETPROCADDRESS pGetProcAddress = NULL;
	VIRTUALALLOC pVirtualAlloc = NULL;
	NTFLUSHINSTRUCTIONCACHE pNtFlushInstructionCache = NULL;

	USHORT usCounter;

	// the initial location of this image in memory
	ULONG_PTR uiLibraryAddress;
	// the kernels base address and later this images newly loaded base address
	ULONG_PTR uiBaseAddress;

	// variables for processing the kernels export table
	ULONG_PTR uiAddressArray;
	ULONG_PTR uiNameArray;
	ULONG_PTR uiExportDir;
	ULONG_PTR uiNameOrdinals;
	DWORD dwHashValue;

	// variables for loading this image
	ULONG_PTR uiHeaderValue;
	ULONG_PTR uiValueA;
	ULONG_PTR uiValueB;
	ULONG_PTR uiValueC;
	ULONG_PTR uiValueD;
	ULONG_PTR uiValueE;

	// STEP 0: calculate our images current base address
	uiLibraryAddress = static_cast<ULONG_PTR>(buffer);

	// STEP 1: process the kernels exports for the functions our loader needs...

	// get the Process Enviroment Block
#ifdef WIN_X64
	uiBaseAddress = __readgsqword(0x60);
#else
#ifdef WIN_X86
	uiBaseAddress = __readfsdword(0x30);
#else WIN_ARM
	uiBaseAddress = *reinterpret_cast<DWORD*>(reinterpret_cast<BYTE*>(_MoveFromCoprocessor(15, 0, 13, 0, 2)) + 0x30);
#endif
#endif

	// get the processes loaded modules. ref: http://msdn.microsoft.com/en-us/library/aa813708(VS.85).aspx
	uiBaseAddress = reinterpret_cast<ULONG_PTR>(reinterpret_cast<_PPEB>(uiBaseAddress)->pLdr);

	// get the first entry of the InMemoryOrder module list
	uiValueA = reinterpret_cast<ULONG_PTR>(reinterpret_cast<PPEB_LDR_DATA>(uiBaseAddress)->InMemoryOrderModuleList.Flink);
	while (uiValueA)
	{
		// get pointer to current modules name (unicode string)
		uiValueB = reinterpret_cast<ULONG_PTR>(reinterpret_cast<PLDR_DATA_TABLE_ENTRY>(uiValueA)->BaseDllName.pBuffer);
		// set bCounter to the length for the loop
		usCounter = reinterpret_cast<PLDR_DATA_TABLE_ENTRY>(uiValueA)->BaseDllName.Length;
		// clear uiValueC which will store the hash of the module name
		uiValueC = 0;

		// compute the hash of the module name...
		do
		{
			uiValueC = ror(static_cast<DWORD>(uiValueC));
			// normalize to uppercase if the madule name is in lowercase
			if (*reinterpret_cast<BYTE*>(uiValueB) >= 'a')
				uiValueC += *reinterpret_cast<BYTE*>(uiValueB) - 0x20;
			else
				uiValueC += *reinterpret_cast<BYTE*>(uiValueB);
			uiValueB++;
		} while (--usCounter);

		// compare the hash with that of kernel32.dll
		if (static_cast<DWORD>(uiValueC) == KERNEL32DLL_HASH)
		{
			// get this modules base address
			uiBaseAddress = reinterpret_cast<ULONG_PTR>(reinterpret_cast<PLDR_DATA_TABLE_ENTRY>(uiValueA)->DllBase);

			// get the VA of the modules NT Header
			uiExportDir = uiBaseAddress + reinterpret_cast<PIMAGE_DOS_HEADER>(uiBaseAddress)->e_lfanew;

			// uiNameArray = the address of the modules export directory entry
			uiNameArray = reinterpret_cast<ULONG_PTR>(&reinterpret_cast<PIMAGE_NT_HEADERS>(uiExportDir)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);

			// get the VA of the export directory
			uiExportDir = uiBaseAddress + reinterpret_cast<PIMAGE_DATA_DIRECTORY>(uiNameArray)->VirtualAddress;

			// get the VA for the array of name pointers
			uiNameArray = uiBaseAddress + reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(uiExportDir)->AddressOfNames;

			// get the VA for the array of name ordinals
			uiNameOrdinals = uiBaseAddress + reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(uiExportDir)->AddressOfNameOrdinals;

			usCounter = 3;

			// loop while we still have imports to find
			while (usCounter > 0)
			{
				// compute the hash values for this function name
				dwHashValue = hash(reinterpret_cast<char*>(uiBaseAddress + DEREF_32(uiNameArray)));

				// if we have found a function we want we get its virtual address
				if (dwHashValue == LOADLIBRARYA_HASH || dwHashValue == GETPROCADDRESS_HASH || dwHashValue == VIRTUALALLOC_HASH)
				{
					// get the VA for the array of addresses
					uiAddressArray = uiBaseAddress + reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(uiExportDir)->AddressOfFunctions;

					// use this functions name ordinal as an index into the array of name pointers
					uiAddressArray += DEREF_16(uiNameOrdinals) * sizeof(DWORD);

					// store this functions VA
					if (dwHashValue == LOADLIBRARYA_HASH)
						pLoadLibraryA = reinterpret_cast<LOADLIBRARYA>(uiBaseAddress + DEREF_32(uiAddressArray));
					else if (dwHashValue == GETPROCADDRESS_HASH)
						pGetProcAddress = reinterpret_cast<GETPROCADDRESS>(uiBaseAddress + DEREF_32(uiAddressArray));
					else if (dwHashValue == VIRTUALALLOC_HASH)
						pVirtualAlloc = reinterpret_cast<VIRTUALALLOC>(uiBaseAddress + DEREF_32(uiAddressArray));

					// decrement our counter
					usCounter--;
				}

				// get the next exported function name
				uiNameArray += sizeof(DWORD);

				// get the next exported function name ordinal
				uiNameOrdinals += sizeof(WORD);
			}
		}
		else if (static_cast<DWORD>(uiValueC) == NTDLLDLL_HASH)
		{
			// get this modules base address
			uiBaseAddress = reinterpret_cast<ULONG_PTR>(reinterpret_cast<PLDR_DATA_TABLE_ENTRY>(uiValueA)->DllBase);

			// get the VA of the modules NT Header
			uiExportDir = uiBaseAddress + reinterpret_cast<PIMAGE_DOS_HEADER>(uiBaseAddress)->e_lfanew;

			// uiNameArray = the address of the modules export directory entry
			uiNameArray = reinterpret_cast<ULONG_PTR>(&reinterpret_cast<PIMAGE_NT_HEADERS>(uiExportDir)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);

			// get the VA of the export directory
			uiExportDir = uiBaseAddress + reinterpret_cast<PIMAGE_DATA_DIRECTORY>(uiNameArray)->VirtualAddress;

			// get the VA for the array of name pointers
			uiNameArray = uiBaseAddress + reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(uiExportDir)->AddressOfNames;

			// get the VA for the array of name ordinals
			uiNameOrdinals = uiBaseAddress + reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(uiExportDir)->AddressOfNameOrdinals;

			usCounter = 1;

			// loop while we still have imports to find
			while (usCounter > 0)
			{
				// compute the hash values for this function name
				dwHashValue = hash(reinterpret_cast<char*>(uiBaseAddress + DEREF_32(uiNameArray)));

				// if we have found a function we want we get its virtual address
				if (dwHashValue == NTFLUSHINSTRUCTIONCACHE_HASH)
				{
					// get the VA for the array of addresses
					uiAddressArray = uiBaseAddress + reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(uiExportDir)->AddressOfFunctions;

					// use this functions name ordinal as an index into the array of name pointers
					uiAddressArray += DEREF_16(uiNameOrdinals) * sizeof(DWORD);

					// store this functions VA
					if (dwHashValue == NTFLUSHINSTRUCTIONCACHE_HASH)
						pNtFlushInstructionCache = reinterpret_cast<NTFLUSHINSTRUCTIONCACHE>(uiBaseAddress + DEREF_32(uiAddressArray));

					// decrement our counter
					usCounter--;
				}

				// get the next exported function name
				uiNameArray += sizeof(DWORD);

				// get the next exported function name ordinal
				uiNameOrdinals += sizeof(WORD);
			}
		}

		// we stop searching when we have found everything we need.
		if (pLoadLibraryA && pGetProcAddress && pVirtualAlloc && pNtFlushInstructionCache)
			break;

		// get the next entry
		uiValueA = DEREF(uiValueA);
	}

	// STEP 2: load our image into a new permanent location in memory...

	// get the VA of the NT Header for the PE to be loaded
	uiHeaderValue = uiLibraryAddress + reinterpret_cast<PIMAGE_DOS_HEADER>(uiLibraryAddress)->e_lfanew;

	// allocate all the memory for the DLL to be loaded into. we can load at any address because we will  
	// relocate the image. Also zeros all memory and marks it as READ, WRITE and EXECUTE to avoid any problems.
	uiBaseAddress = static_cast<ULONG_PTR>(pVirtualAlloc(NULL, reinterpret_cast<PIMAGE_NT_HEADERS>(uiHeaderValue)->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE));

	// we must now copy over the headers
	uiValueA = reinterpret_cast<PIMAGE_NT_HEADERS>(uiHeaderValue)->OptionalHeader.SizeOfHeaders;
	uiValueB = uiLibraryAddress;
	uiValueC = uiBaseAddress;

	while (uiValueA--)
		*reinterpret_cast<BYTE*>(uiValueC++) = *reinterpret_cast<BYTE*>(uiValueB++);

	// STEP 3: load in all of our sections...

	// uiValueA = the VA of the first section
	uiValueA = reinterpret_cast<ULONG_PTR>(&reinterpret_cast<PIMAGE_NT_HEADERS>(uiHeaderValue)->OptionalHeader + reinterpret_cast<PIMAGE_NT_HEADERS>(uiHeaderValue)->FileHeader.SizeOfOptionalHeader);

	// itterate through all sections, loading them into memory.
	uiValueE = reinterpret_cast<PIMAGE_NT_HEADERS>(uiHeaderValue)->FileHeader.NumberOfSections;
	while (uiValueE--)
	{
		// uiValueB is the VA for this section
		uiValueB = uiBaseAddress + reinterpret_cast<PIMAGE_SECTION_HEADER>(uiValueA)->VirtualAddress;

		// uiValueC if the VA for this sections data
		uiValueC = uiLibraryAddress + reinterpret_cast<PIMAGE_SECTION_HEADER>(uiValueA)->PointerToRawData;

		// copy the section over
		uiValueD = reinterpret_cast<PIMAGE_SECTION_HEADER>(uiValueA)->SizeOfRawData;

		while (uiValueD--)
			*reinterpret_cast<BYTE*>(uiValueB++) = *reinterpret_cast<BYTE*>(uiValueC++);

		// get the VA of the next section
		uiValueA += sizeof(IMAGE_SECTION_HEADER);
	}

	// STEP 4: process our images import table...

	// uiValueB = the address of the import directory
	uiValueB = reinterpret_cast<ULONG_PTR>(&reinterpret_cast<PIMAGE_NT_HEADERS>(uiHeaderValue)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]);

	// we assume their is an import table to process
	// uiValueC is the first entry in the import table
	uiValueC = uiBaseAddress + reinterpret_cast<PIMAGE_DATA_DIRECTORY>(uiValueB)->VirtualAddress;

	// itterate through all imports
	while (reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(uiValueC)->Name)
	{
		// use LoadLibraryA to load the imported module into memory
		uiLibraryAddress = static_cast<ULONG_PTR>(pLoadLibraryA(reinterpret_cast<LPCSTR>(uiBaseAddress + reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(uiValueC)->Name)));

		// uiValueD = VA of the OriginalFirstThunk
		uiValueD = uiBaseAddress + reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(uiValueC)->OriginalFirstThunk;

		// uiValueA = VA of the IAT (via first thunk not origionalfirstthunk)
		uiValueA = uiBaseAddress + reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(uiValueC)->FirstThunk;

		// itterate through all imported functions, importing by ordinal if no name present
		while (DEREF(uiValueA))
		{
			// sanity check uiValueD as some compilers only import by FirstThunk
			if (uiValueD && (reinterpret_cast<PIMAGE_THUNK_DATA>(uiValueD)->u1.Ordinal & IMAGE_ORDINAL_FLAG))
			{
				// get the VA of the modules NT Header
				uiExportDir = uiLibraryAddress + reinterpret_cast<PIMAGE_DOS_HEADER>(uiLibraryAddress)->e_lfanew;

				// uiNameArray = the address of the modules export directory entry
				uiNameArray = reinterpret_cast<ULONG_PTR>(&reinterpret_cast<PIMAGE_NT_HEADERS>(uiExportDir)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);

				// get the VA of the export directory
				uiExportDir = uiLibraryAddress + reinterpret_cast<PIMAGE_DATA_DIRECTORY>(uiNameArray)->VirtualAddress;

				// get the VA for the array of addresses
				uiAddressArray = uiLibraryAddress + reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(uiExportDir)->AddressOfFunctions;

				// use the import ordinal (- export ordinal base) as an index into the array of addresses
				uiAddressArray += (IMAGE_ORDINAL(reinterpret_cast<PIMAGE_THUNK_DATA>(uiValueD)->u1.Ordinal) - reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(uiExportDir)->Base) * sizeof(DWORD);

				// patch in the address for this imported function
				DEREF(uiValueA) = uiLibraryAddress + DEREF_32(uiAddressArray);
			}
			else
			{
				// get the VA of this functions import by name struct
				uiValueB = uiBaseAddress + DEREF(uiValueA);

				// use GetProcAddress and patch in the address for this imported function
				DEREF(uiValueA) = static_cast<ULONG_PTR>(pGetProcAddress(reinterpret_cast<HMODULE>(uiLibraryAddress), reinterpret_cast<LPCSTR>(reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(uiValueB)->Name)));
			}
			// get the next imported function
			uiValueA += sizeof(ULONG_PTR);
			if (uiValueD)
				uiValueD += sizeof(ULONG_PTR);
		}

		// get the next import
		uiValueC += sizeof(IMAGE_IMPORT_DESCRIPTOR);
	}

	// STEP 5: process all of our images relocations...

	// calculate the base address delta and perform relocations (even if we load at desired image base)
	uiLibraryAddress = uiBaseAddress - reinterpret_cast<PIMAGE_NT_HEADERS>(uiHeaderValue)->OptionalHeader.ImageBase;

	// uiValueB = the address of the relocation directory
	uiValueB = reinterpret_cast<ULONG_PTR>(&reinterpret_cast<PIMAGE_NT_HEADERS>(uiHeaderValue)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]);

	// check if their are any relocations present
	if (reinterpret_cast<PIMAGE_DATA_DIRECTORY>(uiValueB)->Size)
	{
		// uiValueC is now the first entry (IMAGE_BASE_RELOCATION)
		uiValueC = uiBaseAddress + reinterpret_cast<PIMAGE_DATA_DIRECTORY>(uiValueB)->VirtualAddress;

		// and we itterate through all entries...
		while (reinterpret_cast<PIMAGE_BASE_RELOCATION>(uiValueC)->SizeOfBlock)
		{
			// uiValueA = the VA for this relocation block
			uiValueA = uiBaseAddress + reinterpret_cast<PIMAGE_BASE_RELOCATION>(uiValueC)->VirtualAddress;

			// uiValueB = number of entries in this relocation block
			uiValueB = (reinterpret_cast<PIMAGE_BASE_RELOCATION>(uiValueC)->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_RELOC);

			// uiValueD is now the first entry in the current relocation block
			uiValueD = uiValueC + sizeof(IMAGE_BASE_RELOCATION);

			// we itterate through all the entries in the current block...
			while (uiValueB--)
			{
				// perform the relocation, skipping IMAGE_REL_BASED_ABSOLUTE as required.
				// we dont use a switch statement to avoid the compiler building a jump table
				// which would not be very position independent!
				if (reinterpret_cast<PIMAGE_RELOC>(uiValueD)->type == IMAGE_REL_BASED_DIR64)
					*reinterpret_cast<ULONG_PTR*>(uiValueA + reinterpret_cast<PIMAGE_RELOC>(uiValueD)->offset) += uiLibraryAddress;
				else if (reinterpret_cast<PIMAGE_RELOC>(uiValueD)->type == IMAGE_REL_BASED_HIGHLOW)
					*reinterpret_cast<DWORD*>(uiValueA + reinterpret_cast<PIMAGE_RELOC>(uiValueD)->offset) += static_cast<DWORD>(uiLibraryAddress);
#ifdef WIN_ARM
				// Note: On ARM, the compiler optimization /O2 seems to introduce an off by one issue, possibly a code gen bug. Using /O1 instead avoids this problem.
				else if (reinterpret_cast<PIMAGE_RELOC>(uiValueD)->type == IMAGE_REL_BASED_ARM_MOV32T)
				{
					register DWORD dwInstruction;
					register DWORD dwAddress;
					register WORD wImm;
					// get the MOV.T instructions DWORD value (We add 4 to the offset to go past the first MOV.W which handles the low word)
					dwInstruction = *reinterpret_cast<DWORD*>(uiValueA + reinterpret_cast<PIMAGE_RELOC>(uiValueD)->offset + sizeof(DWORD));
					// flip the words to get the instruction as expected
					dwInstruction = MAKELONG(HIWORD(dwInstruction), LOWORD(dwInstruction));
					// sanity chack we are processing a MOV instruction...
					if ((dwInstruction & ARM_MOV_MASK) == ARM_MOVT)
					{
						// pull out the encoded 16bit value (the high portion of the address-to-relocate)
						wImm = static_cast<WORD>(dwInstruction & 0x000000FF);
						wImm |= static_cast<WORD>((dwInstruction & 0x00007000) >> 4);
						wImm |= static_cast<WORD>((dwInstruction & 0x04000000) >> 15);
						wImm |= static_cast<WORD>((dwInstruction & 0x000F0000) >> 4);
						// apply the relocation to the target address
						dwAddress = ((WORD)HIWORD(uiLibraryAddress) + wImm) & 0xFFFF;
						// now create a new instruction with the same opcode and register param.
						dwInstruction = static_cast<DWORD>(dwInstruction & ARM_MOV_MASK2);
						// patch in the relocated address...
						dwInstruction |= static_cast<DWORD>(dwAddress & 0x00FF);
						dwInstruction |= static_cast<DWORD>(dwAddress & 0x0700) << 4;
						dwInstruction |= static_cast<DWORD>(dwAddress & 0x0800) << 15;
						dwInstruction |= static_cast<DWORD>(dwAddress & 0xF000) << 4;
						// now flip the instructions words and patch back into the code...
						*reinterpret_cast<DWORD*>(uiValueA + reinterpret_cast<PIMAGE_RELOC>(uiValueD)->offset + sizeof(DWORD)) = MAKELONG(HIWORD(dwInstruction), LOWORD(dwInstruction));
					}
				}
#endif
				else if (reinterpret_cast<PIMAGE_RELOC>(uiValueD)->type == IMAGE_REL_BASED_HIGH)
					*reinterpret_cast<WORD*>(uiValueA + reinterpret_cast<PIMAGE_RELOC>(uiValueD)->offset) += HIWORD(uiLibraryAddress);
				else if (reinterpret_cast<PIMAGE_RELOC>(uiValueD)->type == IMAGE_REL_BASED_LOW)
					*reinterpret_cast<WORD*>(uiValueA + reinterpret_cast<PIMAGE_RELOC>(uiValueD)->offset) += LOWORD(uiLibraryAddress);

				// get the next entry in the current relocation block
				uiValueD += sizeof(IMAGE_RELOC);
			}

			// get the next entry in the relocation directory
			uiValueC = uiValueC + reinterpret_cast<PIMAGE_BASE_RELOCATION>(uiValueC)->SizeOfBlock;
		}
	}

	// STEP 6: call our images entry point

	// uiValueA = the VA of our newly loaded DLL/EXE's entry point
	uiValueA = uiBaseAddress + reinterpret_cast<PIMAGE_NT_HEADERS>(uiHeaderValue)->OptionalHeader.AddressOfEntryPoint;

	// We must flush the instruction cache to avoid stale code being used which was updated by our relocation processing.
	pNtFlushInstructionCache(reinterpret_cast<HANDLE>(-1), NULL, 0);

	// call our respective entry point, fudging our hInstance value
	reinterpret_cast<DLLMAIN>(uiValueA)(reinterpret_cast<HINSTANCE>(uiBaseAddress), DLL_PROCESS_ATTACH, reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(-1)));

	// STEP 8: return our base address.
	return uiBaseAddress;
}
#endif