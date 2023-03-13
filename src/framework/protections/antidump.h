
#pragma once

#include "xorstr.hpp"

#include <Windows.h>  // for antidump only
#include <winternl.h> // for antidump only
#include <intrin.h> // for __readfsdword
class AntiDump
{
public:
	void ModifySizeOfImage() 
	{ 
		#if defined(_WIN64)
			PPEB pPeb = (PPEB)__readgsqword(0x60);
		#else
			PPEB pPeb = (PPEB)__readfsdword(0x30);
		#endif

		// The following pointer hackery is because winternl.h defines incomplete PEB types
		PLIST_ENTRY InLoadOrderModuleList = (PLIST_ENTRY)pPeb->Ldr->Reserved2[1]; // pPeb->Ldr->InLoadOrderModuleList
		PLDR_DATA_TABLE_ENTRY tableEntry = CONTAINING_RECORD(InLoadOrderModuleList, LDR_DATA_TABLE_ENTRY, Reserved1[0] /*InLoadOrderLinks*/);
		PULONG pEntrySizeOfImage = (PULONG)&tableEntry->Reserved3[1]; // &tableEntry->SizeOfImage
		*pEntrySizeOfImage = (ULONG)((INT_PTR)tableEntry->DllBase + 0x100000);
	}
	void ModifyPEHeader() 
	{ 
		DWORD OldProtect = 0;

		// Get base address of module
		char* pBaseAddr = (char*)GetModuleHandle(NULL);

		// Change memory protection
		VirtualProtect(pBaseAddr, 4096, // Assume x86 page size
			PAGE_READWRITE, &OldProtect);

		// Erase the header
		SecureZeroMemory(pBaseAddr, 4096);
	}
private:
};

extern AntiDump g_antidump;
