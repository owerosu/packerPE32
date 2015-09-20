/*
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>
https://www.livecoding.tv/owerosu/
*/


#include <Windows.h>

/*
void shellcode(DWORD imageBaseStub,DWORD ptrImageBase,
	DWORD ptrImageBaseBuffer,DWORD sizeImageBase,
	DWORD ptrVirtualAlloc,DWORD ptrUnmapViewOfFile,DWORD OEP)
	{

	typedef BOOL(WINAPI *XVirtualAlloc)(
		LPVOID lpAddress,
		SIZE_T dwSize,
		DWORD  flAllocationType,
		DWORD  flProtect
		);
	typedef BOOL(WINAPI *XUnmapViewOfFile)(
		LPCVOID lpBaseAddress
		);
	PIMAGE_DOS_HEADER dosHeaderStub = NULL;
	PIMAGE_NT_HEADERS ntHeaderStub = NULL;
	PIMAGE_SECTION_HEADER sectionHeaderStub = NULL;
	PIMAGE_FILE_HEADER fileHeaderStub = NULL;
	DWORD nbSectionsStub;
	XVirtualAlloc xVirtualAlloc = (XVirtualAlloc)ptrVirtualAlloc;
	XUnmapViewOfFile xUnmapViewOfFile = (XUnmapViewOfFile)ptrUnmapViewOfFile;


	dosHeaderStub = (PIMAGE_DOS_HEADER)imageBaseStub;
	ntHeaderStub = (PIMAGE_NT_HEADERS)((PUCHAR)dosHeaderStub + dosHeaderStub->e_lfanew);
	sectionHeaderStub = (PIMAGE_SECTION_HEADER)IMAGE_FIRST_SECTION(ntHeaderStub);
	fileHeaderStub = (PIMAGE_FILE_HEADER)&ntHeaderStub->FileHeader;
	nbSectionsStub = fileHeaderStub->NumberOfSections;
	xUnmapViewOfFile((PBYTE)imageBaseStub);
	xVirtualAlloc((PBYTE)ptrImageBase, sizeImageBase, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	for (DWORD i = 0;i < sizeImageBase;i++)
		*(PBYTE)(ptrImageBase + i) = *(PBYTE)(ptrImageBaseBuffer + i);
	__asm {

		jmp OEP;
	}
}
*/
void CopyMemory2(PBYTE out, PBYTE in, DWORD size)// Original Name
{
	for (DWORD i = 0;i < size;i++)
		*(out + i) = *(in + i);
}
int main()
{
	unsigned char data[228] = {
		0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x20, 0xC7, 0x45, 0xF4, 0x00, 0x00, 0x00, 0x00, 0xC7, 0x45, 0xF8,
		0x00, 0x00, 0x00, 0x00, 0xC7, 0x45, 0xEC, 0x00, 0x00, 0x00, 0x00, 0xC7, 0x45, 0xF0, 0x00, 0x00,
		0x00, 0x00, 0x8B, 0x45, 0x18, 0x89, 0x45, 0xE4, 0x8B, 0x4D, 0x1C, 0x89, 0x4D, 0xE8, 0x8B, 0x55,
		0x08, 0x89, 0x55, 0xF4, 0x8B, 0x45, 0xF4, 0x8B, 0x4D, 0xF4, 0x03, 0x48, 0x3C, 0x89, 0x4D, 0xF8,
		0x8B, 0x55, 0xF8, 0x0F, 0xB7, 0x42, 0x14, 0x8B, 0x4D, 0xF8, 0x8D, 0x54, 0x01, 0x18, 0x89, 0x55,
		0xEC, 0x8B, 0x45, 0xF8, 0x83, 0xC0, 0x04, 0x89, 0x45, 0xF0, 0x8B, 0x4D, 0xF0, 0x0F, 0xB7, 0x51,
		0x02, 0x89, 0x55, 0xE0, 0x8B, 0x45, 0x08, 0x50, 0xFF, 0x55, 0xE8, 0x6A, 0x40, 0x68, 0x00, 0x30,
		0x00, 0x00, 0x8B, 0x4D, 0x14, 0x51, 0x8B, 0x55, 0x0C, 0x52, 0xFF, 0x55, 0xE4, 0xC7, 0x45, 0xFC,
		0x00, 0x00, 0x00, 0x00, 0xEB, 0x09, 0x8B, 0x45, 0xFC, 0x83, 0xC0, 0x01, 0x89, 0x45, 0xFC, 0x8B,
		0x4D, 0xFC, 0x3B, 0x4D, 0x14, 0x73, 0x12, 0x8B, 0x55, 0x0C, 0x03, 0x55, 0xFC, 0x8B, 0x45, 0x10,
		0x03, 0x45, 0xFC, 0x8A, 0x08, 0x88, 0x0A, 0xEB, 0xDD, 0xFF, 0x65, 0x20, 0x8B, 0xE5, 0x5D, 0xC3,
		0x55, 0x8B, 0xEC, 0x51, 0xC7, 0x45, 0xFC, 0x00, 0x00, 0x00, 0x00, 0xEB, 0x09, 0x8B, 0x45, 0xFC,
		0x83, 0xC0, 0x01, 0x89, 0x45, 0xFC, 0x8B, 0x4D, 0xFC, 0x3B, 0x4D, 0x10, 0x73, 0x12, 0x8B, 0x55,
		0x08, 0x03, 0x55, 0xFC, 0x8B, 0x45, 0x0C, 0x03, 0x45, 0xFC, 0x8A, 0x08, 0x88, 0x0A, 0xEB, 0xDD,
		0x8B, 0xE5, 0x5D, 0xC3
	};
	// This time less check we need to win spaces as this is the stub
	//////////////////
	typedef NTSTATUS (WINAPI *XRtlDecompressBuffer)(
		USHORT CompressionFormat,
		PUCHAR UncompressedBuffer,
		ULONG  UncompressedBufferSize,
		PUCHAR CompressedBuffer,
		ULONG  CompressedBufferSize,
		PULONG FinalUncompressedSize
		);
	//////
	///////////////////
	HMODULE imageBaseStub;
	DWORD imageBase;
	PIMAGE_DOS_HEADER dosHeaderStub = NULL;
	PIMAGE_NT_HEADERS ntHeaderStub = NULL;
	PIMAGE_SECTION_HEADER sectionHeaderStub = NULL;
	PIMAGE_FILE_HEADER fileHeaderStub = NULL;
	PIMAGE_DOS_HEADER dosHeader = NULL;
	PIMAGE_NT_HEADERS ntHeader = NULL;
	PIMAGE_SECTION_HEADER sectionHeader = NULL;
	PIMAGE_FILE_HEADER fileHeader = NULL;
	DWORD nbSectionsStub,nbSections;
	DWORD sizeHeaders;
	DWORD sizeImage;
	DWORD decompressedSize = 0;
	DWORD ptrCompressedData = 0;
	DWORD oldAccess;
	DWORD sectionAlignement;
	DWORD OEP;
	LPVOID ptrDecompressedData = NULL;
	DWORD ptrImageBase=0;
	XRtlDecompressBuffer xRtlDecompressBuffer = (XRtlDecompressBuffer)GetProcAddress(
		GetModuleHandle("ntdll.dll"), "RtlDecompressBuffer");
	///////////////////
	imageBaseStub = GetModuleHandle(0);
	dosHeaderStub = (PIMAGE_DOS_HEADER)imageBaseStub;
	ntHeaderStub = (PIMAGE_NT_HEADERS)((PUCHAR)dosHeaderStub + dosHeaderStub->e_lfanew);
	sectionHeaderStub = (PIMAGE_SECTION_HEADER)IMAGE_FIRST_SECTION(ntHeaderStub);
	fileHeaderStub = (PIMAGE_FILE_HEADER)&ntHeaderStub->FileHeader;
	nbSectionsStub = fileHeaderStub->NumberOfSections;
	nbSectionsStub = fileHeaderStub->NumberOfSections;
	// We look for the section containing compressed data
	DWORD oldState;
	//VirtualProtect(imageBaseStub, 0x1000, PAGE_EXECUTE_READWRITE, &oldState);
	
	for (DWORD i = 0;i < nbSectionsStub;i++)
	{
		/*
		DWORD sectionAlignementStub = ntHeaderStub->OptionalHeader.SectionAlignment;
		DWORD sectionSizeVirtual = sectionHeaderStub[i].SizeOfRawData / sectionAlignementStub;
		DWORD sectionVirtualAddress = sectionHeaderStub[i].VirtualAddress;
		sectionVirtualAddress += (DWORD)imageBaseStub;
		sectionSizeVirtual = (sectionSizeVirtual + 1)*sectionAlignementStub;
		VirtualProtect((PBYTE)sectionVirtualAddress, sectionSizeVirtual, PAGE_EXECUTE_READWRITE, &oldState);
		*/
		if (!strcmp((const char*)sectionHeaderStub[i].Name, ".pack3"))
		{
			//ptrCompressedData = (LPVOID)(sectionHeaderStub[i].VirtualAddress) ;
			// Decompression
			ptrCompressedData = (DWORD)imageBaseStub;
			ptrCompressedData = ptrCompressedData + sectionHeaderStub[i].VirtualAddress;

			DWORD add = (DWORD)imageBaseStub;
			do
			{
				ptrDecompressedData = VirtualAlloc((PBYTE)((DWORD)imageBaseStub + add), sectionHeaderStub[i].SizeOfRawData * 4,
					MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
				add += 0x1000;
			} while (!ptrDecompressedData);


			xRtlDecompressBuffer(COMPRESSION_FORMAT_LZNT1 | COMPRESSION_ENGINE_MAXIMUM,
				(PUCHAR)ptrDecompressedData, sectionHeaderStub[i].SizeOfRawData * 4,
				(PUCHAR)ptrCompressedData, sectionHeaderStub[i].SizeOfRawData,
				&decompressedSize);
			////////
		}
	}
			/////// Usefull stuff we need to get
			dosHeader = (PIMAGE_DOS_HEADER)ptrDecompressedData;
			ntHeader = (PIMAGE_NT_HEADERS)((PUCHAR)dosHeader + dosHeader->e_lfanew);
			sectionHeader = (PIMAGE_SECTION_HEADER)IMAGE_FIRST_SECTION(ntHeader);
			fileHeader = (PIMAGE_FILE_HEADER)&ntHeader->FileHeader;
			nbSections = fileHeader->NumberOfSections;
			sizeHeaders = ntHeader->OptionalHeader.SizeOfHeaders;
			imageBase = ntHeader->OptionalHeader.ImageBase;
			sizeImage = ntHeader->OptionalHeader.SizeOfImage;
			sectionAlignement = ntHeader->OptionalHeader.SectionAlignment;
			OEP = imageBase + ntHeader->OptionalHeader.AddressOfEntryPoint;
			//////////

			//////// Allocate memory space and map the PE

			// Hmm, we could get proper rights for each section
			// So let's do a buffer per sections instead
			// So the allocation for headers :
			//0x400000
			//0x2D000
			//VirtualFree((PBYTE)imageBase - 0x10000, sizeImage + 0x10000, MEM_DECOMMIT | MEM_RELEASE);
			DWORD add = (DWORD)imageBaseStub;
			do
			{ 
			ptrImageBase = (DWORD)VirtualAlloc((PBYTE)((DWORD)imageBaseStub + sizeImage +  add), sizeImage,
				MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
			add += 0x1000;
			} while (!ptrImageBase);
			//CopyMemory(ptrImageBase, ptrDecompressedData, sizeHeaders);
			// Ok we can't use CopyMemory without linking the runtime C which will bloat our stub ..
			// Let's do our own Copy memory !
			CopyMemory2((PBYTE)ptrImageBase, (PBYTE)ptrDecompressedData, sizeHeaders);
			//VirtualProtect(ptrImageBase, sizeHeaders, PAGE_READONLY, &oldAccess);

			// Sections !
			for (DWORD i;i < nbSections;i++)
			{
				DWORD ptrSection = ptrImageBase + sectionHeader[i].VirtualAddress;
	
				DWORD ptrRawData = (DWORD)ptrDecompressedData + sectionHeader[i].PointerToRawData;
				DWORD sizeRawData = sectionHeader[i].SizeOfRawData;
				/*/
				I have some trouble to allocate contiguous memory for some reasons
				So, I allocate one big memory space for all the unpacked PE
				I'll try to figure out later why I can't.
				if (ptrSection != (DWORD)VirtualAlloc((LPVOID)ptrSection, 
					sectionSizeVirtual, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)) // For now we'll put
					// executables rights, then we'll read characteristics to put the right ones
						ExitProcess(-2);
						*/
				CopyMemory2((PBYTE)ptrSection, (PBYTE)ptrRawData, sizeRawData);
			}
			// Ok now we need to rebuild IAT
			////////////////// Use the new mapped headers instead of old ones ...
			dosHeader = (PIMAGE_DOS_HEADER)ptrImageBase;
			ntHeader = (PIMAGE_NT_HEADERS)((PUCHAR)dosHeader + dosHeader->e_lfanew);
			sectionHeader = (PIMAGE_SECTION_HEADER)IMAGE_FIRST_SECTION(ntHeader);
			fileHeader = (PIMAGE_FILE_HEADER)&ntHeader->FileHeader;
				//////////////////
			//(PIMAGE_IMPORT_DESCRIPTOR)imageBase + 
			IMAGE_OPTIONAL_HEADER* optionalHeader = (&(ntHeader->OptionalHeader));
			DWORD va = optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
			DWORD ptrImport = ptrImageBase + va;
			if (!va)
				ExitProcess(-5);
			if (!ptrImport)
				ExitProcess(-5);
			
			while (((IMAGE_IMPORT_DESCRIPTOR*)ptrImport)->FirstThunk)
			{
				
				DWORD ptrThunkData;
				char* dllName = (char*)ptrImageBase + ((IMAGE_IMPORT_DESCRIPTOR*)ptrImport)->Name;
				

					ptrThunkData= ptrImageBase + ((IMAGE_IMPORT_DESCRIPTOR*)ptrImport)->FirstThunk;
				
				while (((IMAGE_THUNK_DATA*)ptrThunkData)->u1.AddressOfData)
				{
					// First we'll only resolve by name. Import by ordinal will come later

					if (((IMAGE_THUNK_DATA*)ptrThunkData)->u1.Ordinal & IMAGE_ORDINAL_FLAG32)
					{
						DWORD ordinal = ((IMAGE_THUNK_DATA*)ptrThunkData)->u1.Ordinal & 0xFFFF;
						((IMAGE_THUNK_DATA*)ptrThunkData)->u1.Function = (DWORD)GetProcAddress(LoadLibraryA(dllName), (char*)ordinal);
					}
					else
					{
						DWORD ptrImageByName;
						char* functionName;
						ptrImageByName = ptrImageBase + ((IMAGE_THUNK_DATA*)ptrThunkData)->u1.AddressOfData;
						functionName = ((IMAGE_IMPORT_BY_NAME*)ptrImageByName)->Name;
						((IMAGE_THUNK_DATA*)ptrThunkData)->u1.Function = (DWORD)GetProcAddress(LoadLibraryA(dllName), functionName);
					}
					
					ptrThunkData += sizeof(IMAGE_THUNK_DATA); // next Thunk_Data
				}
				
				ptrImport += sizeof(IMAGE_IMPORT_DESCRIPTOR); // next IMAGE_IMPORT_DESCRIPTOR
			}
			// Support .reloc section
			
			//
			// Try 
			/*
			void shellcode(DWORD imageBaseStub,DWORD ptrImageBase,
				DWORD ptrImageBaseBuffer,DWORD sizeImageBase,DWORD ptrVirtualFree,
				DWORD ptrVirtualAlloc,DWORD OEP)
			*/
			DWORD ptrVirtualAlloc = (DWORD)GetProcAddress(GetModuleHandleA("kernel32.dll"), "VirtualAlloc");

			DWORD ptrUnmap = (DWORD)GetProcAddress(GetModuleHandleA("kernel32.dll"), "UnmapViewOfFile");
			//shellcode(0, 0, 0, 0, 0, 0, 0, 0);
			BOOL bReloc = FALSE;
			for (DWORD i = 0;i < nbSections;i++)
			{
				if (!strcmp((const char*)sectionHeader[i].Name, ".reloc"))
					bReloc = TRUE;
			}
			/*
			If we can allocate at prefered imagebase then we just jump on eop
			elseif
			If we can do reloc, we'll allocate anywhere and just reloc.
			elseif
			If we can't, we'll do the shellcode trick to run packed executable at
			stub's memory space.
			Stub we'll be reallocated at the packed .exe's prefered image base by the builder (todo)
			*/
			DWORD ptrNewImageBase = 0;
			do // Allocate buffer at any location
			{
				ptrNewImageBase = (DWORD)VirtualAlloc((PBYTE)imageBase + add, sizeImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
				add += 0x1000;
			} while (!ptrNewImageBase);
			if (ptrNewImageBase == imageBase) // If we get lucky and same imagebase than prefered image base.
			{
				VirtualFree(ptrDecompressedData, sectionHeaderStub[3].SizeOfRawData * 4, MEM_DECOMMIT | MEM_RELEASE);
				CopyMemory2((PBYTE)ptrNewImageBase, (PBYTE)ptrImageBase, sizeImage);
				VirtualFree((PBYTE)ptrImageBase, sizeImage, MEM_DECOMMIT | MEM_RELEASE);
				__asm {
					jmp OEP;
				}
			}
			else if (bReloc) // If we a .reloc section
			{
				
				CopyMemory2((PBYTE)ptrNewImageBase, (PBYTE)ptrImageBase, sizeImage);
				OEP = ptrNewImageBase + ntHeader->OptionalHeader.AddressOfEntryPoint;
				DWORD add = 0;
				DWORD delta = 0;
				DWORD dirSize = 0;
				PIMAGE_DATA_DIRECTORY pRelocEntry;
				PIMAGE_BASE_RELOCATION pBaseReloc,pEndReloc;
				pRelocEntry = &ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
				pBaseReloc = (PIMAGE_BASE_RELOCATION)(PBYTE)(ptrImageBase + pRelocEntry->VirtualAddress);
				dirSize = pRelocEntry->Size;
				delta = ptrNewImageBase - imageBase;
				pEndReloc = (PIMAGE_BASE_RELOCATION)(PBYTE)(pBaseReloc + dirSize);

				while (pBaseReloc < pEndReloc && pBaseReloc->VirtualAddress)
				{
					int count = (pBaseReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
					PWORD entry = (PWORD)(pBaseReloc + 1);
					void *pageVa = (void*)((PBYTE)ptrNewImageBase + pBaseReloc->VirtualAddress);
					while (count--)
					{
						if (*entry >> 12 == IMAGE_REL_BASED_HIGHLOW)
							*(PDWORD)((PBYTE)pageVa + (*entry & 0x0fff)) += delta;
						entry++;
					}
					pBaseReloc = (PIMAGE_BASE_RELOCATION)((PBYTE)pBaseReloc + pBaseReloc->SizeOfBlock);
				}
				VirtualFree(ptrDecompressedData, sectionHeaderStub[3].SizeOfRawData * 4, MEM_DECOMMIT | MEM_RELEASE);
				VirtualFree((PBYTE)ptrImageBase, sizeImage, MEM_DECOMMIT | MEM_RELEASE);
				__asm {
					jmp OEP;
				}
			}
			else // Shellcode trick
			{
				DWORD buffCopy = (DWORD)VirtualAlloc((LPVOID)0, 182, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
				CopyMemory2((PBYTE)buffCopy, data, 182);
				VirtualFree(ptrDecompressedData, sectionHeaderStub[3].SizeOfRawData * 4, MEM_DECOMMIT | MEM_RELEASE);
				__asm {
					push OEP
						push ptrUnmap
						push ptrVirtualAlloc
						push sizeImage
						push ptrImageBase
						push imageBase
						push imageBaseStub
						call buffCopy
				};
			}
			/////////////////
			// We jump on Original Entry Point (OEP)
	
	return 0;
}
