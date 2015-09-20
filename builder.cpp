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
#include <stdio.h>
#include <stdlib.h>
// Error codes
// -1, invalid args
// -2 Can't open files
// -3 Invalid file size
// -4 Can't alloc shit
// -5 Can't read
// -6 Diff sizes
// -7 Can't get ntdll functions
// -8 Can't get work space size
// -9 Can't compress
// -10 Invalid headers, not a pe file etc ..
// -11 can't write
typedef NTSTATUS(WINAPI * XRtlCompressBuffer)(USHORT CompressionFormatAndEngine, PUCHAR UncompressedBuffer, ULONG  UncompressedBufferSize, PUCHAR CompressedBuffer,
	ULONG  CompressedBufferSize, ULONG  UncompressedChunkSize, PULONG FinalCompressedSize, PVOID  WorkSpace);
typedef NTSTATUS(WINAPI * XRtlGetCompressionWorkSpaceSize)(USHORT CompressionFormatAndEngine, PULONG CompressBufferWorkSpaceSize, PULONG CompressFragmentWorkSpaceSize);

DWORD memToFile(LPVOID in, char* str, DWORD size)
{
	HANDLE handle = CreateFile(str, GENERIC_READ | GENERIC_WRITE, 0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
	DWORD nbWritten = 0;
	if (handle == INVALID_HANDLE_VALUE)
		exit(-2);
	if (!WriteFile(handle, in, size, &nbWritten, 0))
		exit(-11);
	if (nbWritten != size)
		exit(-6);
	CloseHandle(handle);
}
LPVOID CompressBuffer(LPVOID in,DWORD size, LPDWORD ptrSizeCompressed)
{
	LPVOID out,workSpace = NULL;
	DWORD spaceSize,sizeFragment,sizeCompressed ;
	spaceSize = 0;
	XRtlCompressBuffer xRtlCompressBuffer = (XRtlCompressBuffer)GetProcAddress(GetModuleHandle("ntdll.dll"), "RtlCompressBuffer");
	XRtlGetCompressionWorkSpaceSize xRtlGetCompressionWorkSpaceSize = (XRtlGetCompressionWorkSpaceSize)GetProcAddress(GetModuleHandle("ntdll.dll"), "RtlGetCompressionWorkSpaceSize");
	if (!xRtlCompressBuffer && !xRtlGetCompressionWorkSpaceSize)
		exit(-7);
	out = VirtualAlloc(0, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE); // We allocate at least the same size
	if (xRtlGetCompressionWorkSpaceSize(COMPRESSION_FORMAT_LZNT1 | COMPRESSION_ENGINE_MAXIMUM, &spaceSize, &sizeFragment))
		exit(-8);
	workSpace = VirtualAlloc(0, spaceSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if(!out || ! workSpace)
			exit(-4);
	if (xRtlCompressBuffer(COMPRESSION_FORMAT_LZNT1 | COMPRESSION_ENGINE_MAXIMUM, (PUCHAR)in, size, (PUCHAR)out, size, 4096, &sizeCompressed, workSpace))
		exit(-9);
	*ptrSizeCompressed = sizeCompressed;
	//*ptrSizeFragment = sizeFragment;
	return out;
}
LPVOID fileToMem(char* str,LPDWORD size,DWORD overlay)
{
	HANDLE handle = CreateFile(str, GENERIC_READ, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	DWORD nbRead = 0;
	if (handle == INVALID_HANDLE_VALUE)
		exit(-2);
	*size = GetFileSize(handle, 0);
	if(*size == INVALID_FILE_SIZE)
		exit(-3);
	LPVOID ptr = VirtualAlloc(0, (*size)+overlay, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!ptr)
		exit(-4);
	if (!ReadFile(handle, ptr, *size, &nbRead, 0))
		exit(-5);
	if (*size != nbRead)
		exit(-6);
	CloseHandle(handle);
	return ptr;
}
int main(int argc, char* argv[])
{
	char* strStub, *strTarget = 0;
	char strOutput[] = "output.exe";
	if (argc > 2)
	{
		DWORD sizeStub, sizeTarget,sizeTargetCompressed = 0;
		LPVOID ptrStub, ptrTarget,ptrTargetTemp, ptrOutput,ptrTargetAligned = NULL;
		//////////////
		PIMAGE_DOS_HEADER dosHeader,dosHeaderTarget = NULL;
		PIMAGE_NT_HEADERS ntHeader,ntHeaderTarget = NULL;
		PIMAGE_SECTION_HEADER sectionHeader = NULL;
		PIMAGE_FILE_HEADER fileHeader = NULL;
		DWORD nbSections = 0;
		DWORD sizeHeaders = 0;
		DWORD sizeHeadersWritten = 0;
		DWORD virtualAddress = 0;
		DWORD rawSize = 0;
		DWORD sizeOfImage = 0;
		DWORD ptrRawData = 0;
		//////////////
		sizeTarget = 0;
		strStub = argv[1];
		strTarget = argv[2];

		ptrTargetTemp = fileToMem(strTarget,&sizeTarget,0);
		ptrTarget = CompressBuffer(ptrTargetTemp, sizeTarget,&sizeTargetCompressed);
		ptrStub = fileToMem(strStub, &sizeStub, sizeTargetCompressed);
		printf("[....] Stub loaded.\n");
		
		printf("[....] Target loaded.\n");
		printf("Size before compression : %d\n", sizeTarget);
		printf("Size after compression : %d\n", sizeTargetCompressed);
		dosHeader = (PIMAGE_DOS_HEADER)ptrStub;
		dosHeaderTarget = (PIMAGE_DOS_HEADER)ptrTargetTemp;
		if (dosHeader->e_magic != 0x5A4D)
			exit(-10);
		ntHeader = (PIMAGE_NT_HEADERS)((PUCHAR)dosHeader + dosHeader->e_lfanew);
		ntHeaderTarget = (PIMAGE_NT_HEADERS)((PUCHAR)dosHeaderTarget + dosHeaderTarget->e_lfanew);
		if(ntHeader->Signature != 0x00004550)
			exit(-10);
		sectionHeader = (PIMAGE_SECTION_HEADER)IMAGE_FIRST_SECTION(ntHeader);
		fileHeader = (PIMAGE_FILE_HEADER)&ntHeader->FileHeader;
		nbSections = fileHeader->NumberOfSections;
		printf("[...] Stub ... : \n");
		/*
		printf("Number of sections : %d\n", nbSections);
		for (DWORD i = 0;i < nbSections;i++)
		{
			printf("... Name %s : \n", sectionHeader[i].Name);
			printf("... SizeRawData 0x%x : \n", sectionHeader[i].SizeOfRawData);
			printf("... PointerToRawData 0x%x : \n", sectionHeader[i].PointerToRawData);
			printf("... VirtualAddress 0x%x : \n", sectionHeader[i].VirtualAddress);
			printf("\n\n");
		}*/
		// We need to check if there is enough space to add a sectionheader in sectionheader tab
		sizeHeaders = ntHeader->OptionalHeader.SizeOfHeaders;
		sizeHeadersWritten = fileHeader->SizeOfOptionalHeader; // Size of Optional
		sizeHeadersWritten += sizeof(IMAGE_FILE_HEADER);
		sizeHeadersWritten += sizeof(IMAGE_SECTION_HEADER)*nbSections; // Size of all header for each sections
		sizeHeadersWritten += dosHeader->e_lfanew; 
		/*Ok so IMAGE_DOS_HEADER add some padding
		We need to use this instead of sizeof
		dosHeader->e_lfanew	0x000000c8	long
		sizeof(IMAGE_DOS_HEADER)	0x00000040	unsigned int
		*/
		sizeHeaders -= sizeHeadersWritten;
		//printf("Space left in headers : %x\n", sizeHeaders);
		IMAGE_SECTION_HEADER newSection,test;
		
		newSection.Characteristics = IMAGE_SCN_MEM_READ ;// This on will be change later
		CopyMemory(&newSection.Name, (void *)".pack3", strlen(".pack3") + 1);
		// Not used ?
		newSection.NumberOfLinenumbers = 0;
		newSection.NumberOfRelocations = 0;
		newSection.PointerToLinenumbers = 0;
		newSection.PointerToRelocations = 0;  
		////////

		
		virtualAddress = sectionHeader[nbSections - 1].SizeOfRawData
			/ ntHeader->OptionalHeader.SectionAlignment;
		virtualAddress = (virtualAddress + 1)*ntHeader->OptionalHeader.SectionAlignment;
		virtualAddress += sectionHeader[nbSections - 1].VirtualAddress;
		newSection.VirtualAddress = virtualAddress;
		//We need to calc the RVA for this new section
		//So we get the last RVA and add the size rounded with the section alignement
		newSection.Misc.VirtualSize = sizeTargetCompressed;
		// Same for rawSize
		rawSize = sizeTargetCompressed
			/ ntHeader->OptionalHeader.FileAlignment;
		if (sizeTargetCompressed % ntHeader->OptionalHeader.FileAlignment);
			rawSize++;
		rawSize = (rawSize) * ntHeader->OptionalHeader.FileAlignment;
		newSection.SizeOfRawData = rawSize;
		// Pointer to rawdata calc
		ptrRawData = sectionHeader[nbSections - 1].PointerToRawData+ sectionHeader[nbSections - 1].SizeOfRawData;
		newSection.PointerToRawData = ptrRawData;


		
		sizeOfImage = ntHeader->OptionalHeader.SizeOfImage + rawSize;

		//fileHeader->NumberOfSections = nbSections + 1;

		ntHeader->OptionalHeader.SizeOfImage = sizeOfImage ;
		CopyMemory(&sectionHeader[nbSections], &newSection, sizeof(IMAGE_SECTION_HEADER));
		////// Adjust allocated memory to stabilize execution
		CopyMemory(&newSection.Name, (void *)".pack4", strlen(".pack4") + 1);

		DWORD delta = ntHeaderTarget->OptionalHeader.SizeOfImage - ntHeader->OptionalHeader.SizeOfImage;
		DWORD rvaAligned = rawSize;
		rvaAligned /= ntHeader->OptionalHeader.SectionAlignment;
		if (rawSize%ntHeader->OptionalHeader.SectionAlignment)
			rvaAligned++;
		rvaAligned =(rvaAligned)*ntHeader->OptionalHeader.SectionAlignment;
		delta /= ntHeader->OptionalHeader.SectionAlignment;
		delta = (delta+1)*ntHeader->OptionalHeader.SectionAlignment;
		newSection.VirtualAddress += rvaAligned;
		newSection.Misc.VirtualSize = delta;
		newSection.SizeOfRawData = 0;
		ntHeader->OptionalHeader.SizeOfImage += delta;
		CopyMemory(&sectionHeader[nbSections+1], &newSection, sizeof(IMAGE_SECTION_HEADER));
		fileHeader->NumberOfSections = nbSections + 2;
		


		/////
		ptrTargetAligned = VirtualAlloc(0, rawSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		CopyMemory(ptrTargetAligned,ptrTarget,sizeTargetCompressed);
		ptrRawData += (DWORD)ptrStub;
		CopyMemory((PVOID)ptrRawData, ptrTargetAligned, rawSize);
		memToFile(ptrStub, strOutput, sizeStub + rawSize);
		printf("[...] Build done !");
		//printf("IMAGE_SECTION_HEADER size: %d\n", sizeof(IMAGE_SECTION_HEADER));
		//printf("Fragment Size : %d\n", sizeFragment);
			
		getc(stdin);
		VirtualFree(ptrTargetTemp, sizeTarget,MEM_DECOMMIT);
	}
	else
		return -1;
	return 0;
}
