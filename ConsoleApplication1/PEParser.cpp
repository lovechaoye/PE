
#include"PEParser.h"
/**
	解析PE文件
**/
void   parsePE(char* path) {
	FILE* file = fopen(path, "rb");

	PIMAGE_DOS_HEADER pdos = (PIMAGE_DOS_HEADER)malloc(sizeof(IMAGE_DOS_HEADER));
	PIMAGE_FILE_HEADER pfile = (PIMAGE_FILE_HEADER)malloc(sizeof(IMAGE_FILE_HEADER));
	PIMAGE_OPTIONAL_HEADER32 poptional = (PIMAGE_OPTIONAL_HEADER32)malloc(sizeof(IMAGE_OPTIONAL_HEADER32));

	int sizeOfFILE_HEADER = 20;
	if (file == NULL) {
		printf("Can't open %s\n", path);
		exit(EXIT_FAILURE);
	}
	char buff[256];
	/*
		解析_IMAGE_DOS_HEADER
	*/
	printf("************************_IMAGE_DOS_HEADER************************\n");
	fseek(file, 0, SEEK_SET);
	fgets(buff, sizeof(IMAGE_DOS_HEADER), file);
	memcpy(pdos, buff, sizeof(IMAGE_DOS_HEADER));
	LONG e_lfanew = pdos->e_lfanew;
	//printf("%#x",pdos->e_lfanew);
	printDOS(pdos);
	/*
		解析_IMAGE_FILE_HEADER
	*/
	printf("************************_IMAGE_FILE_HEADER************************\n");
	fseek(file, e_lfanew + 4, SEEK_SET);
	fgets(buff, sizeof(IMAGE_FILE_HEADER), file);
	memcpy(pfile, buff, sizeof(IMAGE_FILE_HEADER));
	WORD NumberOfSections = pfile->NumberOfSections;
	WORD SizeOfOptionalHeader = pfile->SizeOfOptionalHeader;
	printFileHeader(pfile);


	/*
	解析_IMAGE_OPTIONAL_HEADER32
	*/
	printf("************************_IMAGE_OPTIONAL_HEADER32************************\n");
	fseek(file, e_lfanew + 4 + 20, SEEK_SET);
	fgets(buff, sizeof(IMAGE_OPTIONAL_HEADER32), file);
	memcpy(poptional, buff, sizeof(IMAGE_OPTIONAL_HEADER32));
	printOPTIONAL_HEADER32(poptional);
	/*
		解析_IMAGE_SECTION_HEADER节区头，是个数组
	*/
	PIMAGE_SECTION_HEADER sections = (PIMAGE_SECTION_HEADER)malloc(NumberOfSections * sizeof(IMAGE_SECTION_HEADER));
	PIMAGE_SECTION_HEADER cpy_sections = sections;
	fseek(file, e_lfanew + 4 + sizeOfFILE_HEADER + SizeOfOptionalHeader, SEEK_SET);
	fgets(buff, NumberOfSections * sizeof(IMAGE_SECTION_HEADER), file);
	memcpy(sections, buff, NumberOfSections * sizeof(IMAGE_SECTION_HEADER));
	for (int i = 0; i < NumberOfSections; i++)
	{
		printf("************************_IMAGE_SECTION_HEADER************************\n");
		printSection(sections);
		sections += 1;//type ** 类型的加法 ，规则是：newAdress=address+sizeof(type** -*号)*后的值

	}
	fclose(file);
	free(pdos);
	free(pfile);
	free(poptional);
	free(cpy_sections);
}





void printDOS(PIMAGE_DOS_HEADER p) {
	printf("struct _IMAGE_DOS_HEADER {\n");
	printf("    WORD   e_magic=%x\n", p->e_magic);
	printf("    LONG   e_lfanew=%#x\n", p->e_lfanew);
	printf("}\n");
}
void printFileHeader(PIMAGE_FILE_HEADER p) {
	printf("struct _IMAGE_FILE_HEADER {\n");
	printf("    WORD    Machine=%#x\n", p->Machine);
	printf("    WORD    NumberOfSections=%#x\n", p->NumberOfSections);
	printf("    DWORD   TimeDateStamp=%#x\n", p->TimeDateStamp);
	printf("    DWORD   PointerToSymbolTable=%#x\n", p->PointerToSymbolTable);
	printf("    DWORD   NumberOfSymbols=%#x\n", p->NumberOfSymbols);
	printf("    WORD    SizeOfOptionalHeader=%#x\n", p->SizeOfOptionalHeader);
	printf("    WORD    Characteristics=%#x\n", p->Characteristics);
	printf("}\n");
}
void printOPTIONAL_HEADER32(PIMAGE_OPTIONAL_HEADER32 p) {
	printf("struct _IMAGE_OPTIONAL_HEADER {\n");
	printf("    WORD    Magic=%#x\n", p->Magic);
	printf("    BYTE    MajorLinkerVersion=%#x\n", p->MajorLinkerVersion);
	printf("    BYTE    MinorLinkerVersion=%#x\n", p->MinorLinkerVersion);
	printf("    DWORD   SizeOfCode=%#x\n", p->SizeOfCode);
	printf("    DWORD   SizeOfInitializedData=%#x\n", p->SizeOfInitializedData);
	printf("    DWORD   SizeOfUninitializedData=%#x\n", p->SizeOfUninitializedData);
	printf("    DWORD   AddressOfEntryPoint=%#x\n", p->AddressOfEntryPoint);
	printf("    DWORD   BaseOfCode=%#x\n", p->BaseOfCode);
	printf("    DWORD   BaseOfData=%#x\n", p->BaseOfData);
	printf("    DWORD   ImageBase=%#x\n", p->ImageBase);
	printf("    DWORD   SectionAlignment=%#x\n", p->SectionAlignment);
	printf("    DWORD   FileAlignment=%#x\n", p->FileAlignment);
	printf("    WORD    MajorOperatingSystemVersion=%#x\n", p->MajorOperatingSystemVersion);
	printf("    WORD    MinorOperatingSystemVersion=%#x\n", p->MinorOperatingSystemVersion);
	printf("    WORD    MajorImageVersion=%#x\n", p->MajorImageVersion);
	printf("    WORD    MinorImageVersion=%#x\n", p->MinorImageVersion);
	printf("    WORD    MajorSubsystemVersion=%#x\n", p->MajorSubsystemVersion);
	printf("    WORD    MinorSubsystemVersion=%#x\n", p->MinorSubsystemVersion);
	printf("    DWORD   Win32VersionValue=%#x\n", p->Win32VersionValue);
	printf("    DWORD   SizeOfImage=%#x\n", p->SizeOfImage);
	printf("    DWORD   SizeOfHeaders=%#x\n", p->SizeOfHeaders);
	printf("    DWORD   CheckSum=%#x\n", p->CheckSum);
	printf("    WORD    Subsystem=%#x\n", p->Subsystem);
	printf("    WORD    DllCharacteristics=%#x\n", p->DllCharacteristics);
	printf("    DWORD   SizeOfStackReserve=%#x\n", p->SizeOfStackReserve);
	printf("    DWORD   SizeOfStackCommit=%#x\n", p->SizeOfStackCommit);
	printf("    DWORD   SizeOfHeapReserve=%#x\n", p->SizeOfHeapReserve);
	printf("    DWORD   SizeOfHeapCommit=%#x\n", p->SizeOfHeapCommit);
	printf("    DWORD   LoaderFlags=%#x\n", p->LoaderFlags);
	printf("    DWORD   NumberOfRvaAndSizes=%#x\n", p->NumberOfRvaAndSizes);
	printf("}\n");
}

void printSection(PIMAGE_SECTION_HEADER p) {
	printf("struct _IMAGE_SECTION_HEADER {\n");
	printf("    BYTE    Name[IMAGE_SIZEOF_SHORT_NAME]=%s\n", p->Name);
	printf("    DWORD   PhysicalAddress=%#x\n", p->Misc.PhysicalAddress);
	printf("    DWORD   VirtualSize=%#x\n", p->Misc.VirtualSize);
	printf("    DWORD   VirtualAddress=%#x\n", p->VirtualAddress);
	printf("    DWORD   SizeOfRawData=%#x\n", p->SizeOfRawData);
	printf("    DWORD   PointerToRawData=%#x\n", p->PointerToRawData);
	printf("    DWORD   PointerToRelocations=%#x\n", p->PointerToRelocations);
	printf("    DWORD   PointerToLinenumbers=%#x\n", p->PointerToLinenumbers);
	printf("    WORD    NumberOfRelocations=%#x\n", p->NumberOfRelocations);
	printf("    WORD    NumberOfLinenumbers=%#x\n", p->NumberOfLinenumbers);
	printf("    DWORD   Characteristics=%#x\n", p->Characteristics);
	printf("}\n");
}

DWORD ReadPEFile(IN LPSTR lpszFile, OUT LPVOID* pFileBuffer)
{
	return 0;
}

DWORD CopyFileBufferToImageBuffer(IN LPVOID pFileBuffer, OUT LPVOID* pImageBuffer)
{
	return 0;
}

DWORD CopyImageBufferToNewBuffer(IN LPVOID pImageBuffer, OUT LPVOID* pNewBuffer)
{
	return 0;
}

BOOL MemeryToFile(IN LPVOID pMemBuffer, IN size_t size, OUT LPSTR lpszFile)
{
	return 0;
}

DWORD RvaToFileOffset(IN LPVOID pFileBuffer, IN DWORD dwRva)
{
	return 0;
}
