#pragma once
#define _CRT_SECURE_NO_WARNINGS
#include<Windows.h>
#include<string.h>
#include<stdio.h>
#include<stdlib.h>

void printDOS(PIMAGE_DOS_HEADER);
void printFileHeader(PIMAGE_FILE_HEADER);
void printOPTIONAL_HEADER32(PIMAGE_OPTIONAL_HEADER32);
void printSection(PIMAGE_SECTION_HEADER p);
void parsePE(char* path);

DWORD ReadPEFile(IN LPSTR lpszFile, OUT LPVOID* pFileBuffer);

DWORD CopyFileBufferToImageBuffer(IN LPVOID pImageBuffer, OUT LPVOID* pNewBuffer);

DWORD CopyImageBufferToNewBuffer(IN LPVOID pImageBuffer, OUT LPVOID* pNewBuffer);

BOOL MemeryToFile(IN LPVOID pMemBuffer,IN size_t size,OUT LPSTR lpszFile);

DWORD RvaToFileOffset(IN LPVOID pFileBuffer,IN DWORD dwRva);