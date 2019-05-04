
#include"PEParser.h"
int main() {
	IN DWORD o;
	LPVOID* p;
	//parsePE("C:\\Windows\\System32\\notepad.exe");
	char path[] = "D:\\MASM\\Notepad2.exe";
	parsePE(path);
	return 0;
}


