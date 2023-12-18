// @NUL0x4C | @mrd0x : MalDevAcademy

#include <Windows.h>
#include <stdio.h>
#include "Packer.h"

#define GET_FILENAME(path)		(strrchr(path, '\\') ? strrchr(path, '\\') + 1 : path)

int main(int argc, char* argv[]) {

	if (argc != 2) {
		printf("[!] Example: %s mimikatz.exe \n", GET_FILENAME(argv[0]) );
		return -1;
	}

	Packer packer = Packer();
	return packer.Pack(argv[1]);
}