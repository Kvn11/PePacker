#pragma once
#include <Windows.h>
#include <stdio.h>

class Packer {
private:
	BOOL PreparePayload(IN LPCSTR cFileName, OUT PBYTE* ppFileBuf, OUT SIZE_T* pdwFileSize);

	BOOL WritePayload(IN PBYTE pFileBuffer, IN DWORD dwSize);

	BOOL VerifyPE(IN PBYTE pBuffer);

public:
	int Pack(LPCSTR cFileName);
};