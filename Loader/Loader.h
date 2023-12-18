#pragma once
#include <Windows.h>
#include "Common.h"

class Loader {
private:
	PE_HDRS PeHdrStruct = { 0 };

	BOOL GetResourceData(IN HMODULE hModule, IN WORD ResourceId, OUT PVOID* ppResourceRawData, OUT PDWORD psResourceDataSize);

public:

	BOOL GetDecompressedRsrcPayload(IN HMODULE hModule, IN WORD wResourceId, OUT PBYTE* ppDecompressedPe, OUT PSIZE_T psDecompressedPeSize);

	BOOL InitPeStruct(IN PBYTE pFileBuffer, IN DWORD dwFileSize);

	BOOL RunPayload();
};