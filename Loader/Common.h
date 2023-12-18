#pragma once
#include <Windows.h>

#ifndef COMMON_H
#define COMMON_H

typedef struct _PE_HDRS
{
	PBYTE					pFileBuffer;
	DWORD					dwFileSize;

	PIMAGE_NT_HEADERS		pImgNtHdrs;
	PIMAGE_SECTION_HEADER	pImgSecHdr;

	PIMAGE_DATA_DIRECTORY	pEntryImportDataDir;
	PIMAGE_DATA_DIRECTORY	pEntryBaseRelocDataDir;
	PIMAGE_DATA_DIRECTORY	pEntryTLSDataDir;
	PIMAGE_DATA_DIRECTORY	pEntryExceptionDataDir;
	PIMAGE_DATA_DIRECTORY	pEntryExportDataDir;

	BOOL					bIsDLLFile;
}PE_HDRS, * PPE_HDRS;

#endif // !COMMON_H