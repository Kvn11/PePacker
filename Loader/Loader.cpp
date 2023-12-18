#include <Windows.h>
#include "Lzw.h"
#include "Loader.h"

typedef BOOL(WINAPI* DLLMAIN)(HINSTANCE, DWORD, LPVOID);
typedef BOOL(WINAPI* MAIN)();

// https://github.com/NUL0x4C/ManualRsrcDataFetching

BOOL Loader::GetResourceData(IN HMODULE hModule, IN WORD ResourceId, OUT PVOID* ppResourceRawData, OUT PDWORD psResourceDataSize) {
	
	CHAR*					pBaseAddr		= (CHAR*)hModule;
	PIMAGE_DOS_HEADER		pImgDosHdr		= (PIMAGE_DOS_HEADER)pBaseAddr;
	PIMAGE_NT_HEADERS		pImgNtHdr		= (PIMAGE_NT_HEADERS)(pBaseAddr + pImgDosHdr->e_lfanew);
	PIMAGE_OPTIONAL_HEADER	pImgOptionalHdr = (PIMAGE_OPTIONAL_HEADER)&pImgNtHdr->OptionalHeader;
	PIMAGE_DATA_DIRECTORY	pDataDir		= (PIMAGE_DATA_DIRECTORY)&pImgOptionalHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE];

	PIMAGE_RESOURCE_DIRECTORY pResourceDir	= NULL;
	PIMAGE_RESOURCE_DIRECTORY pResourceDir2	= NULL;
	PIMAGE_RESOURCE_DIRECTORY pResourceDir3	= NULL;

	PIMAGE_RESOURCE_DIRECTORY_ENTRY pResourceEntry	= NULL;
	PIMAGE_RESOURCE_DIRECTORY_ENTRY pResourceEntry2	= NULL;
	PIMAGE_RESOURCE_DIRECTORY_ENTRY pResourceEntry3	= NULL;

	PIMAGE_RESOURCE_DATA_ENTRY pResource = NULL;

	pResourceDir	= (PIMAGE_RESOURCE_DIRECTORY)(pBaseAddr + pDataDir->VirtualAddress);
	pResourceEntry	= (IMAGE_RESOURCE_DIRECTORY_ENTRY*)(pResourceDir + 1);

	for (DWORD i = 0; i < (pResourceDir->NumberOfNamedEntries + pResourceDir->NumberOfIdEntries); i++) {

		if (pResourceEntry[i].DataIsDirectory == 0)
			break;

		pResourceDir2	= (PIMAGE_RESOURCE_DIRECTORY)(pBaseAddr + pDataDir->VirtualAddress + (pResourceEntry[i].OffsetToDirectory & 0x7FFFFFFF));
		pResourceEntry2 = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(pResourceDir2 + 1);

		if (pResourceEntry2->DataIsDirectory == 1 && pResourceEntry2->Id == ResourceId) {

			pResourceDir3 = (PIMAGE_RESOURCE_DIRECTORY)(pBaseAddr + pDataDir->VirtualAddress + (pResourceEntry2->OffsetToDirectory & 0x7FFFFFFF));
			pResourceEntry3 = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(pResourceDir3 + 1);
			pResource = (PIMAGE_RESOURCE_DATA_ENTRY)(pBaseAddr + pDataDir->VirtualAddress + (pResourceEntry3->OffsetToData & 0x7FFFFFFF));

			*ppResourceRawData = (PVOID)(pBaseAddr + (pResource->OffsetToData));
			*psResourceDataSize = pResource->Size;

			break;
		}
	}

	if (*ppResourceRawData != NULL && *psResourceDataSize != NULL)
		return TRUE;

	return FALSE;
}

BOOL Loader::GetDecompressedRsrcPayload(IN HMODULE hModule, IN WORD wResourceId, OUT PBYTE* ppDecompressedPe, OUT PSIZE_T psDecompressedPeSize) {
	
	PBYTE	pCompressedPe		= NULL;
	SIZE_T	sCompressedPeSize	= NULL;

	if (!GetResourceData(hModule, wResourceId, (PVOID*)&pCompressedPe, (PDWORD) &sCompressedPeSize)) {
		// TODO: Add Debug
		return FALSE;
	}

	*psDecompressedPeSize = *(PSIZE_T)(pCompressedPe + sCompressedPeSize - sizeof(SIZE_T));

	*ppDecompressedPe = (PBYTE)LocalAlloc(LPTR, *psDecompressedPeSize);
	if (! *ppDecompressedPe) {
		return FALSE;
	}

	if (!LzwDecompressData(pCompressedPe, sCompressedPeSize, ppDecompressedPe, psDecompressedPeSize)) {
		LocalFree(*ppDecompressedPe);
		return FALSE;
	}

	return TRUE;
}

BOOL Loader::InitPeStruct(IN PBYTE pFileBuffer, IN DWORD dwFileSize) {

	if (!pFileBuffer || !dwFileSize)
		return FALSE;

	PPE_HDRS pPeHdrs = &PeHdrStruct;

	pPeHdrs->pFileBuffer = pFileBuffer;
	pPeHdrs->dwFileSize = dwFileSize;
	pPeHdrs->pImgNtHdrs = (PIMAGE_NT_HEADERS)(pFileBuffer + ((PIMAGE_DOS_HEADER)pFileBuffer)->e_lfanew);

	if (pPeHdrs->pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
		return FALSE;

	pPeHdrs->bIsDLLFile = (pPeHdrs->pImgNtHdrs->FileHeader.Characteristics & IMAGE_FILE_DLL) ? TRUE : FALSE;
	pPeHdrs->pImgSecHdr = IMAGE_FIRST_SECTION(pPeHdrs->pImgNtHdrs);
	pPeHdrs->pEntryImportDataDir = &pPeHdrs->pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	pPeHdrs->pEntryBaseRelocDataDir = &pPeHdrs->pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	pPeHdrs->pEntryTLSDataDir = &pPeHdrs->pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
	pPeHdrs->pEntryExceptionDataDir = &pPeHdrs->pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
	pPeHdrs->pEntryExportDataDir = &pPeHdrs->pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

	return TRUE;
}

BOOL Loader::RunPayload() {

	PPE_HDRS	pPeHdrs					= &PeHdrStruct;
	NTSTATUS	STATUS					= 0x00;
	PBYTE		pPeBaseAddress			= NULL;
	SIZE_T		sPeSize					= (SIZE_T)pPeHdrs->pImgNtHdrs->OptionalHeader.SizeOfImage;
	PVOID		pVectoredExptHandler	= NULL;
	PVOID		pEntryPoint				= NULL;
	DLLMAIN		pDllMain				= NULL;
	MAIN		pMain					= NULL;

}
