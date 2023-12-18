#include <Windows.h>
#include <stdio.h>
#include "Packer.h"
#include "lzw.h"

#define NEW_NAME "Payload.lzw"

#define ALLOC(SIZE)				LocalAlloc(LPTR, (SIZE_T)SIZE)
#define FREE(BUFF)				LocalFree((LPVOID)BUFF)
#define REALLOC(BUFF, SIZE)		LocalReAlloc(BUFF, SIZE,  LMEM_MOVEABLE | LMEM_ZEROINIT)
#define GET_FILENAME(path)		(strrchr(path, '\\') ? strrchr(path, '\\') + 1 : path)

BOOL Packer::PreparePayload(IN LPCSTR cFileName, OUT PBYTE* ppFileBuffer, OUT SIZE_T* pdwFileSize) {
	HANDLE	hFile				= INVALID_HANDLE_VALUE;
	PBYTE	pTmpReadBuffer		= NULL;
	DWORD	dwFileSize			= NULL;
	DWORD	dwNumberOfBytesRead = NULL;

	if (!pdwFileSize || !ppFileBuffer)
		return FALSE;

	if ((hFile = CreateFileA(cFileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE) {
		printf("\t[!] CreateFileA failed with error: %d\n", GetLastError());
		return FALSE;
	}

	if ((dwFileSize = GetFileSize(hFile, NULL)) == INVALID_FILE_SIZE) {
		printf("\t[!] GetFileSize Failed.\n");
		goto _FUNC_CLEANUP;
	}

	if (!(pTmpReadBuffer = (PBYTE)ALLOC(dwFileSize))) {
		printf("\t[!] LocalAlloc Failed.\n");
		goto _FUNC_CLEANUP;
	}

	if (!ReadFile(hFile, pTmpReadBuffer, dwFileSize, &dwNumberOfBytesRead, NULL) || dwFileSize != dwNumberOfBytesRead) {
		printf("\t[!] ReadFile Failed.\n");
		goto _FUNC_CLEANUP;
	}

	*ppFileBuffer = pTmpReadBuffer;
	*pdwFileSize = dwFileSize;

_FUNC_CLEANUP:
	if (hFile != INVALID_HANDLE_VALUE)
		CloseHandle(hFile);
	if (pTmpReadBuffer && !*ppFileBuffer)
		FREE(pTmpReadBuffer);
	return *ppFileBuffer == NULL ? FALSE : TRUE;
}

BOOL Packer::WritePayload(IN PBYTE pFileBuffer, IN DWORD dwFileSize) {
	HANDLE	hFile					= INVALID_HANDLE_VALUE;
	DWORD	dwNumberOfBytesWritten	= 0x00;

	if (!pFileBuffer || !dwFileSize)
		return FALSE;

	hFile = CreateFileA(NEW_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		printf("\t[!] CreateFileA failed.");
		goto _FUNC_CLEANUP;
	}

	if (!WriteFile(hFile, pFileBuffer, dwFileSize, &dwNumberOfBytesWritten, NULL) || dwFileSize != dwNumberOfBytesWritten) {
		printf("\t[!] WriteFile failed.\n");
		goto _FUNC_CLEANUP;
	}

_FUNC_CLEANUP:
	if (hFile != INVALID_HANDLE_VALUE)
		CloseHandle(hFile);
	return dwNumberOfBytesWritten == dwFileSize ? TRUE : FALSE;
}

BOOL Packer::VerifyPE(IN PBYTE pBuffer) {
	PIMAGE_NT_HEADERS pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBuffer + ((PIMAGE_DOS_HEADER)pBuffer)->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
		return FALSE;

	if (pImgNtHdrs->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE && pImgNtHdrs->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
		return TRUE;

	return FALSE;
}

int Packer::Pack(LPCSTR cFileName) {
	PBYTE	pRawData				= NULL;
	PBYTE	pCompressedData			= NULL;
	PBYTE	pCompressedDataWithConf	= NULL;
	SIZE_T	sRawDataSize			= NULL;
	SIZE_T	sCompressedDataSize		= NULL;

	printf("[i] Reading %s from disk...\n", GET_FILENAME(cFileName));
	if (!PreparePayload(cFileName, &pRawData, &sRawDataSize))
		return -1;
	printf("[+] DONE\n");

	if (!VerifyPE(pRawData)) {
		printf("[!] File is not valid PE.\n");
		return -1;
	}

	printf("[i] Compressing Payload...");
	if (!LzwCompressData(pRawData, sRawDataSize, &pCompressedData, &sCompressedDataSize)) {
		printf("[!] Compression Failed.\n");
		return -1;
	}

	if (!(pCompressedDataWithConf = (PBYTE)REALLOC(pCompressedData, (sCompressedDataSize + sizeof(SIZE_T))))) {
		printf("[!] LocalRealloc Failed.\n");
		return -1;
	}

	*(PSIZE_T)(pCompressedDataWithConf + sCompressedDataSize) = (SIZE_T)sRawDataSize;
	printf("[+] DONE.\n");

	printf("[*] Compressed Data: 0x%p \n", pCompressedDataWithConf);
	printf("[*] Compressed Data Size: %d [ Was: %d ]\n", (int)(sCompressedDataSize + sizeof(SIZE_T)), (int)sRawDataSize);
	printf("[*] Compression Ratio: %2.01f%% \n", (FLOAT)((1.0f - ((float)sCompressedDataSize / sRawDataSize)) * 100.0f));

	printf("[i] Writing \"%s\" payload to disk...", NEW_NAME);
	if (!WritePayload(pCompressedDataWithConf, (sCompressedDataSize + sizeof(SIZE_T))))
		return -1;
	printf("[+] DONE \n");

	FREE(pCompressedDataWithConf);
	return 0;
}
