#include <Windows.h>
#include "Loader.h"
#include "resource.h"

#define IDR_RCDATA1                     101

int main() {
	
	PBYTE	pDecompressedPe		= NULL;
	SIZE_T	sDecompressedPeSize = NULL;
	
	Loader loader = Loader();

	// TESTED AND WORKED
	if (!loader.GetDecompressedRsrcPayload(GetModuleHandle(NULL), IDR_RCDATA1, &pDecompressedPe, &sDecompressedPeSize)) {
		return -1;
	}
}