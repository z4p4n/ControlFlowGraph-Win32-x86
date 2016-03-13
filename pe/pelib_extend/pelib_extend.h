#ifndef PELIB_EXTEND_H
#define PELIB_EXTEND_H

#include "../../hde28c/hde32.h"

class PEExtend
{
protected:
private:
public:

	PELibrary *PE;
	LPCTSTR lpFileName;

	BYTE *pbMappedFile;
	BYTE *pbTextSection;

	PIMAGE_FILE_HEADER       FileHeader;
	PIMAGE_NT_HEADERS        NtHeaders;
	PIMAGE_OPTIONAL_HEADER   OptionalHeader;
	PIMAGE_SECTION_HEADER    SectionHeader;
	PIMAGE_DATA_DIRECTORY    DirectoryEntryImport;

	LPDWORD lpdwColoredGraph;

	DWORD dwImageBase;
	DWORD dwPointerToRawData;
	DWORD dwAddressOfEntryPoint;
	DWORD dwSizeOfRawData;
	DWORD dwBaseOfCode;
	DWORD dwEntryPoint;

	DWORD dwTextSectionVirtualAddress;
	DWORD dwTextSectionHeaderPosition;

	PEExtend();
	~PEExtend();
	/* Get function name from IAT with address given in opcode */
	LPCTSTR GetFunctionNameFromIAT (DWORD RVA, LPCTSTR lpDLL);

	LPCTSTR GetFunctionName (hde32s *hde, DWORD dwOffset, LPCTSTR lpDLL);
	BOOL DetectExitProcedure  (hde32s *hde, DWORD dwOffset);
	BOOL DetectAlignmentBlock (DWORD dwOffset);
};


#endif
