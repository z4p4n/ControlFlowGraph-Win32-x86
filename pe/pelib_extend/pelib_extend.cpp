#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>
#include <winnt.h>

#include "../pelib/pelib.h"
#include "pelib_extend.h"
#include "../../dbglib/dbg.h"

/* To avoid some overflow exploit */
#define MAPPED_FILE(a, b, type) if ((int) PE->RVA2Offset (a) > PE->dwFileSize) { \
				fprintf (stderr, "[!!] Broken PE file [%d]\n",__LINE__); \
				return NULL; \
			} \
			b = type &(pbMappedFile[PE->RVA2Offset (a)]);

#define CHECK_MAPPED_FILE(a) if (((int) a - (int) pbMappedFile) > PE->dwFileSize) { \
					fprintf (stderr, "[!!] Broken PE file [%d]\n",  \
							__LINE__); \
					return NULL; \
				}


/* Get function name from IAT with address given in opcode */
LPCTSTR PEExtend::GetFunctionNameFromIAT (DWORD dwRVA, LPCTSTR lpDLL) {

	PIMAGE_IMPORT_DESCRIPTOR ImportDescriptor;
	PIMAGE_THUNK_DATA        ImportAddressTable;
	PIMAGE_THUNK_DATA        HintNameArray;
	PIMAGE_IMPORT_BY_NAME    ImportByName;

	DWORD addr;
	DWORD ret;

	BYTE *DLLName;

	/* In order to find function, we need to find  *
	 * directory entry import                      */
	if (OptionalHeader != NULL) {

		DirectoryEntryImport = 
			&((OptionalHeader->DataDirectory)[IMAGE_DIRECTORY_ENTRY_IMPORT]);

		/* Get ImportDescriptor from mapped file */
		MAPPED_FILE((int) DirectoryEntryImport->VirtualAddress, 
			    ImportDescriptor, 
			    (PIMAGE_IMPORT_DESCRIPTOR));

		if (ImportDescriptor != NULL) {

			//fprintf (stdout, "[+] Bind ImageImportDescriptor 0x%x"
			//		   " to mapped file\n\n", ImportDescriptor);
			//fprintf (stdout, "< ImageImportDescriptor >\n",ImportDescriptor);

			/* Search DLL imported by name */
			while (*(LPDWORD *) ImportDescriptor != 0) {


				/* Get DLL name from mapped file */
				MAPPED_FILE((int) ImportDescriptor->Name,
				            DLLName,(BYTE *));
				//fprintf (stdout, "\t[DLL] %s\n", DLLName);
				
				if (DLLName != NULL && lpDLL != NULL && 0 != 
						strcmp ((char *)DLLName, lpDLL))
					goto jump_this_DLL;

				/* Search functions imported by name */
				MAPPED_FILE ((int) ImportDescriptor->FirstThunk,
				             ImportAddressTable,
					     (PIMAGE_THUNK_DATA));
				MAPPED_FILE ((int) ImportDescriptor->OriginalFirstThunk,
				             HintNameArray,
					     (PIMAGE_THUNK_DATA));

				while (*(LPDWORD) HintNameArray != 0) {

					/* Dump Function name */
					MAPPED_FILE ((int)HintNameArray->u1.AddressOfData,
					             ImportByName, 
						     (PIMAGE_IMPORT_BY_NAME));
					//fprintf (stdout, "\t\t[FUNCTION] %s %x\n",
					//	       	&(ImportByName->Name),
					addr = dwImageBase + PE->Offset2RVA ((int) 
					    &(ImportAddressTable->u1.Function) - 
					    (int) pbMappedFile);


					/* If we found the RVA in IAT */
					if (addr == dwRVA) {
						return (LPCTSTR) &(ImportByName->Name);
					}

					/* Next function */
					ImportAddressTable++;
					HintNameArray++;
					CHECK_MAPPED_FILE (ImportAddressTable);
					CHECK_MAPPED_FILE (HintNameArray);
				}

				jump_this_DLL: 
				ImportDescriptor++;

				CHECK_MAPPED_FILE (ImportDescriptor);
			}

		} else fprintf (stdout, "[!] Cannot find DirectoryEntryImport\n");
	} else fprintf (stdout, "[!] Cannot find IMAGE_OPTIONAL_HEADER\n");

	return NULL;
}

LPCTSTR PEExtend::GetFunctionName (hde32s *hde, DWORD dwOffset, LPCTSTR lpDLL) {

	hde32s hde_next;
	LPCTSTR lpFunctionName = NULL;

	dwOffset += hde->len;

	if (hde->opcode == 0xFF && hde->len == 6) {

		lpFunctionName = GetFunctionNameFromIAT ((DWORD) hde->disp.disp32, lpDLL);

	} else if (hde->opcode == 0xE8) {

		if (hde->len == 3) dwOffset += (DWORD) ((signed short) hde->imm.imm16);
		else if (hde->len == 5) dwOffset += (DWORD) hde->imm.imm32;
		else DBG("Unknown situation");


		if (dwOffset < 0 || dwOffset >= dwSizeOfRawData) DBG_FAIL("Out of memory");
		hde32_disasm ((const void *) (pbTextSection + dwOffset), &hde_next);

		if (hde_next.opcode == 0xFF && hde_next.len == 6) 
			lpFunctionName = 
			  GetFunctionNameFromIAT ((DWORD) hde_next.disp.disp32, lpDLL);
	}

	return lpFunctionName;
}

BOOL PEExtend::DetectAlignmentBlock (DWORD dwOffset) {
	
	BYTE block1[] = {0x8D, 0x74, 0x26, 0x00, 0x8D, 0xBC, 0x27, 0x00, 0x00, 0x00, 0x00};
	BYTE block2[] = {0x8D, 0xB6, 0x00, 0x00, 0x00, 0x00, 
		         0x8D, 0xBC, 0x27, 0x00, 0x00, 0x00, 0x00};
	BYTE block3[] = {0x89, 0xF6, 0x8D, 0xBC, 0x27, 0x00, 0x00, 0x00, 0x00};
	BYTE block4[] = {0x8D, 0x76, 0x00, 0x8D, 0xBC, 0x27, 0x00, 0x00, 0x00, 0x00};
	BYTE block5[] = {0x8D, 0xBC, 0x27, 0x00, 0x00};

	BYTE block6[] = {0x8D, 0xB4, 0x26, 0x00, 0x00, 0x00, 0x00,
		         0x8D, 0xBC, 0x27, 0x00, 0x00, 0x00, 0x00};

	DWORD dwAddr = (DWORD)pbTextSection - (DWORD) pbMappedFile + dwOffset;

	if (dwAddr + sizeof (block1) <= dwSizeOfRawData &&
	!memcmp (block1, pbTextSection + dwOffset, sizeof (block1)))
		return TRUE;

	if (dwAddr + sizeof (block2) <= dwSizeOfRawData &&
	    !memcmp (block2, pbTextSection + dwOffset, sizeof (block2)))
		return TRUE;

	if (dwAddr + sizeof (block3) <= dwSizeOfRawData &&
	    !memcmp (block3, pbTextSection + dwOffset, sizeof (block3)))
		return TRUE;

	if (dwAddr + sizeof (block4) <= dwSizeOfRawData &&
	    !memcmp (block4, pbTextSection + dwOffset, sizeof (block4)))
		return TRUE;
	
	if (dwAddr + sizeof (block5) <= dwSizeOfRawData &&
	    !memcmp (block5, pbTextSection + dwOffset, sizeof (block5)))
		return TRUE;

	if (dwAddr + sizeof (block6) <= dwSizeOfRawData &&
	    !memcmp (block6, pbTextSection + dwOffset, sizeof (block6)))
		return TRUE;

	return FALSE;
}


BOOL PEExtend::DetectExitProcedure (hde32s *hde, DWORD dwOffset) {

	LPCTSTR lpFunctionName = NULL;

	lpFunctionName = GetFunctionName (hde, dwOffset, (LPCSTR) "msvcrt.dll");

	if (lpFunctionName != NULL && 
	    (!strcmp ((char *) lpFunctionName, "exit") ||
	    !strcmp ((char *) lpFunctionName, "_exit")))
		return TRUE;

	lpFunctionName = GetFunctionName (hde, dwOffset, (LPCSTR) "Kernel32.dll");

	if (lpFunctionName != NULL && 
	    (!strcmp ((char *) lpFunctionName, "ExitProcess")))
		return TRUE;

	return FALSE;
}

PEExtend::~PEExtend () {

	if (PE != NULL)
		delete PE;
	
	if (pbMappedFile != NULL)
		free (pbMappedFile);

	if (lpdwColoredGraph != NULL)
		free (lpdwColoredGraph);


	return;
}

PEExtend::PEExtend () {

	PE                          = NULL;
	lpFileName                  = NULL;

	pbMappedFile                = NULL;
	pbTextSection               = NULL;

	FileHeader                  = NULL;
	NtHeaders                   = NULL;
	OptionalHeader              = NULL;
	SectionHeader               = NULL;
	DirectoryEntryImport        = NULL;

	lpdwColoredGraph            = NULL;

	dwImageBase                 = 0;
	dwPointerToRawData          = 0;
	dwAddressOfEntryPoint       = 0;
	dwSizeOfRawData             = 0;
	dwBaseOfCode                = 0;
	dwEntryPoint                = 0;

	dwTextSectionVirtualAddress = 0;
	dwTextSectionHeaderPosition = 0;

	return;
}
