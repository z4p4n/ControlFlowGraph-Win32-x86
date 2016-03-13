#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>
#include <winnt.h>

#include "pe/pelib/pelib.h"
#include "pe/pelib_extend/pelib_extend.h"
#include "cfg/win32_cfg.h"

#define DBG { fprintf (stdout, "%s %d\n", __FILE__, __LINE__); fflush (stdout); }

int main (int argc, char *argv[]) {

	/* PE vars */
	PEExtend *PE;

	int ret;

	/* .text section data vars */
	FILE *fd;
	
	/* Usage */
	if (argc < 3) {

		fprintf (stderr, "usage : %s executable_name graph_name\n", argv[0]);
		exit (EXIT_FAILURE);
	}

	PE = new (PEExtend);
	PE->lpFileName = argv[1];
	PE->PE = new (PELibrary);

	/* Read PE Format */
	ret = PE->PE->OpenFileName ((char *) PE->lpFileName);
	if (!ret) exit (EXIT_FAILURE);
	fprintf (stdout, "[+] Read PE Format from %s.\n", argv[1]);

	PE->NtHeaders      = (PIMAGE_NT_HEADERS)     PE->PE->image_nt_headers;
	PE->SectionHeader  = (PIMAGE_SECTION_HEADER) *(PE->PE->image_section_header);
	PE->FileHeader     = (PIMAGE_FILE_HEADER)    &(PE->PE->image_nt_headers->FileHeader);
	PE->OptionalHeader = (PIMAGE_OPTIONAL_HEADER) &(PE->NtHeaders->OptionalHeader);
	PE->DirectoryEntryImport = 
	  &((PE->OptionalHeader->DataDirectory)[IMAGE_DIRECTORY_ENTRY_IMPORT]);

	/* Search .text section */
	/*
	for (i = 0 ; i < PE->FileHeader->NumberOfSections ; i++) {

		fprintf (stdout, "\t-> Section %s\n",PE->SectionHeader[i].Name);
		if (!strcmp ((char *) PE->SectionHeader[i].Name, ".text"))
			break;
	}

	if (i == PE->FileHeader->NumberOfSections) {
		fprintf (stderr, "[!!] Cannot find .text section header\n");
		delete PE;
		exit (EXIT_FAILURE);
	}
	*/

	/* Read data from .text section/Entry point section header */
	PE->dwTextSectionHeaderPosition = PE->PE->EPSectionNum;
	PE->dwSizeOfRawData = 
		PE->SectionHeader[PE->dwTextSectionHeaderPosition].SizeOfRawData;
	PE->dwPointerToRawData = 
		PE->SectionHeader[PE->dwTextSectionHeaderPosition].PointerToRawData;
	PE->dwAddressOfEntryPoint = PE->OptionalHeader->AddressOfEntryPoint;
	PE->dwBaseOfCode = PE->OptionalHeader->BaseOfCode;
	PE->dwEntryPoint = PE->dwAddressOfEntryPoint - PE->dwBaseOfCode;
	PE->dwImageBase  = PE->OptionalHeader->ImageBase;
	PE->dwTextSectionVirtualAddress = 
		PE->SectionHeader[PE->dwTextSectionHeaderPosition].VirtualAddress;

	/* Avoid some PE Corrupt */
	if (PE->dwSizeOfRawData > PE->PE->dwFileSize) {
		PE->dwSizeOfRawData = PE->PE->dwFileSize - PE->dwEntryPoint;
	}

	fprintf (stdout, "\t-> File Size : 0x%x\n", PE->PE->dwFileSize);
	fprintf (stdout, "\t-> Section Of Entry Point = 0x%x\n", 
			PE->dwTextSectionHeaderPosition);
	fprintf (stdout, "\t-> SizeOfRawData    = 0x%x\n", PE->dwSizeOfRawData);
	fprintf (stdout, "\t-> PointerToRawData = 0x%x\n", PE->dwPointerToRawData);
	fprintf (stdout, "\t-> AddressOfEntryPoint = 0x%x\n", PE->dwAddressOfEntryPoint);
	fprintf (stdout, "\t-> BaseOfCode = 0x%x\n", PE->dwBaseOfCode);
	fprintf (stdout, "\t-> EntryPoint = 0x%x\n", PE->dwEntryPoint);
	fprintf (stdout, "\t-> ImageBase = 0x%x\n",  PE->dwImageBase);
//	fprintf (stdout, "\t-> ROAddressOfEntryPoint = 0x%x\n", 
//			PE->PE->Offset2RVA(PE->PE->ROAddressOfEntryPoint));

	/* Avoid some PE Corrupt */
	if (PE->dwSizeOfRawData > PE->PE->dwFileSize) {
		PE->dwSizeOfRawData = PE->PE->dwFileSize - PE->dwEntryPoint;
		fprintf (stdout, "[+] Recompute dwSizeOfRawData : 0x%x\n", 
				PE->dwSizeOfRawData);
	}

	/* Check for avoid some overflow attack */
	if (PE->dwPointerToRawData >= PE->PE->dwFileSize) {
		fprintf (stderr, "PE File is broken !\n");
		exit (EXIT_FAILURE);
	}

	/* Load file in order to read .text section data */
	fd = fopen (PE->lpFileName, "rb");
	if (fd == NULL) {
		fprintf (stderr, "File %s cannot be open!\n", PE->lpFileName);
		delete PE;
		exit (EXIT_FAILURE);
	}

	PE->pbMappedFile = (BYTE *) malloc (sizeof (BYTE) * PE->PE->dwFileSize);
	if (PE->pbMappedFile == NULL) {
		fprintf (stderr, "Fail with malloc function!\n");
		fclose (fd);
		delete PE;
		exit (EXIT_FAILURE);
	}
	
	PE->pbTextSection = &(PE->pbMappedFile[PE->dwPointerToRawData]);

	if (fread (PE->pbMappedFile, sizeof (BYTE), PE->PE->dwFileSize, fd) 
	  < PE->PE->dwFileSize) {
		fclose (fd);
		fprintf (stderr, "Fail with fread function!\n");
		delete PE;
		exit (EXIT_FAILURE);
	}

	fprintf (stdout, "[+] map file %s into memory, size : 0x%X\n", 
			PE->lpFileName, PE->PE->dwFileSize);
	fprintf (stdout, "[+] select .text section data from memory\n");

	/* Don't forget to close file */
	fclose (fd);

	/* Load id dump (modelized with ColoredGraph) */
	PE->lpdwColoredGraph = (DWORD *) malloc (sizeof (DWORD) * PE->dwSizeOfRawData);
	
	if (PE->lpdwColoredGraph == NULL) {

		fprintf (stderr, "Error with malloc function.\n");
		return 0;
	}

	/* Build control flow graph */
	ret = cfg_build (PE, argv[2]);

	if (ret == 0) {
		delete PE;
		exit (EXIT_FAILURE);
	}
	fprintf (stdout, "[+] Control Flow Graph built\n");

	/* release memory */
	delete PE;

	exit (EXIT_SUCCESS);
}

