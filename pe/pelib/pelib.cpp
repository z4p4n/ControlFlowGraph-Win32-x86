/* pelib.cpp --

   This file is part of the "PE Maker".

   Copyright (C) 2005-2006 Ashkbiz Danehkar
   All Rights Reserved.

   "PE Maker" library are free software; you can redistribute them
   and/or modify them under the terms of the GNU General Public License as
   published by the Free Software Foundation.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; see the file COPYRIGHT.TXT.
   If not, write to the Free Software Foundation, Inc.,
   59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.

   yodap's Forum:
   http://yodap.sourceforge.net/forum/

   yodap's Site:
   http://yodap.has.it
   http://yodap.cjb.net
   http://yodap.sourceforge.net

   Ashkbiz Danehkar
   <ashkbiz@yahoo.com>
*/
#include "stdafx.h"
#include <winnt.h>
#include <imagehlp.h>//#include <Dbghelp.h>
//#include <string.h>
#include <Winreg.h>
//#include <stdlib.h>
//#include <commctrl.h>
#include "PELib.h"
#include "PELibErr.h"

#ifdef _DEBUG
#define DEBUG_NEW
#endif

//----------------------------------------------------------------
//------- DATA ---------
//HANDLE	pMap			= NULL;
DWORD	dwBytesRead		= 0;
DWORD	dwBytesWritten	= 0;
DWORD	dwFsize			= 0;
HANDLE	hFile			= NULL;
//----------------------------
//------- FUNCTION ---------
//----------------------------------------------------------------
bool SaveToRegistry(DWORD dwProtectFlags,
					DWORD dwAdvancedFlags,
					DWORD dwCompressLevel,
					char* CrypterSectionName,
					DWORD dwLangID);
bool LoadFromRegistry(DWORD *dwProtectFlags,
					  DWORD *dwAdvancedFlags,
					  DWORD *dwCompressLevel,
					  char* CrypterSectionName,
					  DWORD *dwLangID);
//----------------------------------------------------------------

//----------------------------------------------------------------------------
bool SaveToRegistry(DWORD dwProtectFlags,
					DWORD dwAdvancedFlags,
					DWORD dwCompressLevel,
					char* CrypterSectionName,
					DWORD dwLangID)
{
    char KeyMain[127];
	HKEY RootKey=HKEY_CURRENT_USER;
    strcpy(KeyMain,"Software\\PEiD Maker");
    bool Result;
	HKEY hKeyOption;
	DWORD dwDispos;
	if(ERROR_SUCCESS!=::RegCreateKeyEx(RootKey,KeyMain,
									0,NULL,
									REG_OPTION_NON_VOLATILE	
									,KEY_ALL_ACCESS,NULL,
									&hKeyOption,&dwDispos))
	{
		return FALSE;
	}
		if(::RegOpenKeyEx(RootKey,KeyMain,0,KEY_ALL_ACCESS,&hKeyOption)== ERROR_SUCCESS) 
        {	
			::RegSetValueEx(hKeyOption,
						"ProtectionFlags",0,
						REG_DWORD,
						reinterpret_cast<BYTE *>(&dwProtectFlags),
						4);

			::RegSetValueEx(hKeyOption,
						"AdvancedFlags",0,
						REG_DWORD,
						reinterpret_cast<BYTE *>(&dwAdvancedFlags),
						sizeof(dwAdvancedFlags));

			::RegSetValueEx(hKeyOption,
						"CompressLevel",0,
						REG_DWORD,
						reinterpret_cast<BYTE *>(&dwCompressLevel),
						sizeof(dwCompressLevel));		

			::RegSetValueEx(hKeyOption,
						"SectionName",0,
						REG_SZ,
						reinterpret_cast<BYTE *>(CrypterSectionName),
						9);		

			::RegSetValueEx(hKeyOption,
						"LanguageID",0,
						REG_DWORD,
						reinterpret_cast<BYTE *>(&dwLangID),
						sizeof(dwLangID));		

			Result=TRUE;
        }
		else Result=FALSE;

    		::RegCloseKey(hKeyOption);
    return(Result);
}
//----------------------------------------------------------------------------
bool LoadFromRegistry(DWORD *dwProtectFlags,
					  DWORD *dwAdvancedFlags,
					  DWORD *dwCompressLevel,
					  char* CrypterSectionName,
					  DWORD *dwLangID)
{
    char KeyMain[127];
	HKEY RootKey=HKEY_CURRENT_USER;
    strcpy(KeyMain,"Software\\PEiD Maker");
	HKEY hKeyOption;
	bool Result;
	DWORD dwSize     = 0; 
	DWORD dwDataType = 0; 
	DWORD dwValue    = 0; 
	if(::RegOpenKeyEx(RootKey,KeyMain,0,KEY_ALL_ACCESS,&hKeyOption) != ERROR_SUCCESS) 
	{ 
		return FALSE;
	}
		if(::RegOpenKeyEx(RootKey,KeyMain,0,KEY_ALL_ACCESS,&hKeyOption) == ERROR_SUCCESS) 
		{ 

			dwSize = sizeof(dwProtectFlags); 
			::RegQueryValueEx(hKeyOption,
						"ProtectionFlags",NULL,
						&dwDataType,
						reinterpret_cast<BYTE *>(dwProtectFlags),
						&dwSize);

			dwSize = sizeof(dwAdvancedFlags); 
			::RegQueryValueEx(hKeyOption,
						"AdvancedFlags",NULL,
						&dwDataType,
						reinterpret_cast<BYTE *>(dwAdvancedFlags),
						&dwSize);

			dwSize = sizeof(dwCompressLevel); 
			::RegQueryValueEx(hKeyOption,
						"CompressLevel",NULL,
						&dwDataType,
						reinterpret_cast<BYTE *>(dwCompressLevel),
						&dwSize);

			dwSize = 9;
				//sizeof(CrypterSectionName); 
			::RegQueryValueEx(hKeyOption,
						"SectionName",0,
						&dwDataType,
						reinterpret_cast<BYTE *>(CrypterSectionName),
						&dwSize);	

			dwSize = sizeof(dwLangID); 
			::RegQueryValueEx(hKeyOption,
						"LanguageID",NULL,
						&dwDataType,
						reinterpret_cast<BYTE *>(dwLangID),
						&dwSize);

			Result=TRUE;
        }
		else Result=FALSE;
    ::RegCloseKey(hKeyOption);
    
    return(Result);
}
//----------------------------------------------------------------
PELibrary::PELibrary()
{
	image_dos_header=new (IMAGE_DOS_HEADER);
	image_nt_headers=new (IMAGE_NT_HEADERS);
	for(int i=0;i<MAX_SECTION_NUM;i++) image_section_header[i]=new (IMAGE_SECTION_HEADER);
	FirstBytes=new char[4095];
}
//----------------------------------------------------------------
PELibrary::~PELibrary()
{
	delete []image_dos_header;
	delete []image_nt_headers;
	for(int i=0;i<MAX_SECTION_NUM;i++) delete []image_section_header[i];
	delete []FirstBytes;
}
//----------------------------------------------------------------
int PELibrary::OpenFileName(char* FileName)
{
	DWORD i;
	DWORD dwRO_first_section;
	pMem=NULL;
	hFile=CreateFile(FileName,
					 GENERIC_READ,
					 FILE_SHARE_WRITE | FILE_SHARE_READ,
	                 NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
	if(hFile==INVALID_HANDLE_VALUE)
	{
		ShowErr(FileErr);
		return 0;
	}
	dwFsize=GetFileSize(hFile,0);
	if(dwFsize == 0)
	{
		CloseHandle(hFile);
		ShowErr(FsizeErr);
		return 0;
	}
	pMem=(char*)GlobalAlloc(GMEM_FIXED | GMEM_ZEROINIT,dwFsize);
	if(pMem == NULL)
	{
		CloseHandle(hFile);
		ShowErr(MemErr);
		return 0;
	}
	ReadFile(hFile,pMem,dwFsize,&dwBytesRead,NULL);
	CloseHandle(hFile);

	CopyMemory(image_dos_header,pMem,sizeof(IMAGE_DOS_HEADER));
	CopyMemory(image_nt_headers,
		       pMem+image_dos_header->e_lfanew,
			   sizeof(IMAGE_NT_HEADERS));
	dwRO_first_section=image_dos_header->e_lfanew+sizeof(IMAGE_NT_HEADERS);
	if(image_dos_header->e_magic!=IMAGE_DOS_SIGNATURE)// MZ
	{
		ShowErr(PEErr);
		GlobalFree(pMem);
		return 0;
	}
	if(image_nt_headers->Signature!=IMAGE_NT_SIGNATURE)// PE00
	{
		ShowErr(PEErr);
		GlobalFree(pMem);
		return 0;
	}
	DWORD SectionNum=image_nt_headers->FileHeader.NumberOfSections;
	for( i=0;i<SectionNum;i++) 
	{
		CopyMemory(image_section_header[i],pMem+dwRO_first_section+i*sizeof(IMAGE_SECTION_HEADER),
			sizeof(IMAGE_SECTION_HEADER));
	}
	ROAddressOfEntryPoint=RVA2Offset(image_nt_headers->OptionalHeader.AddressOfEntryPoint);
	EPSectionNum=ImageROToSectionNum(ROAddressOfEntryPoint);
	CopyMemory(FirstBytes,pMem+ROAddressOfEntryPoint,sizeof(FirstBytes));
	GlobalFree(pMem);
	dwFileSize=dwFsize;

	return 1;
}
//----------------------------------------------------------------
// retrieve Enrty Point Section Number
// Base    - base of the MMF
// dwRVA - the RVA to calculate
// returns -1 if an error occurred else the calculated Offset will be returned
DWORD PELibrary::ImageROToSectionNum(DWORD dwRO)
{
	for(int i=0;i<image_nt_headers->FileHeader.NumberOfSections;i++)
	{
		if((dwRO>=image_section_header[i]->PointerToRawData) && (dwRO<(image_section_header[i]->PointerToRawData+image_section_header[i]->SizeOfRawData)))
		{
			return (i);
		}
	}
	return(-1);
}

PIMAGE_SECTION_HEADER PELibrary::ImageRvaToSection2(DWORD dwRVA)
{
	int i;
	for(i=0;i<image_nt_headers->FileHeader.NumberOfSections;i++)
	{
		if((dwRVA>=image_section_header[i]->VirtualAddress) && (dwRVA<=(image_section_header[i]->VirtualAddress+image_section_header[i]->SizeOfRawData)))
		{
			return ((PIMAGE_SECTION_HEADER)image_section_header[i]);
		}
	}
	return(NULL);
}
//----------------------------------------------------------------
// calulates the Offset from a RVA
// Base    - base of the MMF
// dwRVA - the RVA to calculate
// returns 0 if an error occurred else the calculated Offset will be returned
DWORD PELibrary::RVA2Offset(DWORD dwRVA)
{
	DWORD _offset;
	PIMAGE_SECTION_HEADER section;
	section=ImageRvaToSection2(dwRVA);//ImageRvaToSection(pimage_nt_headers,Base,dwRVA);
	if(section==NULL)
	{
		return(0);
	}
	_offset=dwRVA+section->PointerToRawData-section->VirtualAddress;
	return(_offset);
}
//----------------------------------------------------------------
//The _ImageROToSection function locates a Off Set address (RO) 
//within the image header of a file that is mapped as a file and
//returns a pointer to the section table entry for that virtual 
//address.
PIMAGE_SECTION_HEADER PELibrary::ImageROToSection2(DWORD dwRO)
{
	for(int i=0;i<image_nt_headers->FileHeader.NumberOfSections;i++)
	{
		if((dwRO>=image_section_header[i]->PointerToRawData) && (dwRO<(image_section_header[i]->PointerToRawData+image_section_header[i]->SizeOfRawData)))
		{
			return ((PIMAGE_SECTION_HEADER)image_section_header[i]);
		}
	}
	return(NULL);
}
//----------------------------------------------------------------
// calulates the RVA from a Offset
// Base    - base of the MMF
// dwRO - the Offset to calculate
// returns 0 if an error occurred else the calculated Offset will be returned
DWORD PELibrary::Offset2RVA(DWORD dwRO)
{
	PIMAGE_SECTION_HEADER section;
	section=ImageROToSection2(dwRO);
	if(section==NULL)
	{
		return(0);
	}
	return(dwRO+section->VirtualAddress-section->PointerToRawData);
}
//----------------------------------------------------------------
// returns aligned value
DWORD PELibrary::PEAlign(DWORD dwTarNum,DWORD dwAlignTo)
{	
	DWORD dwtemp;
	dwtemp=dwTarNum/dwAlignTo;
	if((dwTarNum%dwAlignTo)!=0)
	{
		dwtemp++;
	}
	dwtemp=dwtemp*dwAlignTo;
	return(dwtemp);
}
//----------------------------------------------------------------
int PELibrary::SaveEP(LPSTR pOutputFile)
{
	hFile=CreateFile(pOutputFile,
					 GENERIC_WRITE,
					 FILE_SHARE_WRITE | FILE_SHARE_READ,
	                 NULL,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,NULL);
	if(hFile==INVALID_HANDLE_VALUE)
	{
		hFile=CreateFile(pOutputFile,
					 GENERIC_WRITE,
					 FILE_SHARE_WRITE | FILE_SHARE_READ,
	                 NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
		if(hFile==INVALID_HANDLE_VALUE)
		{
			return 1;
		}	
	}
	// ----- WRITE FILE MEMORY TO DISK -----
	SetFilePointer(hFile,0,NULL,FILE_BEGIN);
	WriteFile(hFile,FirstBytes,sizeof(FirstBytes),&dwBytesRead,NULL);
	
	// ------ FORCE CALCULATED FILE SIZE ------
	SetFilePointer(hFile,sizeof(FirstBytes),NULL,FILE_BEGIN);
	SetEndOfFile(hFile);

	CloseHandle(hFile);
	return 0;
}
