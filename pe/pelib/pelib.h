/* pelib.h --

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
#pragma once
#define MAX_SECTION_NUM         20
//----------------------------------------------------------------
class PELibrary 
{
protected:
private:
public:
	DWORD					dwFileSize;
	DWORD					ROAddressOfEntryPoint;
	DWORD					EPSectionNum;
	IMAGE_DOS_HEADER		*image_dos_header;
	char					*pMem;
	IMAGE_NT_HEADERS		*image_nt_headers;
	IMAGE_SECTION_HEADER	*image_section_header[MAX_SECTION_NUM];
	char					*image_section[MAX_SECTION_NUM];
	char					*FirstBytes;
	PELibrary();
	~PELibrary();
	DWORD Offset2RVA(DWORD dwRO);
	PIMAGE_SECTION_HEADER ImageRvaToSection2(DWORD dwRVA);
	DWORD RVA2Offset(DWORD dwRVA);
	DWORD ImageROToSectionNum(DWORD dwRVA);
	PIMAGE_SECTION_HEADER ImageROToSection2(DWORD dwRO);
	DWORD PEAlign(DWORD dwTarNum,DWORD dwAlignTo);
	int OpenFileName(char* FileName);
	int SaveEP(LPSTR pOutputFile);
};
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
