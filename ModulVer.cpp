/**
* RDNSLOGS 7.0
* Performs Reverse DNS lookups on multiple logfiles.
* This program is designed to work with the Analog Logfile analyzer.
*
* Supports compressed files
*
* Antonio C. Silvestri
* tonysilvestri@bytecodeman.com
*
***/

#include "ModulVer.h"

ModuleVersion::ModuleVersion()
{
	m_pVersionInfo = NULL;				// raw version info data 
}

//////////////////
// Destroy: delete version info
//
ModuleVersion::~ModuleVersion()
{
	delete [] m_pVersionInfo;
}

//////////////////
// Get file version info for a given module
// Allocates storage for all info, fills "this" with
// VS_FIXEDFILEINFO, and sets codepage.
//
bool ModuleVersion::GetFileVersionInfo(const char *modulename) 
{
	m_translation.charset = 1252;		// default = ANSI code page
	memset((VS_FIXEDFILEINFO*)this, 0, sizeof(VS_FIXEDFILEINFO));

	// get module handle
	char filename[_MAX_PATH];
	HMODULE hModule = ::GetModuleHandle(modulename);
	if (hModule==NULL && modulename!=NULL)
		return false;

	// get module file name
	DWORD len = GetModuleFileName(hModule, filename, sizeof(filename)/sizeof(filename[0]));
	if (len <= 0)
		return false;

	// read file version info
	DWORD dwDummyHandle; // will always be set to zero
	len = GetFileVersionInfoSize(filename, &dwDummyHandle);
	if (len <= 0)
		return false;

	m_pVersionInfo = new BYTE[len]; // allocate version info
	if (!::GetFileVersionInfo(filename, 0, len, m_pVersionInfo))
		return false;

	LPVOID lpvi;
	UINT iLen;
	if (!VerQueryValue(m_pVersionInfo, "\\", &lpvi, &iLen))
		return false;

	// copy fixed info to myself, which is derived from VS_FIXEDFILEINFO
	*(VS_FIXEDFILEINFO*)this = *(VS_FIXEDFILEINFO*)lpvi;

	// Get translation info
	if (VerQueryValue(m_pVersionInfo,
		"\\VarFileInfo\\Translation", &lpvi, &iLen) && iLen >= 4) {
		m_translation = *(TRANSLATION*)lpvi;
	}

	return dwSignature == VS_FFI_SIGNATURE;
}

//////////////////
// Get string file info.
// Key name is something like "CompanyName".
// returns the value as a CString.
//
string ModuleVersion::GetValue(const char *key)
{
	string sVal;
	if (m_pVersionInfo) {

		// To get a string value must pass query in the form
		//
		//    "\StringFileInfo\<langID><codepage>\keyname"
		//
		// where <lang-codepage> is the languageID concatenated with the
		// code page, in hex. Wow.
		//
		char query[256];
		sprintf(query, "\\StringFileInfo\\%04x%04x\\%s", m_translation.langID,
			m_translation.charset, key);

		LPCTSTR pVal;
		UINT iLenVal;
		if (VerQueryValue(m_pVersionInfo, query, (LPVOID*)&pVal, &iLenVal)) {
			sVal = pVal;
		}
	}
	return sVal;
}
