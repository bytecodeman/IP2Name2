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

#ifndef __MODULEVER_H
#define __MODULEVER_H

#ifndef WINDOWS_LEAN_AND_MEAN
#define WINDOWS_LEAN_AND_MEAN
#endif
#include <Windows.h>
#include "LookupIPRoutines.h"

// tell linker to link with version.lib for VerQueryValue, etc.
#pragma comment(linker, "/defaultlib:version.lib")

//////////////////
// ModuleVersion version info about a module.
// To use:
//
// ModuleVersion ver
// if (ver.GetFileVersionInfo("_T("mymodule))) {
//		// info is in ver, you can call GetValue to get variable info like
//		CString s = ver.GetValue(_T("CompanyName"));
// }
//
class ModuleVersion : public VS_FIXEDFILEINFO {
protected:
	BYTE* m_pVersionInfo;	// all version info

	struct TRANSLATION {
		WORD langID;			// language ID
		WORD charset;			// character set (code page)
	} m_translation;

public:
	ModuleVersion();
	~ModuleVersion();

	bool GetFileVersionInfo(const char *modulename);
	string GetValue(const char *key);
};

#endif
