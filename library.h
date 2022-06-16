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

#ifndef _LIBRARY
#define _LIBRARY

#ifndef WINDOWS_LEAN_AND_MEAN
#define WINDOWS_LEAN_AND_MEAN
#endif
#include <windows.h>

extern bool nameOK(const char *str);
extern char *rmlead(char *str);
extern char *rmtrail(char *str);
extern char *trim(char *str);
extern char *rmquotes(char *str);
extern char *rmparen(char *str);
extern void endItAll(const char *errmsg);
extern const char *stristr( const char *string, const char *substr);
extern int myatoi(const char *p);
extern inline char *getLogFileSpec(char *str);
extern inline char *getZipType(char *str, char *&next);

inline char *stripComment(char *str) {
	return getLogFileSpec(str);
}

inline char *getCmdStr(char *str) {
	return rmparen(str);
}

inline const char *plural(int x) {
	return x == 1 ? "" : "s";
}

inline void IPToString(DWORD ip, char s[]) {
	sprintf(s, "%u.%u.%u.%u", ip >> 24, (ip >> 16) % 256, (ip >> 8) % 256, ip % 256);
}

#endif
