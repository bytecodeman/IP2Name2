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

#include <iostream>
#include "sync.h"
#include "globaldata.h"

HANDLE hEvent;

#ifdef MUTEX
HANDLE hsync;
HANDLE hmapsync;
HANDLE hmutex;
#endif
#ifdef CRITSEC
CRITICAL_SECTION sync;
CRITICAL_SECTION mapsync;
CRITICAL_SECTION mutex;
#endif

//********************************************************************

void syncVerboseMessages(const char *fmt, ...) {
	if (!verbose)
		return;
#ifdef MUTEX
	WaitForSingleObject(hsync, INFINITE);
#endif
#ifdef CRITSEC
	EnterCriticalSection(&sync);
#endif

	va_list ap;
	va_start(ap, fmt);
	for (const char *p = fmt; *p; p++) {
		if (*p != '%') {
			cout << *p;
			continue;
		}
		DWORD ival;
		const char *sval;
		switch (*++p) {
		case 'd':
		case 'i':
			ival = va_arg(ap, int);
			cout << ival;
			break;
		case 's':
			sval = va_arg(ap, const char *);
			cout << sval;
			break;
		default:
			putchar(*p);
			break;
		}
	}
	va_end(ap);
#ifdef MUTEX
	ReleaseMutex(hsync);
#endif
#ifdef CRITSEC
	LeaveCriticalSection(&sync);
#endif
}
