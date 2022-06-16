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

#ifndef _MXROUTINES
#define _MXROUTINES

#include "LookupIPRoutines.h"

int querydns(const char *dnsserver, const char *szQuery, char *host, WORD hostlen);

#endif

