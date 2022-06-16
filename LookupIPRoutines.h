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

#ifndef _LOOKUPIPROUTINES
#define _LOOKUPIPROUTINES

#include <string>
#include "globaltypes.h"
#include "globaldata.h"

using namespace std;

void PerformRDNSFunction(const string dnsfilespec, const stringBag &logdir);

#endif
