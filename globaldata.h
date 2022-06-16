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

#ifndef _GLOBALDATA
#define _GLOBALDATA

#include <time.h>
#include <string>

using namespace std;

const int DEFAULTTHREADS = 20;
const int MAXTHREADS = 400;
const int MAXDAYSGOOD = 90;
const int MAXDAYSBAD = 14;
const int MAXNAMELEN = 256;
const int MAXLINELEN = 8192;
const char *const UNKNOWNHOST = "*";
const char *const DEFAULTDNSFILENAME = "dns.txt";

extern bool verbose;
extern bool modified;
extern bool subNetLookup;
extern int maxThreadCount;
extern bool recursiveVisit;
extern bool bypass;
extern bool convert;
extern char *configFilename;
extern int threadCount;
extern string dnsserver;
extern int dnsTimeout;
extern int noOfTries;
extern time_t maxAge;
extern time_t maxUnknownAge;
extern string dnsfilespec;
extern string tospec;

extern string ProductName;
extern string ProductVersion;
extern string Comments;
extern string LegalCopyright;

#endif
