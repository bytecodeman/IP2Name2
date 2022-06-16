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

#include "globaldata.h"
#include "sync.h"

int maxThreadCount = DEFAULTTHREADS;
time_t maxAge = MAXDAYSGOOD;
time_t maxUnknownAge = MAXDAYSBAD;
bool modified = false;
bool verbose = false;
bool subNetLookup = true;
bool recursiveVisit = false;
bool bypass = false;
bool convert = false;
char *configFilename = NULL;
int threadCount = 0;
string dnsserver = "";
int dnsTimeout = 4;
int noOfTries = 3;

string dnsfilespec = DEFAULTDNSFILENAME;
string tospec;

string ProductName, ProductVersion, Comments, LegalCopyright;

