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

#include <winsock2.h>
#include <Ws2tcpip.h>

#include <iostream>
#include <io.h>
#include <process.h>
#include "globaltypes.h"
#include "sync.h"
#include "globaldata.h"
#include "library.h"
#include "LookupIPRoutines.h"
#include "zlib.h"
#include "pcre.h"
#include "querydns.h"

using namespace std;

struct HostInfo {
	time_t lastLookup;
	char name[MAXNAMELEN];

	HostInfo() {
      time_t tm;
	  time(&tm);
	  tm /= 60;
	  lastLookup = tm;
	  strcpy(name, UNKNOWNHOST);
	}
};

typedef map< DWORD, HostInfo > HostMap;
typedef HostMap::const_iterator constHostMapIter;
typedef HostMap::iterator HostMapIter;

static HostMap hosts;

static pcre *re;
static pcre_extra *pe;
static int *ovector;
static int oveccount;

static pcre *re_dns;
static pcre_extra *pe_dns;
static int *ovector_dns;
static int oveccount_dns;

extern UnCompressMap uncompressmap;

//********************************************************************
// Extract all numerical IP addresses from a given string. New addresses 
// are added to the hosts map.
// 
// s --- The string from which addresses are to be extracted.

static void ExtractIPs(HostMap &hosts, const char *s) {
	int start_offset = 0;
	size_t slen = strlen(s);
	while (pcre_exec(re, pe, s, (int)slen, start_offset, 0, ovector, oveccount) >= 0) {
		DWORD tip = 0;
		int i;
		for (i = 0; i < 4; i++) {
			int b = myatoi(s + ovector[2*i + 2]);
			tip = (tip << 8) + b;
		}

		if (i >= 4 && hosts.find(tip) == hosts.end()) {
			HostInfo info;
			info.lastLookup = 0;
			info.name[0] = 0;
			hosts[tip] = info;
			modified = true;
		}

		start_offset = ovector[1];
	}
}


//********************************************************************

static void setHostMap(DWORD ip, const HostInfo &info) {
#ifdef MUTEX
	WaitForSingleObject(hmapsync, INFINITE);
#endif
#ifdef CRITSEC
	EnterCriticalSection(&mapsync);
#endif

	hosts[ip] = info;

#ifdef MUTEX
	ReleaseMutex(hmapsync);
#endif
#ifdef CRITSEC
	LeaveCriticalSection(&mapsync);
#endif
}


//********************************************************************

static bool getHostMap(DWORD ip, HostInfo &info) {
#ifdef MUTEX
	WaitForSingleObject(hmapsync, INFINITE);
#endif
#ifdef CRITSEC
	EnterCriticalSection(&mapsync);
#endif

	HostMapIter it = hosts.find(ip);
	bool retval = it != hosts.end();
	if (retval)
		info = it->second;

#ifdef MUTEX
	ReleaseMutex(hmapsync);
#endif
#ifdef CRITSEC
	LeaveCriticalSection(&mapsync);
#endif
	return retval;
}

//******************************************************************

static int doTheLookup(const char *ip, char* host, WORD hostlen) {
	if (dnsserver == "") {
		sockaddr_in tAddr;
		memset(&tAddr, 0, sizeof(sockaddr_in));
		tAddr.sin_family=AF_INET;
		tAddr.sin_addr.S_un.S_addr=inet_addr(ip);
		return getnameinfo((const struct sockaddr *)&tAddr, sizeof(sockaddr_in), host, hostlen, 0, 0, NI_NAMEREQD);
	}
	else {
		return querydns(dnsserver.c_str(), ip, host, hostlen);
	}
}

//******************************************************************

static void LookupIP(LPVOID param) {
	HostInfo info;

	DWORD ip = (DWORD)param;
	char s[16];
	IPToString(ip, s);
	syncVerboseMessages("Looking up %s\n", s);

	if (!doTheLookup(s, info.name, sizeof(info.name)))
		syncVerboseMessages("Found %s for IP %s at %d\n", info.name, s, info.lastLookup);
	else if (subNetLookup) {
		HostInfo tmpinfo;
		DWORD tmpip;
		if (ip < 128 << 24)  // Class A IP
			tmpip = ip & (255 << 24);
		else if (ip < 192 << 24)  // Class B IP
			tmpip = ip & (65535 << 16);
		else // Class C IP
			tmpip = ip & (16777215 << 8);
		char tmps[16];
		IPToString(tmpip, tmps);
		if (!getHostMap(tmpip, tmpinfo)) {
			syncVerboseMessages("IP %s not found.  Attempting subclass search for IP %s\n", s, tmps);
			if (!doTheLookup(tmps, tmpinfo.name, sizeof(tmpinfo.name))) 
				syncVerboseMessages("Found subclass %s for IP %s\n", tmpinfo.name, tmps);
			else 
				syncVerboseMessages("Not Found subclass %s\n", tmps);
			setHostMap(tmpip, tmpinfo);
		}
		else {
			syncVerboseMessages("IP %s not found.  Using Found subclass IP %s\n", s, tmps);
		}
		info = tmpinfo;
	}

	setHostMap(ip, info);
	SetEvent(hEvent);
#ifdef MUTEX
	WaitForSingleObject(hmutex, INFINITE);
#endif
#ifdef CRITSEC
	EnterCriticalSection(&mutex);
#endif
	threadCount--;
#ifdef MUTEX
	ReleaseMutex(hmutex);
#endif
#ifdef CRITSEC
	LeaveCriticalSection(&mutex);
#endif
}


//******************************************************************

static int loadTmpMap(const char *logfname, HostMap &tmp) { 
	UnCompressMap::const_iterator pos;
	string cmdstr;
	for (pos = uncompressmap.begin(); pos != uncompressmap.end(); ++pos) {
		string ziptype = pos->first;
		if (_stricmp(&logfname[strlen(logfname) - strlen(ziptype.c_str())], ziptype.c_str()) == 0) {
			cmdstr = pos->second;
			break;
		}
	}
	if (cmdstr != "") {
		FILE *in;
		char command[256];
		if (cmdstr.length() + strlen(logfname) + 2 > sizeof(command))
			endItAll("Buffer Overflow on _popen command");
		sprintf(command, "%s %s", cmdstr.c_str(), logfname);
		if( (in = _popen( command, "rt" )) == NULL ) {
			cerr << "_popen error with command: " << command << endl;
			return 1;
		}
		char line[MAXLINELEN];
		while (fgets(line, MAXLINELEN, in)) 
			ExtractIPs(tmp, line);
		if (_pclose(in) == -1) {
			cerr << "Cannot Close Pipe File Spec: " << logfname << endl;
			return 1;
		}
	}
	else {
		char line[MAXLINELEN];
		gzFile gzin = gzopen(logfname, "rb");
		if (!gzin) {
			cerr << "Could not open file " << logfname << endl;
			return 1;
		}
		while (gzgets(gzin, line, MAXLINELEN)) 
			ExtractIPs(tmp, line);
		if (gzclose(gzin) != Z_OK) {
			cerr << "Cannot Close Compressed File Spec: " << logfname << endl;
			return 1;
		}
	}
	return 0;
}


//******************************************************************
// ReadLogfile 'logfname' and add DNS results to hosts

int ProcessLogFile(const char *logfname, int &addresses) {
	syncVerboseMessages("Opening: %s\n", logfname);
	HostMap tmp;

	syncVerboseMessages("Extracting IP addresses...\n");
	if (loadTmpMap(logfname, tmp))
		return 1;
	addresses = (int)tmp.size();

	// Now, lookup unknown hosts.
	HostMapIter pos;
	for (pos = tmp.begin(); pos != tmp.end(); ++pos) {
		HostInfo info;
		DWORD ip;
		ip = pos->first;
		if (getHostMap(ip, info))
			continue;
		WaitForSingleObject(hEvent, INFINITE);

		_beginthread(LookupIP, 0, (LPVOID)ip);

#ifdef MUTEX
		WaitForSingleObject(hmutex, INFINITE);
#endif
#ifdef CRITSEC
		EnterCriticalSection(&mutex);
#endif

		threadCount++;
		if (threadCount >= maxThreadCount)
			ResetEvent(hEvent);

#ifdef MUTEX
		ReleaseMutex(hmutex);
#endif
#ifdef CRITSEC
		LeaveCriticalSection(&mutex);
#endif
	}

	return 0;
}

//********************************************************************
// Read line from dns.txt.
//
// s --- The line from dns.txt.

static void ReadIP(HostMap &hosts, char *s) {
	static time_t now = 0;
	if (!now) {
		time(&now);
		now /= 60;
	}
	s[strlen(s)-1] = '\0';
	if (pcre_exec(re_dns, pe_dns, s, (int)strlen(s), 0, 0, ovector_dns, oveccount_dns) < 0)
		return;

	HostInfo info;
	s[ovector_dns[1*2+1]] = '\0';
	info.lastLookup = atol(s + ovector_dns[1*2]);

	DWORD tip = 0;
	int i;
	for (i = 2; i <= 5; i++) {
		int b = myatoi(s + ovector_dns[2*i]);
		tip = (tip << 8) + b;
	}

	// If parsing failed or it is a duplicate, discard this line.
	if (i <= 5 || hosts.find(tip) != hosts.end()) 
		return;

	s[ovector_dns[6*2 + 1]] = '\0';
	strncpy(info.name, s + ovector_dns[6*2], MAXNAMELEN);
	info.name[MAXNAMELEN - 1] = '\0';

	if (now - info.lastLookup > maxAge * 24*60 || 
		!strcmp(info.name, UNKNOWNHOST) && now - info.lastLookup > maxUnknownAge * 24*60) 
		return;

	hosts[tip] = info;
}

//********************************************************************

static void ReadDNSFile(HostMap &hosts, const string &dnsFile) {
	// Read known host names from dnsFile
	FILE *in = fopen(dnsFile.c_str(), "r");
	if (!in) {
		cout << "Cannot Open DNS File " << dnsFile << endl;
	}
	else {
		char line[MAXLINELEN];
		syncVerboseMessages("Reading %s ...\n", dnsFile.c_str());
		while (fgets(line, MAXLINELEN, in)) {
			ReadIP(hosts, line);
		}
		fclose(in);
		cout << "Read DNS File " << dnsFile << " containing " << hosts.size() << " IP addresses." << endl;
	}
}

//********************************************************************

static void WriteDNSFile(const HostMap &hosts, const string &dnsFileSpec) {
	if (!::modified) 
		return;
	char drive[_MAX_DRIVE];
	char dir[_MAX_DIR];
	char fname[_MAX_PATH];
	char ext[_MAX_EXT];
	_splitpath(dnsFileSpec.c_str(), drive, dir, fname, ext);
	char tmpname[_MAX_PATH], bakname[_MAX_PATH];
	sprintf(tmpname, "%s%s%s%s", drive, dir, "temp", ".tmp");
	sprintf(bakname, "%s%s%s%s", drive, dir, fname, ".bak");

	FILE *out = fopen(tmpname, "w");
	if (!out) {
		char errmsg[128];
		sprintf(errmsg, "Error: Could not open %s for writing", tmpname);
		endItAll(errmsg);
		return;
	}
	constHostMapIter pos;
	int count = 0;
	for (pos = hosts.begin(); pos != hosts.end(); ++pos) {
		HostInfo info;
		DWORD ip;
		ip = pos->first;
		info = pos->second;
		if (nameOK(info.name)) {
			count++;
			char s[16];
			IPToString(ip, s);
			if (fprintf(out, "%lld %s %s\n", info.lastLookup, s, info.name) < 0) {
				cerr << "Error while writing to " << tmpname << endl;
			}
		}
	}
	fclose(out);
	cout << "Writing: " << dnsFileSpec << " with " << count << " IP Addresses" << endl;

	if (remove(bakname) == -1) 
		syncVerboseMessages("ERROR Deleting Backup file: %s\n", bakname);
	else 
		syncVerboseMessages("Backup file: %s Deleted!!!\n", bakname);
	if (rename(dnsFileSpec.c_str(), bakname) == -1) 
		syncVerboseMessages("ERROR Renaming %s to %s\n", dnsFileSpec.c_str(), bakname);
	else 
		syncVerboseMessages("Renaming %s to %s Successful\n", dnsFileSpec.c_str(), bakname);
	if (rename(tmpname, dnsFileSpec.c_str()) == -1)
		syncVerboseMessages("ERROR Renaming %s to %s\n", tmpname, dnsFileSpec.c_str());
	else 
		syncVerboseMessages("Renaming %s to %s Successful\n", tmpname, dnsFileSpec.c_str());
}


//********************************************************************

static void processFiles(const stringBag &files) {
	cout << "Starting IP Address Reverse DNS Lookup Process" << endl;
	size_t filecount = files.size();
	for (int i = 0; i < filecount; i++) {
		cout << "Reverse IP Address Processing File " << (i + 1) << " of " << filecount << ": " << files[i] << "; IPs: ";
		int addresses;
		ProcessLogFile(files[i].c_str(), addresses);
		cout << addresses << endl;
	}
}

//********************************************************************

static void visitSpecs(const stringBag &logdir) {

#ifdef MUTEX
	hmapsync = CreateMutex(NULL, false, NULL);
	hmutex = CreateMutex(NULL, false, NULL);
#endif
#ifdef CRITSEC
	InitializeCriticalSection(&mutex);
	InitializeCriticalSection(&mapsync);
#endif

	hEvent = CreateEvent(NULL, true, true, NULL);

	stringBag files;
	for (int indx = 0; indx < (int)logdir.size(); indx++) {
		syncVerboseMessages("Visiting: %s\n", logdir[indx].c_str());
		char drive[_MAX_DRIVE], dir[_MAX_DIR];
		_splitpath(logdir[indx].c_str(), drive, dir, NULL, NULL );

		_finddata_t c_file;
		intptr_t hFile;
		if( (hFile = _findfirst(logdir[indx].c_str(), &c_file )) == -1L ) {
			cout << "No log files found using spec: " << logdir[indx].c_str() << endl;
		}
		else {
			do {
				char fname[_MAX_FNAME];
				char ext[_MAX_EXT];
				_splitpath(c_file.name, NULL, NULL, fname, ext );
				char tmpfile[_MAX_PATH];
				_makepath(tmpfile, drive, dir, fname, ext);
				files.push_back(tmpfile);
			} while( _findnext( hFile, &c_file ) == 0 );
		}
		_findclose( hFile );
	}

	processFiles(files);

	// Wait for all lookup threads to finish.
	while (threadCount) 
		Sleep(100);

	CloseHandle(hEvent);

#ifdef MUTEX
	CloseHandle(hmapsync);
	CloseHandle(hmutex);
#endif
#ifdef CRITSEC
	DeleteCriticalSection(&mapsync);
	DeleteCriticalSection(&mutex);
#endif
}

//********************************************************************

static bool initpcre() {
	const char *pattern = "(?<!\\d)(25[0-5]|2[0-4]\\d|1\\d{2}|[1-9]\\d|\\d)\\.(25[0-5]|2[0-4]\\d|1\\d{2}|[1-9]\\d|\\d)\\.(25[0-5]|2[0-4]\\d|1\\d{2}|[1-9]\\d|\\d)\\.(25[0-5]|2[0-4]\\d|1\\d{2}|[1-9]\\d|\\d)(?!\\d)";
	string tmp = "^(\\d+)\\s+";
	tmp += pattern;
	tmp += "\\s+(.*)$";
	const char *pattern_dns = tmp.c_str();

	const char *error;
	int erroffset, errorcode, count;
	try {
		if ((re = pcre_compile(pattern, 0, &error, &erroffset, NULL)) == NULL) {
			cerr << "PCRE compilation 1 failed at offset " << erroffset << ": " << error << endl;
			throw false;
		}
		pe = pcre_study(re, 0, &error);
		if (error != NULL) {
			cerr << "PCRE Study 1 Error: " << error << endl;
			throw false;
		}
		if ((errorcode = pcre_fullinfo(re, pe, PCRE_INFO_CAPTURECOUNT, &count)) != 0) {
			cerr << "PCRE Info 1 Error Code = " << errorcode << endl;
			throw false;
		}
		oveccount = 3 * (count + 1);
		if ((ovector = (int *)pcre_malloc(oveccount * sizeof(int))) == NULL) {
			cerr << "PCRE Malloc 1 Error" << endl;
			throw false;
		}

		if ((re_dns = pcre_compile(pattern_dns, 0, &error, &erroffset, NULL)) == NULL) {
			cerr << "PCRE compilation 2 failed at offset " << erroffset << ": " << error << endl;
			throw false;
		}
		pe_dns = pcre_study(re_dns, 0, &error);
		if (error != NULL) {
			cerr << "PCRE Study 2 Error: " << error << endl;
			throw false;
		}
		if ((errorcode = pcre_fullinfo(re_dns, pe_dns, PCRE_INFO_CAPTURECOUNT, &count)) != 0) {
			cerr << "PCRE Info 2 Error Code = " << errorcode << endl;
			throw false;
		}
		oveccount_dns = 3 * (count + 1);
		if ((ovector_dns = (int *)pcre_malloc(oveccount_dns * sizeof(int))) == NULL) {
			cerr << "PCRE Malloc 2 Error" << endl;
			throw false;
		}

		return true;
	}
	catch (bool) {
		return false;
	}
}


//********************************************************************

static void termpcre() {
	pcre_free(ovector);
	pcre_free(pe);
	pcre_free(ovector_dns);
	pcre_free(pe_dns);
}

//********************************************************************

void PerformRDNSFunction(const string dnsfilespec, const stringBag &logdir) {
	cout <<"Starting Reverse IP Lookup on Files ..." << endl;
	cout << "Number of lookup threads = " << ::maxThreadCount << endl;
	if (::dnsserver != "") {
		cout << "Using DNS Server: " << ::dnsserver << endl;
		cout << "  DNS Timeout: " << ::dnsTimeout << " secs" <<endl;
		cout << "  Number of Lookup Attempts: " << ::noOfTries << endl;
	}	
	if (::verbose) {
#ifdef MUTEX
		hsync = CreateMutex(NULL, false, NULL);
#endif
#ifdef CRITSEC
		InitializeCriticalSection(&sync);
#endif
	}
	// Initialize TCPIP stack
	WSADATA wsaData;
	if (WSAStartup(0x101, &wsaData))
		endItAll("Error: Could not initialize WinSock");
	if (!initpcre())
		endItAll("Error: Could not initialize Lookup PCRE Stage");
	// Read the DNS File and load the hosts map with that data
	ReadDNSFile(hosts, dnsfilespec);
	// Now Visit All Log File Specs
	visitSpecs(logdir);
	// Close up PCRE
	termpcre();
	// Close TCPIP stack
	WSACleanup();	
	WriteDNSFile(hosts, dnsfilespec);

	if (::verbose) {
#ifdef MUTEX
		CloseHandle(hsync);
#endif
#ifdef CRITSEC
		DeleteCriticalSection(&sync);
#endif
	}
	cout << endl;
}