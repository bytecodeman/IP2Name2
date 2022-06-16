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

//C:\Temp\rdnslogs6_with_source\rdnslogs6_with_source\Release>rdnslogs -b -c -l test.log -l test2.txt -l ex*.log -l ex*.gz

#include <iostream>
#include <string>
#include <unordered_map>
#include <io.h>
#include "globaldata.h"
#include "sync.h"
#include "library.h"
#include "logfileConversion.h"
#include "zlib.h"
#include "pcre.h"

using namespace std;

static pcre *re_trans;
static pcre_extra *pe_trans;
static int *ovector_trans;
static int oveccount_trans;

static pcre *re_dns;
static pcre_extra *pe_dns;
static int *ovector_dns;
static int oveccount_dns;

typedef unordered_map< string, string > TranslationHostMap;
static TranslationHostMap hosts;

class mystring: public string {
public:
	mystring() {
		reserve(MAXLINELEN);
	}
};

static mystring templine;

//******************************************************************

static void ConvertIPs(TranslationHostMap &hosts, char *line) {
	int start = 0;
	templine.clear();
	while (pcre_exec(re_trans, pe_trans, line + start, (int)strlen(line + start), 0, 0, ovector_trans, oveccount_trans) >= 0) {
	    char IPAddress[16] = {0};
		strncpy(IPAddress, line + start + ovector_trans[2*2], ovector_trans[2*2 + 1] - ovector_trans[2*2]);	
		templine.append(line + start + ovector_trans[2*1], ovector_trans[2*1+1] - ovector_trans[2*1]);
		if (hosts.find(IPAddress) == hosts.end()) {
			templine.append("[");
			templine.append(line + start + ovector_trans[2*2], ovector_trans[2*2 + 1] - ovector_trans[2*2]);
			templine.append("]");
		}
		else {
			templine.append(hosts[IPAddress]);
		}
		start += ovector_trans[2 * 2 + 1];
	}
	templine.append(line + start);
	if (templine.length() < MAXLINELEN)
		strcpy(line, templine.c_str());
	else
		strncpy(line, templine.c_str(), MAXLINELEN - 1);
}


//******************************************************************

static bool isCompressedFile(const char *logfname) { 
	string tmp;
	FILE *fin = NULL;
	byte magicno[2] = {0};
	try {
		if (!(fin = fopen(logfname, "rb"))) {
			tmp = "Could not open input file with fopen ";
			tmp += logfname;
			throw tmp;
		}
		fread(magicno, sizeof(byte), 2, fin);
		if (fclose(fin)) {
			tmp = "Could not close input file with fclose ";
			tmp += logfname;
			throw tmp;
		}
	}
	catch (string &e) {
		cerr << e << endl;
	}
	try { fclose(fin); } catch (...) {}
	return magicno[0] == 0x1f && magicno[1] == 0x8b;
}

//******************************************************************

static int ProcessLogFile(const char *logfname, int &count) { 
	bool error = false;
	bool isCompressed = isCompressedFile(logfname);


	gzFile gzin = NULL;
	gzFile gzout = NULL;

	string tmp = logfname;
	tmp += ".trans";
	const char *transfname = tmp.c_str();

	char line[MAXLINELEN];
	count = 0;
	try {
		if (!(gzin = gzopen(logfname, "rb"))) {
			tmp = "Could not open input file ";
			tmp += logfname;
			throw tmp;
		}
		if (!(gzout = gzopen(transfname, (isCompressed ? "wb" : "wbT")))) {
			tmp = "Could not open output file ";
			tmp += transfname;
			throw tmp;
		}
		while (gzgets(gzin, line, MAXLINELEN)) {
			count++;
			ConvertIPs(hosts, line);
			gzputs(gzout, line);
		}
	}
	catch (string &e) {
		cerr << e << endl;
		error = true;
	}
	try { gzclose(gzin); } catch (...) {}
	try { gzclose(gzout); } catch (...) {}
	return error;
}

//********************************************************************

static void processFiles(const stringBag &files) {
	cout << "Starting Log File Translation Process" << endl;
	size_t filecount = files.size();
	for (int i = 0; i < filecount; i++) {
		cout << "Translating File " << (i + 1) << " of " << filecount << ": " << files[i] << "; Lines: ";
		int lines;
		ProcessLogFile(files[i].c_str(), lines);
		cout << lines << endl;
	}
}

//********************************************************************

static bool initpcre() {
	const char* pattern = "(.*?)(?<!\\d)((25[0-5]|2[0-4]\\d|1\\d{2}|[1-9]\\d|\\d)\\.(25[0-5]|2[0-4]\\d|1\\d{2}|[1-9]\\d|\\d)\\.(25[0-5]|2[0-4]\\d|1\\d{2}|[1-9]\\d|\\d)\\.(25[0-5]|2[0-4]\\d|1\\d{2}|[1-9]\\d|\\d))(?!\\d)";
	const char *pattern_dns =  "^\\d+\\s+(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})\\s+(.*)$";

	const char *error;
	int erroffset, errorcode, count;
	try {
		if ((re_trans = pcre_compile(pattern, 0, &error, &erroffset, NULL)) == NULL) {
			cerr << "PCRE compilation 3 failed at offset " << erroffset << ": " << error << endl;
			throw false;
		}
		pe_trans = pcre_study(re_trans, 0, &error);
		if (error != NULL) {
			cerr << "PCRE Study 3 Error: " << error << endl;
			throw false;
		}
		if ((errorcode = pcre_fullinfo(re_trans, pe_trans, PCRE_INFO_CAPTURECOUNT, &count)) != 0) {
			cerr << "PCRE Info 3 Error Code = " << errorcode << endl;
			throw false;
		}
		oveccount_trans = 3 * (count + 1);
		if ((ovector_trans = (int *)pcre_malloc(oveccount_trans * sizeof(int))) == NULL) {
			cerr << "PCRE Malloc 3 Error" << endl;
			throw false;
		}

		if ((re_dns = pcre_compile(pattern_dns, 0, &error, &erroffset, NULL)) == NULL) {
			cerr << "PCRE compilation 4 failed at offset " << erroffset << ": " << error << endl;
			throw false;
		}
		pe_dns = pcre_study(re_dns, 0, &error);
		if (error != NULL) {
			cerr << "PCRE Study 4 Error: " << error << endl;
			throw false;
		}
		if ((errorcode = pcre_fullinfo(re_dns, pe_dns, PCRE_INFO_CAPTURECOUNT, &count)) != 0) {
			cerr << "PCRE Info 4 Error Code = " << errorcode << endl;
			throw false;
		}
		oveccount_dns = 3 * (count + 1);
		if ((ovector_dns = (int *)pcre_malloc(oveccount_dns * sizeof(int))) == NULL) {
			cerr << "PCRE Malloc 4 Error" << endl;
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
	pcre_free(ovector_trans);
	pcre_free(pe_trans);
	pcre_free(ovector_dns);
	pcre_free(pe_dns);
}

//********************************************************************

static void visitSpecs(const stringBag &logdir) {
	stringBag files;
	for (int indx = 0; indx < (int)logdir.size(); indx++) {
		syncVerboseMessages("Visiting: %s\n", logdir[indx].c_str());
		char drive[_MAX_DRIVE], dir[_MAX_DIR];
		_splitpath(logdir[indx].c_str(), drive, dir, NULL, NULL );

		_finddata_t c_file;
		intptr_t hFile; 
		if( (hFile = _findfirst(logdir[indx].c_str(), &c_file )) == -1L ) {
			cout << "No files found using spec: " << logdir[indx].c_str() << endl;
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
}

//********************************************************************

static void ReadIP(TranslationHostMap &hosts, char *s) {
	if (pcre_exec(re_dns, pe_dns, s, (int)strlen(s), 0, 0, ovector_dns, oveccount_dns) < 0)
		return;

	char IPAddress[16] = {0};
	char hostname[MAXNAMELEN] = {0};

	strncpy(IPAddress, s + ovector_dns[1*2], ovector_dns[1*2 + 1] - ovector_dns[1*2]);
	strncpy(hostname, s + ovector_dns[2*2],  ovector_dns[2*2 + 1] - ovector_dns[2*2]);
	if (strcmp(hostname, UNKNOWNHOST)) {
		hosts[IPAddress] = hostname;
	}
}

//********************************************************************

static void ReadDNSFile(TranslationHostMap &hosts, const string &dnsFile) {
	FILE *in = fopen(dnsFile.c_str(), "r");
	if (!in) {
		cout << "Cannot Open DNS File for Translation Phase" << dnsFile << endl;
	}
	else {
		char line[MAXLINELEN];
		syncVerboseMessages("Reading %s ...\n", dnsFile.c_str());
		while (fgets(line, MAXLINELEN, in)) {
			ReadIP(hosts, line);
		}
		fclose(in);
		cout << "Read DNS File " << dnsFile << " containing " << hosts.size() << " valid IP addresses in Translation Phase." << endl;
	}
}

//********************************************************************

void PerformLogfileConversion(stringBag &logdir) {
	cout << "Starting Translation Phase on Files ..." << endl;

#ifdef MUTEX
	hsync = CreateMutex(NULL, false, NULL);
#endif
#ifdef CRITSEC
	InitializeCriticalSection(&sync);
#endif

	if (!initpcre())
		endItAll("Error: Could not initialize of PCRE in Translation Stage");
	// Read the DNS File and load the hosts map with that data
	ReadDNSFile(hosts, dnsfilespec);

	// Now Visit All Log File Specs
	visitSpecs(logdir);
	// Close up PCRE
	termpcre();

#ifdef MUTEX
	CloseHandle(hsync);
#endif
#ifdef CRITSEC
	DeleteCriticalSection(&sync);
#endif

	cout << endl;
}

