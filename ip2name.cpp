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
#include <fstream>
#include <string>
#include "globaldata.h"
#include "sync.h"
#include "library.h"
#include "dates.h"
#include "LookupIPRoutines.h"
#include "logfileConversion.h"
#include "ModulVer.h"
#include "zlib.h"
#include "pcre.h"

static stringBag cfgfiles;

using namespace std;

UnCompressMap uncompressmap;

//********************************************************************

static bool inBag(const stringBag &cfgfiles, const string &cfgname) { 
	for (stringBag::const_iterator it = cfgfiles.begin(); it != cfgfiles.end(); it++) 
		if (*it == cfgname)
			return true;
	return false;
}


//********************************************************************

static void Usage(const char *err) {
	cout << ProductName << " " << ProductVersion << 
#ifdef MUTEX
		"M"
#endif
#ifdef CRITSEC
		"C"
#endif
#ifdef  _WIN64
		<< "x64"
#endif
		<< endl;
	cout << Comments << endl;
	cout << "Copyright (C) " << LegalCopyright << endl << endl;
	if (err)
		cout << "ERROR: " << err << endl << endl;
	cout << "Uses ZLIB Version " << zlibVersion() << endl;	
	cout << "     PCRE Version " << pcre_version() << endl << endl;
	cout <<	"Usage: " << ProductName << " [options] <analog config file>" << endl; 
	cout << "Options:" << endl;
	cout << "  -t  Max count of concurrent DNS lookups (thread count) ";
	cout << "(def: " << DEFAULTTHREADS << ", max: " << MAXTHREADS << ")" << endl;
	cout << "  -v  Verbosity switch" << endl;
	cout << "  -r  Recursively visit all configuration files specified by CONFIGFILE command" << endl;
	cout << "  -n  NO subnet host lookups" << endl;
	cout << "  -l  Logfile spec, i.e. -l *.log" << endl;
	cout << "  -o  Output DNS cache filename (def: " << DEFAULTDNSFILENAME << ")" << endl;
	cout << "  -y  Dns server, i.e. -y 192.168.0.1" << endl;
	cout << "  -x  Number of lookup attempts (def: " << noOfTries << ") used with -y" << endl;
	cout << "  -m  Dns timeout in secs (def: " << dnsTimeout << ") used with -y" << endl;
	cout << "  -c  Convert IP addresses to domain names in logfiles.  Creates *.trans files" << endl;
	cout << "  -b  Bypass Reverse Loopup.  Use existing dnscache for logfile translation" << endl;
	cout << endl;
	exit(0);
}


//********************************************************************

static void addFileSpec(stringBag &logdir, const char *filespec) {
	char tmpbuf[256];
	if (processPercentDirectives(filespec, tmpbuf, sizeof(tmpbuf))) { 
		cerr << "Error in processing percent directives for logfile: " << filespec << endl;
		cerr << "      Ignoring logfile spec" << endl;
	}
	else
		logdir.push_back(tmpbuf);
}


//********************************************************************

static void setOutputFile(const char *filespec) {
	char tmpbuf[256];
	if (processPercentDirectives(filespec, tmpbuf, sizeof(tmpbuf))) {
		cerr << "Error in processing percent directives for dnsfile: " << filespec << endl;
		cerr << "      Using default dnsfile name: " << dnsfilespec << endl;
	}
	else
		::dnsfilespec = tmpbuf;
}


//********************************************************************
// Locate, Read, & Process Analog Configuration File Data

static void	ProcessAnalogConfigFile(const char *configFilename, stringBag &logdir) {
	char buffer[MAX_PATH];
	GetFullPathName(configFilename, sizeof(buffer), buffer, NULL);
	string cfgname = buffer;
	cfgfiles.push_back(cfgname);
	cout << "Opening Input File " << configFilename << " to extract log file location specs" << endl;

	ifstream infile;
	infile.open(configFilename, ios::in);
	if (!infile) {
		char errmsg[128];
		sprintf(errmsg, "Cannot open %s for input", configFilename);
		endItAll(errmsg);
	}

	// Must First Get TO Spec From Config File
	tospec = "-00-00-00:-00-00";
	char input[256];
	while (!infile.eof()) {
		infile.getline(input, sizeof(input));
		char *tmp = input + strspn(input, " \t");
		if (tmp == stristr(tmp, "to")) {
			tmp += strlen("to");
			tmp = stripComment(tmp);
			if (tmp == stristr(tmp, "off"))
				tospec = "-00-00-00:-00-00";
			else
				tospec = tmp;
			break;
		}
	}

	// Initialize Time Data with tospec now available
	initTimeData(tospec.c_str());

	// Reset to beginning of file
	infile.clear();
	infile.seekg(0);

	while (!infile.eof()) {
		infile.getline(input, sizeof(input));
		char *tmp = input + strspn(input, " \t");
		if (tmp == stristr(tmp, "logfile ")) {
			tmp += strlen("logfile ");
			tmp = getLogFileSpec(tmp);
			addFileSpec(logdir, tmp);
		}
		else if (tmp == stristr(tmp, "dnsgoodhours ")) {
			tmp += strlen("dnsgoodhours ");
			tmp += strspn(tmp, " \t");
			if ((maxAge = atoi(tmp) / 24) <= 0)
				maxAge = MAXDAYSGOOD;
		}
		else if (tmp == stristr(tmp, "dnsbadhours ")) {
			tmp += strlen("dnsbadhours ");
			tmp += strspn(tmp, " \t");
			if ((maxUnknownAge = atoi(tmp) / 24) <= 0)
				maxUnknownAge = MAXDAYSBAD;
		}
		else if (recursiveVisit && tmp == stristr(tmp, "configfile ")) {
			tmp += strlen("configfile ");
			tmp = rmquotes(tmp);
			char buffer[MAX_PATH];
			GetFullPathName(tmp, sizeof(buffer), buffer, NULL);
			string tmpname = buffer;
			if (!inBag(cfgfiles, tmpname))
				ProcessAnalogConfigFile(tmp, logdir);
		}
		else if (tmp == stristr(tmp, "dnsfile ")) {
			char tmpbuf[sizeof(input)];
			tmp += strlen("dnsfile ");
			tmp = rmquotes(tmp);
			if (processPercentDirectives(tmp, tmpbuf, sizeof(tmpbuf))) {
				cerr << "Error in processing percent directives for dnsfile: " << tmp << endl;
				cerr << "      Using default dnsfile name: " << dnsfilespec << endl;
			}
			else
				dnsfilespec = tmpbuf;
		}
		else if (tmp == stristr(tmp, "uncompress ")) {
			tmp += strlen("uncompress ");
			char *c_ziptype = getZipType(tmp, tmp);
			char *ztmp;
			if ((ztmp = strchr(c_ziptype, '.')) != NULL)
				c_ziptype = ztmp + 1;
			string ziptype = c_ziptype;
			char *cmdstr = getCmdStr(tmp);
			uncompressmap[ziptype] = cmdstr;
		}
	}
	infile.close();
}


//********************************************************************

static void getVersionInfo() {
	char prgmname[_MAX_PATH];
	GetModuleFileName(NULL, prgmname, sizeof(prgmname)/sizeof(prgmname[0]));
	ModuleVersion ver;
	if (ver.GetFileVersionInfo(prgmname)) {
		ProductName = ver.GetValue("ProductName");
		int major, minor, x, y;
		sscanf(ver.GetValue("ProductVersion").c_str(), "%d.%d.%d.%d", &major, &minor, &x, &y);
		char buffer[25];
		sprintf(buffer, "%d.%02d", major, minor);
		ProductVersion = buffer;
		Comments = ver.GetValue("Comments");
		LegalCopyright = ver.GetValue("LegalCopyright");
	}
}


//********************************************************************

static void reportElapsedTime(time_t starttime) {
	time_t finaltime;
	time(&finaltime);

	time_t duration = finaltime - starttime;
	time_t hours, minutes, secs;
	hours = duration / 3600;
	minutes = (duration - hours * 3600) / 60;
	secs = duration % 60;
	cout << "Elapsed Time: ";
	if (hours != 0) 
		cout << hours << " hr" << plural((int)hours) << ", " << minutes << " min" 
		<< plural((int)minutes) << ", ";
	else if (minutes != 0)
		cout << minutes << " min" << plural((int)minutes) << ", ";
	cout << secs << " sec" << plural((int)secs) << endl;
}


//********************************************************************

static void processCommandArguments(int argc, char *argv[], stringBag &logdir) {
	if (argc == 1)
		Usage(NULL);
	int i;
	for (i = 1; i < argc && argv[i][0] == '-'; i++)
	{
		if (_stricmp(argv[i] + 1, "v") == 0)
			verbose = true;
		else if (_stricmp(argv[i] + 1, "t") == 0) {
			if (i + 1 < argc) {
				maxThreadCount = atoi(argv[++i]);
				if (maxThreadCount <= 0 || maxThreadCount > MAXTHREADS) 
					Usage("Bad Thread Spec");
			}
			else
				Usage("No Thread Spec Found");
		}
		else if (_stricmp(argv[i] + 1, "y") == 0)
			if (i + 1 < argc)
				dnsserver = argv[++i];
			else
				Usage("No DNS Server Specified.");
		else if (_stricmp(argv[i] + 1, "x") == 0) {
			if (i + 1 < argc) {
				noOfTries = atoi(argv[++i]);
				if (noOfTries < 0) 
					Usage("Bad Number of Tries Spec");
			}
			else
				Usage("No Number of Tries Spec");
		}
		else if (_stricmp(argv[i] + 1, "m") == 0) {
			if (i + 1 < argc) {
				dnsTimeout = atoi(argv[++i]);
				if (noOfTries < 0) 
					Usage("Bad Timeout Spec");
			}
			else
				Usage("No Timeout Spec");
		}
		else if (_stricmp(argv[i] + 1, "n") == 0)
			::subNetLookup = false;
		else if (_stricmp(argv[i] + 1, "r") == 0)
			::recursiveVisit = true;
		else if (_stricmp(argv[i] + 1, "c") == 0)
			::convert = true;
		else if (_stricmp(argv[i] + 1, "b") == 0)
			::bypass = true;
		else if (_stricmp(argv[i] + 1, "l") == 0)
			if (i + 1 < argc)
				addFileSpec(logdir, argv[++i]);
			else
				Usage("No Logfile Specified");
		else if (_stricmp(argv[i] + 1, "o") == 0)
			if (i + 1 < argc)
				setOutputFile(argv[++i]);
			else
				Usage("No Output File Specified");
		else 
			Usage("Illegal Option");
	}
	if (::bypass && !::convert) 
		Usage("You specified Bypassimg Reverse Lookup and Not Converting Logfiles.\nWhat's the point?");
	if (logdir.size() == 0) {
		if (argc - i == 1) 
			configFilename = argv[i];
		else
			Usage("No Config File Specified");
	}
	else {
		if (argc - i == 1)
			configFilename = argv[i];
		else if (argc - i > 1)
			Usage("Too Many Config Files Specified");
	}
}

//********************************************************************

int main(int argc, char *argv[]) {
	time_t starttime;
	time(&starttime);

	getVersionInfo();

	stringBag logdir;
	processCommandArguments(argc, argv, logdir);

	cout << ProductName << " " << ProductVersion 
#ifdef MUTEX
		<< "M"
#endif
#ifdef CRITSEC
		<< "C"
#endif		
#ifdef  _WIN64
		<< "x64"
#endif
		<< endl;
	
	if (::configFilename)
		ProcessAnalogConfigFile(configFilename, logdir);

	if (!::bypass) {
		PerformRDNSFunction(dnsfilespec, logdir);
	}
	if (::convert) {
		PerformLogfileConversion(logdir);
	}

	reportElapsedTime(starttime);

	return 0;
}
