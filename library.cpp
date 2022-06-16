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
#include <ctype.h>
#include <string.h>
#include "globaldata.h"
#include "library.h"
#include "LookupIPRoutines.h"

using namespace std;

/**************************************************************/

bool nameOK(const char *str) {
  if (strlen(str) == 0)
	  return false;
  if (strcmp(str, UNKNOWNHOST) == 0)
	  return true;
  for (; *str; str++) {
	  char ch = (char)tolower(*str);
	  if (!strchr("abcdefghijklmnopqrstuvwxyz0123456789-._", ch)) 
		  return false;
  }
  return true;
}


/**************************************************************
 ** like strcpy, except guaranteed to work with overlapping 
 ** strings
 */

static inline void *strMove(void *d,void *s) {
	return memmove(d, s, strlen((const char *)s) + 1);
}


/**************************************************************
**  remove leading whitespace from a string
*/

char *rmlead(char *str) {
	char *obuf;
	if (str) {
		for (obuf = str; *obuf && isspace(*obuf); ++obuf)
			;
		if (str != obuf)
			strMove(str, obuf);
	}
	return str;
}


/**************************************************************
**  remove trailing whitespace from a string
*/

char *rmtrail(char *str) {
	size_t i;
	if (str && 0 != (i = strlen(str))) {
		while (--i >= 0) {
			if (!isspace(str[i]))
				break;
		}
		str[++i] = NULL;
	}
	return str;
}


/**************************************************************
**  remove leading AND trailing whitespace from a string
*/

char *trim(char *str) {
	return rmlead(rmtrail(str));
}

/**************************************************************
**  remove any double quote characters from around a string
*/

char *rmquotes(char *str) {
	str = trim(str);
	if (*str == '"')
		strMove(str, str + 1);
	if (*(str + strlen(str) - 1) == '"')
		*(str + strlen(str) - 1) = NULL;
	return str;
}


/**************************************************************
**  remove any parenthesis characters from around a string
*/

char *rmparen(char *str) {
	str = trim(str);
	if (*str == '(')
		strMove(str, str + 1);
	if (*(str + strlen(str) - 1) == ')')
		*(str + strlen(str) - 1) = NULL;
	return str;
}


/**************************************************************
**  utility function to remove any leading and trailing spaces and quotes
*/

static char *stripquotes(char *str, char **next) {
	char *tmp;
	for (tmp = str; isspace(*tmp); tmp++)
		;
	if (tmp != str)
		strMove(str, tmp);
	if (*str == '"') {
		for (tmp = str + 1; *tmp && *tmp != '"'; tmp++)
			;
		if (*tmp == '"')
			*++tmp = NULL;
	}
	else {
		for (tmp = str; !isspace(*tmp); tmp++)
			;
		if (*tmp == ' ')
			*tmp = NULL;
	}
	if (next)
		*next = tmp + 1;
	return rmquotes(str);
}

/**************************************************************
**  find the logfile specifier and remove any double quote characters
**  from that string
*/

inline char *getLogFileSpec(char *str) {
	return stripquotes(str, NULL);
}


/**************************************************************
**  find the zip file type specifier and remove any double quote characters
**  from that string
*/

inline char *getZipType(char *str, char *&next) {
	return stripquotes(str, &next);
}


/**************************************************************
**  Output Errmsg and terminate RDNSLOGS
*/

void endItAll(const char *errmsg) {
	cerr << errmsg << endl;
    cerr << ProductName << " Terminating" << endl;
	exit(1);
}


//********************************************************************
// A case insensitive substring search

const char *stristr( const char *str, const char *substr) {
	char *tmpstr = new char[strlen(str) + 1];
	if (!tmpstr)
		endItAll("Error in stristr memory allocation");
	strcpy(tmpstr, str);
	_strlwr(tmpstr);
	char *tmpsubstr = new char[strlen(substr) + 1];
	if (!tmpsubstr)
		endItAll("Error in stristr memory allocation");
	strcpy(tmpsubstr, substr);
	_strlwr(tmpsubstr);
	char *retval = strstr(tmpstr, tmpsubstr);
	delete []tmpstr;
	delete []tmpsubstr;
	if (retval == NULL)
		return NULL;
	return str + (retval - tmpstr);
}

//********************************************************************

int myatoi(const char *p) {
	int v = 0;
	for (int i = 0; i < 3 && isdigit(*p); i++, p++) 
		v = 10 * v + *p - '0';
	return v;
}

