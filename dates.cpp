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

#pragma warning( push )
#pragma warning(disable:4786)

#include <time.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include "dates.h"
#include "LookupIPRoutines.h"
#include "library.h"

const int FEB = 1;
const int DEC = 11;

static int year, month, date, hour, min;
static const char *cmonths[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
static const char *cdays[] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};


static inline int dow(int m, int d, int y) {
	y -= m < 3;
	return (y + y/4 - y/100 + y/400 + "-bed=pen+mad."[m] + d) % 7;
}

static inline bool isLeapYear(int nYear) {
  return ((nYear % 4 == 0) && (nYear % 100 != 0 || nYear % 400 == 0));
}

static inline void putc(char *&s, char c) {
	*s++ = c; 
}

static inline void put02d(char *&s, int d) {
	putc(s, (char)((d / 10) + '0'));
	putc(s, (char)((d % 10) + '0'));
}

static inline void put04d(char *&s, int d) {
	putc(s, (char)((d / 1000) + '0'));
	putc(s, (char)((d / 100) % 10 + '0'));
	putc(s, (char)((d / 10) % 10 + '0'));
	putc(s, (char)((d % 10) + '0'));
}

static inline void puts(char *&s, const char *t, int n) {
	int i;
	for (i = 0; i < n && *t; i++, t++)
		putc(s, *t);
	for (; i < n; i++)
		putc(s, ' ');
}


// Much of the logic and code found in the following function has been adapted from
// Stephen Turner's analog 5.24 dates.c source located at http://www.analog.cx/

static bool parsedate(time_t starttime, const char *s, int &y, int &m, int &d, int &h, int &n) {
  int monthlength[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
  tm *st;
  char *p;

  st = localtime(&starttime);
  if (isdigit(s[0]) && isdigit(s[1])) {
    y = 10 * (s[0] - '0') + (s[1] - '0');
    s += 2;
    y += 1900;
    if (y < 1970)
      y += 100;
  }
  else if (s[0] == '+' && isdigit(s[1]) && isdigit(s[2])) {
    y = st->tm_year + 1900 + 10 * (s[1] - '0') + (s[2] - '0');
    s += 3;
  }
  else if (s[0] == '-' && isdigit(s[1]) && isdigit(s[2])) {
    y = st->tm_year + 1900 - 10 * (s[1] - '0') - (s[2] - '0');
    s += 3;
  }
  else
    return true;

  if (isdigit(s[0]) && isdigit(s[1])) {
    m = 10 * (s[0] - '0') + (s[1] - '0') - 1;
    if (m > 11 || m < 0)
      return true;
    s += 2;
  }
  else if (s[0] == '+' && isdigit(s[1]) && isdigit(s[2])) {
    m = st->tm_mon + 10 * (s[1] - '0') + (s[2] - '0');
    s += 3;
  }
  else if (s[0] == '-' && isdigit(s[1]) && isdigit(s[2])) {
    m = st->tm_mon - 10 * (s[1] - '0') - (s[2] - '0');
    s += 3;
  }
  else
    return true;
  while (m < 0) {   /* need to do this now because about to use monthlength */
    m += 12;
    y--;
  }
  while (m > 11) {
    m -= 12;
    y++;
  }

  if (isdigit(s[0]) && isdigit(s[1])) {
    d = (int)strtol(s, &p, 10);
    if (d > 31 || d <= 0)
      return true;
    else if (d > (int)(monthlength[m]) + (m == FEB && isLeapYear(y)))
      d = monthlength[m] + (m == FEB && isLeapYear(y));
  }                   /* relative dates must be >= 2 digits but can be more */
  else if (s[0] == '+' && isdigit(s[1]) && isdigit(s[2]))
    d = st->tm_mday + (int)strtol(s + 1, &p, 10);
  else if (s[0] == '-' && isdigit(s[1]) && isdigit(s[2]))
    d = st->tm_mday - (int)strtol(s + 1, &p, 10);
  else
    return true;

  if (*p == ':') {  /* parse hour & minute */
    s = p + 1;
    if (isdigit(s[0]) && isdigit(s[1])) {
      h = 10 * (s[0] - '0') + (s[1] - '0');
      if (h > 23)
	return true;
      s += 2;
    }
    else if (s[0] == '+' && isdigit(s[1]) && isdigit(s[2])) {
      h = st->tm_hour + 10 * (s[1] - '0') + (s[2] - '0');
      s += 3;
    }
    else if (s[0] == '-' && isdigit(s[1]) && isdigit(s[2])) {
      h = st->tm_hour - 10 * (s[1] - '0') - (s[2] - '0');
      s += 3;
    }
    else
      return true;

    if (isdigit(s[0]) && isdigit(s[1])) {
      n = 10 * (s[0] - '0') + (s[1] - '0');
      if (n > 59)
	return true;
      s += 2;
    }
    else if (s[0] == '+' && isdigit(s[1]) && isdigit(s[2])) {
      n = st->tm_min + 10 * (s[1] - '0') + (s[2] - '0');
      s += 3;
    }
    else if (s[0] == '-' && isdigit(s[1]) && isdigit(s[2])) {
      n = st->tm_min - 10 * (s[1] - '0') - (s[2] - '0');
      s += 3;
    }
    else
      return true;

    if (s[0] != '\0')
      return true;
  }
  else if (*p == '\0') {
    h = 0;
    n = 0;
  }
  else
    return true;

  while (n < 0) {
    n += 60;
    h--;
  }
  while (n > 59) {
    n -= 60;
    h++;
  }
  while (h < 0) {
    h += 24;
    d--;
  }
  while (h > 23) {
    h -= 24;
    d++;
  }
  while (d < 0) {
    m--;
    if (m < 0) {   /* NB already adjusted m once above */
      m += 12;
      y--;
    }
    d += monthlength[m] + (m == FEB && isLeapYear(y));
  }
  while (d > (int)(monthlength[m]) + (m == FEB && isLeapYear(y))) {
    d -= monthlength[m] + (m == FEB && isLeapYear(y));
    m++;
    if (m > 11) {
      m -= 12;
      y++;
    }
  }

  return false;
}


//**************************************************************************************

void initTimeData(const char*tospec) {
  time_t starttime;
  time(&starttime);
  if (parsedate(starttime, tospec, ::year, ::month, ::date, ::hour, ::min)) {
	  char buf[128];
	  sprintf(buf, "Illegal TO string specified: %s\n", tospec);
	  endItAll(buf);
  }
}


//**************************************************************************************

bool processPercentDirectives(const char *tmp, char *tmpbuffer, int lentmpbuffer) {
	bool escape = false;
	bool error = false;
	char *ptr = tmpbuffer;
	char *end = tmpbuffer + lentmpbuffer - 1;

	for (;!error && *tmp && ptr < end; tmp++) {
		if (!escape) {
			if (end - ptr > 1) {
				if (*tmp != '%')
					putc(ptr, *tmp);
				else 
					escape = true;
			}
			else
				error = true;
		}
		else {
			escape = false;
			switch (*tmp) {
				case '%':
					putc(ptr, '%');
					break;
				case 'D': // %D  date of month
					if (end - ptr > 2)
						put02d(ptr, ::date);
					else
						error = true;
					break;
				case 'm': // %m  month name, in English
					if (end - ptr > 3)
						puts(ptr, cmonths[::month], 3);
					else
						error = true;
					break;
				case 'M': // %M  month number
					if (end - ptr > 2)
						put02d(ptr, ::month + 1);
					else
						error = true;
					break;
				case 'y': // %y  two-digit year
					if (end - ptr > 2)
						put02d(ptr, ::year % 100);
					else
						error = true;
					break;
				case 'Y': // %Y  four-digit year
					if (end - ptr > 4)
						put04d(ptr, ::year);
					else
						error = true;
					break; 
				case 'H': // %H  hour
					if (end - ptr > 2)
						put02d(ptr, ::hour % 100);
					else
						error = true;
					break;
				case 'n': // %n  minute
					if (end - ptr > 2)
						put02d(ptr, ::min % 100);
					else
						error = true;
					break;
				case 'w': // %w  day of week, in English
					if (end - ptr > 3)
						puts(ptr, cdays[dow(month + 1, date, year)], 3);
					else
						error = true;
					break;
			}
		}
	}

	putc(ptr, '\0');
	return error;
}
#pragma warning( pop ) 
