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

#ifndef _DATE_H
#define _DATE_H

void initTimeData(const char *tospec);
bool processPercentDirectives(const char *tmp, char *tmpbuffer, int lentmpbuffer);

#endif
