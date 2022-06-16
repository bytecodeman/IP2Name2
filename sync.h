/**
 * RDNSLOGS 6.10
 * Performs Reverse DNS lookups on multiple logfiles.  
 * This program is designed to work with the Analog Logfile analyzer.
 *
 * Supports compressed files
 *
 * Antonio C. Silvestri
 * Springfield Technical Community College
 * 1 Armory Square
 * Springfield, MA  01105
 * silvestri@stcc.edu
 *
 * The latest program can be obtained from: http://www.stcc.edu/compsci/rdnslogs
 * 
 ***/

#ifndef _SYNC
#define _SYNC

#ifndef WINDOWS_LEAN_AND_MEAN
#define WINDOWS_LEAN_AND_MEAN
#endif
#include <windows.h>

//#define MUTEX
//#define CRITSEC

#if !defined(MUTEX) && !defined(CRITSEC)
#error Must Define Synchronization Method (MUTEX or CRITSEC)
#endif
#if defined(MUTEX) && defined(CRITSEC)
#error Cannot Define Both Synchronization Methods (MUTEX and CRITSEC)
#endif

#ifdef MUTEX
#pragma message( "MUTEX Build" )
#endif
#ifdef CRITSEC
#pragma message( "CRITICAL SECTION Build" )
#endif

extern HANDLE hEvent;

#ifdef MUTEX
  extern HANDLE hsync;
  extern HANDLE hmapsync;
  extern HANDLE hmutex;
#endif
#ifdef CRITSEC
  extern CRITICAL_SECTION sync;
  extern CRITICAL_SECTION mapsync;
  extern CRITICAL_SECTION mutex;
#endif

void syncVerboseMessages(const char *fmt, ...);

#endif
