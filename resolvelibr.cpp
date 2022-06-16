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
#include <stdio.h>
#include "globaldata.h"
#include "sync.h"
#include "LookupIPRoutines.h"
#include "library.h"
#include "resolvelibr.h"
#include "querydns.h"

//***************************************************************************************

int querydns(const char *dnsserver, const char *szQuery, char *host, WORD hostlen) {
	char szQueryBuffer[255] = { 0 };
	char Qbuf[BUFSIZE]={0};
	int nRC; 
	struct in_addr i_addr;

	syncVerboseMessages("Querying %s for %s\n", dnsserver, szQuery);

	memset(&i_addr, 0, sizeof(i_addr));
	if (!isdotip(szQuery))
		strncpy(host, szQuery, hostlen);
	else if (strlen(szQuery) < sizeof(szQueryBuffer) - 13) {
        i_addr.s_addr = htonl(inet_addr(szQuery));
		strncpy(szQueryBuffer, inet_ntoa(i_addr), 25);
		strcat(szQueryBuffer, ".IN-ADDR.ARPA");
		nRC = DNS_Query(szQueryBuffer, dnsserver, Qbuf);
		if (nRC > 0) {
			if (grabPTRRecord(Qbuf, nRC, host, hostlen))
                return 1;
		}
		else {
			syncVerboseMessages("DNS Query Failed with Error Code %d\n", nRC);
			return 1;
		}
	}
	else {
		syncVerboseMessages("Buffer OverFlow Found with %s \n", szQuery);
		return 1;
	}	
	return 0;
}

//***************************************************************************************

int DNS_Query(const char *pszQuery, const char *pszServer, char *achBufIn) {
	HEADER *pDNShdr;
	SOCKET s = NULL;
	struct sockaddr_in stSockAddr;
	struct sockaddr_in recSockAddr;
	int recSockAddrLen = sizeof(recSockAddr);
	char achBufOut[BUFSIZE]={0};
	int nQueryLen, nRC = 1, nWSAErr;
    struct hostent *pHostEnt;

	try {
		memset(&stSockAddr,0,sizeof(stSockAddr));
		stSockAddr.sin_family=AF_INET;
		stSockAddr.sin_port=htons(IPPORT_DNS);
		stSockAddr.sin_addr.s_addr=inet_addr(pszServer);
		if(stSockAddr.sin_addr.s_addr == INADDR_NONE){
			pHostEnt=gethostbyname(pszServer);
			if(pHostEnt){
				stSockAddr.sin_addr.s_addr = *((u_long *)pHostEnt->h_addr_list[0]);
			}
			else{
				throw -2;
			}
		}
		
		s=socket(AF_INET,SOCK_DGRAM,0);
		if(s==INVALID_SOCKET){
			syncVerboseMessages("socket() failed: %d\n",WSAGetLastError());
			throw -3;
		}

		// form the DNS query..
		pDNShdr=(HEADER *)&(achBufOut[0]);
		pDNShdr->id=htons(DNSID);        // request ID
		pDNShdr->rd=1;                    // recursion desired bit, makes life a LOT easier :-)
		pDNShdr->qdcount=htons(1);        // number of queries
		pDNShdr->ancount=0;               // answer    entries=0 this is a request
		pDNShdr->nscount=0;               // authority entries=0  ''    ''    ''
		pDNShdr->arcount=0;               // resource  entries=0  ''    ''    ''
		// put query name into QNAME for query
		// also, set the initial length of the query
		nQueryLen = PutQName(pszQuery,&(achBufOut[sizeof(HEADER)]));
		// add DNS header size to query length
		nQueryLen+=sizeof(HEADER);
		// QNAME entries are null terminated if we don't use
		// compression, which we don't here
		// add null to query length (nQueryLen++)
		achBufOut[nQueryLen++]=0;
		// set query type (QTYPE); T_A, T_PTR, T_MX, etc..
		*(unsigned short *)&achBufOut[nQueryLen]=htons(T_PTR);
		// set class type, for Internet use this will always be DNS_RRCLASS_IN
		*(unsigned short *)&achBufOut[nQueryLen+2]=htons(DNS_RRCLASS_IN);
		// update query length
		nQueryLen+=5;

        int tries, maxTime;
		for (tries = 1, maxTime = dnsTimeout; 
			 noOfTries == 0 || tries <= noOfTries; 
			 tries++, maxTime *= 2) { 
			nRC=sendto(s, achBufOut, nQueryLen, 0, (struct sockaddr *)&stSockAddr, sizeof(struct sockaddr_in));
			if(nRC==SOCKET_ERROR){
				syncVerboseMessages("sendto() failed, err: %d\n",WSAGetLastError());
				throw -4;
			}

			fd_set readfds;
			struct timeval timeout;
			if (maxTime > 60)
				maxTime = 60;
			timeout.tv_sec = maxTime;
			timeout.tv_usec = 0;
			FD_ZERO(&readfds);

#pragma warning( push )
#pragma warning(disable:4127)
			FD_SET(s, &readfds);
#pragma warning( pop )

	        if (select(0, &readfds, NULL, NULL, &timeout) < 0) {
				syncVerboseMessages("select failed, err: %d\n",WSAGetLastError());
				throw -5;
			}
			if (FD_ISSET(s, &readfds)) {
				nRC=recvfrom(s, (char *)achBufIn, BUFSIZE, 0, (struct sockaddr *)&recSockAddr, &recSockAddrLen );
				if (recSockAddr.sin_addr.s_addr != stSockAddr.sin_addr.s_addr) {
					syncVerboseMessages("Received Packet From Illegal Source!\n");
					throw -8;
				}
				if (nRC == SOCKET_ERROR){
					nWSAErr = WSAGetLastError();
					if (nWSAErr != WSAETIMEDOUT) {
						syncVerboseMessages("recvfrom() failed, err: %d\n", nWSAErr);
						throw -6;
					}
				}
				else
                    break;
				}
			else
				syncVerboseMessages( "recvfrom() attempt %d %d sec time out for lookup of %s.\n", tries, maxTime, pszQuery);
		}
		if (noOfTries != 0 && tries > noOfTries) {
			syncVerboseMessages( "recvfrom() repeatedly times out for lookup of %s. Bailing.\n", pszQuery);
			throw -7;
		}
		closesocket(s);
		return nRC;
	}
	catch (int e) {
		if (s)
			closesocket(s);
		return e;
	}
}


//***************************************************************************************

/*
  Extracts a QNAME from an RR. Compression is taken into  consideration.
*/
void GetQName(char *pszHostName, const char *p, const char *pOrigBuf)
{
  int i, j, k;
  unsigned short comp,pp;

  for(i=0;i<BUFSIZE;i++){
    j=*p;
	// QNAMEs are null terminated stop if found
    if(j==0)break;
    if(j&0xc0){ // the 0xC0 character denotes compression
	  // get location of the rest of QNAME
	  pp = *p;
	  pp = (pp-(pp & 0xc0)) * 256;
      comp=(*(p+1))+pp;
	  // call ourselves with the address of the rest
	  // of the string. Ain't recursion grand?
      GetQName(pszHostName,pOrigBuf+comp,pOrigBuf);
      return;
    }
	// j was a length indicator, copy j characters
    for(k=1;k<=j;k++){
      *pszHostName++=*(p+k);
    }
    if(*(p+j+1)){ // if not a null character
	  // put in a dot separator
      *pszHostName++ ='.';
    }
	// increment string pointer by j+1 characters
    p += j+1;
  }
  *pszHostName=0;
}

//***************************************************************************************
/*
  Here we take a domain name 'somemail.com' and turn
  it into a QNAME. Using this example, we'd end up with
  a string like this:

         8somemail3com\0
*/
int PutQName(const char *pszHostName, char *pQName) {
  int i,j=0,k=0;
  char c;

  for(i=0;*(pszHostName+i);i++){
	// grab a character from our host name
    c=*(pszHostName+i);
    if(c=='.'){ // we got a dot
	  // put character count into QNAME
      *(pQName+j)=(unsigned char)k;
	  // reset character count
      k=0;
	  // adjust character index
      j=i+1;
    }else{ // not dot, put character into QNAME
      *(pQName+i+1)=c;
	  // incrememt character count
      k++;
    }
  }
  // place last character count
  *(pQName+j)=(unsigned char)k;
  // null terminate the string
  *(pQName+i+1)=0;
  return(i+1);
}

//***************************************************************************************
/* 
   Since domain names CAN begin with a digit, I
   rolled this so that we can see if we are looking
   at a dotted-quad IP address or a domain name.
*/
int isdotip(const char *p)
{
	int i=0, ret=1;
	size_t k = strlen(p);
	for (i=0; i<k; i++) {
		if ( (p[i]!='.') && (isalpha(p[i])) ) {
			ret=0;
			break;
		}
	}
	return (ret);
}
//

//***************************************************************************************

int grabPTRRecord(const char *Qbuf, int nRC, char *host, WORD hostlen) {
	HEADER *dr;
	DNS_RR_HDR *q;
	char *s;
	int ancount;

	// Do some paranoid checking on response packet
	dr = (HEADER *)Qbuf;
	if (ntohs(dr->id) != DNSID) // Is this are request id?
		return 1;
	if (dr->qr != 1)  // Is this a response packet?
		return 2;
	if (dr->rcode != 0)  // Is there a valid response from DNS server?
		return 3;
	ancount = ntohs(dr->ancount);
	if (ancount == 0) // Is there at least 1 answer RR?
		return 4;

	// Skip Query Portion of Packet
	s = (char *)Qbuf + sizeof(HEADER);
	while (s < Qbuf + nRC && *s++)
		;
	s += 4;  // Skip Question QType, QClass
	if (s >= Qbuf + nRC)  // Somehow exceeded packet size, bail!!!
		return 5;

	// Skip RR Name
	if (*s >= '\xC0') 
		s += 2;
	else {
		while(s < Qbuf + nRC && *s++) 
			;
		s++;
	}
	if (s >= Qbuf + nRC)  // Somehow exceeded packet size, bail!!!
		return 5;

	// Go through all answer RRs and find the first T_PTR one
	while (ancount) {
		q = (DNS_RR_HDR *)s;
		if (ntohs(q->rr_type) == T_PTR) {
			if (ntohs(q->rr_rdlength) >= hostlen) // No room in destination buffer
				return 6;
			GetQName(host, (char *)&q->rr_rdata, Qbuf);
			break;
		}
		ancount--;
	}
	return  ancount == 0 ? 7 : 0;
}
