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

#ifndef _WRESOLVE_H
#define _WRESOLVE_H

#pragma pack( push, 1 )

#define ASCII_NULL  '\0'
#define MAXHOSTNAME 256
#define BUFSIZE     2048
#define DNSID		0x51AA	
#define IPPORT_DNS  53u

/* DNS Header Format
 *
 * All DNS Message Formats have basically the same structure
 *   (note that an RR (DNS Resource Record) is described in
 *   the other structures that follow this header description):
 *
 *        +--------------------------------+
 *        | DNS Header: <defined below>    |
 *        +--------------------------------+
 *        | Question:   type of query      |
 *        |   QNAME:    <see below>        |
 *        |   QTYPE:    2-octet RR type    |
 *        |   QCLASS:   2-octet RR class   |
 *        +--------------------------------+
 *        | Answer:     RR answer to query |
 *        +--------------------------------+
 *        | Authority:  RR for name server |
 *        +--------------------------------+
 *        | Additional: RR(s) other info   |
 *        +--------------------------------+
 *
 *  QNAME is a variable length field where each portion of the
 *   "dotted-notation" domain name is replaced by the number of
 *   octets to follow.  So, for example, the domain name
 *   "www.sockets.com" is represented by:
 *
 *         0                   1
 *   octet 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6
 *        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        |3|w|w|w|7|s|o|c|k|e|t|s|3|c|o|m|0|
 *        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * NOTE: The last section, "Additional," often contains records
 *  for queries the server anticipates will be sent (to reduce
 *  traffic).  For example, a response to an MX query, would
 *  usually have the A record in additional information.
 */

typedef struct {
	unsigned	short id;// :16;		/* query identification number */
			/* fields in third byte */
	unsigned	short rd :1;		/* recursion desired */
	unsigned	short tc :1;		/* truncated message */
	unsigned	short aa :1;		/* authoritive answer */
	unsigned	short opcode :4;	/* purpose of message */
	unsigned	short qr :1;		/* response flag */
			/* fields in fourth byte */
	unsigned	short rcode :4;	/* response code */
	unsigned	short unused :2;	/* unused bits (MBZ as of 4.9.3a3) */
	unsigned	short pr :1;		/* primary server req'd (!standard) */
	unsigned	short ra :1;		/* recursion available */
			/* remaining bytes */
	unsigned  short qdcount;// :16;	/* number of question entries */
	unsigned	short ancount;// :16;	/* number of answer entries */
	unsigned	short nscount;// :16;	/* number of authority entries */
	unsigned	short arcount;// :16;	/* number of resource entries */
} HEADER;

/* DNS Flags field values
 *
 *  bits:  0     1-4     5    6    7    8     9-11    12-15
 *       +----+--------+----+----+----+----+--------+-------+
 *       | QR | opcode | AA | TC | RD | RA | <zero> | rcode |
 *       +----+--------+----+----+----+----+--------+-------+
 *
 *  QR:     0 for query, and 1 for response
 *  opcode: type of query (0: standard, and 1: inverse query)
 *  AA:     set if answer from domain authority
 *  TC:     set if message had to be truncated
 *  RD:     set if recursive query desired
 *  RA:     set if recursion is available from server
 *  <zero>: reserved field
 *  rcode:  resulting error non-zero value from authoritative
 *           server (0: no error, 3: name does not exist)
 */
#define DNS_FLAG_QR 0x8000
#define DNS_FLAG_AA 0x0400
#define DNS_FLAG_TC 0x0200
#define DNS_FLAG_RD 0x0100
#define DNS_FLAG_RA 0x0080
#define DNS_RCODE_MASK  0x000F
#define DNS_OPCODE_MASK 0x7800

/* DNS Generic Resource Record format (from RFC 1034 and 1035)
 *
 *  NOTE: The first field in the DNS RR Record header is always
 *   the domain name in QNAME format (see earlier description)
 */
typedef struct dns_rr_hdr {
        u_short rr_type;        /* RR type code (e.g. A, MX, NS, etc.) */
        u_short rr_class;       /* RR class code (IN for Internet)*/
        u_long  rr_ttl;         /* Time-to-live for resource */
        u_short rr_rdlength;    /* length of RDATA field (in octets) */
        u_short rr_rdata;       /* (fieldname used as a ptr) */
} DNS_RR_HDR, *PDNS_RR_HDR, FAR *LPDNS_RR_HDR;


/*
 * Type values for resources and queries
 */
#define T_A		1		/* host address */
#define T_NS		2		/* authoritative server */
#define T_MD		3		/* mail destination */
#define T_MF		4		/* mail forwarder */
#define T_CNAME		5		/* canonical name */
#define T_SOA		6		/* start of authority zone */
#define T_MB		7		/* mailbox domain name */
#define T_MG		8		/* mail group member */
#define T_MR		9		/* mail rename name */
#define T_NULL		10		/* null resource record */
#define T_WKS		11		/* well known service */
#define T_PTR		12		/* domain name pointer */
#define T_HINFO		13		/* host information */
#define T_MINFO		14		/* mailbox information */
#define T_MX		15		/* mail routing information */
#define T_TXT		16		/* text strings */
#define	T_RP		17		/* responsible person */
#define T_AFSDB		18		/* AFS cell database */
#define T_X25		19		/* X_25 calling address */
#define T_ISDN		20		/* ISDN calling address */
#define T_RT		21		/* router */
#define T_NSAP		22		/* NSAP address */
#define T_NSAP_PTR	23		/* reverse NSAP lookup (deprecated) */
#define	T_SIG		24		/* security signature */
#define	T_KEY		25		/* security key */
#define	T_PX		26		/* X.400 mail mapping */
#define	T_GPOS		27		/* geographical position (withdrawn) */
#define	T_AAAA		28		/* IP6 Address */
#define	T_LOC		29		/* Location Information */
	/* non standard */
#define T_UINFO		100		/* user (finger) information */
#define T_UID		101		/* user ID */
#define T_GID		102		/* group ID */
#define T_UNSPEC	103		/* Unspecified format (binary data) */
	/* Query type values which do not appear in resource records */
#define T_AXFR		252		/* transfer zone of authority */
#define T_MAILB		253		/* transfer mailbox records */
#define T_MAILA		254		/* transfer mail agent records */
#define T_ANY		255		/* wildcard match */


#define DNS_RRCLASS_IN  1
#define DNS_RRCLASS_CS  2
#define DNS_RRCLASS_CH  3
#define DNS_RRCLASS_HS  4

/* DNS SOA Resource Data Field
 *
 *  NOTE: First two fields not shown here.  They are:
 *    MNAME: QNAME of primary server for this zone
 *    RNAME: QNAME of mailbox of admin for this zone
 */
typedef struct dns_rdata_soa {
        u_long soa_serial;  /* data version for this zone */
        u_long soa_refresh; /* time-to-live for data (in seconds) */
        u_long soa_retry;   /* time between retrieds (in seconds) */
        u_long soa_expire;  /* time until zone not auth (in seconds) */
        u_long soa_minimum; /* default TTL for RRs (in seconds) */
} DNS_RDATA_SOA, PDNS_RDATA_SOA, FAR *LPDNS_RDATA_SOA;


/* DNS WKS Resource Data Field (RFC 1035)
 *
 *  NOTE: The bitmap field is variable length, with as many
 *   octets necessary to indicate the bit field for the port
 *   number.
 */
typedef struct dns_rdata_wks {
        u_long wks_addr;      /* IPv4 address */
        u_char wks_protocol;  /* Protocol (e.g. 6=TCP, 17=UDP) */
        u_char wks_bitmap;    /* e.g. bit 26 = SMTP (port 25) */
} DNS_RDATA_WKS, *PDNS_RDATA_WKS, FAR *LPDNS_RDATA_WKS;


/* DNS MX Resource Data Field
 */
typedef struct dns_rdata_mx {
        u_short mx_pref;     /* Preference value */
        u_short mx_xchange;  /* QNAME (field used as ptr) */
} DNS_RDATA_MX, *PDNS_RDATA_MX, FAR *LPDNS_RDATA_MX;

int DNS_Query(const char *, const char *, char *);
int isdotip(const char *p);
void GetQName(char *,const char *, const char *);
int PutQName(const char *,char *);
int grabPTRRecord(const char *Qbuf, int nRC, char *host, WORD hostlen);

/* END WRESOLV.H */
#pragma pack( pop )
#endif
