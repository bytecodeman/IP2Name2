# IP2NAME -- Performs Reverse DNS lookups on Text Files

![](https://i0.wp.com/cs.stcc.edu/wp-content/uploads/2018/01/ip2namewordcloud.png?fit=960%2C600&ssl=1)

IP2NAME
(formerly RDNSLOGS) is a windows application that scans files for IP
addresses and produces a cache file of their DNS Reverse Lookups.  The
program can be used with any text file that contains IP addresses. 
Through the use of multiple concurrent reverse DNS lookup threads, the
program quickly converts numeric IP addresses to their corresponding
host names.  IP2NAME is written in C++ for fast native mode execution.

The cache file produced by IP2NAME is a text file whose format is:
`timestamp IP_address name`  where the timestamp is the number of
minutes since the beginning of 1970, GMT (i.e., "Unix time" divided by
60), and the name is just \* if the address couldn't be resolved.  This
format should be compatible with most log analyzers.

IP2NAME has internal support for gzip compression and supports all other
external forms of file compression.  There is also an option
to  translate the IP addresses in files to their associated domain
names.

(08/03/2019) IP2NAME V7.0 x64 build  Built with [PCRE](http://www.pcre.org/) and [ZLIB](http://www.zlib.org/) Code.
----------------------------------------------------------------------------------------------------------------------------------------------

**V7.0 now has an improved IP Address regular expression pattern that
will give better and faster IP address recognition results.**

This build also has the option to translate the IP addresses in files to
their actual domain names! This operation is reported to be lightening
quick.  There two additional switches to enable this function:

-   -b  bypasses the long dns resolution if you already have a good dns
    cache file
-   -c  to do the actual translation.  The translation process will look
    at your specified input files and create .trans files of the same
    name in the same directory. Original files are not modified.

This build was made using the latest Visual Studio 2019 C++.  Please
consider purchasing this version.  It is stable and offers
many features and performance enhancements not found in the older
versions.

To purchase **IP2NAME Binary** through PayPal for \$9.99, click

\
![](https://www.paypalobjects.com/en_US/i/scr/pixel.gif){.jetpack-lazy-image
width="1" height="1"
srcset="data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7"}

![](https://www.paypalobjects.com/en_US/i/scr/pixel.gif){width="1"
height="1"}

To purchase **Source code for** IP2NAME (includes the binary)\
through PayPal for \$29.99, click

![](https://www.paypalobjects.com/en_US/i/scr/pixel.gif){.jetpack-lazy-image
width="1" height="1"
srcset="data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7"}

![](https://www.paypalobjects.com/en_US/i/scr/pixel.gif){width="1"
height="1"}

The source code reveals some great examples of how to perform
multithreading and thread synchronization, perform regular expression
operations using the pcre library, as well as how\
to do low level IP packet transmission and reception, all in C++ code.

Upon receipt of PayPal payment, a zip file of the package will be
immediately  emailed to you.  Installation of IP2NAME is
straightforward.  Unzip the  contents of the zip file, and copy
**rdnslogs.exe** into a convenient directory.

How to Use IP2NAME
------------------

The command line syntax is as follows:

    ip2name [options] <configuration filename>

  ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  Option          Description
  --------------- --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  -t threads      Max count of concurrent DNS lookups (thread count) (default:  20, maximum: 400)

  -v              Verbosity switch.  Use the -v switch only when you  want to monitor the state of IP2NAME.  It generates copious amounts of output and generally slows the program.

  -r              Recursively visit all configuration files specified by CONFIGFILE command

  -n              NO subnet host lookups.  Default is to perform the subnet host lookups.

  -l logfile      You specified a log file specification on the command line. i.e. -l c:\\logs\\\*.gz You can specify as many log file specs as can fit on a command line provided that each spec is preceded with a **-l**. If a log file spec contains a space, surround the spec with quotes. If a\
                  log file spec is made, a configuration file does **not** need to be specified.

  -o dnscache     You specify the desired DNS cache output filename.

  -y DNS server   Querying a specific DNS server.  Use this switch to specify a particular DNS server to query.  Not specifying the switch will make IP2NAME revert back to the default method of resolving names.

  -x max tries    Specifies the maximum number of attempts to resolve an IP address.  Specifying 0 forces an indefinite attempt toward resolving the IP address.  Works in conjunction with the **-y** switch. Default is 3 tries.

  -m timeout      Specifies the base timeout value for a lookup. If a lookup fails, the timeout value is doubled, up to a maximum of 60 secs, on the next and subsequent attempts.  Works in conjunction with the **-y** switch.  Default base timeout is 4 secs.

  -c              New in v6.0: Convert IP addresses to domain names in files. Creates \*.trans files. Original files are not modified.

  -b              New in v6.0: Bypass Reverse Lookup.  Used with -c switch.  Use existing dnscache for file translation.
  ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

If a configuration file is specified, command Line switches are
processed  **before** the configuration file.

Example 1:

    C:> ip2name -t 100 config.txt

This command line will read the config.txt file in the current directory
for  DNS related information and use up to 100 threads to resolve IP
addresses in log files.

Example 2:

    C:> ip2name

Displays a complete usage summary including version number and available
options.

Example 3:

    C:> ip2name -v -t 150 myconfig.txt

Read the file myconfig.txt for log file locations and use up to 150
threads to  resolve the IP addresses in those files.  Also, generate
debugging information  on the screen.

Example 4:

    C:> ip2name -l c:\logs\*.log -l "d:\log files\*.gz" -o mynewdns.txt -t 300

Reads all the \*.log files in the C:\\logs directory and all the \*.gz
files in  the "d:\\log files" directory to create a mynewdns.txt file in
the current directory  using 300 lookup threads.

Example 5:

    C:> ip2name -l c:\logs\*.log -t 300 -y 1.2.3.4 -c

Reads all the **\*.log** files in the C:\\logs directory to 
create/update a dns.txt file in the current directory using 300 lookup
threads  and directly communicating with a DNS server whose ip address
is 1.2.3.4.\
After this is done, go through these same .log files and create
corresponding  **.trans** files with IP addresses changed to their
domain names.

Example 6:

    C:> ip2name -l c:\logs\*.log -t 300 -y 1.2.3.4 -b

**ILLEGAL!** You specified to bypass the reverse dns lookup  process and
did not specify a -c to do a translation.

Example 7:

    C:> ip2name -l c:\logs\*.log -t 300 -y 1.2.3.4 -b -c

Reverse DNS lookup is bypassed.  The -y, -t switches are therefore 
ignored.  Only a translation is specified to go through all the 
**.log** files in the c:\\logs directory and  create **.trans** files 
in that same\
c:\\logs directory with IP addresses changed to domain names.

-   **LOGFILE** lines specify the directory locations of your log
    files.  You can have multiple LOGFILE commands.  RDNSLOGS will
    process each specified  directory.
-   **DNSFILE** command specifies the name of your DNS cache file.
-   **DNSGOODHOURS** specifies how many hours a successfully resolved
    IP  address is considered valid.
-   **DNSBADHOURS** specifies how many hours an unsuccessfully resolved
    IP  address needs to wait before attempting to resolve that IP
    address again.
-   **TO** specifies the final timestamp that will be considered in a
    log  file analysis.  It is used when the percent specifiers are used
    in log  file names.  If no TO command line is found, RDNSLOGS
    assumes the current  time when these programs are executed.
-   **UNCOMPRESS** specifies the external program to call if you want
    to  uncompress log files that are compressed using a format other
    than gzip.
-   **CONFIGFILE** command lines specify other configuration files to
    be  read processed.  If the -r command line switch is specified,
    these files will be processed by RDNSLOGS. The default is to **not**
    process this command line.

All other lines in the configuration file are ignored.

The following can be used as a sample configuration file:

    # Start of Sample Configuration File for RDNSLOGS

    # LOGFILE lines specify the directory locations of your log files. 
    # You can have multiple LOGFILE commands. 
    # RDNSLOGS will process each specified directory. 

    LOGFILE D:\WEBSITELOGS\W3SVC1\*.LOG
    LOGFILE D:\WEBSITELOGS\W3SVC1\*.GZ

    # DNSFILE command specifies the name of your DNS cache file. 

    DNSFILE dns.txt

    # DNSGOODHOURS specifies how many hours a successfully resolved IP address is considered valid. 

    DNSGOODHOURS 2880

    # DNSBADHOURS specifies how many hours an unsuccessfully resolved IP address needs to wait before attempting to resolve that IP address again. 

    DNSBADHOURS 336

    # CONFIGFILE command lines specify other configuration files to be read processed. 
    # If the -r command line switch is specified, these files will be processed by RDNSLOGS. 
    # The default is to not process this command line. 

    CONFIGFILE FileAliases.txt
    CONFIGFILE FileExcludes.txt

    # UNCOMPRESS specifies the external program to call if you want to uncompress log files that are 
    # compressed using a format other than gzip.

    UNCOMPRESS *.zip ("winzip32 -e filename[.zip])

    # TO specifies the final timestamp that will be considered in a log file analysis. 
    # It is used when the percent specifiers are used in log file names. 
    # If no TO command line is found, RDNSLOGS assumes the current time when these programs are executed. 

    TO +00+00+00:0000

    # End of Sample Configuration File for RDNSLOGS

It would be advantageous to use the output produced by IP2NAME as a way
to monitor  its progress.   When scheduling IP2NAME, use the **cmd /c**
command to allow for output redirection.  For instance, the following
command in the windows scheduler:

    cmd /c "ip2name.exe -t 100 config.txt > progress.txt"

will cause output to be redirected into a file called
**progress.txt**.  You may periodically view the file to see the state
of ip2name.  **Note:  When scheduling ip2name , redirection is not
possible without the cmd /c.**

Disclaimer
----------

You agree to use it at your own risk.  This software is under no
warranty.  The author assumes no liability in the event of any loss of
data, time, and/or money.
:::
