/*
 * misc.h
 *
 *  Created on: Dec 10, 2010
 *      Author: marco
 */

#ifndef CONFIGURATION_H_
#define CONFIGURATION_H_

#include <netdb.h>
#include <stdio.h>
#include <limits.h>
#include <regex.h>
#include "Misc.h"

#ifdef TLSPROTOCOL
	#include <wolfssl/ssl.h>
#endif

#define CONFIG_FILENAME "/etc/safed/safed.conf"
#define MAX_AUDIT_CONFIG_LINE	8192
#define MAX_HOSTID		256	// Host identifier - usually the fully qualified hostname.

#define	CONFIG_OBJECTIVES	2
#define CONFIG_INPUT		3
#define CONFIG_OUTPUT		4
#define	AUDIT_CONFIG_OBJECTIVES	5
#define CONFIG_HOSTID		6
#define CONFIG_REMOTE		7
#define CONFIG_LOG			8
#define CONFIG_END			9
#define	CONFIG_WATCH	   10

#define TIMEOUT			100000000			// default time, in nanoseconds, to wait between checks of the log files (0.1 sec)
#define MAXMSGSIZE		2048
#define MAXDAYSINCACHE 2
#define LOG_FILE_TO_KEEP 3
#define LOGFILE_DIR "/var/log/safed"
#define LOGFILE_NAME "safed.log"
#define DEFAULT_LOG_LEVEL 1
#define LOG_LEVELS 4
#define CONFIG_FILEDIR "/etc/safed"

#define SIZE_OF_RESTRICTIP               2048
#define MAX_RESTRICTIP               10 //max 10 allowed hosts

#define CRITICALITY_CLEAR	0
#define CRITICALITY_INFO	1
#define CRITICALITY_WARNING 2
#define CRITICALITY_PRIORITY 3
#define CRITICALITY_CRITICAL 4

#define	RETURNCODE_FAILURE	0
#define RETURNCODE_SUCCESS	1
#define RETURNCODE_ANY		999





/****************************************************************/
/*       Data about the syslog server and its connection        */
/****************************************************************/
typedef struct _hostnode {
	int socket;
	struct sockaddr_in socketAddress;
	socklen_t dest_addr_size;
	time_t last_error;
	char desthost[MAX_HOSTID];
	int port;
	int protocol;
	char protocolName[MAX_HOSTID];
#ifdef TLSPROTOCOL
	WOLFSSL* ssl;
#endif
} HostNode;



/* the following functions are needed mainly in order to parse the configuration file */
void trim(char *string);
int getWaitTime(char *string);
int	getport(char *string);
char* getconfstring(char *string, char *file,int length);
int getSyslogPriority(char *string);
int getMaxMsgSize(char *string);
int getSetAudit(char *string);
int getMaxDaysInCache(char *string);

int iscomment(char * line);
int isheader(char *string);
int islog(char *string);
int isnetwork(char *string);
int iswaittime(char *string);
int issyslog(char *string);
int ismaxmsgsize(char *string);
int issetaudit(char *string);
int isdays(char *string);
int isLastSetTime(char *string);
int isLogLevel(char *string);

int regmatchInsensitive(const char *string, const char *pattern);
int getheader(char *string);
int splitobjective(char *string, char *regexp, int *excludematchflag);
int splitwatch(char *string, char *regexp, int *excludematchflag,int *newfile);
int split_audit_objective(char *string, char *event, char *user, char *match, int *excludeflag, int *excludematchflag, int *returncode);

int readConfigurationFile();
int findDirFileName(char *dirpath, char* filename, regex_t *comparePattern);

/*****************************************************/
/* data type definition to handle log file data */
/*****************************************************/
typedef struct _logFileDataElement {
	char fileName[MAX_AUDIT_CONFIG_LINE];
	char dirName[MAX_AUDIT_CONFIG_LINE];

	// File stream on which the file is open; -1 if it's not open.
	FILE *fs;

	// partial msg storage
	char pmsg[LOGBUFSIZE];


	// Attributes of the file the last time we checked.
	off_t size;

#if defined(__hpux__) || defined(_AIX)
	time_t mtime;
#else
	struct timespec mtime;
#endif

	dev_t dev;
	ino_t ino;
	mode_t mode;

	// When did the last error occur (zero means no error)
	time_t last_error;

	struct _logFileDataElement *next;
	regex_t regexp;//in case of format file in directory
	int dirCheck;
	int isCorrectFormat;
} LogFileData;

void openLogFile(LogFileData *element);
void openLogFiles();

/*****************************************************/
/* data type definition to handle the matching rules */
/*****************************************************/
typedef struct _matchingRuleElement {
	int excludematchflag;
	char regexpSource[PATH_MAX];
	regex_t regexpCompiled;
	struct _matchingRuleElement *next;
} MatchingRule;

/*
 * Checks if the given argument, matches any of the regex defined in the MatchinRule list.
 * If a match is found, 1 is returned, otherwise 0 is returned.
 */
int checkObjective(char *item);


void destroyList(void);

#endif /* CONFIGURATION_H_ */
