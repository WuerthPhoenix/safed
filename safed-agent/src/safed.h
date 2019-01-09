/**********************************************************
 * SAFED for UNIX (Linux, Solaris, HP-UX)
 * Author: Wuerth-Phoenix s.r.l.,
 * made starting from:
 * Snare Epilog for UNIX (Linux and Solaris) version 1.1
 *
 * Author: InterSect Alliance Pty Ltd
 *
 * Copyright 2001-2006 InterSect Alliance Pty Ltd
 **********************************************************/

#include <sys/types.h> 
#include <sys/wait.h> 
#include <sys/errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <netdb.h>
#include <signal.h>
#include <pthread.h>
#include <limits.h>
#include <dirent.h>

//#include <regex.h>
#ifdef TLSPROTOCOL
	#include <wolfssl/ssl.h>
#endif

#include "webserver.h"
#include "Configuration.h"

#define CACHE_FILE_NAME "/var/log/safed/error.cache"
#define SOCKETSTATUSFILE "/var/log/safed/socket.status"
#define PIDFILE "/var/run/safed.pid"
#define PIDFILEAUDIT "/var/run/safedaudit.pid"
#define PIPEAUDIT "/tmp/safedpipe"


// safed inner functions ... here only to avoid warnings at compile time
void syslogdate(char *sdate, struct tm *cdate);

int fileHasChanged(LogFileData *f);

void getCurrentTime(struct tm *result);
void updateSequenceNumber(struct tm currentTime);
char* formatMsgForSyslog(const char* message, struct tm *currentTime);
void* sendLogThread(void* args);
int checkDataAvailableToReadOnSocket(int clientSocket);
void usage (char *exe);
int connectToServer();

