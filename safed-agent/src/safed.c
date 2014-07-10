/**********************************************************
 * SAFED for UNIX (Linux, Solaris, HP-UX)
 * Author: Wuerth-Phoenix s.r.l.,
 * made starting from:
 * Snare Epilog for UNIX (Linux and Solaris) version 1.1
 *
 * Author: InterSect Alliance Pty Ltd
 *
 * Copyright 2001-2006 InterSect Alliance Pty Ltd
 *
 * Last Modified: 13/06/2006
 *
 **********************************************************
 *
 * Snare Epilog for UNIX is a cross platform agent designed
 * to monitor any given text file and report to one or more
 * SNARE servers.
 **********************************************************/

#include <sys/types.h> 
#include <sys/stat.h> 
#include <sys/wait.h> 
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <stdlib.h>
#include <strings.h>
#include <stdio.h>
#include <netdb.h>
#include <signal.h>
#include <limits.h>
#include <dirent.h>
#include <netdb.h>
#include <values.h>

#include <regex.h>

#include "safed.h"
#include "Configuration.h"
#include "webserver.h"
#include "MemoryCache.h"
#include "MessageFile.h"
#include "Misc.h"


#ifdef TLSPROTOCOL
	#include "SafedTLS.h"
	#include <gcrypt.h>
	GCRY_THREAD_OPTION_PTHREAD_IMPL;
#endif

#ifdef __hpux__
#include "getline.h"
#endif


// external variables from Configuration.c (configuration)
extern char hostname[MAX_HOSTID];
extern int remoteControlAllowed;
extern int remoteControlHttps;
extern int remote_webport;
extern char remoteControlIp[16];
extern char remoteControlPassword[256];
extern int maxMsgSize;
extern int maxDaysInCache;
extern int waitTime;
extern char USER_CONFIG_FILENAME[MAX_AUDIT_CONFIG_LINE];
extern char initStatus[100];
extern char lastSetTime[25];
extern int priority;			        // (PRI = FACILITY*8 + SEVERITY)
extern HostNode host;
extern int logFileToKeep;
extern int logLevel;

extern LogFileData *logFileHead;


char TLS[4]  = "tls";
int TLSFAIL = 0;
int TLSSERVERFAIL = 0;


// by default, it doesn't run as a daemon
int daemonize = 0;
int logToFile = 0;

// se abbiamo un solo thread a spedire i messaggi, a cosa serve questo MUTEX?
pthread_mutex_t send_mutex = PTHREAD_MUTEX_INITIALIZER; 

pthread_cond_t  log_data_available = PTHREAD_COND_INITIALIZER;


char cacheFileName[MAX_AUDIT_CONFIG_LINE] = CACHE_FILE_NAME;

// the actual day of the month,
int actualDay = 0;
// the sequence number for the messages, that is reset every day
int seqnum = 0;

// the file descriptors for the pipe used by the agent and the web server to communicate
int fds[2];


int agentpid = 0;				/* agent pid */
int webpid = 0;			        /* Web server process id */
int pidaudit = 0; 				/* audit process id */

FILE* auditFile = NULL;			/*pipe PIPEAUDIT */

// variables used by the signal handlers
sig_atomic_t continueloop = 1;
sig_atomic_t usr1 = 0;						/* variable that lets us know when a SIGUSR1 has been received */
sig_atomic_t usr2 = 0;

int restart = 0;

// forward declarations -- just to avoid compilation warnings
void initTLSAndUpdateStatus();
void deinitTLSsession();

void SIGINTandTERMHandler(sig) {
	// this to exit politely the main process loop
	continueloop = 0;
}

void SIGUSR1Handler(sig) {
	usr1 = 1;
}

void SIGUSR2Handler(int signum) {
	usr2 = 1;
}

/**
 * Masks the signals for the process, and sets the handlers for SIGTERM, SIGINT, SIGCHLD, SIGUSR1 and SIGUSR2.
 */
void setSignalHandlers() {
	sigset_t signalset;

	// add all the signals to the mask
	sigfillset(&signalset);

	// remove then the signals that we are going to handle and SIGALRM
	sigdelset(&signalset, SIGTERM);
	sigdelset(&signalset, SIGALRM);
	sigdelset(&signalset, SIGINT);
	sigdelset(&signalset, SIGUSR1);
	sigdelset(&signalset, SIGUSR2);

	// block all the signals in signalset
	sigprocmask(SIG_BLOCK, &signalset, NULL);

	struct sigaction action;
	memset(&action, 0, sizeof(action));

	action.sa_handler = SIGUSR1Handler;
	if (sigaction(SIGUSR1, &action, NULL) == -1) {
		sperror("sigaction SIGUSR1");
	}

	action.sa_handler = SIGUSR2Handler;
	if (sigaction(SIGUSR2, &action, NULL) == -1) {
		sperror("sigaction SIGUSR2");
	}

	action.sa_handler = SIGINTandTERMHandler;
	if (sigaction(SIGTERM, &action, NULL) == -1) {
		sperror("sigaction SIGTERM");
	}

	action.sa_handler = SIGINTandTERMHandler;
	if (sigaction(SIGINT, &action, NULL) == -1) {
		sperror("sigaction SIGINT");
	}
}


/*
 * Writes the given pid in the pidfile /var/run/safed.pid
 */
void writepid(int pid) {
	FILE *pidfile;
	if ((pidfile = fopen(PIDFILE,"w"))) {
		fprintf(pidfile,"%d\n",pid);
		fclose(pidfile);
	} else {
		sperror("... unable to open for writing the pid file");
	}
}


/**
 * @returns 1 if the command line arguments provided are correct, 0 otherwise.
 * It parses the command line and performs side effect on the global variables
 * verbose and USER_CONFIG_FILENAME.
 */
int checkArguments(int argc, char *argv[]) {
	// check the command line arguments, if any is provided
	if (argc > 5) {
		return 0;
	}
	int i = 1;
	while (i < argc) {
		if (strcmp(argv[i],"-c") == 0) {
			// the next argument is the alternative configuration file name
			i++;
			if (i == argc) {
				//filename missing
				return 0;
			}
			strncpy(USER_CONFIG_FILENAME, argv[i], MAX_AUDIT_CONFIG_LINE);
		} else if (strcmp(argv[i], "-d") == 0) {
			daemonize = 1;
			logToFile = 1;
		} else if (strcmp(argv[i], "-l") == 0) {
			logToFile = 1;
		} else {
			// invalid option
			return 0;
		}
		i++;
	}
	return 1;
}


void usage(char * exe) {
	if (!exe) {
		return;
	}
	printf("usage : %s [-c <USER_CONFIG_FILE_PATH>] [-d | -l]\n", exe);
	printf(" -c\tis used to specify an alternate config file\n");
	printf(" -d\tis used to run the agent as a daemon; in this case stdout and stderr are redirected to a log file\n");
	printf(" -l\tis used to redirect stdout and stderr to a log file when the agent is run on the foreground\n");
}


/* checks if data is available to read on the given file descriptor */
int checkDataAvailableToRead(int rfd) {
	if (webpid) {
		// timeout set to 0, the call to select returns immediately
		struct timeval timeout;
		timeout.tv_sec = 0;
		timeout.tv_usec = 0;

		fd_set readfds;
		FD_ZERO(&readfds);
		FD_SET(rfd, &readfds);
		// this call to select returns 1 if and only if there is data available to read on rfd
		int result = select(rfd+1, &readfds, NULL, NULL, &timeout);
		if (result == -1) {
			sperror("select");
		}
		return (result == 1);
	} else {
		// if there is no web server sending data, there is no data available to read!
		return 0;
	}
}


int forkChildWebServer() {
    // opening the pipe for the communication between the agent and the controlling web server
    if (pipe(fds) == -1){
        sperror("pipe");
        exit(-1);
    }

    // forking a child process for the web server
    int result = fork();
    if (result == 0) {
		slog(LOG_NORMAL, "... starting the web service with pid: %d\n", getpid());
		// the child closes all the open fds, except the standard ones, and the write end of the pipe
		closeAllOpenfds(fds[1]);
		// and then runs the web server
        initWebServer(remote_webport, remoteControlIp, remoteControlPassword);
        startWebServer();
        closeWebServer();
        slog(LOG_NORMAL, "... exiting the web service!\n");

        // at the end, before exiting, it closes also the write end
        close(fds[1]);
		exit(0);
	}
    // the parent (i.e. the agent process) closes the write end of the pipe
    close(fds[1]);
    return result;
}

/*
 * It kills the child web server sending it a SIGTERM, and then waits for its termination.
 * If all is fine, 0 is returned; in case of error, it returns -1.
 */
int killChildWebServer() {
    // stopping the web server
	if (webpid) {
		slog(LOG_NORMAL, "killing the child web server: %d ...\n", webpid);

		if (kill(webpid, SIGTERM) == -1) {
			sperror("killChildWebServer - kill");
			return -1;
		}

		int result;

		// a return of 0 means that the child is not yet terminated
		while ( (result = waitpid(webpid, NULL, WNOHANG)) == 0 ) {
			sleep(1);
		}

		if (result == -1) {
			sperror("killChildWebServer - waitpid");
			return -1;
		}

		webpid = 0;

	    // close the read end of the pipe
	    close(fds[0]);

		slog(LOG_NORMAL, "... web server %d killed\n", webpid);
	}

    return 0;
}

int restartChildWebServer() {
	if (killChildWebServer() == 0) {
		webpid = forkChildWebServer();
		slog(LOG_NORMAL, "web server started with pid %d\n", webpid);
		return 0;
	} else {
		slog(LOG_ERROR, "it wasn't possible to restart the web server\n");
		return -1;
	}
}

// returns -1 if error occurred during PIDFILEAUDIT openinig; 0 if atoi fails; 1 on success
int readAuditPid(){
	if (access(PIDFILEAUDIT, F_OK) == 0) {
		FILE *auditFile = fopen(PIDFILEAUDIT, "r");
		if (auditFile) {
			char *line = NULL;
			size_t len = 0;
			ssize_t read = 0;
			if ((read = getline(&line, &len, auditFile)) != -1) {
				pidaudit=atoi(line);
				slog(LOG_NORMAL, "... found auditing process  with pid: %d\n", pidaudit);
			}
			if (line) {
				free(line);
			}
			fclose(auditFile);
		} else {
			sperror("readAuditPid():fopen");
			return -1;
		}
		if(pidaudit == 0)return 0;
		return 1;
	}
	return -1;
}
//returns -1 if kill fails; 0 if pidaudit is 0 and 1 on success
int restartAudit(){
	if(pidaudit){
		if (kill(pidaudit, SIGUSR1) == -1) {
			slog(LOG_ERROR, "Restart Audit - kill: %d %s\n", pidaudit, strerror(errno));
			return -1;
		}
		slog(LOG_NORMAL, "... auditing process with pid: %d to be restarted...\n", pidaudit);
		pidaudit = 0;
		//Linux reinitializes the auditing process and dosn't restart it
		//AIX and Solaris do restart the auditing process
#if defined(_AIX) || defined(__sun)
		unlink(PIDFILEAUDIT);
#endif
	}else return 0;
	return 1;
}


void checkAudit(struct tm currentIterationTime){
	if (pidaudit) {
		if(auditFile){
			//the file descriptors for the audit pipe
			int fda = fileno(auditFile);
			if(fda == -1){
				fclose(auditFile);
				pidaudit = 0;
			}

			// if PID audit != 0 and audit pipe is open -> try to read from pipe and put to cache;
			char *auditLine = NULL;
			size_t len = 0;
			while (checkDataAvailableToRead(fda)) {
				if((getline(&auditLine, &len, auditFile) > -1)){
					if (auditLine) {
						trim(auditLine);
						seqnum++;
						Message *message = new_Message();
						message->msg = formatMsgForSyslog(auditLine, &currentIterationTime);
						message->year = currentIterationTime.tm_year + 1900;
						message->month = currentIterationTime.tm_mon + 1;
						message->day = currentIterationTime.tm_mday;
						message->seqnum = seqnum;

						putMsgToMemoryCache(message);

						slog(LOG_NORMAL, "... added the audit message to the memory cache: %s", message->msg);
						// signaling the sender thread that there are messages available to send
						pthread_cond_signal(&log_data_available);
						// getting back the memory allocated from heap to read the file
						free(auditLine);
						auditLine=NULL;
					}
				}else{
					fclose(auditFile);
					pidaudit = 0;
				}

			}
			if(auditLine) {
				// getting back the memory allocated from heap to read the file
				free(auditLine);
			}
		}else{
			// if PID audit != 0 and audit pipe is null -> reset PID audit;
			pidaudit = 0;
		}
	}else{
		// if PID audit = 0  -> try to open it and try to open the audit pipe;
		if(readAuditPid() > 0){
			auditFile = fopen(PIPEAUDIT, "r");
		}

	}


}

int main(int argc, char *argv[]) {
	// checking if safed is already running ...
	if (access(PIDFILE, F_OK) == 0) {
		slog(LOG_ERROR, "safed agent already running ... exiting!\n");
		exit (1);
	}

	if(readAuditPid() > 0){
		// if PID audit > 0  -> try to open the audit pipe;
		auditFile = fopen(PIPEAUDIT, "r");
	}

	// calculating the day of the month when the agent starts
	time_t startime;
	time(&startime);
	struct tm *t = localtime(&startime);
	actualDay = t->tm_mday;

	// getting the sequence number for the day
	seqnum = getInitialSeqNumber(t->tm_year+1900, t->tm_mon+1, actualDay);

	#ifndef DEBUG
	// The only user who can run the agent is root
	if (getuid() != 0) {
		printf("This program can only be run by root.\n");
		exit(1);
	}
	#endif

    if (!checkArguments(argc, argv)) {
        usage(argv[0]);
        exit(1);
    }

    // reads the configuration file; if some errors happens at this point, the process exits!
    readConfigurationFile();

    // stdout and stderr eventually go to the log file
    initLog(logToFile, logLevel, LOGFILE_DIR, LOGFILE_NAME);

    // inits the tls session, if required
    initTLSAndUpdateStatus();

    // daemonizing the agent ...
    if (daemonize) {
		agentpid = fork();
		if (agentpid > 0) {
			/* this is the parent process; it writes the pid of the child (the real agent process)
			 * and then terminates, and the child is inherited by the init process (process #1);
			 * writing the pid in the parent process avoids inserting arbitrary sleeps in the shell control code
			 * in order to be able to read the pid from the file just after the command returns. */
			writepid(agentpid);
			exit(0);
		} else if (agentpid == 0) {
			// this is the child process, I have to initialize the agent pid
			agentpid = getpid();

			// Change the file mode mask
			umask(0);

			// Creates a new SID for the child process, i.e. a new process group and session and detaches its controlling terminal
			pid_t sid = setsid();
			if (sid < 0) {
				exit(-1);
			}

			/* change the current working directory; this prevents the current directory
			 * from being locked; hence not being able to remove it. */
			if (chdir("/") < 0) {
				exit(-1);
			}

			// redirecting stdin from /dev/null
			freopen("/dev/null", "r", stdin);
		} else {
			// an error occured!
			sperror("fork");
			exit (-1);
		}
	} else {
		// the agent is not daemonized, and in the file I have still to write the pid
		agentpid = getpid();
	    writepid(agentpid);
	}

    if (remoteControlAllowed) {
        webpid = forkChildWebServer();
    }

    setSignalHandlers();

    // open and initialize the log file to monitor
    openLogFiles();

    // this is the period between checks of the log files
    struct timespec timeout;
    timeout.tv_sec = 0;
    timeout.tv_nsec = waitTime;
    
    // init sockets to set SOCKETSTATUSFILE
	connectToServer();

    // create the thread that reads the messages from the cache, and sends them to the syslog server
    pthread_t send_thread_id;
    int result = pthread_create(&send_thread_id, NULL, (void *)sendLogThread, NULL);
    if (result != 0) {
		slog(LOG_ERROR, " ... problems starting the thread to send the messages; pthread_create() returned: %d\n", result);
		exit(1);
	}
	
    slog(LOG_NORMAL, "Start checking the log files ...\n");
    // the main thread that actively checks the files for changes (the producer)
    while (continueloop) {
		if (usr1) {
			// got a SIGUSR1: I flush the logs and reset the flag
			slog(LOG_ERROR, "got SIGUSR1: now flushing stdout ...\n");
			flushLog();
			usr1 = 0;
		}

		if (usr2) {
			// got a SIGUSR2: changing the loglevel
			logLevel = (logLevel + 1) % LOG_LEVELS;
			setLogLevel(logLevel);
			slog(LOG_ERROR, "got SIGUSR2: now going into LOGLEVEL %d\n", logLevel);
			usr2 = 0;
		}

		// get the current date and time
	    struct tm currentIterationTime;
	    getCurrentTime(&currentIterationTime);

	    // if the day changes:
	    if (actualDay != currentIterationTime.tm_mday) {
	        // I have to reset the sequence number, and to update the day
	        actualDay = currentIterationTime.tm_mday;
	        seqnum = 0;
	        // the log should be rotated
	        rotateLog(LOGFILE_DIR, LOGFILE_NAME, logFileToKeep);
	        if (remoteControlAllowed) {
	        	restartChildWebServer();
	        }
	    }

		// checking all the log files for changes
		LogFileData *currentLogFile = logFileHead;
		while (currentLogFile) {
			char *logLine = NULL;
			size_t len = 0;

			if (fileHasChanged(currentLogFile) > 0) {
				while (getline(&logLine, &len, currentLogFile->fs) > -1) {
					trim(logLine);
					if (logLine && checkObjective(logLine)) {
						seqnum++;

						Message *message = new_Message();
						message->msg = formatMsgForSyslog(logLine, &currentIterationTime);;
						message->year = currentIterationTime.tm_year + 1900;
						message->month = currentIterationTime.tm_mon + 1;
						message->day = currentIterationTime.tm_mday;
						message->seqnum = seqnum;

						putMsgToMemoryCache(message);

						slog(LOG_NORMAL, "... added the message to the memory cache: %s", message->msg);
						// signaling the sender thread that there are messages available to send
						pthread_cond_signal(&log_data_available);
					}
				}
				if (logLine) {
					// getting back the memory allocated from heap to read the file
					free(logLine);
				}
			}
			currentLogFile = currentLogFile->next;
		}

		checkAudit(currentIterationTime);



		// suspending the current thread (the producer) for the specified time
		nanosleep(&timeout,NULL);
	}

    slog(LOG_NORMAL, "safed agent is exiting!\n");
    if(auditFile)
    	close(PIPEAUDIT);

    killChildWebServer();

    // closing politely the file cache
	closeMessageFile();
	destroyList();
	deinitTLSsession();
	unlink("/var/run/safed.pid");

	if (restart) {
		slog(LOG_NORMAL, "safed agent is restarting!\n");
		restartAudit();//reinitialize the auditing system
		// closing all open file descriptors, except the standard ones
		closeAllOpenfds(-1);
		execv(argv[0], argv);
	}

	return 0;
}


//TODO: questa funzione non e` utilizzata; andrebbe visto se ha senso in un'implementazione UDP, TCP semplice
/*
 * if the time elapsed since last error is greater than WAITTIME parameter, it tries to reopen
 * the socket (connection)
 */
int fixLastError(HostNode *currentHost) {
	time_t now;
	time(&now);

	if (now - currentHost->last_error >= 0) { //TODO: era WAITTIME
		slog(LOG_NORMAL, "trying to fix the error!\n");
		// close the current socket
		if (currentHost->socket) {
			close(currentHost->socket);
			#ifdef TLSPROTOCOL
			if(strcmp(TLS, currentHost->protocolName) == 0){
				if(!TLSFAIL)deinitTLSSocket(currentHost->tlssession,1);
			}
			#endif

		}

		// reopening the internet socket
		currentHost->socket = socket(AF_INET, currentHost->protocol, 0);
		if (currentHost->socket < 0) {
			slog(LOG_NORMAL, "... cannot reopen network socket, exiting!\n");
			currentHost->last_error=time(&currentHost->last_error);
			currentHost->socket = 0;
			unlink(SOCKETSTATUSFILE);
			return(1);
		}

		if (currentHost->protocol == SOCK_STREAM) {
			slog(LOG_NORMAL, "... connecting a TCP socket!\n");
			// it is a TCP socket; it is required to connect!
			if (connect(currentHost->socket, (struct sockaddr *) &host.socketAddress, sizeof(struct sockaddr_in)) == -1) {
				slog(LOG_NORMAL, "... cannot reconnect to remote host!\n");
					currentHost->last_error=time(&currentHost->last_error);
					unlink(SOCKETSTATUSFILE);
					currentHost->socket = 0;
					return(1);
			}
			#ifdef TLSPROTOCOL
			if(strcmp(TLS, currentHost->protocolName) == 0){
				if(TLSFAIL){
					currentHost->tlssession = NULL;
				}else{
					currentHost->tlssession = initTLSSocket(currentHost->socket, getNameFromIP(currentHost->desthost));
				}
				if (!currentHost->tlssession){
					if(!TLSFAIL)sperror("connect");
					else sperror("TLS initialization failed");
					close(currentHost->socket);
					currentHost->last_error=time(&currentHost->last_error);
					currentHost->socket = 0;
					unlink(SOCKETSTATUSFILE);
					return (1);
				}
			}
			#endif
		}
		currentHost->last_error = 0;
	} else {
		//still waiting
		return(1);
	}
	return(0);
}


/**
 * It transforms the given message in a syslog message, prepending it with the syslog header and
 * other information, following this structure: "<PRI> TIMESTAMP HOSTNAME Safed[pid][seqnum]:message";
 * the timestamp is calculated on the fly, the result is returned in the char array stringout, that is
 * supposed to hold maxMsgSize char.
 */
char* formatMsgForSyslog(const char* message, struct tm *messageTime) {
	char* result = (char *) malloc(maxMsgSize*sizeof(char)+1);

	// converts the current time in a string of the form "Month Date hour:min:sec"
	char syslogTimestamp[16] = "";
	syslogdate(syslogTimestamp, messageTime);

	// builds the message
	snprintf(result, maxMsgSize, "<%d>%s %s %s[%d][%d]:", priority, syslogTimestamp, hostname, "Safed", agentpid, seqnum);
	strncat(result, message, maxMsgSize - strlen(result) - 1);
	// the terminating "\n" is necessary in order to have the TCP connection working
	strncat(result, "\n", maxMsgSize - strlen(result));
	return result;
}


int checkDataAvailableToReadOnSocket(int clientSocket) {
	fd_set readfd;

	// the timeout in microseconds to receive the EOF from the rsyslogd, after executing the shutdown of the connection
	struct timeval timeout;
	timeout.tv_sec = 0;
	timeout.tv_usec = 25000;

	FD_ZERO(&readfd);
	FD_SET(clientSocket, &readfd);

	// this call to select returns 1 if there is data available to read (also EOF) on clientSocket
	int result = select(clientSocket+1, &readfd, NULL, NULL, &timeout);
	if (result == -1) {
		//this is an error situation
		sperror("select");
	}
	// data is available if and only if the call to select returns 1
	return (result == 1);
}


int connectToServer(){
	host.socket = socket(AF_INET, host.protocol, 0);
	if (host.socket < 0) {
		sperror("socket()");
		host.socket = 0;
		host.last_error = time(&host.last_error);
		unlink(SOCKETSTATUSFILE);
		return -1;
	}

	// if I am using TCP ...
	if (host.protocol == SOCK_STREAM) {
		/*
		 * I disable the Nagle algorithm: the segments are always sent as soon
		 * as possible, even if there is only a small amount of  data.
		 */
		int nodelay = 1;
		socklen_t optlen = sizeof nodelay;
		if (setsockopt(host.socket, IPPROTO_TCP, TCP_NODELAY, &nodelay, optlen) == -1) {
			//an error occurred
			sperror("getsockopt(TCP_NODELAY)");
		}

		// ... and I connect the socket
		if (connect(host.socket, (struct sockaddr *)&host.socketAddress, sizeof(struct sockaddr_in)) == -1) {
			sperror("connect");
			close(host.socket);
			host.socket = 0;
			host.last_error = time(&host.last_error);
			unlink(SOCKETSTATUSFILE);
			return (-1);
		}
		#ifdef TLSPROTOCOL
		if(strcmp(TLS, host.protocolName) == 0){
			if(TLSFAIL){
				host.tlssession = NULL;
			}else{
				host.tlssession = initTLSSocket(host.socket, getNameFromIP(host.desthost));
			}
			if (!host.tlssession){
				if(!TLSFAIL)sperror("connect");
				else sperror("TLS initialization failed");
				close(host.socket);
				host.last_error=time(&host.last_error);
				host.socket = 0;
				unlink(SOCKETSTATUSFILE);
				return (1);
			}
		}
		#endif
	}

	struct stat buf;
	if(stat(SOCKETSTATUSFILE, &buf)){
		FILE* pidfile;
		if ((pidfile = fopen(SOCKETSTATUSFILE,"w"))) {
			fclose(pidfile);
		}
	}

	return 0;
}

/**
 * Using the TCP protocol, it returns 0 only if the message is successfully delivered to the destination.
 */
int sendMessage(char *message) {
	if(strlen(message) > maxMsgSize){
		message[maxMsgSize - 2] = '\n';
		message[maxMsgSize - 1] = '\0';
	}
	slog(LOG_NORMAL, "... sendMessage(): sending: %s", message);

	// if the socket is not open, I open it
	if (!host.socket) {
		int connectionStatus = connectToServer();
		if(connectionStatus){
			return connectionStatus;
		}
	}


	// sending the message ...
	int bytesToSend = strlen(message);
	int bytesSent = 0;

#ifdef TLSPROTOCOL
	if(strcmp(TLS, host.protocolName) == 0){
		slog(LOG_NORMAL, "sending to SSL server. ....\n");
		bytesSent = sendTLS(message,host.tlssession);
		if(bytesSent < 0) {
			slog(LOG_NORMAL, "error sending to SSL server. WSA ERROR: %d",getTLSError(bytesSent));
			bytesSent = -1;
		}
	}else{
#endif
		bytesSent = sendto(host.socket, message, strlen(message), 0, (const struct sockaddr *)&host.socketAddress, host.dest_addr_size);
#ifdef TLSPROTOCOL
	}
#endif


	slog(LOG_NORMAL, "... bytes to send to host %s: %d  - bytes sent: %d\n", host.desthost, strlen(message), bytesSent);

	if (bytesSent < bytesToSend && bytesSent != -1) {
		// this is not considered as a problem
		slog(LOG_ERROR, "...error! Sent to destination only %d bytes instead of %d!", bytesSent, bytesToSend);
	}

	// this is the real error situation
	if (bytesSent == -1) {
		sperror("sendto");
		close(host.socket);
		host.socket = 0;
		host.last_error = time(&host.last_error);
#ifdef TLSPROTOCOL
		if(strcmp(TLS, host.protocolName) == 0){
			deinitTLSSocket(host.tlssession,1);
		}
#endif
		unlink(SOCKETSTATUSFILE);
		return -1;
	}

	int result = 0;
	/* I asked to be sure that the message was really delivered to the rsyslog (RTCP) */
	if (host.protocol == SOCK_STREAM && (strcmp("rtcp", host.protocolName) == 0)) {
		//fprintf(stderr, "... closing the socket and waiting for the EOF\n");
		// asymmetric closure of the connection
		if (shutdown(host.socket, SHUT_WR) == -1) {
			sperror("shutdown");
			close(host.socket);
			host.socket = 0;
			host.last_error = time(&host.last_error);
			unlink(SOCKETSTATUSFILE);
			return -1;
		}

		if (!checkDataAvailableToReadOnSocket(host.socket)) {
			// a network error or the EOF was not received within the timeout
			result = -1;
			host.last_error = time(&host.last_error);
		}

		if (close(host.socket) == -1) {
			sperror("close");
			host.socket = 0;
			host.last_error = time(&host.last_error);
			unlink(SOCKETSTATUSFILE);
			return -1;
		}
		// the socket is closed, its file descriptor is not any longer valid
		host.socket = 0;
	}

	slog(LOG_NORMAL, "... exiting sendMessage with return value: %d\n", result);
	return result ;
}

/*
 * Sends the messages in the range [from-to] in the file YYYYMMDD.log via syslog
 */
void reSendMessages(int year, int month, int day, int from, int to) {
	int number = 0;

	char *filename = calculateFileName(NULL, year, month, day);
	FILE *messageFile = fopen(filename, "r");
	if (messageFile) {
		char *line = NULL;
		size_t len = 0;
		ssize_t read = 0;

		while ((read = getline(&line, &len, messageFile)) != -1) {
			number ++;
			if (number >= from && number <=to) {
				sendMessage(line);
			}
		}
		if (line) {
			free(line);
		}
		fclose(messageFile);
	} else {
		sperror("reSendMessages():fopen");
	}
	free(filename);
}


// the thread function (void* thread_function(void*)) responsible to send the logs to the remote syslog
void* sendLogThread(void* args) {
	slog(LOG_NORMAL, "... entering sendLogThread()\n");
	struct timespec timeout;
	time_t now;

	// this mutex has the only purpose to avoid concurrent executions of this same thread
	pthread_mutex_lock(&send_mutex);

	while (continueloop) {
		// gets the current unix time in seconds
		time(&now);

		// run this thread every second, or when signaled.
		timeout.tv_sec = now + 1;
		timeout.tv_nsec = 0;

		// waiting for data available in the memory cache or for the timeout expiring
		pthread_cond_timedwait(&log_data_available, &send_mutex, &timeout);

		if (checkDataAvailableToRead(fds[0])) {
			char buffer[1024];
			size_t bread = read(fds[0], buffer, sizeof(buffer)-1);
			if (bread == -1) {
				sperror("error reading from pipe: read");
			} else {
				buffer[bread] = '\0';
				slog(LOG_NORMAL, "... got a request from the web server: %s\n", buffer);
				if (strstr(buffer, "RESTART")) {
					// got a restart request
					continueloop = 0;
					restart = 1;
				} else {
					int from, to = 0;
					if (sscanf(buffer, "%d %d", &from, &to) == EOF) {
						sperror("sscanf");
					} else {
						// there is a request to send again messages from x to y, coming from the web server, just do it!
						struct tm currentTime;
						getCurrentTime(&currentTime);
						reSendMessages(currentTime.tm_year+1900, currentTime.tm_mon + 1, currentTime.tm_mday, from, to);
					}
				}
			}
		}


		/* sending the messages in the memory cache */
		Message *currentMsg = getMsgFromMemoryCache();
		while (currentMsg) {
			if (!currentMsg->error) {
				// write the message on the persistent cache
				writeMsgOnFile(currentMsg->msg, currentMsg->year, currentMsg->month, currentMsg->day);
			}
			if (sendMessage(currentMsg->msg) == 0) {
				// the message was successfully sent
				slog(LOG_NORMAL, "... message successfully sent to syslog: %s", currentMsg->msg);
				free(currentMsg->msg);
				free(currentMsg);
			} else {
				// an error occurred, and the message was not sent; mark the error flag, and put the message again in the memory cache
				currentMsg->error++;
				putMsgToMemoryCache(currentMsg);
				slog(LOG_NORMAL, "... message put again to the memory cache: %s", currentMsg->msg);
				break;
			}

			currentMsg = getMsgFromMemoryCache();
		}
	}

	pthread_mutex_unlock(&send_mutex);
	slog(LOG_NORMAL, "... exiting sendLogThread()\n");
	return NULL;
}




/*
 * Converts the cdate struct in a string of the form "Mmm dd hh:mm:ss";
 * the receiving string buffer should be at least 16 char in length .
 */
void syslogdate(char *sdate, struct tm *cdate) {
	char Month[4];
	char Date[3];
	char Hour[3];
	char Min[3];
	char Sec[3];

	if (!sdate || !cdate) return;

	//Mmm in {Jan, Feb, Mar, Apr, Jun, Jul, Aug, Sep, Oct, Nov, Dec}
	switch (cdate->tm_mon) {
		case 0:  strcpy(Month, "Jan"); break;
		case 1:  strcpy(Month, "Feb"); break;
		case 2:  strcpy(Month, "Mar"); break;
		case 3:  strcpy(Month, "Apr"); break;
		case 4:  strcpy(Month, "May"); break;
		case 5:  strcpy(Month, "Jun"); break;
		case 6:  strcpy(Month, "Jul"); break;
		case 7:  strcpy(Month, "Aug"); break;
		case 8:  strcpy(Month, "Sep"); break;
		case 9:  strcpy(Month, "Oct"); break;
		case 10: strcpy(Month, "Nov"); break;
		default: strcpy(Month, "Dec"); break;
	}

	// " 1" <= dd <= "31"
	if (cdate->tm_mday < 10) {
		snprintf(Date, 3, " %d", cdate->tm_mday);
	} else {
		snprintf(Date, 3, "%d", cdate->tm_mday);
	}
	// "00" <= hh <= "23"
	if (cdate->tm_hour < 10) {
		snprintf(Hour, 3, "0%d", cdate->tm_hour);
	} else {
		snprintf(Hour, 3, "%d", cdate->tm_hour);
	}
	// "00" <= mm <= "59"
	if (cdate->tm_min < 10) {
		snprintf(Min, 3, "0%d", cdate->tm_min);
	} else {
		snprintf(Min, 3, "%d", cdate->tm_min);
	}
	// "00" <= ss <= "59"
	if (cdate->tm_sec < 10) {
		snprintf(Sec, 3, "0%d", cdate->tm_sec);
	} else {
		snprintf(Sec, 3, "%d", cdate->tm_sec);
	}

	snprintf(sdate, 16, "%s %s %s:%s:%s", Month, Date, Hour, Min, Sec);
}



int fileHasChanged(LogFileData *f) {
	// get the new set of stats regarding the file f->name
	struct stat stats;

	if (stat(f->fileName, &stats) < 0) {
		if (!f->last_error) slog(LOG_NORMAL, "Failed to find log file: %s\n", f->fileName);
		f->last_error=time(&f->last_error);
		return(-1);
	}
	// a file has been rotated if its inode number is changed;
	// anyway, if its device has changed or if previously I had an error, I have to close and reopen it!
	if (f->dev != stats.st_dev || f->ino != stats.st_ino || f->last_error) {
		FILE *fs = fopen(f->fileName, "r");
		// change detected, close the old file,
		// reset the stats and start from the beginning
		slog(LOG_NORMAL, "rotation detected\n");
		if (f->fs) fclose(f->fs);
		f->fs = fs;
		f->size = stats.st_size;
		#if defined(__hpux__) || defined(_AIX)
		f->mtime = stats.st_mtime;
		#else
		f->mtime = stats.st_mtim;
		#endif
		f->dev = stats.st_dev;
		f->ino = stats.st_ino;
		f->mode = stats.st_mode;
		f->last_error = 0;
		return(1);
	}
	if(f->isCorrectFormat ){
		f->dirCheck++;
	}
	// check if the file is changed in size or modification time
	if (
		f->size == stats.st_size &&
		#if defined(__hpux__) || defined(_AIX)
			f->mtime == stats.st_mtime
		#else
		    f->mtime.tv_sec == stats.st_mtim.tv_sec &&
		    f->mtime.tv_nsec == stats.st_mtim.tv_nsec
		#endif
	    ) {
		// no changes in file size and modification time, nothing to do
		//make sure there is no new file to watch yet
		if(f->dirCheck >= 200){//200 checks before file format check. Reduce resources impact
			char filename[MAX_AUDIT_CONFIG_LINE];
			f->dirCheck = 0;
			int findret = findDirFileName(f->dirName, filename, &f->regexp);
			if(!findret && strlen(filename) && strcmp(f->fileName,filename)){
				slog(LOG_NORMAL,  "Found new file %s\n", filename);
				strncpy(f->fileName, filename, MAX_AUDIT_CONFIG_LINE);
				FILE *fs = fopen(f->fileName, "r");
				// change detected, close the old file,
				// reset the stats and start from the beginning
				if (f->fs) fclose(f->fs);
				f->fs = fs;
				if (stat(f->fileName, &stats) < 0) {
					if (!f->last_error) slog(LOG_NORMAL, "Failed to find log file: %s\n", f->fileName);
					f->last_error=time(&f->last_error);
					return(-1);
				}
				f->size = stats.st_size;
				#if defined(__hpux__) || defined(_AIX)
				f->mtime = stats.st_mtime;
				#else
				f->mtime = stats.st_mtim;
				#endif
				f->dev = stats.st_dev;
				f->ino = stats.st_ino;
				f->mode = stats.st_mode;
				f->last_error = 0;
				return(1);
			}
		}
		return(0);
	} else {
		// if I am on this branch, there is a change regarding the size or the modification time of the file
		slog(LOG_NORMAL, " ... detected a change in: %s\n", f->fileName);

		// update the descriptors
		f->size = stats.st_size;	// size of file, in bytes
		#if defined(__hpux__) || defined(_AIX)
		f->mtime = stats.st_mtime;
		#else
		f->mtime = stats.st_mtim;	// time of last modification
		#endif
		f->dev = stats.st_dev;		// device containing the file
		f->ino = stats.st_ino;		// inode number
		f->mode = stats.st_mode;	// file mode

		int strange=0;
		// Something has changed, find out what and take action
		if (stats.st_size < f->size) {
			slog(LOG_NORMAL, "File truncated\n", f->fileName);
			strange = 1;
		}
		#if defined(__hpux__) || defined(_AIX)
		if (f->mtime > stats.st_mtime) {
			slog(LOG_NORMAL, "Modified in the past\n");
			strange = 1;
		}
		#else
		if (f->mtime.tv_sec > stats.st_mtim.tv_sec) {
			slog(LOG_NORMAL, "Modified in the past\n");
			strange = 1;
		} else if (f->mtime.tv_sec == stats.st_mtim.tv_sec && f->mtime.tv_nsec > stats.st_mtim.tv_nsec) {
			slog(LOG_NORMAL, "Modified in the past\n");
			strange = 1;
		}
		#endif

		if (strange) {
			// Something went wrong, so ditch the old descriptor and
			// keep the new one.  However, since it was not a rotation,
			// i.e. we still have the same dev and inode numbers, then
			// seek to the beginning of the file and only return a change
			// if the file is larger than zero.
			FILE *fs = fopen(f->fileName, "r");
			if (f->fs) fclose(f->fs);
			f->fs = fs;
			//fseek(fs, f->size, SEEK_SET);
			if (f->size == (off_t) 0)
				return(0);
			else
				return(1);
		}else{
			//make sure there is no new file to watch yet
			if(f->dirCheck >= 200){//200 checks before file format check. Reduce resources impact
				char filename[MAX_AUDIT_CONFIG_LINE];
				f->dirCheck = 0;
				int findret = findDirFileName(f->dirName, filename, &f->regexp);
				if(!findret && strlen(filename) && strcmp(f->fileName,filename)){
					slog(LOG_NORMAL,  "Found new file %s\n", filename);
					strncpy(f->fileName, filename, MAX_AUDIT_CONFIG_LINE);
					FILE *fs = fopen(f->fileName, "r");
					// change detected, close the old file,
					// reset the stats and start from the beginning
					if (f->fs) fclose(f->fs);
					f->fs = fs;
					if (stat(f->fileName, &stats) < 0) {
						if (!f->last_error) slog(LOG_NORMAL, "Failed to find log file: %s\n", f->fileName);
						f->last_error=time(&f->last_error);
						return(-1);
					}
					f->size = stats.st_size;
					#if defined(__hpux__) || defined(_AIX)
					f->mtime = stats.st_mtime;
					#else
					f->mtime = stats.st_mtim;
					#endif
					f->dev = stats.st_dev;
					f->ino = stats.st_ino;
					f->mode = stats.st_mode;
					f->last_error = 0;
				}
			}

		}
		return(1);
	}
}


void initTLSAndUpdateStatus() {
	#ifdef TLSPROTOCOL
		// init tls for secure communication with the syslog server
		if(strcmp(TLS, host.protocolName) == 0){
			TLSFAIL = initTLS();
			if(TLSFAIL){
				sperror("TLS initialization failed");
				unlink(SOCKETSTATUSFILE);
			} else {
				struct stat buf;
				if(stat(SOCKETSTATUSFILE, &buf)){
					FILE* pidfile;
					if ((pidfile = fopen(SOCKETSTATUSFILE,"w"))) {
						fclose(pidfile);
					}
				}
			}
		}

		//init tls for secure communication with the embedded web server
		if(remoteControlAllowed && remoteControlHttps){
			TLSSERVERFAIL = initSTLS();
			if(TLSSERVERFAIL){
				sperror("TLS https initialization failed");
				deinitSTLS();
				remoteControlHttps = 0;
				strcpy(initStatus,"Attention: NetEye Safed HTTPS FAILED. It will proceed with HTTP");
			}
		}
	#endif
}

void deinitTLSsession() {
	// closure of the TLS session to the syslog server
	#ifdef TLSPROTOCOL
			if(strcmp(TLS, host.protocolName) == 0){
				if(!TLSFAIL)deinitTLSSocket(host.tlssession,1);
			}
	#endif



	#ifdef TLSPROTOCOL
		if(strcmp(TLS, host.protocolName) == 0){
			if(!TLSFAIL)deinitTLS();
		}
		if(remoteControlAllowed && remoteControlHttps){
			if(!TLSSERVERFAIL)deinitSTLS();
		}
	#endif
}
