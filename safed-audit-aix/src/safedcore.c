/*********************************************************
 * SAFED for AIX
 * Author: Wuerth-Phoenix s.r.l.,
 * made starting from:
 * Snare for AIX version 1.6.0
 *
 * Author: InterSect Alliance Pty Ltd
 *
 * Copyright 2001-2010 InterSect Alliance Pty Ltd
 *
 * Last Modified: 5/12/2010
 *
 * Available under the terms of the GNU Public Licence.
 * - See www.gnu.org
 *
 **********************************************************
 *
 * Snare for AIX is a user-space program
 * that interacts with the audit facility within the
 * AIX operating system as a streamcmd filter.
 *
 * Snare takes data from the auditpr command, and sends
 * the resulting text data over the pipe /tmp/safedpipe to th esafed agent
 *
 **********************************************************
 *
 * History:
 *       7/10/2004  Test version - based on Snare for AIX
 *       27/10/2005 Version 1.1 released 
 *       2/8/2006   Latest updates to fix syslog truncation
 *       17/4/2007  Remove debug flag and update syslog message format
 *       23/11/2007 Updated code base including Latest Events
 *       	    and access to /etc/sudoers
 *       5/12/2007  Multiple bug fixes in objective matching code
 *	 24/06/2010 Patched to prevent Cross Site Request Forgery
 *
 **********************************************************
 *
 * Compilation Instructions:
 *    See makefile.
 *    cc -o safedcore safedcore.c webserver.c WebPages.c -lsocket -lnsl -lintl
 *
 **********************************************************/

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/errno.h>
#include <sys/param.h>
#include <sys/audit.h>

#include <netinet/in.h>


#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <signal.h>
#include <limits.h>
#include <dirent.h>
#include <strings.h>
#include <values.h>
#include <time.h>
#include <syslog.h>


#include <regex.h>

// Manually define snprintf etc..
#define SILLY_AIX 1

#include "shared.h"
#include "safedcore.h"


////// DEBUG
#include <stdarg.h>
//#define DEBUG 1
void DebugMsg(int level, const char *pszFormat, ...);
int logLevel = LOGGING_DEFAULT;
////// END DEBUG


// Linked List Functions
static Node *head, *currentnode;
static int AuditDestination = AUDIT_TO_FILE;	// Send to SAFED PIPE
static int SyslogDestination = 13;			// user.notice

char hostid[MAX_HOSTID] = "";

FILE *AuditFile = (FILE *) NULL;





/* Define an error variable so we can communicate with auditsvc */
extern int errno;
int caught_pipe;                // variable that lets us know when a SIGPIPE has been received
int caught_usr1;                // variable that lets us know when a SIGUSR1 has been received
int caught_kill;                // variable that lets us know when a SIGUSR1 has been received

void pipe_signal(sig)
{
	caught_pipe++;
	DebugMsg(LOGGING_DEFAULT,"Caught pipe");
	return;
}

void usr1_signal(sig)
{
	caught_usr1++;
	DebugMsg(LOGGING_DEFAULT,"Caught usr1");
	DebugMsg(LOGGING_DEFAULT,"Restarting agent in 5 seconds");
	sleep(5);
	system("/etc/security/audit/restartsafed");
	return;
}

void kill_signal(sig) {
	caught_kill++;
	DebugMsg(LOGGING_DEFAULT,"Caught kill");
	return;
}


/*
 * Writes the given pid in the pidfile /var/run/safedaudit.pid
 */
void writepid(int pid) {
	FILE *pidfile;
	if ((pidfile = fopen(PIDFILE,"w"))) {
		fprintf(pidfile,"%d\n",pid);
		fclose(pidfile);
	} else {
		DebugMsg(LOGGING_ERROR,"... unable to open for writing the pid file");
	}
}


int main(int argc, char *argv[])
{
	/* General program related variables */
	char logbuffer[LOGBUFFERSIZE];	/* Holds the data from auditpr */

	/* Variables that relate to the network socket */
	// struct hostent *hp;	/* Host Pointer */
	// struct sockaddr_in socketname;
	// struct in_addr ia;

	// Signal related variables
	sigset_t signalset;

	/* Audit related variables */
	char username[MAX_USERNAME];
	char searchterm[MAX_PATH];
	char eventname[MAX_EVENTNAME];
	char options[MAX_OPTIONS];
	char *startrecord;
	int returncode;
	
	// NODE that matches the objective search term.
	Node *nodematch;

	DebugMsg(LOGGING_DEFAULT,"Program starting.");
	/* The only person who can run auditsvc is root, so lets
	   make sure that we discourage other users */
	if (getuid() != 0) {
		DebugMsg(LOGGING_ERROR,"This program can only be run by root.\n");
		exit(1);
	}
	writepid(getpid());

	// Read our configuration file, and set up audit.
	returncode = read_config_file(0);

	if (strlen(hostid) == 0) {
		getfqdn(hostid);
	}



	// Configure / Reinstate signals
	// Trap signals relating to PIPE failures,
	//  and Child process termination
	// Reset this each time through the loop, just in case
	// a signal handler resets our values

	if (!setsignals(&signalset)) {
		DebugMsg(LOGGING_ERROR,"Cannot set important signals - exiting\n");
		return(1);
	}

	while (fgets(logbuffer, sizeof(logbuffer), stdin)) {
		startrecord = logbuffer;
		username[0] = '\0';
		searchterm[0] = '\0';
		eventname[0] = '\0';
		options[0] = '\0';
		returncode = 0;
		/* This is where we implement the SAFED event checker process */
		returncode =
		    GetAIXDetails(logbuffer,
				  username,
				  searchterm,
				  eventname,
				  options);

		DebugMsg(LOGGING_DEBUG,"values: == %s == %s == %s == %s == %d", username, searchterm, eventname, options, returncode);
		if ((nodematch =
			CheckObjective(username,
				       searchterm,
				       eventname,
				       options,
				       returncode))
		       != (Node *) NULL) {

			if (sendevent
			    (startrecord,
			     nodematch->
			     criticality) != 0) {
				// Report an error, but continue
				DebugMsg(LOGGING_ERROR,"error sending log entry to destination");
			}
		}
		//reset the buffer because in GetAIXDetails we deal with pointers!!
		int j;
		for(j = 0; j < LOGBUFFERSIZE; j++){
			logbuffer[j]='\0';
		}
	}
	DebugMsg(LOGGING_DEFAULT,"All done, cleaning up\n");

	DestroyList();
	if(AuditFile){
		fclose(AuditFile);
	}
	unlink(PIDFILE);
	/* All done */
	return 0;
}

int setsignals(sigset_t *signalset)
{
	sigfillset(signalset);
	sigdelset(signalset,SIGTERM);
	sigdelset(signalset,SIGALRM);
	sigdelset(signalset,SIGINT);
	sigdelset(signalset,SIGPIPE);
	sigdelset(signalset,SIGUSR1);
	sigdelset(signalset,SIGCHLD);
	sigprocmask(SIG_BLOCK,signalset, (void *) NULL);

	if (signal(SIGUSR1,usr1_signal) == SIG_ERR)
	{
		DebugMsg(LOGGING_ERROR,"Cannot set signal SIGUSR1\n");
		return(0);
	}

	if (signal(SIGPIPE,pipe_signal) == SIG_ERR)
	{
		DebugMsg(LOGGING_ERROR,"Cannot set signal SIGPIPE\n");
		return(0);
	}

	if (signal(SIGCHLD,pipe_signal) == SIG_ERR)
	{
		DebugMsg(LOGGING_ERROR,"Cannot set signal SIGCHLD\n");
		return(0);
	}

	return(1);
}
// Shortread: don't re-read all the objectives - just the general configuration items.
int read_config_file(int shortread)
{
	FILE *configfile = (FILE *)NULL;
	char inputbuffer[MAX_AUDIT_CONFIG_LINE];	// Should be enough for most config lines.
							// Would love to use gchar here instead, but need to keep this simple.
	// Config file header.
	int headertype = 0;


	// Clear the audit destination
	AuditDestination=0;

	configfile = fopen(CONFIG_FILENAME,"r");

	if (configfile == (FILE *)NULL) {
		fprintf(stderr,"Cannot open audit configuration file");
		return(0);
	}

	while (fgets(inputbuffer, MAX_AUDIT_CONFIG_LINE, configfile)) {

		// Kill whitespace from start and end of line.
		trim(inputbuffer);

		if(strlen(inputbuffer) < 3) {
			continue;
		}

		if (!iscomment(inputbuffer)) {
			// Is this line a header?
			if (isheader(inputbuffer)) {
				headertype = getheader(inputbuffer);

			} else {
				if (headertype == CONFIG_OBJECTIVES) {

					// Save off enough space to store the data we need.
					char event[MAX_AUDIT_CONFIG_LINE],
					    user[MAX_AUDIT_CONFIG_LINE],
					    path[MAX_AUDIT_CONFIG_LINE];
					char event2[MAX_AUDIT_CONFIG_LINE],
					    options[MAX_OPTIONS] = "";
					char *eventpointer = NULL;
					char *eventpointer2 = NULL;
					int criticality;
					int returncode;
					int excludeflag = 0;
					int excludematchflag = 0;

					// Do we need to skip over the objectives?
					if (shortread == 1) {
						continue;
					}
					if ((criticality = splitobjective(inputbuffer, event, user, path, &excludeflag, &excludematchflag, &returncode)) > -1) {
						// add the objective to the linked list.
						trimallwhitespace(event);
						// HERE: Split event into comma separated list of events
						eventpointer = event;
						eventpointer2 = event;

						// While there are no more commas
						while (eventpointer2) {
							eventpointer2 = strstr(eventpointer, ",");
							if (eventpointer2 == (char *)NULL) {
								// No commas left. Just copy to the end of the line.
								strncpy(event2, eventpointer, MAX_AUDIT_CONFIG_LINE);
							} else {
								strncpy(event2, eventpointer, (eventpointer2 - eventpointer));
								// Make sure we have a null on the end of the line.
								event2[eventpointer2 - eventpointer] = '\0';
							}
							if (eventpointer2) {
								// Skip the comma
								eventpointer = eventpointer2 + 1;
							}
							// Clear out any options strings
							strcpy(options, "");

							if (regmatch(event2, "\\(.*\\)$")) {
								char *position;

								// Bonus, we have something. Grab it, add to options.
								// First, trim off the last bracket.
								event2[strlen(event2) - 1] = '\0';
								position = strstr(event2, "(");

								strncpy(options, position + 1, MAX_OPTIONS);
								// truncate the event string at the bracket.
								*position = '\0';
							}
 
							//DebugMsg(LOGGING_DEBUG,"About to AddToList...\n");
							if (!strcmp(event, "*")) {
								AddToList
								    ("AUDIT_ALL",
								     user,
								     path,
								     criticality,
								     "",
								     excludeflag,
								     excludematchflag,
								     returncode);
							} else {
								AddToList
								    (event2,
								     user,
								     path,
								     criticality,
								     options,
								     excludeflag,
								     excludematchflag,
								     returncode);
							}
						}
					} else {
						DebugMsg(LOGGING_NORMAL,"WARNING: Cannot process objective - please ensure configuration line\n\tcontains valid criticality, event, criticality, return, user and match elements\n\t%s\n", inputbuffer);
					}
				}  else if (headertype == CONFIG_LOG) {
					if (regmatchi(inputbuffer, "^logLevel=")) {
						logLevel = getLogLevel(inputbuffer);
					}
				}  else if (headertype == CONFIG_OUTPUT) {

					if(!AuditFile){
						if (!open_audit_output("file=/tmp/safedpipe")) {
							DebugMsg(LOGGING_NORMAL,"WARNING: Could not open the file specified in the audit configuration: %s - Auditing to STDOUT\n", inputbuffer);
						}
					}
					if (issyslog(inputbuffer)) {
						SyslogDestination = get_syslog_dest(inputbuffer);
						if (!SyslogDestination) {
							SyslogDestination = 13;
							DebugMsg(LOGGING_NORMAL,"WARNING: Could not establish the correct syslog destination from the audit configuration: %s - Sending to user.notice\n", inputbuffer);
						}
					}
				} else if (headertype == CONFIG_HOSTID) {
					gethostident(inputbuffer, hostid, MAX_HOSTID);
				} else {
					DebugMsg(LOGGING_NORMAL,"WARNING: Configuration file line does not fit in any recognised header.\n\t%s\n", inputbuffer);
				}
			}
		}
	}

	fclose((FILE *)configfile);
	return(1);
}

int iscomment(char *line)
{
	// Verify that there is something to check.
	if (line == (char *) NULL) return(1);

	// And that there is some data within.
	if (strlen(line) == 0 || strlen(line) > MAX_AUDIT_CONFIG_LINE) return(1);

	// If the first non-whitespace character is a hash, this is a comment line.
	while (*line) {
		// Space or tab or newline / formfeed
		if (*line == ' ' || *line == 9 || *line == 10 || *line == 12) {
			line++;
		} else if (*line == '#') {
			return(1);
		} else {
			// Ahh. A non-whitespace, non hash character.
			return(0);
		}
	}

	// If we are here, then the whole line must have been whitespace
	return(1);
}

int isheader(char *string)
{
	if (string[0] == '[' && string[strlen(string) - 1] == ']') {
		return(1);
	}
	return(0);
}



int getLogLevel(char *string) {
	int logLevel = LOGGING_DEFAULT;
	if (regmatchi(string, "^logLevel=[1-9]+$")) {
		string += strlen("logLevel=");
		logLevel = atoi(string);
		logLevel = logLevel % LOGGING_LEVELS;
	} else {
		// this is an error situation that should be handled
		DebugMsg(LOGGING_DEFAULT,"... problems reading the log level: the line %s is not correct\n", string);
	}
	return logLevel;
}


int issyslog(char *string)
{
	if (regmatch(string, "^syslog=")) {
		return(1);
	}
	return(0);
}

int open_audit_output(char *string)
{
	string += strlen("file=");

	if (strlen(string)) {
		if (regmatchi(string,"stdout")) {
			AuditDestination |= AUDIT_TO_STDOUT;
			return(1);
		}
		AuditFile = fopen(string, "w");
		if (AuditFile != (FILE *) NULL) {
			AuditDestination |= AUDIT_TO_FILE;
			return(1);
		} else {
			AuditDestination |= AUDIT_TO_STDOUT;
			return(0);
		}
	}

	return(0);
}

// For the moment, require the web server to do the work of converting
// destinations to numerics.
int get_syslog_dest(char *string)
{
	int destination;
	string += strlen("syslog=");
	destination = atoi(string);
	if (destination > 0) {
		return(destination);
	}
	return(0);
}


int getheader(char *string)
{
	char temp[256];
	char *stringp;
	strncpy(temp, string, 256);

	stringp = temp;

	// Remove the first and last bracket.
	stringp++;
	stringp[strlen(stringp) - 1] = '\0';

	if (regmatchi(stringp, "^aobjectives$")) {
		return(CONFIG_OBJECTIVES);
	} else if (regmatchi(stringp, "^file$") || regmatchi(stringp, "^output$")) {
		return(CONFIG_OUTPUT);
	} else if (regmatchi(stringp, "^hostid$")) {
		return(CONFIG_HOSTID);
	} else if (regmatchi(stringp, "^log$")) {
		return CONFIG_LOG;
	}

	DebugMsg(LOGGING_DEFAULT,"Unknown header in configuration file: %s\n", stringp);
	return(0);
}



// Return the host identifier
char *gethostident(char *string, char *host, int length)
{
	char *stringp = string;

	stringp = strstr(string, "=");
	if (stringp != (char *)NULL) {
		stringp++;
		if (strlen(stringp)) {
			strncpy(host, stringp, length - 1);
		} else {
			return((char *)NULL);
		}
	} else {
		return((char *)NULL);
	}
	return((char *)host);
}

// Return a string that contains the criticality
// Note that string is assumed to be MAX_AUDITREC in size.
char *criticalitystring(int criticality, char *string)
{
	switch (criticality) {
		case CRITICALITY_CRITICAL:
			return(strncpy(string, "critical",MAX_AUDITREC));
		case CRITICALITY_PRIORITY:
			return(strncpy(string, "priority",MAX_AUDITREC));
		case CRITICALITY_WARNING:
			return(strncpy(string, "warning",MAX_AUDITREC));
		case CRITICALITY_INFO:
			return(strncpy(string, "information",MAX_AUDITREC));
		default:
			return(strncpy(string, "clear",MAX_AUDITREC));
	}
}

// Remove start / end whitespace, including the newline
void trim(char *string)
{
	char *pointer;
	char *pointer2;

	// Verify that there is something to check.
	if (string == (char *) NULL) return;

	// And that there is some data within.
	if (strlen(string) == 0) return;

	// Start from the end, work backwards.
	pointer = &string[strlen(string) - 1];

	while ((*pointer == ' ' || *pointer == 9 || *pointer == 10 || *pointer == 12) && pointer >= string) {
		*pointer = '\0';
		pointer--;
	}

	// Are we back at the start of the string? If so, this line must be null.
	if (pointer == string) return;
	// Pointer is now at the last non-whitespace character of the string.

	pointer2 = string;
	while ((*pointer2 == ' ' || *pointer2 == 9 || *pointer2 == 10 || *pointer2 == 12) && pointer2 < pointer) {
		pointer2++;
	}
	// pointer2 will now point to the start of the first non-null character
	// Copy the truncated string back to the original.
	strcpy(string, pointer2);
}

void trimallwhitespace(char *string)
{
	char *readpointer;
	char *writepointer;

	// Verify that there is something to check.
	if (string == (char *) NULL) return;

	// And that there is some data within.
	if (strlen(string) == 0) return;

	// Start from the end, work backwards.
	readpointer = string;
	writepointer = string;
	while (readpointer < (string + strlen(string))) {
		if (*readpointer == ' ' || *readpointer == 9 || *readpointer == 10 || *readpointer == 12) {
			readpointer++;
		} else {
			if (writepointer != readpointer) {
				*writepointer = *readpointer;
			}
			readpointer++;
			writepointer++;
		}

	}
}

// Strip tabs and newlines out of a string.
char *strip(char *string)
{
	char *stringp = string;

	while (*stringp != '\0') {
		if (*stringp == '\t' || *stringp == '\n') {
			*stringp = ' ';
		}
		stringp++;
	}
	return(string);
}

// Strip ().


// Strip ().
void stripParentheses(char *string)
{
	int len = strlen(string);
	if((len > 1) && (string[0] == '(') && (string[len - 1] == ')')){
		int i;
		for(i = 0; i < len - 1; i++){
			string[i] = string[i + 1];
		}
		string[len - 2] = '\0';
	}
}


int formatUser(char *string)
{
	int ret = 0;
	char *stringp = string;
	while (*stringp != '\0') {
		if (*stringp == ',' ) {
			*stringp = '|';
			ret = 1;
		}
		stringp++;
	}
	return ret;
}



// Take an identified objective line
// NOTE: string, event, user and match must all be the same buffer size!
int splitobjective(char *string, char *event, char *user, char *match, int *excludeflag, int *excludematchflag, int *returncode)
{
	char *startevent, *startuser, *startmatch, *startcrit, *startreturn;
	char *stringpointer, *endstring;
	char *eventp, *userp, *matchp, *critp;
	char criticality[MAX_AUDIT_CONFIG_LINE];
	int crit = 0;

	*returncode = RETURNCODE_ANY;

	// Do some basic sanity checks.
	if (string == (char *) NULL || event == (char *) NULL || user == (char *) NULL || match == (char *) NULL) {
		return(-1);
	}
	if (!strlen(string)) {
		return(-1);
	}

	startcrit = strstr(string, "criticality=");
	startevent = strstr(string, "event=");
	startreturn = strstr(string, "return=");
	startuser = strstr(string, "user=");
	if (startuser == (char *)NULL) {
		startuser = strstr(string, "user!=");
		if (startuser != (char *)NULL) {
			// EXCLUDE USERS rather than include.
			*excludeflag = 1;
		}
	}
	startmatch = strstr(string, "match=");
	if (startmatch == (char *)NULL) {
		startmatch = strstr(string, "match!=");
		if (startmatch != (char *)NULL) {
			// EXCLUDE rather than include.
			*excludematchflag = 1;
		}
	}

	// string pointers for iteration.
	stringpointer = string;
	eventp = event;
	userp = user;
	matchp = match;
	critp = criticality;

	// Pointer to the last character in the string.
	endstring = &string[strlen(string)];

	if (startevent == (char *)NULL || startuser == (char *)NULL ||
	   startmatch == (char *)NULL || startcrit == (char *)NULL || startreturn == (char *)NULL) {
		// Problem, this line is malformed. We really cannot proceed with this line.
		DebugMsg(LOGGING_NORMAL,"The following line does not contain the criticality, event, return, user and match elements: [%s]", string);
		return(-1);
	}

	// Start with the event
	stringpointer = startcrit + strlen("criticality=");
	while (*stringpointer && (stringpointer != startcrit && stringpointer != startreturn && stringpointer != startuser && stringpointer != startmatch && stringpointer != endstring)) {
		*critp = *stringpointer;
		critp++;
		stringpointer++;
	}
	*critp = '\0';
	trim(criticality);
	crit = atoi(criticality);
	if (crit < CRITICALITY_CLEAR) crit = CRITICALITY_CLEAR;
	if (crit > CRITICALITY_CRITICAL) crit = CRITICALITY_CRITICAL;

	// Start with the event
	stringpointer = startevent + strlen("event=");
	while (*stringpointer && (stringpointer != startcrit && stringpointer != startreturn && stringpointer != startuser && stringpointer != startmatch && stringpointer != endstring)) {
		*eventp = *stringpointer;
		eventp++;
		stringpointer++;
	}
	*eventp = '\0';

	// Remove extra whitespace at start and end.
	trim(event);
	// Removes extra () at start and end.
	stripParentheses(event);

	stringpointer = startreturn + strlen("return=");
	if (regmatchi(stringpointer, "^success")) {
		*returncode = RETURNCODE_SUCCESS;
	} else if (regmatchi(stringpointer, "^\\(success\\)")) {
		*returncode = RETURNCODE_SUCCESS;
	} else if (regmatchi(stringpointer, "^failure")) {
		*returncode = RETURNCODE_FAILURE;
	} else if (regmatchi(stringpointer, "^\\(failure\\)")) {
		*returncode = RETURNCODE_FAILURE;
	} else {
		// Any thing else is either success or failure.
		*returncode = RETURNCODE_ANY;
	}

	if (*excludeflag) {
		stringpointer = startuser + strlen("user!=");
	} else {
		stringpointer = startuser + strlen("user=");
	}

	while (*stringpointer && (stringpointer != startcrit && stringpointer != startreturn && stringpointer != startmatch && stringpointer != startevent && stringpointer != endstring)) {
		*userp = *stringpointer;
		stringpointer++;
		userp++;
	}
	*userp = '\0';
	// Remove extra whitespace at start and end.
	trim(user);
	// Removes extra () at start and end.
	stripParentheses(user);

	if(!strcmp(user,"*")){
		strncpy(user,".*",MAX_AUDIT_CONFIG_LINE);
	}else{
		//from , to (|)
		int ret = formatUser(user);
		//from user to ^user$
		char usert[MAX_AUDIT_CONFIG_LINE]="^";
		if(ret)strncat(usert,"(",MAX_AUDIT_CONFIG_LINE);
		strncat(usert,user,MAX_AUDIT_CONFIG_LINE);
		if(ret)strncat(usert,")",MAX_AUDIT_CONFIG_LINE);
		strncat(usert,"$",MAX_AUDIT_CONFIG_LINE);
		strncpy(user,usert,MAX_AUDIT_CONFIG_LINE);
	}


	if (*excludematchflag) {
		stringpointer = startmatch + strlen("match!=");
	} else {
		stringpointer = startmatch + strlen("match=");
	}

	while (*stringpointer && (stringpointer != startcrit && stringpointer != startreturn && stringpointer != startevent && stringpointer != startuser && stringpointer != endstring)) {
		*matchp = *stringpointer;
		stringpointer++;
		matchp++;
	}
	*matchp = '\0';

	// Remove extra whitespace at start and end.
	trim(match);
	// Removes extra () at start and end.
	stripParentheses(match);
	if(!strcmp(match,"*")){
		strncpy(match,".*",MAX_AUDIT_CONFIG_LINE);
	}


	// Return the criticality value.
	return(crit);
}

// Match string against an extended regular expression.
// Return 1 for match, 0 for no-match or error.
int regmatch(const char *string, const char *pattern)
{
	int status;
	regex_t re;

	if (regcomp(&re, pattern, REG_EXTENDED | REG_NOSUB) != 0) {
		return(0);
	}
	status = regexec(&re, string, (size_t) 0, NULL, 0);
	regfree(&re);
	if (status != 0) {
		return(0);
	}
	return(1);
}

// Match string against an extended regular expression.
// Return 1 for match, 0 for no-match or error.
// COMPILED REGULAR EXPRESSION version
int regmatchC(const char *string, regex_t re)
{
	int status;

	status = regexec(&re, string, (size_t) 0, NULL, 0);
	if (status != 0) {
		return(0);
	}
	return(1);
}

// Match string against an extended regular expression. Case insensitive.
// Return 1 for match, 0 for no-match or error.
int regmatchi(const char *string, const char *pattern)
{
	int status;
	regex_t re;

	if (regcomp(&re, pattern, REG_EXTENDED | REG_NOSUB | REG_ICASE) != 0) {
		return(0);
	}

	status = regexec(&re, string, (size_t) 0, NULL, 0);
	regfree(&re);
	if (status != 0) {
		return(0);
	}
	return(1);
}

// Linked List Functions

void CreateLinkedList(void)
{
	head = currentnode = NULL;
}

int IsListEmpty(void)
{
	if (NULL == head)
		return 1;
	else
		return 0;
}

Node *AddToList(char *eventname, char *username, char *path, int criticality, char *options, int excludeflag, int excludematchflag, int returncode)
{
	Node *newNode = NULL;

	newNode = (Node *)malloc(sizeof(Node));

	if (newNode == NULL) {
		DebugMsg(LOGGING_ERROR,"AddToList(): error in dynamic memory allocation\nCould not add a new objective into our linked list. You may be low on memory.\n");
		return((Node *)NULL);
	}


	strncpy(newNode->event_name,eventname,MAX_EVENTNAME);
	newNode->criticality = criticality;
	newNode->returncode = returncode;
	newNode->excludeflag = excludeflag;
	newNode->excludematchflag = excludematchflag;

	strncpy(newNode->username, username, MAX_USERREG);
	// REDRED: NOTE: Must free regexp in objective list at end!
	regcomp(&newNode->usernameRE, username, REG_EXTENDED | REG_NOSUB);

	strncpy(newNode->path, path, PATH_MAX);
	regcomp(&newNode->pathRE, path, REG_EXTENDED | REG_NOSUB);

	strncpy(newNode->options, options, MAX_OPTIONS);
	regcomp(&newNode->optionsRE, options, REG_EXTENDED | REG_NOSUB | REG_ICASE);

	if (head == NULL) {
		head = newNode;
		newNode->next = NULL;
	} else {
		newNode->next = head;
		head = newNode;
	}

	return newNode;
}

void RemoveFromListHead(void)
{
	Node *tempPtr;

	if (NULL == head)
		return;

	tempPtr = head;
	head = head->next;

	// Free regular expressions.
	regfree(&tempPtr->optionsRE);
	regfree(&tempPtr->usernameRE);
	regfree(&tempPtr->pathRE);

	free(tempPtr);
}

void RemoveFromList(Node *node)
{
	Node *tempPtr, *previousPtr;

	if (NULL == node)
		return;

	if (head == node) {
		RemoveFromListHead();
		return;
	}

	tempPtr = head;

	while (NULL != tempPtr) {
		previousPtr = tempPtr;
		tempPtr = tempPtr->next;

		if (tempPtr == node) {
			previousPtr->next = tempPtr->next;

			// Free regular expressions.
			regfree(&tempPtr->optionsRE);
			regfree(&tempPtr->usernameRE);
			regfree(&tempPtr->pathRE);

			free(tempPtr);
			break;
		}
	}
}

void ResetCurrentNode(void)
{
	currentnode = head;
}

int IsValidItem(void)
{
	return(NULL == currentnode) ? 0 : 1;
}

Node *GetCurrentItem()
{
	return(currentnode);
}

void NextItemInList(void)
{
	if (NULL == currentnode)
		return;

	currentnode = currentnode->next;
}

void DestroyList(void)
{
	if (NULL == head) {
		return;
	}

	while (NULL != head) {
		Node *tempPtr = head;
		head = head->next;

		// Free regular expressions.
		regfree(&tempPtr->optionsRE);
		regfree(&tempPtr->usernameRE);
		regfree(&tempPtr->pathRE);

		free(tempPtr);
	}


}

// Pull out the fully qualified domain name, if possible.
char *getfqdn(char *FQDN)
{
	char hname[MAX_HOSTID];
	struct hostent *hp;

	if (gethostname(hname, MAX_HOSTID)) {
		strncpy(FQDN, "localhost.unknown", MAX_HOSTID);
		return(FQDN);
	}

	strncpy(FQDN, hname, MAX_HOSTID);

	hp = gethostbyname(hname);
	if (hp) {
		while (hp->h_aliases && *hp->h_aliases) {
			if (strlen(*(hp->h_aliases)) > strlen(hname) && !strncmp(hname, *(hp->h_aliases), strlen(hname))) {
				strncpy(FQDN, *(hp->h_aliases), MAX_HOSTID);
			}
			hp->h_aliases++;
		}
		if (strlen(hp->h_name) > strlen(hname) && !strncmp(hname, hp->h_name, strlen(hname))) {
			strncpy(FQDN, hp->h_name, MAX_HOSTID);
		}
	}

	return(FQDN);
}




////////////////////////////////////////////////////////////////////////////////
// This routine will send an event to the user-selected output device.
////////////////////////////////////////////////////////////////////////////////
int sendevent(char *string, int criticality)
{
	char stringout[MAX_AUDITREC] = "";
	char blank[2]="";
	char *position=string;
	int size=0;
	char *start=string;
	char *startdate=blank;
	char *startevent=blank;
	char *startcommand=blank;
	char *startuser=blank;
	char *startrealuser=blank;
	char *startpid=blank;
	char *startppid=blank;
	char *startreturn=blank;
	char *starttrail=blank;

	//DebugMsg(LOGGING_NORMAL,"about to send event\n");
	if(!string) {
		return(0);
	}


	size=strlen(string);

	// Work through our string, and convert it into tab-delimited fields.
	// end-fields: 24, 40, 72, 81, 90, 99, 108, 129
	if(size > 24) {
		start=string; startdate=start;
		position=string+24;
		while(position > start && *position==' ') {
			*position='\0';
			position--;
		}
	}
	if(size > 40) {
		start=string+25; startevent=start;
		position=string+40;
		while(position > start && *position==' ') {
			*position='\0';
			position--;
		}
	}
	if(size > 72) {
		start=string+41; startcommand=start;
		position=string+72;
		while(position > start && *position==' ') {
			*position='\0';
			position--;
		}
	}
	if(size > 81) {
		start=string+73; startuser=start;
		position=string+81;
		while(position > start && *position==' ') {
			*position='\0';
			position--;
		}
	}
	if(size > 90) {
		start=string+82; startrealuser=start;
		position=string+90;
		while(position > start && *position==' ') {
			*position='\0';
			position--;
		}
	}
	if(size > 99) {
		start=string+91; startpid=start;
		position=string+99;
		while(position > start && *position==' ') {
			*position='\0';
			position--;
		}
	}
	if(size > 108) {
		start=string+100; startppid=start;
		position=string+108;
		while(position > start && *position==' ') {
			*position='\0';
			position--;
		}
	}
	if(size > 129) {
		start=string+109; startreturn=start;
		position=string+129;
		// NOTE tab:
		while(position > start && (*position==' ' || *position=='	')) {
			*position='\0';
			position--;
		}
	}
	if(size > 130) {
		starttrail=string+130;
		// Kill off tabs/spaces at the start of this field.
		while(*starttrail == ' ' || *starttrail == '\t')  {
			starttrail++;
		}
	}
	// Ok, string is now broken up with null terminators. Go through and collect our items of interest.
	
	// NEW audit record format, including host and AIXAudit identifier string:
	snprintf(stringout, MAX_AUDITREC, "%s\tAIXAudit\t%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s", hostid,
	criticality, startdate,startevent,startcommand,startuser,startrealuser,startpid,startppid,startreturn,starttrail);


	if (AuditDestination & AUDIT_TO_STDOUT) {
		// Send to STDOUT.
		printf("%s\n", stringout);
	}

	if (AuditDestination & AUDIT_TO_FILE) {
		// Write to file
		if (AuditFile != (FILE *) NULL) {
			fprintf(AuditFile, "%s\n", stringout);
			fflush(AuditFile);
		}
	}

	return(0);
}

Node *CheckObjective(char *username, char *searchterm, char *eventname, char *options, int returncode)
{
	static int firstcall = 0;
	static Node *currentnode;

	if (firstcall == 0) {
		ResetCurrentNode();
		firstcall = 1;
	}

	while (IsValidItem()) {
		currentnode = GetCurrentItem();

		if ((!strcmp(eventname, currentnode->event_name) || !strcmp(currentnode->event_name, "AUDIT_ALL")) && (returncode == currentnode->returncode || currentnode->returncode == RETURNCODE_ANY)) {
			// Are we including users, or excluding.
			// if (excludeflag && !regmatchC || !excludeflag && regmatchC) {
			if (currentnode->excludeflag ^ regmatchC(username, currentnode->usernameRE)) {
				// if (excludematch && !regmatchC || !excludematch && regmatchC) {
				if (currentnode->excludematchflag ^ regmatchC(searchterm, currentnode->pathRE)) {
					if (regmatchC(options, currentnode->optionsRE)) {
						NextItemInList();
						DebugMsg(LOGGING_NORMAL,"MATCH");
						ResetCurrentNode();
						return(currentnode);
					}
				}
			}
		}
		NextItemInList();
	}

	ResetCurrentNode();
	return((Node *) NULL);
}

// Pick out the core details from an audit event, and set the username/searchterm/eventname
int GetAIXDetails(char *logbuffer, char *username, char *searchterm, char *eventname, char *options)
{
	char *position = logbuffer;
	char tempreturn[20]="";
	int eventsize=MAX_EVENTNAME;
	int usersize=MAX_USERNAME;
	int searchsize=MAX_PATH;
	int optionssize=MAX_OPTIONS;
	int detailedsearch=0;

	if(!logbuffer || !username || !searchterm || !eventname || !options) {
		return(0);
	}

	// Kill the newline
	position=logbuffer+strlen(logbuffer)-1;
	if(*position == '\n') {
		*position='\0';
	}

	searchterm[0] = '\0';
	eventname[0] = '\0';
	username[0] = '\0';
	options[0] = '\0';

	position=logbuffer+25;
	// Grab the date first.
	if(eventsize > 16) { eventsize=16; }
	strncpy(eventname,position,eventsize);
	eventname[eventsize]='\0';

	// Kill whitespace
	trim(eventname);
	position=logbuffer+73;
	if(usersize>9) { usersize=9; }
	strncpy(username,position,usersize);
	username[usersize]='\0';
	trim(username);

	position=logbuffer+109;
	strncpy(tempreturn,position,16);
	
	trim(tempreturn);

	if(!strcmp(eventname,"PROC_Execute") || !strcmp(eventname,"PROC_LPExecute")) {
		// Pull the command out of the extra details.
		if(strlen(logbuffer) > 130)  {
			position=logbuffer+130;
			position = FindToken("name ",position);
			if(position) {
				strncpy(searchterm,position,searchsize);
				detailedsearch=1;
			}
		}
	} else if(!strcmp(eventname,"USER_SU")) {
		position=logbuffer+130;
		strncpy(searchterm,position,searchsize);
	} else if(!strncmp(eventname,"FILE_",5)) {
		position=logbuffer+130;
		position=FindToken("path: ",position);
		if(position) {
			strncpy(searchterm,position,searchsize);
			detailedsearch=1;
		} else {
			position=FindToken("filename ",logbuffer+130);
			if(position) {
				strncpy(searchterm,position,searchsize);
				detailedsearch=1;
			} else {
				position=FindToken("topath: ",logbuffer+130);
				if(position) {
					strncpy(searchterm,position,searchsize);
					detailedsearch=1;
				}
			}
		}
		position=logbuffer+130;
		position=FindToken("mode: ",position);
		if(position) {
			char *position2;
			position2=strstr(position," ");
			if(position2) {
				if(position2-position < optionssize) {
					optionssize=position2-position;
				}
				// Indicates read vs write.
				// Copy until the next space.
				strncpy(options,position,optionssize);
				options[optionssize-1]='\0';
			}
		}
	}

	// Do we have significant details?
	if(!detailedsearch) {
		// No? Use the entire extra details field as a search term.
		if(strlen(logbuffer) > 130) {
			strncpy(searchterm,logbuffer+130,searchsize);
		} else {
			// Oh dear.. fall back to the entire record.
			strncpy(searchterm,logbuffer,searchsize);
		}
	}
	//searchterm[searchsize]='\0';

	if (!strcmp(tempreturn, "OK")) {
		return(RETURNCODE_SUCCESS);
	}
	return(RETURNCODE_FAILURE);
}

char *FindToken(char *token, char *buffer)
{
	char *position;

	if (!token || !buffer) {
		return((char *)NULL);
	}
	position = strstr(buffer, token);
	if (position) {
		position += strlen(token);
	}
	return(position);
}

void syslogdate(char *sdate, struct tm *cdate)
{
	char Month[4];
	char Date[3];
	char Hour[3];
	char Min[3];
	char Sec[3];

	if (!sdate || !cdate) return;

	switch (cdate->tm_mon) {
		case 0: strcpy(Month, "Jan"); break;
		case 1: strcpy(Month, "Feb"); break;
		case 2: strcpy(Month, "Mar"); break;
		case 3: strcpy(Month, "Apr"); break;
		case 4: strcpy(Month, "May"); break;
		case 5: strcpy(Month, "Jun"); break;
		case 6: strcpy(Month, "Jul"); break;
		case 7: strcpy(Month, "Aug"); break;
		case 8: strcpy(Month, "Sep"); break;
		case 9: strcpy(Month, "Oct"); break;
		case 10: strcpy(Month, "Nov"); break;
		default: strcpy(Month, "Dec"); break;
	}

	if (cdate->tm_mday < 10) {
		snprintf(Date, 3, " %d%c", cdate->tm_mday,0);
	} else {
		snprintf(Date, 3, "%d%c", cdate->tm_mday,0);
	}

	if (cdate->tm_hour < 10) {
		snprintf(Hour, 3, "0%d%c", cdate->tm_hour,0);
	} else {
		snprintf(Hour, 3, "%d%c", cdate->tm_hour,0);
	}

	if (cdate->tm_min < 10) {
		snprintf(Min, 3, "0%d%c", cdate->tm_min,0);
	} else {
		snprintf(Min, 3, "%d%c", cdate->tm_min,0);
	}

	if (cdate->tm_sec < 10) {
		snprintf(Sec, 3, "0%d%c", cdate->tm_sec,0);
	} else {
		snprintf(Sec, 3, "%d%c", cdate->tm_sec,0);
	}

	snprintf(sdate, 16, "%s %s %s:%s:%s%c", Month, Date, Hour, Min, Sec,0);
}






void DebugMsg(int level, const char *pszFormat, ...)
{

	char buf[8192] = "";
	if(logLevel >= level){
		va_list arglist;
		va_start(arglist, pszFormat);
		vsnprintf(&buf[strlen(buf)], 8192 - strlen(buf) - 1, pszFormat, arglist);
		va_end(arglist);
#ifdef DEBUG
		FILE *fp;
		fp=fopen("/tmp/SAFED-OUT", "a");
		if (fp) {
			fputs(buf,fp);
			fputs("\n",fp);
			fclose(fp);
		} else {
			printf("\nERROR: There was an error opening the log file\n");
		}
		//printf("%s\n", buf);
		//fflush(stdout);
#else
		openlog ("SafedCore", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_USER);
		syslog (LOG_INFO, buf);
		closelog ();
#endif //DEBUG
	}
}

