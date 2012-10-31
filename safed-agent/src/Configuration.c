/*
 * misc.c
 *
 *  Created on: Dec 9, 2010
 *      Author: marco
 */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <fcntl.h>
#include "Configuration.h"
#include "Misc.h"



// The actual configuration read from the file
char hostname[MAX_HOSTID] = "";
int remoteControlAllowed = 0;
int remoteControlHttps = 0;
int remote_webport = 6161;
char remoteControlIp[SIZE_OF_RESTRICTIP] = "";
char remoteControlPassword[256] = "";
int maxMsgSize = MAXMSGSIZE;
int maxDaysInCache = MAXDAYSINCACHE;
int waitTime = TIMEOUT;
char USER_CONFIG_FILENAME[MAX_AUDIT_CONFIG_LINE] = "\0";
char initStatus[100] = "";
char lastSetTime[25] = "";
int priority = 13;			        // priority of user.notice (PRI = FACILITY*8 + SEVERITY)
int logFileToKeep = LOG_FILE_TO_KEEP;
int logLevel = DEFAULT_LOG_LEVEL;

// information about the syslog server and its connection
HostNode host;


/*****************************************************************/
/* This section implements the list of log files to be monitored */
/*****************************************************************/
LogFileData *logFileHead,  *logFileTail = NULL;


/*
 * Parses the line that has the syntax: log=LOGTYPE:ABSOLUTE_FILE_PATH,,
 * creates the corresponding LogNode object, opens the log file going at the end,
 * and fills all the LogNode attributes (loading the stat attributes of the file);
 * at the end, it adds the newly created LogNode to the list, updating lhead and ltail.
 */
int addLogWatch(char *string) {
	char *pos, *pos2;
	// removing the "log=" prefix from string
	string += strlen("log=");
	if (strlen(string)) {	// if string is not empty
		// creating a LogNode object to store information about the actual log file
		LogFileData *newLogFile = (LogFileData *) malloc(sizeof(LogFileData));
		if (newLogFile) {
			pos = strstr(string, ":");//for compatibility with format type:absolute path
			pos2 = strstr(string, "/");
			if (pos && pos2 && pos < pos2) {
				string = pos + 1; // now string is the absolute file path
			}
			// recording the log file name
			strncpy(newLogFile->fileName, string, MAX_AUDIT_CONFIG_LINE);
			newLogFile->next = NULL;

			if (logFileTail) {
				logFileTail->next=newLogFile;
				logFileTail=newLogFile;
			}
			if (!logFileHead) {
				logFileHead=newLogFile;
				logFileTail=newLogFile;
			}
			return 1;
		} else {
			slog(LOG_ERROR,  "... failed to allocate memory for log file: %s ... exiting!\n", newLogFile->fileName);
			exit(-1);
		}
	}
	return 0;
}


void openLogFile(LogFileData *element) {
	// opening the log file name for reading
	element->fs = fopen(element->fileName, "r");
	if (element->fs == NULL) {
		// could not open the file
		slog(LOG_NORMAL, "Failed to grab file stream for %s\n", element->fileName);
		sperror("open");
		// storing the actual unix time in seconds in LogNode.last_error
		element->last_error = time(&element->last_error);
		return;
	}

	struct stat stats;
	// grab and record the current stats
	if (stat(element->fileName, &stats) < 0) {
		slog(LOG_ERROR,  "... failed to grab stats for %s\n", element->fileName);
		sperror("stat");
		// storing the actual unix time in seconds in LogNode.last_error
		element->last_error = time(&element->last_error);
		return;
	}

	#if defined(__hpux__) || defined(_AIX)
	element->mtime = stats.st_mtime;
	#else
	element->mtime = stats.st_mtim;
	#endif

	element->size = stats.st_size;
	element->dev = stats.st_dev;
	element->ino = stats.st_ino;
	element->mode = stats.st_mode;
	element->last_error=0;
	element->pmsg[0]='\0';

	// seek to the end of the file and prepare to capture further output
	fseek(element->fs, element->size, SEEK_SET);
}

void openLogFiles() {
	LogFileData *element = logFileHead;
	while (element) {
		openLogFile(element);
		element = element->next;
	}
}

/*****************************************************************/
/*      This section implements the list of matching rules       */
/*****************************************************************/

// the list of matching rules
MatchingRule *matchingRuleHead, *matchingRuleTail = NULL;



/*
 * Creates a new MatchingRule instance for the given arguments,
 * and adds it to the linked list of matching rules.
 * At the end updates the head variable (LIFO strategy).
 */
MatchingRule *addToMatchingRuleList(char *regexpSrc, int excludematchflag) {
	MatchingRule *newNode = (MatchingRule *) malloc(sizeof(MatchingRule));

	if (newNode == NULL) {
		sperror("addToMatchingRuleList(): error in dynamic memory allocation \n");
		exit(1);
	}
	newNode->excludematchflag = excludematchflag;

	strncpy(newNode->regexpSource, regexpSrc, PATH_MAX);

	// compiling the regular expression; if an error occurs, the safed agent exits!
	int errorCode = regcomp(&newNode->regexpCompiled, regexpSrc, REG_EXTENDED | REG_NOSUB);

	if (errorCode != 0) {
		char errorMsg[8192];
		regerror(errorCode, &newNode->regexpCompiled, errorMsg, 8192);
		slog(LOG_ERROR,  "Error compiling the regular expression: %s\nError code = %d\nError message = %s\n", regexpSrc, errorCode, errorMsg);
		exit(1);
	}

	newNode->next = NULL;

	if (!matchingRuleHead) {
		matchingRuleHead = newNode;
		matchingRuleTail = matchingRuleHead;
	} else {
		matchingRuleTail->next = newNode;
		matchingRuleTail = newNode;
	}

	return newNode;
}


// Matches string against a compiled regular expression.
// Return 1 for match, 0 for no-match or error.
int regexMatch(const char *string, regex_t re) {
	return regexec(&re, string, (size_t) 0, NULL, 0) == 0;
}


int checkObjectiveRecursive(char *item, MatchingRule *node) {
	if (node == NULL) {
		// no matching found => nothing passes
		return 0;
	} else {
		if (regexMatch(item, node->regexpCompiled)) {
			// if I find a match, the search is finished
			slog(LOG_NORMAL, "match found: %s\n", item);
			if (node->excludematchflag) {
				return 0;
			} else {
				return 1;
			}
		}
		// no matching found: I continue checking the other rules ...
		return checkObjectiveRecursive(item, node->next);
	}
}

/* checks if the given string matches one of the regular expressions defined */
int checkObjective(char *item) {
	return checkObjectiveRecursive(item, matchingRuleHead);
}




void destroyList(void) {
	if (NULL == matchingRuleHead) {
		return;
	}

	//deallocating the list of matching rules;
	while (NULL != matchingRuleHead) {
		MatchingRule *tempPtr = matchingRuleHead;
		matchingRuleHead = matchingRuleHead->next;

		// Free regular expressions.
		regfree(&tempPtr->regexpCompiled);

		free(tempPtr);
	}

	// closing the connection to the syslog server
	if(host.socket){
		close(host.socket);
	}
	//TODO: invocare qui il destroyMemoryCache()?

	LogFileData *currentLogFile = logFileHead;
	while(currentLogFile) {
		logFileHead=currentLogFile->next;
		if (currentLogFile->fs) fclose(currentLogFile->fs);
		free(currentLogFile);
		currentLogFile=logFileHead;
	}

}






/*
 * This copy function is used instead of the strcpy() function whose behaviour in case of overlapping arguments is undefined.
 * (Actually strcpy() works on 32 bits architecture, and it does not work on 64 bit architectures)
 */
void copy(char *dst, char *src) {
	while(*src) {
		*dst = *src;
		dst++;
		src++;
	}
	*dst='\0';
}


// Remove start / end whitespace, including the newline
void trim(char *string) {
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
	copy(string, pointer2);
}


/*
 * Returns 1 if the given string matches against the given pattern, 0 for no-match or error.
 * The match is CASE INSENSITIVE; pattern is an Extended Regular Expression.
 */
int regmatchInsensitive(const char *string, const char *pattern) {
	int result;
	regex_t re;

	// compiling the regular expression for a match case insensitive
	if (regcomp(&re, pattern, REG_EXTENDED | REG_NOSUB | REG_ICASE) != 0) {
		slog(LOG_ERROR,  "... regmatchInsensitive(): problems compiling the regular expression %s\n", pattern);
		return(0);
	}

	result = regexec(&re, string, (size_t) 0, NULL, 0);

	// after compiling and using a regular expression, the allocated memory should be freed
	regfree(&re);

	if (result != 0) {
		return(0);
	}
	return(1);
}


/*
 * Extracts the wait time from the input string.
 * In case of error it returns -1.
 * A well formed input is in the form: "^waittime=[0-9]+$"
 */
int getWaitTime(char *string) {
	int wt = TIMEOUT;
	// I extract the value only if the input string is well formed
	if (regmatchInsensitive(string, "^waittime=[0-9]+$")) {
		string += strlen("waittime=");
		wt = atoi(string);
	} else {
		// this is an error situation that should be handled
		slog(LOG_ERROR,  "... problems reading the wait time: the line %s is not correct\n", string);
		wt = -1;
	}
	return wt;
}


/*
 * Extracts the syslog priority (facility*8 + severity) from the input string.
 * A well formed input is in the form: "^syslog=[0-9]+$"
 */
int getSyslogPriority(char *string) {
	int pri;
	if (regmatchInsensitive(string, "^syslog=[0-9]+$")) {
		string += strlen("syslog=");
		pri = atoi(string);
	} else {
		// this is an error situation that should be handled
		slog(LOG_ERROR,  "... problems reading the syslog priority: the line %s is not correct\n", string);
		pri = -1;
	}
	return pri;
}


int getLogFileToKeep(char *string) {
	int keep = LOG_FILE_TO_KEEP;
	if (regmatchInsensitive(string, "^logFileToKeep=[1-9]+$")) {
		string += strlen("logFileToKeep=");
		keep = atoi(string);
	} else {
		// this is an error situation that should be handled
		slog(LOG_ERROR,  "... problems reading the log files to keep: the line %s is not correct\n", string);
	}
	return keep;
}


int getLogLevel(char *string) {
	int logLevel = DEFAULT_LOG_LEVEL;
	if (regmatchInsensitive(string, "^logLevel=[1-9]+$")) {
		string += strlen("logLevel=");
		logLevel = atoi(string);
		logLevel = logLevel % LOG_LEVELS;
	} else {
		// this is an error situation that should be handled
		slog(LOG_ERROR,  "... problems reading the log level: the line %s is not correct\n", string);
	}
	return logLevel;
}


int getMaxMsgSize(char *string) {
	int mms = MAXMSGSIZE;
	string += strlen("maxmsgsize=");
	if (strlen(string) > 0) {
		mms = atoi(string);
	}
	slog(LOG_NORMAL, "max message size: %d \n", mms);
	return mms;
}

int getSetAudit(char *string) {
	int sa = 0;
	string += strlen("set_audit=");
	if (strlen(string) > 0) {
		sa = atoi(string);
	}
	if(sa > 1)
		sa=0;
	slog(LOG_NORMAL, "set audit: %d \n", sa);
	return sa;
}

int getMaxDaysInCache(char *string) {
	int days = MAXDAYSINCACHE;
	string += strlen("days=");
	if (strlen(string) > 0) {
		days = atoi(string);
	}
	slog(LOG_NORMAL, "max number of days in cache: %d \n", days);
	return days;
}


int isLastSetTime(char *string) {
    char* posLST;
	posLST =strstr(string,"#LastSetTime=");
	if(posLST){
		return(1);
	} else {
		return(0);
	}
}



//TODO: si potrebbe riscrivere od eliminare sfruttando la funzione getconfstring, che fa quasi la stessa cosa
int getport(char *string) {
	char *stringp = string;
	char strPort[10];

	stringp = strstr(string, "=");

	if (stringp != (char *)NULL) {
		stringp++;
		if (strlen(stringp)) {
			strncpy(strPort, stringp, 10);
			return(atoi((char *)strPort));
		} else {
			return(0);
		}
	} else {
		return(0);
	}
}

/*
 * string is a name=value couple; from this couple it extracts the value, and returns it
 */
char *getconfstring(char *string, char *value, int length) {
	char *stringp = string; // probably this copy is not necessary

	// looking for the first occurrence of '='
	stringp = strstr(string, "=");

	// if '=' is found inside the string
	if (stringp != (char *) NULL) {
		stringp++;	// this is the part of the string following the '=' char
		if (strlen(stringp)) {
			return strncpy(value, stringp, length - 1);
		} else {
			return((char *)NULL);
		}
	} else {
		return((char *)NULL);
	}
}


/*
 * A comment is made by an empty line or a line made of an arbitrary sequence of empty char
 * and then by a # character.
 * It is expressed by the following regular expression: "^[\x20\x09\x0A\x0C]*$|^[\x20\x09\x0A\x0C]*#.*$"
 */
int iscomment(char *line) {
	// Verify that there is something to check.
	if (line == (char *) NULL) return(1);
	return regmatchInsensitive(line, "^[\x20\x09\x0A\x0C]*$|^[\x20\x09\x0A\x0C]*#.*$");
}


/*
 * Returns if the given string is a header line.
 * A line is considered a header if it is of the form [SOMETHING],
 * i.e. if it starts with the '[' char and ends with the ']' char.
 */
int isheader(char *string) {
	if (string[0] == '[' && string[strlen(string) - 1] == ']') {
		return(1);
	}
	return(0);
}

/* returns 1 if the line starts with the string "network=" */
int isnetwork(char *string) {
	return regmatchInsensitive(string, "^network=");
}

/* returns 1 if the line starts with the string "log=" */
int islog(char *string) {
	return regmatchInsensitive(string, "^log=");
}

/* returns 1 if the line starts with the string "waittime=" */
int iswaittime(char *string) {
	return regmatchInsensitive(string, "^waittime=");
}

/* returns 1 if the line starts with the string "syslog=" */
int issyslog(char *string) {
	if (regmatchInsensitive(string, "^syslog=")) {
		return(1);
	}
	return(0);
}

/* returns 1 if the line starts with the string "maxmsgsize=" */
int ismaxmsgsize(char *string) {
 	if (regmatchInsensitive(string, "^maxmsgsize=")) {
 		return(1);
 	} else {
 		return(0);
 	}
}

/* returns 1 if the line starts with the string "set_audit=" */
int issetaudit(char *string) {
 	if (regmatchInsensitive(string, "^set_audit=")) {
 		return(1);
 	} else {
 		return(0);
 	}
}

/* returns 1 if the line starts with the string "days=" */
int isdays(char *string) {
	if (regmatchInsensitive(string, "^days=")) {
		return(1);
	}
	return(0);
}


int isLogFileToKeep(char *string) {
	if (regmatchInsensitive(string, "^logFileToKeep")) {
		return(1);
	}
	return (0);
}


int isLogLevel(char *string) {
	if (regmatchInsensitive(string, "^logLevel=[1-9]+$")) {
		return(1);
	}
	return (0);
}



int getheader(char *string) {
	/* \\] is needed in the code to have \] into the string:
	   the first \ escapes the following \ to the compiler;
	   the second slash escapes the ] metacharacter so the
	   regex compiler regards it literally. */
	if (regmatchInsensitive(string, "^\\[objectives\\]$")) {
		return(CONFIG_OBJECTIVES);
	} else if (regmatchInsensitive(string, "^\\[watch\\]$")) {
		return(CONFIG_WATCH);
	} else if (regmatchInsensitive(string, "^\\[aobjectives\\]$")) {
		return(AUDIT_CONFIG_OBJECTIVES);
	} else if (regmatchInsensitive(string, "^\\[input\\]$")) {
		return(CONFIG_INPUT);
	} else if (regmatchInsensitive(string, "^\\[output\\]$")) {
		return(CONFIG_OUTPUT);
	} else if (regmatchInsensitive(string, "^\\[hostid\\]$")) {
		return(CONFIG_HOSTID);
	} else if (regmatchInsensitive(string, "^\\[remote\\]$")) {
		return(CONFIG_REMOTE);
	} else if (regmatchInsensitive(string, "^\\[log\\]$")) {
		return CONFIG_LOG;
	} else if (regmatchInsensitive(string, "^\\[End\\]$")) {
		return CONFIG_END;
	}

	slog(LOG_NORMAL, "Unknown header in configuration file: %s\n", string);
	return(0);
}
// Take an identified objective line
// NOTE: string, event, user and match must all be the same buffer size!
int split_audit_objective(char *string, char *event, char *user, char *match, int *excludeflag, int *excludematchflag, int *returncode)
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
		}else{
			*excludeflag = -1;
		}
	}
	startmatch = strstr(string, "match=");
	if (startmatch == (char *)NULL) {
		startmatch = strstr(string, "match!=");
		if (startmatch != (char *)NULL) {
			// EXCLUDE rather than include.
			*excludematchflag = 1;
		}else{
			*excludematchflag = -1;
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

	if (startevent == (char *)NULL  || startcrit == (char *)NULL) {
		// Problem, this line is malformed. We really cannot proceed with this line.
		slog(LOG_ERROR, "The following line does not contain the criticality, event: [%s]", string);
		return(-1);
	}
#if defined(__sun) || defined(_AIX)
	if (startuser == (char *)NULL ||   startmatch == (char *)NULL ||  startreturn == (char *)NULL) {
		// Problem, this line is malformed. We really cannot proceed with this line.
		slog(LOG_ERROR, "The following line does not contain the  return, user and match elements: [%s]", string);
		return(-1);
	}
#endif
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
	if (startreturn != (char *)NULL) {
		stringpointer = startreturn + strlen("return=");
		if (regmatchInsensitive(stringpointer, "^[(]?success[)]?")) {
			*returncode = RETURNCODE_SUCCESS;
		} else if (regmatchInsensitive(stringpointer, "^[(]?failure[)]?")) {
			*returncode = RETURNCODE_FAILURE;
		} else {
			// Any thing else is either success or failure.
			*returncode = RETURNCODE_ANY;
		}
	}else{
		*returncode = RETURNCODE_ANY;
	}

	if (startuser != (char *)NULL) {

		if (*excludeflag) {
			stringpointer = startuser + strlen("user!=");
		}else {
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
		if(((strlen(user) == 1 )&&(!strcmp(user,"*"))) ||
			((strlen(user) == 3)&&(!strcmp(user,"(*)")))){
			user[0]='\0';
		}
	}

	if (startmatch != (char *)NULL ) {
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
		if(((strlen(match) == 1 )&&(!strcmp(match,"*"))) ||
			((strlen(match) == 3)&&(!strcmp(match,"(*)")))){
			match[0]='\0';
		}
	}

	// Return the criticality value.
	return(crit);
}





// NOTE: line and regexp must all be the same buffer size!
/*
 * The argument line is of the form "match=regexp" or "match!=regexp";
 * the function sets the excludematchflag to 1 if the line is of
 * the form "match!=regexp" and copies the part following the '=' sign to regexp,
 * deleting the whitespace at the beginning and at the end.
 * If line is malformed the function returns -1, otherwise returns 1.
 */
int splitobjective(char *line, char *regexp, int *excludematchflag){

	char *startmatch, *regexpStart;

	// return an error if line == NULL
	if (line == (char *) NULL || regexp == (char *) NULL) {
		return(-1);
	}
	// return an error if line == ""
	if (!strlen(line)) {
		return(-1);
	}

	// looking for inclusive or exclusive match
	startmatch = strstr(line, "match=");
	if (startmatch) {
		*excludematchflag = 0;
	} else {
		startmatch = strstr(line, "match!=");
		if (startmatch) {
			*excludematchflag = 1;
		} else {
			//no match found: error!
			return -1;
		}
	}

	// stringpointer points at the beginning of the regexp part
	regexpStart = startmatch + strlen("match=") + *excludematchflag;

	//TODO: here we have a potential buffer overflow!
	strcpy(regexp, regexpStart);

	// removing extra whitespace at start and end.
	trim(regexp);

	return 1;
}



// NOTE: line and regexp must all be the same buffer size!
/*
 * The argument line is of the form "path=regexp", "path~=regexp" or "path!=regexp";
 * the function sets the excludematchflag to 1 if the line is of
 * the form "path!=regexp" and copies the part following the '=' sign to regexp,
 * deleting the whitespace at the beginning and at the end.
  * the function sets the newfile to 1 if the line is of
 * the form "path~=regexp" and copies the part following the '=' sign to regexp,
 * deleting the whitespace at the beginning and at the end.
 *
 * If line is malformed the function returns -1, otherwise returns 1.
 */
int splitwatch(char *line, char *regexp, int *excludematchflag, int* newfile){

	char *startmatch, *regexpStart;

	// return an error if line == NULL
	if (line == (char *) NULL || regexp == (char *) NULL) {
		return(-1);
	}
	// return an error if line == ""
	if (!strlen(line)) {
		return(-1);
	}

	// looking for inclusive or exclusive match
	startmatch = strstr(line, "path=");
	if (startmatch) {
		*excludematchflag = 0;
		*newfile=0;
	} else {
		startmatch = strstr(line, "path!=");
		if (startmatch) {
			*excludematchflag = 1;
			*newfile=0;
		} else {
			startmatch = strstr(line, "path~=");
			if (startmatch) {
				*excludematchflag = 0;
				*newfile=1;
			} else {
				//no match found: error!
				return -1;
			}
		}
	}

	// stringpointer points at the beginning of the regexp part
	regexpStart = startmatch + strlen("path=") + *excludematchflag + *newfile;

	//TODO: here we have a potential buffer overflow!
	strcpy(regexp, regexpStart);

	// removing extra whitespace at start and end.
	trim(regexp);

	return 1;
}

//???
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


void parseNetworkData(char* string, char* destinationHost, int* destinationPort, int* socketType, char* protocolName) {
	// default values
	*destinationPort = 514;
	*socketType = SOCK_DGRAM;
	strncpy(destinationHost, "localhost", MAX_HOSTID);
	strncpy(protocolName, "udp", MAX_HOSTID);

	// removing the heading "network=" from string
	string += strlen("network=");

	if (strlen(string)) {
		char* port = strstr(string, ":");
		if (port) {
			// the destination port is specified

			// acquiring the destination host
			if ((port - string) < MAX_HOSTID) {
				strncpy(destinationHost, string, (port - string));
				destinationHost[port - string] = '\0';
			} else {
				strncpy(destinationHost, string, MAX_HOSTID);
				destinationHost[MAX_HOSTID - 1] = '\0';
				slog(LOG_NORMAL, "WARNING: hostname truncated to: %s!\n", destinationHost);
			}

			string = ++port; // now string points at the string following the ':' char, that is the port

			char* proto = strstr(string, ":");

			if (proto) {
				// the protocol is specified
				// acquiring the destination port
				char destPortStr[proto-string+1];
				strncpy(destPortStr, string, proto - string);
				destPortStr[proto-string] = '\0'; // adding the string terminator to the destinationPort string
				*destinationPort = atoi(destPortStr);
				// the protocol is in the string pos
				proto ++;
				if (strcmp("tcp", proto) == 0 || strcmp("TCP", proto) == 0) {
					strncpy(protocolName, "tcp", MAX_HOSTID);
					*socketType = SOCK_STREAM;
				} else if (strcmp("rtcp", proto) == 0 || strcmp("TCP", proto) == 0) {
					strncpy(protocolName, "rtcp", MAX_HOSTID);
					*socketType = SOCK_STREAM;
				}
				#ifdef TLSPROTOCOL
				else if (strcmp("tls", proto) == 0 || strcmp("TLS", proto) == 0) {
					strncpy(protocolName, "tls", MAX_HOSTID);
					*socketType = SOCK_STREAM;
				}
				#endif
			} else {
				// the protocol is not specified
				if (strlen(port)) {
					*destinationPort = atoi(port); //TODO: se si verifica un errore nella conversione da stringa a numero? forse meglio usare strtol()
				}
			}
		} else {
			// no destination port specified => no protocol also; assuming default values
			strncpy(destinationHost, string, MAX_HOSTID);
		}

		// just in case the user has entered a blank field ...
		if (strlen(destinationHost) == 0) {
			strncpy(destinationHost, "localhost", MAX_HOSTID);
			slog(LOG_NORMAL, "WARNING: assuming hostname: %s!\n", destinationHost);
		}
	}
}


/*
 * Parses the destination host and port, opens the socket to communicate to the destination,
 * and fills the data for the corresponding HostNode.
 * The string syntax in BNF should be: network=hostname[:port[:tcp|udp]], but the expected one is
 * network=hostname[:port]; if no hostname is provided, localhost is assumed.
 */
int configureHostNode(char *string) {
	char destinationHost[MAX_HOSTID];
	char protocolName[MAX_HOSTID];
	int destinationPort;
	int socketType;

	parseNetworkData(string, destinationHost, &destinationPort, &socketType, protocolName);

	slog(LOG_NORMAL, "destinationHost: %s\n", destinationHost);
	slog(LOG_NORMAL, "destinationPort: %d\n", destinationPort);
	slog(LOG_NORMAL, "protocol: %d\n", socketType);
	slog(LOG_NORMAL, "protocolName: %s\n", protocolName);

	// getting the remote host address by the name resolver
	struct hostent *hostAddress;
	hostAddress = gethostbyname(destinationHost);
	if (hostAddress == 0) {
		slog(LOG_ERROR,  "... cannot resolve host %s\n, exiting!", destinationHost);
		exit(0);
	}

	host.socket = 0;
	host.socketAddress.sin_family = AF_INET;
	host.socketAddress.sin_addr = * ((struct in_addr *) hostAddress->h_addr);
	host.socketAddress.sin_port = htons(destinationPort);
	host.dest_addr_size = sizeof(host.socketAddress);

	strncpy(host.desthost, destinationHost, MAX_HOSTID);
	strncpy(host.protocolName, protocolName, MAX_HOSTID);

	host.port = destinationPort;
	host.protocol = socketType;

	return 1;
}



int readConfigurationFile() {
	FILE *configfile = (FILE *)NULL;
	char line[MAX_AUDIT_CONFIG_LINE];	// Should be enough for most config lines.
							// Would love to use gchar here instead, but need to keep this simple.
	// Config file header.
	int currentHeader = 0;

	// default configuration for remote control
	remoteControlAllowed = 0;
	remoteControlIp[0] = '\0';
	remoteControlPassword[0] = '\0';

	// opening the configuration file
	char* configFileName = NULL;
	if (strlen(USER_CONFIG_FILENAME)) {
		configFileName = USER_CONFIG_FILENAME;
	} else {
		configFileName = CONFIG_FILENAME;
	}
	slog(LOG_NORMAL, "... reading configuration from: %s\n", configFileName);
	configfile = fopen(configFileName, "r");

	if (configfile == (FILE *)NULL) {
		perror("Cannot open audit configuration file.\n");
		exit(1);
	}

	while (fgets(line, MAX_AUDIT_CONFIG_LINE, configfile)) {
		// remove whitespace from start and end of line (the result could be an empty string)
		trim(line);

		if (!iscomment(line)) {
			// Is this line a header?
			if (isheader(line)) {
				currentHeader = getheader(line);
			} else {
				if (currentHeader == CONFIG_OBJECTIVES) {
					// Save off enough space to store the data we need.
					char path[MAX_AUDIT_CONFIG_LINE];
					int excludematchflag = 0;

					if (splitobjective(line, path, &excludematchflag) > -1) {
						addToMatchingRuleList(path, excludematchflag);
					} else {
						slog(LOG_NORMAL, "WARNING: Cannot process objective - please ensure configuration line\n\tcontains valid match elements\n\t%s\n", line);
					}
				} else if (currentHeader == CONFIG_OUTPUT) {
					if (isnetwork(line)) {
						if (!configureHostNode(line)) {
							slog(LOG_NORMAL, "WARNING: could not open a socket for the host to send the logs: %s\n", line);
						}
					} else if (issyslog(line)) {
						// defining the priority for all the syslog messages generated by the agent!
						priority = getSyslogPriority(line);
						if (!priority) {
							priority = 13;
							slog(LOG_NORMAL, "WARNING: Could not establish the correct syslog destination from the audit configuration: %s - Sending to user.notice\n", line);
						}
					} else if (iswaittime(line)) {
						waitTime = getWaitTime(line);
					} else if (ismaxmsgsize(line)) {
						maxMsgSize = getMaxMsgSize(line);
					} else  if (isdays(line)) {
						maxDaysInCache = getMaxDaysInCache(line);
					}
				} else if (currentHeader == CONFIG_INPUT) {
					if (islog(line)) {
						if (!addLogWatch(line)) {
							slog(LOG_NORMAL, "WARNING: Could not open the log file specified in the audit configuration: %s\n", line);
						}
					}
				} else if (currentHeader == CONFIG_HOSTID) {
					// reads the hostname and copies it in hostid
					getconfstring(line, hostname, MAX_HOSTID);
				} else if (currentHeader == CONFIG_REMOTE) {
					// Grab the remote control stuff here
					if (regmatchInsensitive(line, "^allow=")) {
						if (regmatchInsensitive(line, "=1")) {
							remoteControlAllowed = 1;
						}
					} else if (regmatchInsensitive(line, "^https=")) {
						if (regmatchInsensitive(line, "=1")) {
							remoteControlHttps = 1;
						}
					} else if (regmatchInsensitive(line, "^listen_port=")) {
						remote_webport = getport(line);
					} else if (regmatchInsensitive(line, "^restrict_ip=")) {
						if (!getconfstring(line, remoteControlIp, sizeof(remoteControlIp))) {
							strncpy(remoteControlIp, "", sizeof(remoteControlIp));
						}
					} else if (regmatchInsensitive(line, "^accesskey=")) {
						if (!getconfstring(line, remoteControlPassword, sizeof(remoteControlPassword))) {
							strncpy(remoteControlPassword, "", sizeof(remoteControlPassword));
						}
					}
				} else if (currentHeader == CONFIG_LOG) {
					if (regmatchInsensitive(line, "^logFileToKeep=")) {
						logFileToKeep = getLogFileToKeep(line);
					} else if (regmatchInsensitive(line, "^logLevel=")) {
						logLevel = getLogLevel(line);
					}
				} else if (currentHeader == CONFIG_LOG) {
					// probably we should check that at this point we are really at the end of the file
				}else if ((currentHeader == AUDIT_CONFIG_OBJECTIVES) || (currentHeader == CONFIG_WATCH)) {
					// skip them. They are used by the audit process
				}else {
					slog(LOG_NORMAL, "WARNING: Configuration file line does not fit in any recognized header.\n\t%s\n", line);
				}
			}
		} else if(isLastSetTime(line)){
			char* pos = strstr(line,"=") + 1;
			strcpy(lastSetTime,pos);
		}
	}

	fclose((FILE *)configfile);

	if (strlen(hostname) == 0) {
		getfqdn(hostname);
	}
	return(1);
}




