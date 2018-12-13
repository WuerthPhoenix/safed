/*
 * Misc.c
 *
 *  Created on: Dec 30, 2010
 *      Author: marco
 */
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <regex.h>
#include <unistd.h>
#include <stdarg.h>
#include <errno.h>
#include "Misc.h"

#define ROTATION_SUFFIX "^\\.[0-9]$"

regex_t _rotSufRegex;
char *_logfilename;

int _logLevel = 2;
int _logOnFile = 0;

/*
 * the filter function to use with scandir/4; it returns a value different from 0
 * only if entry->d_name is of the form: logfilename.N, where 0<=N<=9.
 */
int oldLogFilter(const struct dirent *entry) {
	static int firstTime = 1;
	if (firstTime) {
		firstTime = 0;
		regcomp(&_rotSufRegex, ROTATION_SUFFIX, REG_EXTENDED|REG_NOSUB);
	}
	if (strstr(entry->d_name, _logfilename) == entry->d_name) {
		return (regexec(&_rotSufRegex, (char *) (entry->d_name + strlen(_logfilename)), (size_t) 0, NULL, 0) == 0);
	}
	return 0;
}


/*
 * Gets the entries in the given directory that are in the form: logfilename.N;
 * the entries exceeding max (the oldest ones) are removed; for the other it shifts the names.
 * It works only if max is a number till 10.
 */
int rotateOldLogs(char *dirpath, int max) {
	if (max > 10) {
		slog(LOG_ERROR,  "rotateLog(): the parameter cannot be greater than 10 - converting from %d to 10\n", max);
		max = 10;
	}

	int error = 0;
	struct dirent **entrylist;

	int n = scandir(dirpath, &entrylist, oldLogFilter, alphasort);
	if (n < 0) {
		sperror("scandir");
		error = -1;
	} else {
		max--;
		max = max > n ? n : max;

		int i;
		// these are exceeding entries, they should be at most 1 that should be overwritten through the shift
		for (i = max; i<n; i++) {
			// free the resources allocated by scandir
			free(entrylist[i]);
		}

		// shifting the first max entry names
		for (i = max-1; i >= 0; i--) {
			char * ssubfix = strrchr(entrylist[i]->d_name, '.');
			int oldsubfix = atoi(++ssubfix);

			int pathNameLen = strlen(dirpath)+1+strlen(_logfilename)+2+1; // DIRPATH+'/'+logfilename+".N"+'\0'
			char oldPathName[pathNameLen];
			snprintf(oldPathName, pathNameLen, "%s/%s", dirpath, entrylist[i]->d_name);

			char newPathName[pathNameLen];
			int newsubfix = oldsubfix + 1;

			snprintf(newPathName, pathNameLen, "%s/%s.%d", dirpath, _logfilename, newsubfix);

			error = rename(oldPathName, newPathName);
			if (error) {
				sperror("rename");
				slog(LOG_ERROR,  "rotateOldLogs() - error renaming file: %s to: %s\n", oldPathName, newPathName);
			}

			free(entrylist[i]);
		}
		free(entrylist);
	}
	return n < max ? n : max;
}

/**
 * Flush the content of the log streams (stderr and stdout) to the log file.
 */
void flushLog() {
	fflush(stdout);
	fsync(STDOUT_FILENO);
}

/**
 * Closes stdout and stderr file descriptors, and reopens them as the logfile
 * passed as argument. From now on, stdout and stderr will be written to the logfile.
 */
void initLog(int logOnFile, int logLevel, char *logdir, char *logfile) {
	_logLevel = logLevel;
	_logOnFile = logOnFile;

	if (logOnFile) {
		int logfilefd;

		if (logLevel) {
			char logPathName[strlen(logdir)+1+strlen(logfile)+1];
			sprintf(logPathName, "%s/%s", logdir, logfile);
			// logging active: open (maybe also create) the logfile
			logfilefd = open(logPathName, O_WRONLY|O_CREAT|O_APPEND, S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
		} else {
			// logging not active: opening /dev/null
			logfilefd = open("/dev/null", O_WRONLY|O_APPEND);
		}

		if (logfilefd == -1) {
			sperror("open");
			slog(LOG_ERROR,  "problems opening the log file; redirection of stdout and stderr not possible!\n");
			return;
		}

		// redirect to it stdout and stderr
		dup2(logfilefd, STDOUT_FILENO);
		dup2(logfilefd, STDERR_FILENO);

		// the file descriptor of the log file is not any longer necessary
		close(logfilefd);
	}
}


void setLogLevel(int level) {
	_logLevel = level;
}

/**
 * stdout and stderr are redirected to logfile in logdir; the old log files are handled inside logdir following
 * the naming convention: logfile.0, logfile.1, .., logfile.n-1.
 * A call to this method, performs the rotation of the old logfiles (discarding logfile.n-1), renames the actual
 * logfile to logfile.0, open a new logfile associating to it the standard streams, and closes the old one.
 */
int rotateLog(char *logdir, char *logfile, int n) {
	if (_logLevel && _logOnFile) {
		// the rotation happens only if the logging is active
		_logfilename = logfile;

		rotateOldLogs(logdir, n);

		char logPathName[strlen(logdir)+1+strlen(logfile)+1];
		sprintf(logPathName, "%s/%s", logdir, logfile);

		char logPathNameForTheOldLog[strlen(logdir)+1+strlen(logfile)+strlen(".0")+1];
		sprintf(logPathNameForTheOldLog, "%s/%s.0", logdir, logfile);

		// mv logfile logfile.0
		if (rename(logPathName, logPathNameForTheOldLog) != 0) {
			sperror("rename");
			slog(LOG_ERROR,  "%s\n", "overwriting the old log, if any ...");
		}

		// create the new logfile
		int logfilefd = open(logPathName, O_WRONLY|O_CREAT|O_APPEND, S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
		if (logfilefd == -1) {
			sperror("open");
			slog(LOG_ERROR,  "problems opening the file: %s\n", logPathName);
			return 0;
		}

		// redirect to it stdout and stderr
		dup2(logfilefd, STDOUT_FILENO);
		dup2(logfilefd, STDERR_FILENO);

		// the file descriptor of the log file is not any longer necessary
		close(logfilefd);
	}

	return 1;
}

// Calculates the current time
void getCurrentTime(struct tm *result) {
    time_t currentunixtime;
    time(&currentunixtime);
    localtime_r(&currentunixtime, result);
}

/**
 * Close all the open fds, excepts the standard one and the given fd (if it is a valid one).
 */
void closeAllOpenfds(int fd) {
	int j;
	for (j = getdtablesize(); j >= 0; --j) {
		if (j != STDIN_FILENO && j != STDOUT_FILENO && j != STDERR_FILENO && j != fd) {
			close(j);
		}
	}
}

/**
 * Transforms the given string from dos format to unix format.
 */
void dos2unix(char *source) {
	char *dest = source;
	while (*source) {
		if (*source != '\015' && *source != '\032') {
			*dest = *source;
			dest ++;
		}
		source ++;
	}
	*dest='\0';
}


void sperror(char *message) {
	slog(LOG_ERROR, "%s: %s\n", message, strerror(errno));
}

void slog(int level, const char *pszFormat, ...) {
	char buf[LOGBUFSIZE] = "";
	if (level <= _logLevel) {

		// calculate the timestamp - dd/mm/yyyy hh:mm:ss
	    char timestamp[20];
		struct tm now;
	    getCurrentTime(&now);
	    snprintf(timestamp, 20, "%02d/%02d/%04d %02d:%02d:%02d", now.tm_mday, now.tm_mon + 1, now.tm_year+1900, now.tm_hour, now.tm_min, now.tm_sec);

		va_list arglist;
		va_start(arglist, pszFormat);
		vsnprintf(&buf[strlen(buf)], LOGBUFSIZE - strlen(buf) - 1, pszFormat, arglist);
		va_end(arglist);

		fprintf(stdout, "(%d - %s): %s", getpid(), timestamp, buf);
		flushLog();
	}
}



/*
int main(int argc, char *argv[]) {
	rotateLog("/home/marco/prova", "pippo.log", 3);
	fprintf(stdout, "Ciao mondo\n");
	fprintf(stderr, "Eccoci\n");
//	fclose(logStream);
}
*/
