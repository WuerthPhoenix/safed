/*
 * MessageFile.c
 *
 *  Created on: 22/feb/2010
 *      Author: marco
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <dirent.h>
#include <regex.h>
#include "MessageFile.h"
#ifdef __hpux__
#include "getline.h"
#endif

FILE* _messageFile = NULL;
int _day = 0;
char *currentfilename;

extern int maxDaysInCache;

regex_t compPattern;

/*
 * the filter function to use with scandir/4; it returns a value different from 0
 * only if entry->name is of the form: YYYYMMDD.log
 */
int filter(const struct dirent *entry) {
	static int firstTime = 1;
	if (firstTime) {
		firstTime = 0;
		regcomp(&compPattern, "^[0-9]{8}\\.log$", REG_EXTENDED | REG_NOSUB);
	}
	return (regexec(&compPattern, entry->d_name, (size_t) 0, NULL, 0) == 0);
}


/*
 * the sort function to use with scandir/4; it allows to sort the directory entries
 * in descending order; if the entries are in the form YYYYMMDD.log then it means that
 * it starts from the youngest to the oldest.
 */
int reverseSort(const struct dirent **e1, const struct dirent **e2) {
	return alphasort(e2, e1);
}

/*
 * gets the entries in the given directory that match the pattern YYYYMMDD.log,
 * and removes the oldest ones that exceeds the parameter MAXLOGENTRIES.
 */
int checkDir(char *dirpath) {
	struct dirent **entrylist;
	int n = scandir(dirpath, &entrylist, filter, reverseSort);
	if (n < 0) {
		perror("scandir");
	} else {
		int i = 0;
		while (i < n) {
			if (i >= maxDaysInCache) {
				char fullPathName[strlen(dirpath)+14];
				snprintf(fullPathName, strlen(dirpath)+14, "%s/%s", dirpath, entrylist[i]->d_name);
				printf("... removing entry %s that is too old!\n", fullPathName);
				unlink(fullPathName);
			}
		   free(entrylist[i]);
		   i++;
		}
		free(entrylist);
	}
	return n < maxDaysInCache ? n : maxDaysInCache;
}

char* calculateFileName(char *current, int year, int month, int day) {
	int len = strlen(CACHE_DIR_NAME)+14;
	char *filename = (char *) realloc (current, strlen(CACHE_DIR_NAME)+14);
	if (month < 10) {
		if (day < 10) {
			snprintf(filename, len, "%s/%d0%d0%d.log", CACHE_DIR_NAME, year, month, day);
		} else {
			snprintf(filename, len, "%s/%d0%d%d.log", CACHE_DIR_NAME, year, month, day);
		}
	} else {
		if (day < 10) {
			snprintf(filename, len, "%s/%d%d0%d.log", CACHE_DIR_NAME, year, month, day);
		} else {
			snprintf(filename, len, "%s/%d%d%d.log", CACHE_DIR_NAME, year, month, day);
		}
	}
	return filename;
}

void closeMessageFile() {
	if (_messageFile) {
		fclose(_messageFile);
		_messageFile = NULL;
	}
}

void writeMsgOnFile(char* message, int year, int month, int day) {
	/* the day is changed: I have to close the actual log file
	and I have to open a new one with the name YYYYMMDD.log */
	if (day != _day) {
		_day = day;
		closeMessageFile();
		currentfilename = calculateFileName(currentfilename, year, month, day);
	}

	if (_messageFile == NULL) {
		_messageFile = fopen(currentfilename, "a");
		// if necessary, remove the oldest file
		checkDir(CACHE_DIR_NAME);
	}
	fputs(message, _messageFile);
	fflush(_messageFile);
	fsync(fileno(_messageFile));
}


int getInitialSeqNumber(int year, int month, int day) {
	int result = 0;

	char *filename = calculateFileName(NULL, year, month, day);
	FILE *messageFile = fopen(filename, "r");
	if (messageFile) {
		char *line = NULL;
		size_t len = 0;
		ssize_t read = 0;

		while ((read = getline(&line, &len, messageFile)) != -1) {
			result ++;
		}
		if (line) {
			free(line);
		}
		fclose(messageFile);
	} else {
		char errorMessage[2000];
		sprintf(errorMessage, "... error opening the file: %s - fopen", filename);
		perror(errorMessage);
	}
	free(filename);

	return result;
}

int getTotalSavedLogs(FILE * fp){
        char line[8192];
        int cnt = 0;
        if(fp) {
                while (fgets(line, 8192, fp)) {
                        cnt++;
                }
        }

        return cnt;
}

void getSavedLogAt(FILE * fp, char* line, int position){
        int cnt = 0;
        if(fp) {
                while ((cnt <= position) && fgets(line, 8192, fp)) {
                        cnt++;
                }
                if(cnt <= position)
                        *line = '\0';
        }
}


