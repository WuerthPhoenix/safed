/*
 * Misc.h
 *
 *  Created on: Dec 30, 2010
 *      Author: marco
 */

#ifndef MISC_H_
#define MISC_H_

#define LOG_ERROR 1
#define LOG_NORMAL 2
#define LOG_DEBUG 3

#define LOGBUFSIZE 8192		/* MAX UDP string buffer size */

void dos2unix(char *source);
void getCurrentTime(struct tm *result);
void closeAllOpenfds(int fd);

void flushLog();
void initLog(int logOnFile, int loglevel, char *logdir, char *logfile);
void setLogLevel(int level);

int rotateLog(char *logdir, char *logfile, int n);

void sperror(char *message);
void slog(int level, const char *pszFormat, ...);


#endif /* MISC_H_ */
