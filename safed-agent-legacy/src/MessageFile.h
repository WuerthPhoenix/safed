/*
 * MessageFile.h
 *
 *  Created on: 22/feb/2010
 *      Author: marco
 */

#ifndef MESSAGEFILE_H_
#define CACHE_DIR_NAME "/var/log/safed"
#define MESSAGEFILE_H_


char* calculateFileName(char *current, int year, int month, int day);
void writeMsgOnFile(char* message, int year, int month, int day);
void closeMessageFile();
int getInitialSeqNumber(int year, int month, int day);

int getTotalSavedLogs(FILE * fp);
void getSavedLogAt(FILE * fp, char* line, int position);

#endif /* MESSAGEFILE_H_ */
