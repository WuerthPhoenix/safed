#include <stdio.h>
#include <windows.h>
#include <time.h>

#include "LogUtils.h"
#include "RegKeyUtilities.h"

int SAFEDDEBUG = 0;
HANDLE hMutexLogFile;
DWORD dwNumberLogFiles = 1;
DWORD dwLogLevel = 0;
BOOL uselogfile = FALSE;
struct tm savedlogtime;
char logfilename[1024] = "";

BOOL initLogMutex(){
	SECURITY_ATTRIBUTES MutexOptions;
	MutexOptions.bInheritHandle = true;
	MutexOptions.nLength = sizeof(SECURITY_ATTRIBUTES);
	MutexOptions.lpSecurityDescriptor = NULL;
	hMutexLogFile = CreateMutex(&MutexOptions,FALSE,"FileLogLock");
	if(hMutexLogFile == NULL) {
		LogExtOnlyDebugMsg(ERROR_LOG,"I cannot create the Safed Agent Log File 'Mutex' lock. This probably means that you already have another instance of the Safed Agent running.\nPlease stop the other incarnation of the Safed Agent (eg: net stop safed) before continuing.");
		return FALSE;
	}
	return TRUE;
}

void initLog(){
	// Initialise the elements of savedlogtime that we use.
	savedlogtime.tm_mday=0;
	savedlogtime.tm_mon=0;
	savedlogtime.tm_year=0;
	dwNumberLogFiles=MyGetProfileDWORD("Config","NumberLogFiles",1);
	dwLogLevel=MyGetProfileDWORD("Config","LogLevel",0);
	uselogfile = GetFileName(logfilename, NULL, FALSE);
}

HANDLE getLogMutex(){
	return hMutexLogFile;
}

void deinitLog(){
	if(hMutexLogFile)CloseHandle(hMutexLogFile);
}


void setSAFEDDEBUG(int _SAFEDDEBUG){
	SAFEDDEBUG = _SAFEDDEBUG;
}

int getSAFEDDEBUG(){
	return SAFEDDEBUG;
}


BOOL getUselogfile(){
	return uselogfile;
}


char* getLogfilename(){
	return logfilename;
}

int getDwLogLevel(){
	return dwLogLevel;
}




void LogExtOnlyDebugMsg(int level , const char* pszFormat, ...)
{
	EXPANDINPUT;
	//LogMsg(level,TRUE, buf);
	LogMsg(level,FALSE, buf);
}

void LogExtMsg(int level , const char* pszFormat, ...)
{
	EXPANDINPUT;
	LogMsg(level,FALSE, buf);
}


void LogMsg(int level, BOOL onlyDebug, char* str)
{
	char buf[8192];
	char date[50];
	char stime[50];
	FILE * OutputFile=(FILE *)NULL;
	errno_t err;
	SYSTEMTIME st;
	GetLocalTime(&st);
	GetDateFormat(LOCALE_SYSTEM_DEFAULT,0,&st,"dd'/'MM'/'yyyy",date,_countof(date));
	GetTimeFormat(LOCALE_SYSTEM_DEFAULT,0,&st,"HH':'mm':'ss",stime,_countof(stime));
	_snprintf_s(buf, 8192,_TRUNCATE, "[NetEye Safed](%lu - %s %s): %s\n",GetCurrentThreadId(),date,stime, str);
	//if(buf) { OutputDebugString(buf); }
	//debuging
	if(SAFEDDEBUG && (SAFEDDEBUG >= level)){
		if(buf) { 
			printf("%s",buf); 
			fflush(stdout); 
		}
	}
	//logging
	if(!onlyDebug){
		if(uselogfile){
			time_t currenttime;
			struct tm newtime;
			time(&currenttime);
			localtime_s(&newtime,&currenttime);
			if(changeFileName(newtime,&savedlogtime, hMutexLogFile, dwNumberLogFiles,FALSE)){
				uselogfile = GetFileName(logfilename, NULL, FALSE);
			}	
		}
		if(uselogfile && dwLogLevel && (dwLogLevel >= level )){

			DWORD dwWaitFile = WaitForSingleObject(hMutexLogFile,500);
			if(dwWaitFile == WAIT_OBJECT_0) {
				fopen_s(&OutputFile,logfilename,"a");
				if(OutputFile) {
						fputs(buf,OutputFile);
						fflush(OutputFile);
						fclose(OutputFile);
				}
			}
			ReleaseMutex(hMutexLogFile);	
		}
	}
}

//deletes files in cache/log directory
void DeleteOldFiles(DWORD dwNumberFiles, BOOL cache){
	char dir[MAX_PATH];
	char tempdir[MAX_PATH];
	char tempfile[MAX_PATH];
	HANDLE hFind = INVALID_HANDLE_VALUE;
	WIN32_FIND_DATA ffd;
	char *list[100];
	DWORD dwError=0;
	if(cache){
		ExpandEnvironmentStrings("%SystemRoot%\\system32\\LogFiles\\Safed",tempdir,MAX_PATH);
	}else{
		ExpandEnvironmentStrings("%SystemRoot%\\system32\\LogFiles\\SafedLogs",tempdir,MAX_PATH);
	}
	strcpy(dir, tempdir);
	strcat_s(tempdir, MAX_PATH, "\\*");
    hFind = FindFirstFile(tempdir, &ffd);

	if (INVALID_HANDLE_VALUE == hFind){
		 if(cache)LogExtMsg(ERROR_LOG,"Error opening: %s\n", tempdir);
		 else LogExtOnlyDebugMsg(ERROR_LOG,"Error opening: %s\n", tempdir);
		 return;
	 } 
   
   // List all the files in the directory with some info about them.
	int i =0;
	char *next;
	do{
		if (!(ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) && (i < 100))
		{
			next = (char *)malloc(MAX_PATH);
			strcpy(next,ffd.cFileName);
			list[i] = next;
			i++;
		}
	}while (FindNextFile(hFind, &ffd) != 0);
	dwError = GetLastError();
	if (dwError != ERROR_NO_MORE_FILES){
      if(cache)LogExtMsg(ERROR_LOG,"Error opening files: %d\n", dwError);
	  else LogExtOnlyDebugMsg(ERROR_LOG,"Error opening files: %d\n", dwError);
	}

	for(int j =0; j<i; j++){
		int k = i - dwNumberFiles;
		if(j < k){
			strcpy(tempfile, dir);
			strcat_s(tempfile, MAX_PATH, "\\");
			strcat_s(tempfile, MAX_PATH, list[j]);

			int ret = _unlink(tempfile);
			if(ret){
				if(cache)LogExtMsg(ERROR_LOG,"%s has been deleted \n", tempfile);
				else LogExtOnlyDebugMsg(ERROR_LOG,"%s has been deleted \n", tempfile);
			}else{
				if(cache)LogExtMsg(ERROR_LOG,"Error deleting %s \n", tempfile);
				else LogExtOnlyDebugMsg(ERROR_LOG,"Error deleting %s \n", tempfile);
			}
		}
		free(list[j]);
	}

	FindClose(hFind);
	return;



}
void GetFullFileNames(char* filename,BOOL cache) {
	char dir[MAX_PATH];
	char tempdir[MAX_PATH];
	char tempfile[MAX_PATH];
	char temp[MAX_PATH];
	if(filename && strlen(filename)){
		_snprintf_s(temp,MAX_PATH,_TRUNCATE,"%s",filename);
		if(cache){
			ExpandEnvironmentStrings("%SystemRoot%\\system32\\LogFiles\\Safed",tempdir,MAX_PATH);
		}else{
			ExpandEnvironmentStrings("%SystemRoot%\\system32\\LogFiles\\SafedLogs",tempdir,MAX_PATH);
		}
		_snprintf_s(filename,MAX_PATH,_TRUNCATE,"%s\\%s",tempdir,temp);
	}
}


//gets file name for cache/log file
char** GetAllFileNames(int* number, BOOL cache) {
	char dir[MAX_PATH];
	char tempdir[MAX_PATH];
	char tempfile[MAX_PATH];
	HANDLE hFind = INVALID_HANDLE_VALUE;
	WIN32_FIND_DATA ffd;
	char **list = NULL;
	DWORD dwError=0;
	if(cache){
		ExpandEnvironmentStrings("%SystemRoot%\\system32\\LogFiles\\Safed",tempdir,MAX_PATH);
	}else{
		ExpandEnvironmentStrings("%SystemRoot%\\system32\\LogFiles\\SafedLogs",tempdir,MAX_PATH);
	}
	strcpy(dir, tempdir);
	strcat_s(tempdir, MAX_PATH, "\\*");
    hFind = FindFirstFile(tempdir, &ffd);

	if (INVALID_HANDLE_VALUE == hFind){
		 if(cache)LogExtMsg(ERROR_LOG,"Error opening: %s\n", tempdir);
		 else LogExtOnlyDebugMsg(ERROR_LOG,"Error opening: %s\n", tempdir);
		 return NULL;
	 } 
   
   // List all the files in the directory with some info about them.
	int i =0;
	char *next;
	list = (char **)malloc(100*sizeof(char*));
	if(list){
		do{
			if (!(ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) && (i < 100))
			{
				next = (char *)malloc(MAX_PATH);
				if(next){
					strcpy(next,ffd.cFileName);
					list[i] = next;
					i++;
					*number=i;
				}
			}
		}while (FindNextFile(hFind, &ffd) != 0);
		dwError = GetLastError();
		if (dwError != ERROR_NO_MORE_FILES){
		  if(cache)LogExtMsg(ERROR_LOG,"Error opening files: %d\n", dwError);
		  else LogExtOnlyDebugMsg(ERROR_LOG,"Error opening files: %d\n", dwError);
		}
	}
	FindClose(hFind);
	
	return list;
}


//gets file name for cache file
BOOL GetOutputFile(char* tempdir, char* date) {
	return GetFileName(tempdir, date, TRUE);
}
//gets file name for cache/log file
BOOL GetFileName(char* tempdir, char* date, BOOL cache) {
	DWORD FileExport=0;
	DWORD LogLevel=0;

		//char tempdir[1024]="";
	char tempdir2[1024];
	int returncode=0;
	time_t currenttime;
	struct tm newtime;
	FILE * fp;
	errno_t err;

	if(cache){
		FileExport=MyGetProfileDWORD("Config","FileExport",0);
		if(!FileExport) {
			return(FALSE);
		}
	}else{
		LogLevel=MyGetProfileDWORD("Config","LogLevel",0);
		if(!LogLevel) {
			return(FALSE);
		}

	}
	// Ok, the user wants to save the data off to a file.
	// Pull back our directory location.
	ExpandEnvironmentStrings("%SystemRoot%\\system32\\LogFiles",tempdir,1024);
	returncode=DirExists(tempdir);
	if(returncode== -1) {
		if(cache)LogExtMsg(ERROR_LOG,"Error opening dir %SystemRoot%\\system32\\LogFiles");
		else LogExtOnlyDebugMsg(ERROR_LOG,"Error opening dir %SystemRoot%\\system32\\LogFiles");
		return(FALSE);
	}
	if(returncode==0) {
		// Create it...
		returncode=CreateDirectory(tempdir,NULL);
		if(!returncode) {
			return(FALSE);
		}
	}
	if(cache){
		ExpandEnvironmentStrings("%SystemRoot%\\system32\\LogFiles\\Safed",tempdir,1024);
		returncode=DirExists(tempdir);
		if(returncode== -1) {
			if(cache)LogExtMsg(ERROR_LOG,"Error opening dir %SystemRoot%\\system32\\LogFiles\\Safed");
			else LogExtOnlyDebugMsg(ERROR_LOG,"Error opening dir %SystemRoot%\\system32\\LogFiles\\Safed");
			return(FALSE);
		}
	}else{
		ExpandEnvironmentStrings("%SystemRoot%\\system32\\LogFiles\\SafedLogs",tempdir,1024);
		returncode=DirExists(tempdir);
		if(returncode== -1) {
			if(cache)LogExtMsg(ERROR_LOG,"Error opening dir %SystemRoot%\\system32\\LogFiles\\SafedLogs");
			else LogExtOnlyDebugMsg(ERROR_LOG,"Error opening dir %SystemRoot%\\system32\\LogFiles\\SafedLogs");
			return(FALSE);
		}	
	
	}
	if(returncode==0) {
		// Create it...
		returncode=CreateDirectory(tempdir,NULL);
		if(!returncode) {
			return(FALSE);
		}
	}

	time(&currenttime);                
	localtime_s(&newtime,&currenttime);
	if(cache){
		if(date && strlen(date)>0)
			_snprintf_s(tempdir2,_countof(tempdir2),_TRUNCATE,"%s%s.log","%SystemRoot%\\system32\\LogFiles\\Safed\\",date);
		else
			_snprintf_s(tempdir2,_countof(tempdir2),_TRUNCATE,"%s%04d%02d%02d.log","%SystemRoot%\\system32\\LogFiles\\Safed\\",newtime.tm_year+1900,newtime.tm_mon+1,newtime.tm_mday);
		ExpandEnvironmentStrings(tempdir2,tempdir,1024);
	}else{
		if(date && strlen(date)>0)
			_snprintf_s(tempdir2,_countof(tempdir2),_TRUNCATE,"%s%sLog.log","%SystemRoot%\\system32\\LogFiles\\SafedLogs\\",date);
		else
			_snprintf_s(tempdir2,_countof(tempdir2),_TRUNCATE,"%s%04d%02d%02dLog.log","%SystemRoot%\\system32\\LogFiles\\SafedLogs\\",newtime.tm_year+1900,newtime.tm_mon+1,newtime.tm_mday);
		ExpandEnvironmentStrings(tempdir2,tempdir,1024);
	
	}

/*	if(read){
		err = fopen_s(&fp,tempdir,"r");
	}else{
		err = fopen_s(&fp,tempdir,"a");
	}
	return(fp);
*/
	return(TRUE);
}
//checks directory
int DirExists(char * dir)
{
    WIN32_FIND_DATA data;
    HANDLE hFile = FindFirstFile(dir, &data);

	if(!dir) {
		return(-1);
	}

    if (hFile == INVALID_HANDLE_VALUE) { // directory doesn't exist
        return FALSE;
    } else {
        // is it folder or file?
        FindClose(hFile);
        if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            return TRUE;
		}
        return -1;
    }
}
//changes filename of cache/log file - rotation
BOOL changeFileName(struct tm newtime, struct tm* savedtime, HANDLE hMutex, DWORD dwNumberFiles,BOOL cache){
	BOOL ret = TRUE;
	char filename[1024]="";
	FILE * OutputFile=(FILE *)NULL;
	// Check to see whether we need to rotate our log file.
	DWORD  dwWaitFile = WaitForSingleObject(hMutex,500);
	if(newtime.tm_year != savedtime->tm_year ||
		newtime.tm_mon != savedtime->tm_mon ||
		newtime.tm_mday != savedtime->tm_mday) {
		

		if(GetFileName(filename, NULL, cache)){
			if(dwWaitFile == WAIT_OBJECT_0) {
				fopen_s(&OutputFile,filename,"a");
				fclose(OutputFile);
			}
			DeleteOldFiles(dwNumberFiles, cache);

		}
		//fopen_s(&OutputFile,filename,"a");
		savedtime->tm_year=newtime.tm_year;
		savedtime->tm_mon=newtime.tm_mon;
		savedtime->tm_mday=newtime.tm_mday;
		

	}else ret = FALSE;
	ReleaseMutex(hMutex);	
	return ret;
}