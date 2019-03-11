#define EXPANDINPUT					      \
	char buf[8192] = "";\
	if(!pszFormat) return;\
	va_list arglist;\
	va_start(arglist, pszFormat);\
    _vsnprintf_s(&buf[strlen(buf)],8192 - strlen(buf),_TRUNCATE,pszFormat,arglist);\
	va_end(arglist);\


#define NONE_LOG 0
#define ERROR_LOG 1
#define WARNING_LOG 2
#define INFORMATION_LOG 3
#define DEBUG_LOG 4

void initLog();
BOOL initLogMutex();
void deinitLog();
void setSAFEDDEBUG(int SNAREDEBUG);
int getSAFEDDEBUG();
int getDwLogLevel();
BOOL getUselogfile();
char* getLogfilename();
HANDLE getLogMutex();

void LogExtOnlyDebugMsg(int level , const char* pszFormat, ...);
void LogExtMsg(int level , const char* pszFormat, ...);
void LogMsg(int level, BOOL onlyDebug, char* str);


int	DirExists(char *);
void DeleteOldFiles(DWORD dwNumberFiles, BOOL cache);
BOOL GetOutputFile(char* filename, char* date);
BOOL GetFileName(char* tempdir, char* date, BOOL cache);
BOOL changeFileName(struct tm newtime, struct tm* savedtime, HANDLE hMutex, DWORD dwNumberFiles,BOOL cache);
char** GetAllFileNames(int* number, BOOL cache);
void GetFullFileNames(char* filename,BOOL cache);