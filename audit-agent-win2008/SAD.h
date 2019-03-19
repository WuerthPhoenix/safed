#define SYSADMINMACRO "@SYSADMINS@"
#define VBSCRIPT 1
#define ADQUERY 0
#define ADQUERYDNET 2
char* getSADStatus();
char* getSAStr();
void initSADStatus();
void deinitSAD();
void writeSADStatus(char * str);
//Terminates the SAD each time an apply is done or a schedule is fired
void TerminateSAProcess(PROCESS_INFORMATION* piProcessInfo);
int checkEndOfASDiscoveryProcess(PROCESS_INFORMATION* piProcessInfo);
BOOL  updateSA(DWORD start, DWORD* delta);
BOOL LoadSAObjective(DWORD dwForceNextTime, int dwTimesADay, DWORD dwNextTimeDiscovery, PROCESS_INFORMATION* piProcessInfo, DWORD* start);
void getstrdate(DWORD date, char * out);
void setIsVBS(DWORD _isVBS);
