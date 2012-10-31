// SAFED for Windows
// Author: Wuerth-Phoenix s.r.l.,
//  made starting from:
// SNARE - Audit / EventLog analysis and forwarding
// Copyright 2001-2009 InterSect Alliance Pty Ltd
// http://www.intersectalliance.com/
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Library General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
//
// See Readme.txt file for more information.
//
// NOTE: Use the \data\64bit.bat file to compile in 64 bit mode!!!!
#include <stdio.h>
#include <stdlib.h>
#include <winsock2.h>
#include <windows.h>
#include <time.h>
#include <tchar.h>
#include <sys/stat.h>
#include <wincrypt.h>
#include <psapi.h>
#include <regex.h>
#include <share.h>
#include <math.h>

#include "support.h"
#include "NTServApp.h"
#include "MD5.h"
#include "LogUtils.h"
#include "RegKeyUtilities.h"
#include "SAD.h"
#include "Communication.h"
#include "webserver.h"
#include "SafedLog.h"
#include "Safed.h"



// memory testing only
//#define MEMDEBUG 1

#ifdef MEMDEBUG
// MEMORY LEAK DETECTION ROUTINES
	// #define _CRTDBG_MAP_ALLOC
	#define CRTDBG_MAP_ALLOC
	#include <stdlib.h>
	#include <crtdbg.h>
#endif

//#define DEBUG_TO_FILE 1

// Quick function proto


// Pull this from registry
DWORD			WEBSERVER_ACTIVE = 0;
DWORD			WEBSERVER_TLS = 0;

DWORD			g_dwLastError			= 0L;
char			Hostname[100];
DWORD dwSyslogHeader=0; // Send the Syslog header?
DWORD dwPortNumber=6162;
DWORD dwRestrictIP=0;
DWORD dwUsePassword=0;
TCHAR lpszIPAddress[SIZE_OF_RESTRICTIP];
TCHAR lpszPassword[256];
DWORD dwSyslog=13;
DWORD dwSyslogDynamic=0;


char initStatus[16384] = "";

ThreadStruct	g_Info;
//SOCKET *		g_hSockets;						// Array of socket pointers - one for each destination.
//char **			SocketNames;					// HostNames for each of the sockets.
//int				SocketCount=0;
//SOCKET			g_hSocket = INVALID_SOCKET;     // client/server socket, used in for/next loops.
int				nStopListening=0;
int				OtherEventLogCount=0;
DWORD			dwNumEventLogs=6;
DWORD			dwNumCustomEventLogs = 0;
TCHAR			(* EventLogStatusName)[_MAX_PATH + 1]=NULL;
TCHAR			(* OtherEventLogSourceNames)[_MAX_PATH + 1]=NULL;
char			CustomLogName[10*SIZE_OF_EVENTLOG]="";// max 10 objectives with custom event logs are supported
TCHAR			(* EventLogSourceName)[_MAX_PATH + 1]=NULL;


DWORD			*EventLogCounter;
DWORD			*dwEventIDRead;				// maintain entries for those events that we have already read.
DWORD			*dwEventIDOldest;				// Save off the 'oldest' entry in each list, so we know when to rotate.
DWORD			*dwEventLogCleared;			// Used to flag when an event log has been cleared, during normal operations
TCHAR			DELIM[2]="	";					// TAB

char			sentFile[255]="";
int				sentIndex=0;

int				AuditFlags[9];					// Array of audit flags to set.
												// Note: Increase this if the POLICY_AUDIT_EVENTTYPE grows in ntsecapi.h




int				USB_ENABLED=0;					// Are we looking for USB events.

Node *head=NULL, *tail=NULL, *currentnode=NULL;



static HostNode *hostcurrentnode;


int MCCount=0;
MsgCache *MCHead=NULL;
MsgCache *MCTail=NULL;
MsgCache *MCCurrent=NULL;



int USBMsgFlag=0;
USBCache *USBMsg=NULL;
USBCache *USBMsgHead=NULL;
USBCache *USBMsgTail=NULL;



// Locker
HANDLE hMutex=NULL;
HANDLE hUSBMutex=NULL;
HANDLE hMutexFile=NULL;
HANDLE hMutexCount=NULL;
HANDLE web_hEventList[3]; // two elements at the moment. The forth is fore resend logs
DWORD WebResetFlag=0;

DWORD dwDNSCheckTime=600;

DWORD dwMaxMsgSize=MAXMSGSIZE;

int pid = 0;
DWORD SafedCounter=0;
BOOL usefile = FALSE;

struct tm savedtime;
struct tm cnttime;

FILE * OutputFile=(FILE *)NULL;
char filename[1024]="";
DWORD dwNumberFiles=2;
BOOL SAOBJ=FALSE;




int TLSSERVERFAIL = 0;


CSafedService::CSafedService()
:CNTService("SAFED")
{
	//TODO: Initialize your class members here
}




DWORD getNumberCustomLogName(){
	char* p = strstr(CustomLogName,"#");
	DWORD cnt = 1;
	while(p){
		cnt++;
		p = strstr(p + 1,"#");
	}
	return cnt;
}

char* toup(char* cln){
	if(!cln) return NULL;
	 char* tmp = (char*)malloc(strlen(cln));
	 int i = 0;
	 for (i = 0; cln[i]; i++){
		tmp[i] = toupper(cln[i]);	
		if(tmp[i] == ' ')tmp[i]='_';
	 }
	 tmp[i] = '\0';
	 return tmp;
}


int ReadCustomEventLogs()
{
	Reg_Objective reg_objective;
	DWORD dw_objective_error;
	int i_objective_count=0;
	int tot_custom = 0;

    CustomLogName[0]='\0';
	

	while((dw_objective_error = Read_Objective_Registry(i_objective_count,&reg_objective))==0) {

		// For each event number defined.
	
		if(reg_objective.str_eventlog_type_custom && (strlen(reg_objective.str_eventlog_type_custom) > 0)){
			if(strlen(CustomLogName) == 0){
				tot_custom++;
				strncpy_s(CustomLogName,_countof(CustomLogName),reg_objective.str_eventlog_type_custom,_TRUNCATE);
			}else{
				if(!strstr(CustomLogName,reg_objective.str_eventlog_type_custom)){
					tot_custom++;
					strncat_s(CustomLogName,_countof(CustomLogName),"#",_TRUNCATE);
					strncat_s(CustomLogName,_countof(CustomLogName),reg_objective.str_eventlog_type_custom,_TRUNCATE);
				}
			}
		}
		i_objective_count++;
	}
	return tot_custom;
}

void cleanEventLogStructures(HANDLE **m_hEventList, HANDLE **hEventLog){
	if(*hEventLog){
		for(int i = 0 ; i<dwNumEventLogs + dwNumCustomEventLogs;i++){

				if((*hEventLog)[i]) CloseEventLog((*hEventLog)[i]);
		}
		delete [] (*hEventLog);
		(*hEventLog) = NULL;
	}

	if(*m_hEventList){
		for(int i = 0 ; i<dwNumEventLogs + dwNumCustomEventLogs;i++){
			if((*m_hEventList)[i]) ::CloseHandle((*m_hEventList)[i]);
		}
		delete [] (*m_hEventList);
		(*m_hEventList) = NULL;
	}


	if(EventLogCounter){
		delete[] EventLogCounter;
		EventLogCounter = NULL;
	}

	if(dwEventIDRead){
		delete[] dwEventIDRead;
		dwEventIDRead = NULL;
	}

	if(dwEventLogCleared){
		delete[] dwEventLogCleared;
		dwEventLogCleared = NULL;
	}

	if(dwEventIDOldest){
		delete[] dwEventIDOldest;
		dwEventIDOldest = NULL;
	}

	if(EventLogSourceName){
		delete[] EventLogSourceName;
		EventLogSourceName = NULL;
	}

	if(EventLogStatusName){
		delete[] EventLogStatusName;
		EventLogStatusName = NULL;
	}

}

BOOL InitEvents(HANDLE **m_hEventList, HANDLE **hEventLog,HANDLE* m_hRestartEventList){
	DWORD dwEventLogRecords = 0, dwOldestEventLogRecord = 0, dwNewestEventLogRecord = 0;
	BOOL nRet = TRUE;
	BOOL LeaveRetention=0;

	dwNumCustomEventLogs = ReadCustomEventLogs();

	cleanEventLogStructures(m_hEventList, hEventLog);

	*m_hEventList = new HANDLE[dwNumEventLogs + dwNumCustomEventLogs + 2]; // minimum 8 elements, 6 standard event logs, 1 web event, 1 Safed thread


	for (DWORD i=0;i<dwNumEventLogs + dwNumCustomEventLogs;i++) {
		(*m_hEventList)[i] = CreateEvent(NULL, TRUE, FALSE, NULL);
		if((*m_hEventList)[i] == NULL) {
			LogExtMsg(ERROR_LOG,"CreateEvent() %d failed",i);
			return FALSE;
		}
	}
	(*m_hEventList)[dwNumEventLogs + dwNumCustomEventLogs] = m_hRestartEventList[0];
	(*m_hEventList)[dwNumEventLogs + dwNumCustomEventLogs + 1] = m_hRestartEventList[1];

	//Resize all the necessary fields
	EventLogCounter = new DWORD[dwNumEventLogs + dwNumCustomEventLogs];
	dwEventIDRead = new DWORD[dwNumEventLogs + dwNumCustomEventLogs];
	dwEventLogCleared = new DWORD[dwNumEventLogs + dwNumCustomEventLogs];
	dwEventIDOldest = new DWORD[dwNumEventLogs + dwNumCustomEventLogs];
	EventLogSourceName = new TCHAR[dwNumEventLogs + dwNumCustomEventLogs][_MAX_PATH + 1];
	EventLogStatusName = new TCHAR[dwNumEventLogs + dwNumCustomEventLogs][_MAX_PATH + 1];
	*hEventLog = new HANDLE[dwNumEventLogs + dwNumCustomEventLogs];

	strncpy_s(EventLogSourceName[LOG_TYPE_SECURITY],_countof(EventLogSourceName[LOG_TYPE_SECURITY]),"Security",_TRUNCATE);
	strncpy_s(EventLogSourceName[LOG_TYPE_SYSTEM],_countof(EventLogSourceName[LOG_TYPE_SYSTEM]),"System",_TRUNCATE);
	strncpy_s(EventLogSourceName[LOG_TYPE_APPLICATION],_countof(EventLogSourceName[LOG_TYPE_APPLICATION]),"Application",_TRUNCATE);
	strncpy_s(EventLogSourceName[LOG_TYPE_DS],_countof(EventLogSourceName[LOG_TYPE_DS]),"Directory Service",_TRUNCATE);
	strncpy_s(EventLogSourceName[LOG_TYPE_DNS],_countof(EventLogSourceName[LOG_TYPE_DNS]),"DNS Server",_TRUNCATE);
	strncpy_s(EventLogSourceName[LOG_TYPE_FRS],_countof(EventLogSourceName[LOG_TYPE_FRS]),"File Replication Service",_TRUNCATE);

	strncpy_s(EventLogStatusName[LOG_TYPE_SECURITY],_countof(EventLogStatusName[LOG_TYPE_SECURITY]),"LOG_TYPE_SECURITY",_TRUNCATE);
	strncpy_s(EventLogStatusName[LOG_TYPE_SYSTEM],_countof(EventLogStatusName[LOG_TYPE_SYSTEM]),"LOG_TYPE_SYSTEM",_TRUNCATE);
	strncpy_s(EventLogStatusName[LOG_TYPE_APPLICATION],_countof(EventLogStatusName[LOG_TYPE_APPLICATION]),"LOG_TYPE_APPLICATION",_TRUNCATE);
	strncpy_s(EventLogStatusName[LOG_TYPE_DS],_countof(EventLogStatusName[LOG_TYPE_DS]),"LOG_TYPE_DS",_TRUNCATE);
	strncpy_s(EventLogStatusName[LOG_TYPE_DNS],_countof(EventLogStatusName[LOG_TYPE_DNS]),"LOG_TYPE_DNS",_TRUNCATE);
	strncpy_s(EventLogStatusName[LOG_TYPE_FRS],_countof(EventLogStatusName[LOG_TYPE_FRS]),"LOG_TYPE_FRS",_TRUNCATE);

	char* begin = CustomLogName;
	for (DWORD i=0;i<dwNumCustomEventLogs;i++) {
		char* p = strstr(begin,"#");
		char tmp[SIZE_OF_EVENTLOG] = "";
		if(!p){
				strncpy_s(tmp,SIZE_OF_EVENTLOG,begin,_TRUNCATE);
		}else{
			strncpy_s(tmp,p - begin,begin,_TRUNCATE);
			tmp[p - begin] = '\0'; 
			begin = p + 1;
			p = strstr(begin,"#");
		}

		strncpy_s(EventLogSourceName[dwNumEventLogs + i],_countof(EventLogSourceName[dwNumEventLogs + i]),tmp,_TRUNCATE);
		strncpy_s(EventLogStatusName[dwNumEventLogs + i],_countof(EventLogStatusName[dwNumEventLogs + i]),"LOG_TYPE_",_TRUNCATE);
		char* toupchars = toup(tmp);

		if(toupchars){
			strncat_s(EventLogStatusName[dwNumEventLogs + i],_countof(EventLogStatusName[dwNumEventLogs + i]),toupchars,_TRUNCATE);
			free(toupchars);
		}

	}


	for (DWORD i=0;i<(dwNumEventLogs + dwNumCustomEventLogs);i++) {
		EventLogCounter[i]=0;
		dwEventIDRead[i]=0;
		dwEventLogCleared[i]=0;
		dwEventIDOldest[i]=0;
	}

	LogExtMsg(INFORMATION_LOG,"Opening event log sources"); 
	GetLeaveRetention(&LeaveRetention);

	// Open each event log, and if the log exists, bind the event notifier.
	// Logs 4-6 (DS,DNS,FRS) Optional event logs - ie: not present on NT
	// NOTE: If this eventlog does not exist, Windows returns
	//       a handle to the Application log.

	for (DWORD i=0;i<dwNumEventLogs + dwNumCustomEventLogs;i++) {
		(*hEventLog)[i] = OpenEventLog( NULL, EventLogSourceName[i] );
		if((*hEventLog)[i])
		{
			if(CheckLogExists(EventLogSourceName[i],LeaveRetention))
			{
				nRet = NotifyChangeEventLog( (*hEventLog)[i], (*m_hEventList)[i] );
				if(!nRet) { 
					LogExtMsg(ERROR_LOG,"Event Bind %d failed",i);
					return FALSE;
				}
				// Work out the latest audit log record
				GetOldestEventLogRecord((*hEventLog)[i], &dwOldestEventLogRecord);
				dwEventIDOldest[i]=dwOldestEventLogRecord;
				GetNumberOfEventLogRecords((*hEventLog)[i], &dwEventLogRecords);
				if(dwEventLogRecords) {
					dwNewestEventLogRecord = (dwEventLogRecords + dwOldestEventLogRecord) -1;
				} else {
					dwNewestEventLogRecord = 0;
				}
				// Pull in our current position from the registry
				dwEventIDRead[i]=MyGetProfileDWORD("Status",EventLogStatusName[i],0);
				// If it's over 5000 events in the past, go to the most recent log.
				if(dwEventIDRead[i] == 0 || ((dwNewestEventLogRecord - dwEventIDRead[i]) > 5000)) {
					dwEventIDRead[i]=dwNewestEventLogRecord;
				}

				LogExtMsg(INFORMATION_LOG,"Opened %s",EventLogSourceName[i]); 
			} else {
				CloseEventLog((*hEventLog)[i]);
				(*hEventLog)[i]=NULL;
			}

		}
	}
	return TRUE;
}



BOOL CSafedService::OnInit()
{
	char szError[MAX_STRING];
	//TODO: Perform any initialization that needs to be done before entering the main loop
	if(!initSocketMutex())return FALSE;
	if(!initLogMutex()) return FALSE;

	if( !InitWinsock( szError,_countof(szError) ) )
	{
		LogExtMsg(ERROR_LOG,szError);
		return FALSE;
	}
	m_hEventList = NULL; 
	hEventLog = NULL;

	m_hRestartEventList = new HANDLE[2];
	m_hRestartEventList[0] = CreateEvent(NULL, TRUE, FALSE, NULL);
	m_hRestartEventList[1] = CreateEvent(NULL, TRUE, FALSE, NULL);

	if(!InitEvents(&m_hEventList, &hEventLog, m_hRestartEventList))return FALSE;

	// Web server
	web_hEventList[0] = CreateEvent(NULL, TRUE, FALSE, NULL);
	// Web server reset
	web_hEventList[1] = CreateEvent(NULL, TRUE, FALSE, NULL);
	// Web server exit
	web_hEventList[2] = CreateEvent(NULL, TRUE, FALSE, NULL);
	
	SECURITY_ATTRIBUTES MutexOptions;
	MutexOptions.bInheritHandle = true;
	MutexOptions.nLength = sizeof(SECURITY_ATTRIBUTES);
	MutexOptions.lpSecurityDescriptor = NULL;

	hMutex = CreateMutex(&MutexOptions,FALSE,"SnareAgentLock");
	if(hMutex == NULL) {
		LogExtMsg(ERROR_LOG,"I cannot create the Safed Agent 'Mutex' lock. This probably means that you already have another instance of the Safed Agent running.\nPlease stop the other incarnation of the Safed Agent (eg: net stop safed) before continuing.");
		return FALSE;
	}
	hUSBMutex = CreateMutex(&MutexOptions,FALSE,"SnareAgentUSBLock");
	if(hUSBMutex == NULL) {
		LogExtMsg(ERROR_LOG,"I cannot create the Safed Agent USB 'Mutex' lock. This probably means that you already have another instance of the Safed Agent running.\nPlease stop the other incarnation of the Safed Agent (eg: net stop safed) before continuing."); 
		return FALSE;
	}
	hMutexFile = CreateMutex(&MutexOptions,FALSE,"FileLock");
	if(hMutexFile == NULL) {
		LogExtMsg(ERROR_LOG,"I cannot create the Safed Agent File 'Mutex' lock. This probably means that you already have another instance of the Safed Agent running.\nPlease stop the other incarnation of the Safed Agent (eg: net stop safed) before continuing."); 
		return FALSE;
	}

	
	hMutexCount = CreateMutex(&MutexOptions,FALSE,"CountLock");
	if(hMutexCount == NULL) {
		LogExtMsg(ERROR_LOG,"I cannot create the Safed Agent Count 'Mutex' lock. This probably means that you already have another instance of the Safed Agent running.\nPlease stop the other incarnation of the Safed Agent (eg: net stop safed) before continuing."); 
		return FALSE;
	}

	LogExtMsg(DEBUG_LOG,"NetEye Safed Initialisation complete");
#ifdef DEBUG_TO_FILE
	setSAFEDDEBUG(9);
#endif
	LogExtMsg(WARNING_LOG,"SAFEDDEBUG: %d", getSAFEDDEBUG());
	// return FALSE here if initialization failed & the service shouldn't start
	return TRUE;
}


BOOL InitFromRegistry(int* dwTimesADay, DWORD* dwNextTimeDiscovery, DWORD* dwForceNextTime, DWORD* dwSysAdminEnable, BOOL* ActivateChecksum, DWORD* dwCritAudit, DWORD* ClearTabs,
			   char** szSendString, char** szSendStringBkp){
	SAOBJ = FALSE;
	GetHostname(Hostname,_countof(Hostname));
	initLog();
	initSocket();//MM
	GetSyslog(&dwSyslog);
	GetSyslogDynamic(&dwSyslogDynamic);
	GetSyslogHeader(&dwSyslogHeader);
	GetWEBSERVER_ACTIVE(&WEBSERVER_ACTIVE);
	GetWEBSERVER_TLS(&WEBSERVER_TLS);
	GetPortNumber(&dwPortNumber);
	GetNumberFiles(&dwNumberFiles);
	GetMaxMsgSize();
	GetTimesADay(dwTimesADay);
	GetNextTimeDiscovery(dwNextTimeDiscovery);
	GetForceSysAdmin(dwForceNextTime);
	GetSysAdminEnable(dwSysAdminEnable);
	setIsVBS(GetVBS());
	if(*dwSysAdminEnable){
		if((*dwNextTimeDiscovery) == 0){
			*dwNextTimeDiscovery = time(NULL) + (*dwTimesADay);
			MyWriteProfileDWORD("SysAdmin","NextTimeDiscovery",*dwNextTimeDiscovery);

		}
	}	
	GetChecksum(ActivateChecksum);
	GetCrit(dwCritAudit);
	GetPassword(lpszPassword,_countof(lpszPassword));
	GetSentIndex(sentFile,_countof(sentFile), &sentIndex);
	GetIPAddress(lpszIPAddress,_countof(lpszIPAddress));
	GetClearTabs(ClearTabs);
	if(dwSyslogHeader) {
		GetDelim(DELIM,_countof(DELIM));
	}
	*szSendString = (char*)realloc(*szSendString,dwMaxMsgSize*sizeof(char)); // Nice big memory buffer - just in case.
	*szSendStringBkp = (char*)realloc(*szSendStringBkp, dwMaxMsgSize*sizeof(char));  // Nice big memory buffer - just in case.
	if (*szSendString)*szSendString[0]='\0';
	else {
		LogExtMsg(ERROR_LOG,"NO MEMORY LEFT!!!"); 
		return false;
	}
	if (*szSendStringBkp)*szSendStringBkp[0]='\0';
	else {
		LogExtMsg(ERROR_LOG,"NO MEMORY LEFT!!!"); 
		return false;
	}
	usefile = GetOutputFile(filename, NULL);
	initSADStatus();
	DWORD SetAudit=MyGetProfileDWORD("Config","Audit",0);
	if(!SetAudit)
		_snprintf_s(initStatus,_countof(initStatus),_TRUNCATE,"Attention: NetEye Safed will NOT set automatically the audit configuration!<p>");
	else
		_snprintf_s(initStatus,_countof(initStatus),_TRUNCATE,"");


	if(WEBSERVER_ACTIVE && WEBSERVER_TLS){
		TLSSERVERFAIL = initSTLS();
		if(TLSSERVERFAIL){
			deinitSTLS();
			WEBSERVER_TLS = 0;
			strncat_s(initStatus,_countof(initStatus),"Attention: NetEye Safed HTTPS FAILED. It will proceed with HTTP",_TRUNCATE);	
		}
	}
	return true;
}




void CSafedService::Run()
{

	DWORD dwEventLogRecords = 0, dwOldestEventLogRecord = 0, dwNewestEventLogRecord = 0,
		dwEvLogStart = 0, dwEvLogCounter = 0, dwNumberOfBytesToRead = 0, 
		dwBytesRead = 0, dwMinNumberOfBytesNeeded = 0, dwCancel = 0, dwClose = 0;
	static int recovery = 0;
	//static int seqnum = 1;
	char* szSendString = NULL; // Nice big memory buffer - just in case.
	char* szSendStringBkp = NULL;  // Nice big memory buffer - just in case.

	DWORD ClearTabs=0;
	DWORD dwSysAdminEnable=0;
	int dwTimesADay=1;
	DWORD dwNextTimeDiscovery=0;
	DWORD dwForceNextTime=0;

	DWORD dwCatchUpCount=0;
	DWORD dwWaitRes=0,dwWaitReset=0,dwWaitFile=0;

	long Category=0;

	// Define an eventlogrecord buffer of 8k.
	// Should be enough for an overwhelming majority of circumstances.
	TCHAR EventLogRecordBuffer[MAX_EVENT]="";
	TCHAR SourceName[100]="";	// Eg: "Security" or "Active Directory"
	TCHAR SIDType[100]="";		// User or System
	TCHAR EventLogType[60]=""; // Warning / Information / success / failure
	TCHAR ExpandedString[MAX_EVENT]="";
	TCHAR DataString[MAX_EVENT]="";
	TCHAR ComputerName[256]="";
	TCHAR UserName[256]="";
	TCHAR szCategoryString[256]=""; // "Detailed Tracking"

  	TCHAR szError[MAX_STRING]="";

	TCHAR SubmitTime[26]="None Yet";
	TCHAR WriteTime[26];


	HCRYPTPROV hProv = 0;
	HCRYPTKEY hSessionKey = 0;

	short TimeoutCounter=0;
	short MessageCounter=0;
	short LogCounter=0;
	short SnareTimeout=0;


	PEVENTLOGRECORD pELR = 0;
	PSID UserSID = 0;
	unsigned long EventID=0;
	
	BOOL bRetVal = FALSE;
	BOOL fExit = FALSE;
	UINT uStep = 0, uStepAt = 0, uPos = 0, uOffset = 0;

	int nRet;
	int etype=0;	// eventlog type
	int stype=0;	// source type
	UINT EventTriggered=0;
	UINT PreUSBEventTriggered=0;


	DWORD Offset=0;
	DWORD dwCritAudit=0;
	DWORD dwObjectiveCount=0;
	Node **MatchList=NULL;
	Node **MatchPointer=NULL;
	DWORD MatchCount;
	BOOL MatchFound=0;

	static BOOL ActivateChecksum=0;
	

	int retThread = 0;

	// Syslog, and output log time variables.
	time_t currenttime,lasttime,lastdeadtime;
	struct tm newtime;

    HANDLE hProcess= GetCurrentProcess();
	DWORD dwMin, dwMax;
	PROCESS_MEMORY_COUNTERS memCounters;
	SYSTEM_INFO si;
	GetSystemInfo(&si);

	SafedCounter=1;

	pid = GetCurrentProcessId();

	usefile = GetOutputFile(filename, NULL);
	dwWaitFile = WaitForSingleObject(hMutexFile,500);
	if(dwWaitFile == WAIT_OBJECT_0) {
		fopen_s(&OutputFile,filename,"r");

		if(usefile && OutputFile) {
				SafedCounter = GetTotalSavedLogs(OutputFile) + 1;
				fclose(OutputFile);
		}
	}
	ReleaseMutex(hMutexFile);	


	LogExtMsg(WARNING_LOG,"The page size for this system is %u bytes.\n", si.dwPageSize);

 //    Retrieve the working set size of the process.
	if (!GetProcessMemoryInfo(hProcess,&memCounters,sizeof(PROCESS_MEMORY_COUNTERS))) {
        LogExtMsg(WARNING_LOG, "GetProcessMemoryInfo failed (%d)", GetLastError() );
	}
	LogExtMsg(WARNING_LOG,"MemCounter.Pagefaults: %d",memCounters.PageFaultCount);
	if (!GetProcessWorkingSetSize(hProcess, (PSIZE_T)&dwMin, (PSIZE_T)&dwMax))
	{
		LogExtMsg(WARNING_LOG,"GetProcessWorkingSetSize failed (%d)", GetLastError());
	}
	LogExtMsg(WARNING_LOG,"Working Set: Min-%d Max-%d",dwMin, dwMax);

	dwMax = 2*10485760; //20Mb
	dwMin = 2*1413120;
	if (!SetProcessWorkingSetSize(hProcess, dwMin, dwMax))
    {
        LogExtMsg(ERROR_LOG,"SetProcessWorkingSetSize failed (%d)", GetLastError());
    }
	if (!GetProcessWorkingSetSize(hProcess, (PSIZE_T)&dwMin, (PSIZE_T)&dwMax))
	{
		LogExtMsg(WARNING_LOG,"GetProcessWorkingSetSize failed (%d)", GetLastError());
	}
	LogExtMsg(WARNING_LOG,"Working Set: Min-%d Max-%d",dwMin, dwMax);
    CloseHandle(hProcess);

	// Initialise the elements of savedtime that we use.
	savedtime.tm_mday=0;
	savedtime.tm_mon=0;
	savedtime.tm_year=0;
	// Initialise the elements of cnttime that we use.
	time(&currenttime);
	localtime_s(&cnttime,&currenttime);
	



	//discovery process !!
	PROCESS_INFORMATION piProcessInfo;
	piProcessInfo.dwProcessId = 0;

	//Start discovery process timestamp
	DWORD SADStrt = 0;
	// READ in our data

	if(!InitFromRegistry(&dwTimesADay, &dwNextTimeDiscovery, &dwForceNextTime, &dwSysAdminEnable, &ActivateChecksum, &dwCritAudit, &ClearTabs, &szSendString, &szSendStringBkp))goto nomemory;;
	//if(!InitEvents(m_hEventList, hEventLog, m_hRestartEventList))goto nomemory;;
	if(WEBSERVER_ACTIVE) {

		if(InitWebServer((unsigned short)dwPortNumber,lpszPassword,lpszIPAddress) >0) {
			StartWebThread(m_hEventList[dwNumEventLogs + dwNumCustomEventLogs]);
		} else {
			LogExtMsg(ERROR_LOG,"Unable to start web server [1], disabling.");
			WEBSERVER_ACTIVE = 0;
		}
	}
	
	if(dwSysAdminEnable){
		SAOBJ = LoadSAObjective(dwForceNextTime, dwTimesADay, dwNextTimeDiscovery, &piProcessInfo,&SADStrt);
		dwForceNextTime = 0;
	}

	

	// Load the objective data here.
	dwObjectiveCount=ReadObjectives();
	LogExtMsg(INFORMATION_LOG,"NetEye Safed is Running"); 
	if(dwObjectiveCount) {
		// Malloc a array for our FastCheckObjective process
		MatchList = (Node **)malloc(dwObjectiveCount * sizeof(Node *));
		if(!MatchList) {
			LogExtMsg(ERROR_LOG,"Cannot allocate memory for our internal Objective match list");
			dwObjectiveCount=0;
		}
	}





	OpenSockets();
	
	LogExtMsg(INFORMATION_LOG,"Sockets opened/connected");
	////////////////// REMEMBER TO FREE THESE SOCKETS LATER!!!!   REDREDRED
	// Ok, we have finished our general configuration reads.


	retThread = StartSafedEThread(m_hEventList[dwNumEventLogs + dwNumCustomEventLogs+ 1]);


	// Monitor the pipe
	// Set the terminate flag to zero.
	// setting this value to TRUE will terminate the service,
	// and ask it to save it's current status.
	g_Info.bTerminate = FALSE;
	BOOL failure_exit = FALSE;
	
	LogExtMsg(INFORMATION_LOG,"Entering main loop."); 
	// This is the service's main run loop.
    while (m_bIsRunning) 
	{

		// TODO: Add code to perform processing here  
		// If we have been asked to terminate, do so.
		if(g_Info.bTerminate)
		{
			m_bIsRunning=0;
			break;
		}
		// The service performs one check per 5 seconds. This should not be
		// a significant drain on resources.
		dwWaitRes=WaitForMultipleObjects(dwNumEventLogs+ dwNumCustomEventLogs +2,m_hEventList,FALSE,5000);

		// if(dwWaitRes != WAIT_FAILED && dwWaitRes != WAIT_TIMEOUT)
		if(dwWaitRes != WAIT_FAILED)
		{

			EventTriggered=0;
			stype = LOG_APP;	 // Assume application log if no valid source provided.
			BOOL webevent = FALSE;
			if(dwWaitRes == WAIT_OBJECT_0 + dwNumEventLogs + dwNumCustomEventLogs+ 1) {
				ResetEvent(m_hEventList[dwNumEventLogs +  dwNumCustomEventLogs +1]);
				retThread = StartSafedEThread(m_hEventList[dwNumEventLogs + dwNumCustomEventLogs+ 1]);
				if(retThread <= 0 )goto nomemory;
			}else if(dwWaitRes >= WAIT_OBJECT_0 && dwWaitRes < WAIT_OBJECT_0 + dwNumEventLogs + dwNumCustomEventLogs) {
				EventTriggered=dwWaitRes - WAIT_OBJECT_0;
				ResetEvent(m_hEventList[EventTriggered]);
				TimeoutCounter=0;
				LogExtMsg(DEBUG_LOG,"WAIT_OBJECT %d Triggered.",EventTriggered); 
				if(EventTriggered == 0) {
					stype = LOG_SEC;
				} else if(EventTriggered == 1) {
					stype = LOG_SYS;
				} else if(EventTriggered == 2) {
					stype = LOG_APP;
				} else if(EventTriggered == 3) {
					stype = LOG_DIR;
				} else if(EventTriggered == 4) {
					stype = LOG_DNS;
				} else if(EventTriggered == 5) {
					stype = LOG_REP;
				} else {
					stype = LOG_CUS;
				}

			} else if (dwWaitRes == WAIT_OBJECT_0 + dwNumEventLogs + dwNumCustomEventLogs) {
				webevent = TRUE;
				//do nothing, this means there has been a web reset event, it will be handled below.
				// this is just to prevent a delay
				ResetEvent(m_hEventList[dwNumEventLogs + dwNumCustomEventLogs]);
				LogExtMsg(INFORMATION_LOG,"HandleWebThread: WEB Server Reset event received"); 
			} else if (dwWaitRes == WAIT_TIMEOUT) {
 				LogExtMsg(DEBUG_LOG,"Timeout hit");
				if(dwSysAdminEnable && dwTimesADay){
					if(piProcessInfo.dwProcessId && (checkEndOfASDiscoveryProcess(&piProcessInfo) > 0)){
						DWORD delta = 0;
						SAOBJ = updateSA(SADStrt, &delta);//only if SAD is finished
						//only if SAD is finished prepare the web string
						char tdate[16] = "";
						char sdate[16] = "";
						getstrdate(SADStrt, sdate);
						getstrdate(dwNextTimeDiscovery, tdate);
						char sadStatusStr[200] = "";
						if(!SAOBJ)
							_snprintf_s(sadStatusStr,_countof(sadStatusStr),_TRUNCATE,"The system administrators discovery is failed! [Started: %s; Last Dutation: %d(s); Next scheduled:  %s]\n", sdate, delta, tdate);
						else
							_snprintf_s(sadStatusStr,_countof(sadStatusStr),_TRUNCATE,"The system administrators discovery is done! [Started: %s; Last Dutation: %d(s); Next scheduled:  %s]\n", sdate, delta, tdate);
						writeSADStatus(sadStatusStr);
					}
					if(dwNextTimeDiscovery <= time(NULL)){
						TerminateSAProcess(&piProcessInfo);
						SAOBJ = LoadSAObjective(1,dwTimesADay, dwNextTimeDiscovery, &piProcessInfo, &SADStrt);
						dwNextTimeDiscovery = time(NULL) + dwTimesADay;
						MyWriteProfileDWORD("SysAdmin","NextTimeDiscovery",dwNextTimeDiscovery);
						freeMatchLists();
						if(MatchList) {
							free(MatchList);
							MatchList=NULL;
						}
						dwObjectiveCount=ReadObjectives();
						if(dwObjectiveCount) {
							// Malloc a array for our FastCheckObjective process
							MatchList = (Node **)malloc(dwObjectiveCount * sizeof(Node *));
							if(!MatchList) {
								LogExtMsg(ERROR_LOG,"Cannot allocate memory for our internal Objective match list");
								dwObjectiveCount=0;
							}
						}
						ResetCurrentNode();
					}
				}

				// Every 20 seconds, check one of the open log files for new events.
				// This is just in case notifychangeeventlog does not let us know
				// about new events
				if(TimeoutCounter < 4) {
					TimeoutCounter++;
					continue;
				}
				TimeoutCounter=0;
				
				
				for(int tcounter=0;tcounter<=MAX_LOG_TYPE + dwNumCustomEventLogs;tcounter++) {
					LogCounter++;
					if(LogCounter > MAX_LOG_TYPE + dwNumCustomEventLogs) {
						LogCounter=0;
					}
					if(hEventLog[LogCounter]) {
						break;
					}
				}
				// set STYPE here, as it's not set due to a normal WAIT event.
				MyWriteProfileDWORD("Status",EventLogStatusName[LogCounter],dwEventIDRead[LogCounter]);
				if(LogCounter == 0) {
					stype = LOG_SEC;
				} else if(LogCounter == 1) {
					stype = LOG_SYS;
				} else if(LogCounter == 2) {
					stype = LOG_APP;
				} else if(LogCounter == 3) {
					stype = LOG_DIR;
				} else if(LogCounter == 4) {
					stype = LOG_DNS;
				} else if(LogCounter == 5) {
					stype = LOG_REP;
				}
				//MessageCounter = 0;

				LogExtMsg(INFORMATION_LOG,"20 seconds have elapsed. Checking a log file: %d",LogCounter); 

				if(hEventLog[LogCounter]!=NULL) {
					EventTriggered=LogCounter;
				} else {
					// No logs to check? Urk.
					// Hop back into the loop.
					LogExtMsg(INFORMATION_LOG,"Oh dear. I can't seem to find the next open log file. Something quite strange is going on here."); 
					continue;
				}

				SnareTimeout=1;
			} else {

				LogExtMsg(INFORMATION_LOG,"Warning: An event occured that I am not programmed to deal with. Continuing");
				continue;
			}

			//firstly, check to see if the web server needs resetting:
			if (WebResetFlag) {
				LogExtMsg(INFORMATION_LOG,"HandleWebThread: resetting the web thread"); 

				// Save off our current position in each of our log files.
				for (DWORD i=0;i<dwNumEventLogs + dwNumCustomEventLogs;i++) {
					MyWriteProfileDWORD("Status",EventLogStatusName[i],dwEventIDRead[i]);
				}
				DWORD WebResetFlagTmp = WebResetFlag;
				WebResetFlag = 0;//change the value before starting the web server
				if (WebResetFlagTmp == FULL_WEB_RESET) {
					if(retThread > 0 ){
						retThread = 0;
						CloseSafedE();
					}

					DestroyList();
					if(WEBSERVER_ACTIVE) {
						CloseWebServer();
					}

					// cancel blocking calls, if any
					WSACancelBlockingCall();

					// Close all active sockets.
					HostNode * temphostnode;

					hostcurrentnode=getHostHead();
					while(hostcurrentnode) {
						if(hostcurrentnode->Socket != INVALID_SOCKET) {
							CloseSocket(hostcurrentnode->Socket, hostcurrentnode->tlssession);
							hostcurrentnode->Socket=INVALID_SOCKET;
						}
						temphostnode=hostcurrentnode->next;

						// Free the RAM associated with this node. We don't need it any more.
						free(hostcurrentnode);
						hostcurrentnode=temphostnode;
						// Just in case
						setHostHead(hostcurrentnode);
					}
					setHostHead(NULL);

					//stop sda process before reinitializing isVBA
					TerminateSAProcess(&piProcessInfo);
					if(MatchList) {
						free(MatchList);
						MatchList=NULL;
					}
					// READ in our data
					if(!InitFromRegistry(&dwTimesADay, &dwNextTimeDiscovery, &dwForceNextTime, &dwSysAdminEnable, &ActivateChecksum, &dwCritAudit, &ClearTabs, &szSendString, &szSendString))goto nomemory;;
					if(!InitEvents(&m_hEventList, &hEventLog, m_hRestartEventList))goto nomemory;;
					// Open our outgoing sockets.
					OpenSockets();

					// Ok, we have finished our general configuration reads.
					if(WEBSERVER_ACTIVE) {

						LogExtMsg(INFORMATION_LOG,"Starting web thread."); 
						if(InitWebServer((unsigned short)dwPortNumber,lpszPassword,lpszIPAddress) >0) {
							StartWebThread(m_hEventList[dwNumEventLogs + dwNumCustomEventLogs]);
						} else {
							//sleep and try again
							Sleep(2000);
							if(InitWebServer((unsigned short)dwPortNumber,lpszPassword,lpszIPAddress) >0) {
								StartWebThread(m_hEventList[dwNumEventLogs + dwNumCustomEventLogs]);
							} else {
								LogExtMsg(ERROR_LOG,"Unable to start web server [2], disabling.");
								WEBSERVER_ACTIVE = 0;
							}
						}
						
					}
					if(dwSysAdminEnable){
						SAOBJ = LoadSAObjective(dwForceNextTime,dwTimesADay, dwNextTimeDiscovery, &piProcessInfo, &SADStrt);
						dwForceNextTime = 0;
					}
	
					// Load the objective data here.
					dwObjectiveCount=ReadObjectives();
					if(dwObjectiveCount) {
						// Malloc a array for our FastCheckObjective process
						MatchList = (Node **)malloc(dwObjectiveCount * sizeof(Node *));
						if(!MatchList) {
							LogExtMsg(ERROR_LOG,"Cannot allocate memory for our internal Objective match list");
							dwObjectiveCount=0;
						}
					}
					ResetCurrentNode();					

				} else if (WebResetFlagTmp == BASIC_WEB_RESET) {
					if(WEBSERVER_ACTIVE) {
						LogExtMsg(INFORMATION_LOG,"Restarting web thread."); 
						CloseWebServer();
						if(InitWebServer((unsigned short)dwPortNumber,lpszPassword,lpszIPAddress) >0) {
							StartWebThread(m_hEventList[dwNumEventLogs + dwNumCustomEventLogs]);
						} else {
							//sleep and try again
							Sleep(2000);
							if(InitWebServer((unsigned short)dwPortNumber,lpszPassword,lpszIPAddress) >0) {
								StartWebThread(m_hEventList[dwNumEventLogs + dwNumCustomEventLogs]);
							} else {
								LogExtMsg(ERROR_LOG,"Unable to start web server [2], disabling.");
								WEBSERVER_ACTIVE = 0;
							}
						}
					}
					hostcurrentnode=getHostHead();
					while(hostcurrentnode) {
						//if(hostcurrentnode->Socket != INVALID_SOCKET) {
						if(hostcurrentnode->Socket != INVALID_SOCKET) {
							CloseSocket(hostcurrentnode->Socket, hostcurrentnode->tlssession);
							hostcurrentnode->Socket=INVALID_SOCKET;
						}
						hostcurrentnode=hostcurrentnode->next;
					}
				}
				if(webevent) continue;//Avoid consuming not sent events
			}

			// The first eventlog record in the file - absolute record number.
			bRetVal=GetOldestEventLogRecord(hEventLog[EventTriggered], &dwOldestEventLogRecord);
			if(bRetVal) {
				// Check to see if the log has rotated.
				if(dwOldestEventLogRecord < dwEventIDOldest[EventTriggered]) {
					dwNewestEventLogRecord=-2;
					LogExtMsg(ERROR_LOG,"Oldest Event log is less than the last known value. Log must have recycled. Prev was is %d, current is %d. Reopening log file from the start.",dwEventIDOldest[EventTriggered],dwOldestEventLogRecord); 
				} else {
					// The total number of eventlog records.
					bRetVal=GetNumberOfEventLogRecords(hEventLog[EventTriggered], &dwEventLogRecords);
					if(bRetVal) {
						// The last eventlog record number
						// Note: This number could shift a little as events drop off the 'bottom' of the pile
						// ie: pass 1, newest might be 1000 (oldest=10, number = 990)
						//     pass 2, newest might be 9999 (oldest=11, number = 990).. so no new events, but one less in the pile.
						dwNewestEventLogRecord = (dwEventLogRecords + dwOldestEventLogRecord) -1;
						LogExtMsg(INFORMATION_LOG,"OLDEST: %d Number: %d Newest: %d",dwOldestEventLogRecord,dwEventLogRecords,dwNewestEventLogRecord); 
					} else {
						// Something wierd is happening. Force a close/reopen of this log file.
						dwNewestEventLogRecord=-1;
					}
					dwEventIDOldest[EventTriggered]=dwOldestEventLogRecord;
				}
			} else {
				// Something wierd is happening. Force a close/reopen of this log file.
				dwNewestEventLogRecord=-1;
			}

			// Have we been signaled without any new events being added?
			if(((dwNewestEventLogRecord == dwEventIDRead[EventTriggered]) && dwNewestEventLogRecord != 0 && SnareTimeout==0)) {
				// This should not be happening.. unless the newest event log has an id of 0
				// for some reason, or perhaps we have rolled around to the exact same
				// audit record number while the audit service was no-t running.
				// Either way, ignore the event, and do nothing.
				LogExtMsg(WARNING_LOG,"Event Log counter is still %d. Recording position and continuing at next event.",dwNewestEventLogRecord);

				//While we are here, may as well record the value
				MyWriteProfileDWORD("Status",EventLogStatusName[EventTriggered],dwEventIDRead[EventTriggered]);

				// Sleep for a moment, just to give the system time to rotate appropriately.
				Sleep(1000);
				
				// Force a close/reopen of the eventlog
				
				// ACTUALLY, Dont reopen. dwNewestEventLogRecord is slightly variable, and could wander a little.
				//dwNewestEventLogRecord=-1;

				//LogExtMsg(WARNING_LOG,"Event log seems to have rotated strangely!. Jumped to end of log, and continuing."); 
				continue;
			} else if((dwNewestEventLogRecord == dwEventIDRead[EventTriggered]) && dwNewestEventLogRecord != 0 && SnareTimeout==1) {
				// SnareTimeout has asked us to check the eventlog for new events as a result
				// of a regular timeout. If there are no new events, continue on.
				SnareTimeout=0;
				continue;
			}

			if(dwNewestEventLogRecord < 0) {
				for(int i=0;i<10;i++) {
					if(!CloseEventLog(hEventLog[EventTriggered])) {
						LogExtMsg(WARNING_LOG,"1: Closure of eventlog failed! Error is %d.",GetLastError()); 
						if(i==9) { LogExtMsg(ERROR_LOG,"Bailing out! Cannot seem to close this eventlog. Name is %s, hEventLog[EventTriggered] is %ld, EventTriggered is %d",EventLogSourceName[EventTriggered],hEventLog[EventTriggered],EventTriggered); }
						Sleep(1000);
					} else {
						LogExtMsg(INFORMATION_LOG,"Closure of eventlog succeeded");
						break;
					}
				}

				LogExtMsg(WARNING_LOG,"%s has recycled. Reopening eventlog file.",EventLogSourceName[EventTriggered]); 

				int count=0;
				// open it again.
				do {
					hEventLog[EventTriggered] = OpenEventLog( NULL, EventLogSourceName[EventTriggered] );
					if(hEventLog[EventTriggered] != NULL) {
						break;
					}
					LogExtMsg(WARNING_LOG,"1: Could not re-open event log.. EventTriggered is %d, log name is %s - sleeping for 5 seconds (Error code was %d)",EventTriggered,EventLogSourceName[EventTriggered],GetLastError()); 
					Sleep(5000);
					count++;
					if(count > 20) {
						hEventLog[EventTriggered]=NULL;
						LogExtMsg(WARNING_LOG,"%s wont reopen after 20 attempts. Bailing out.",EventLogSourceName[EventTriggered]); 
						break;
					}
				} while(hEventLog[EventTriggered] == NULL);
				
				if(hEventLog[EventTriggered]==NULL) {
					continue;
				}

				while((nRet = NotifyChangeEventLog( hEventLog[EventTriggered], m_hEventList[EventTriggered] )) == 0) {
					LogExtMsg(WARNING_LOG,"1: Could not re-bind to event log.. sleeping for 5 seconds. Error code was %d",GetLastError()); 
					Sleep(5000);
				}

				// Grab these details again
				GetOldestEventLogRecord(hEventLog[EventTriggered], &dwOldestEventLogRecord);
				dwEventIDOldest[EventTriggered]=dwOldestEventLogRecord;
				// The total number of eventlog records.
				GetNumberOfEventLogRecords(hEventLog[EventTriggered], &dwEventLogRecords);
				// The last eventlog record number
				

				// Jump to the newest event log
				if(dwNewestEventLogRecord == -1) {
					dwNewestEventLogRecord = (dwEventLogRecords + dwOldestEventLogRecord) -1;
					dwEventIDRead[EventTriggered]=dwNewestEventLogRecord;
					dwEvLogStart=dwNewestEventLogRecord;
				} else {
					// Jump to the start of the log file (log rotation)
					dwNewestEventLogRecord = (dwEventLogRecords + dwOldestEventLogRecord) -1;
					dwEventIDRead[EventTriggered]=dwOldestEventLogRecord;
					dwEvLogStart=dwOldestEventLogRecord;
				}

				LogExtMsg(WARNING_LOG,"Event log seems to have wrapped!. Continuing."); 
				// Wrap around, and wait for a new signal?


				// Need to continue here, or we will hit the 'log rotation problem' code.
				continue;
			} else {
				//if (EventTriggered != 0 || dwEventIDRead[EventTriggered]!=1 ) dwEvLogStart=dwEventIDRead[EventTriggered]+1;
				// Check if the log has been cleared, if it has, then reset the flag and do NOT increment the log counter
				if (dwEventLogCleared[EventTriggered] == 0) dwEvLogStart=dwEventIDRead[EventTriggered]+1;
				else dwEventLogCleared[EventTriggered] = 0;
			}


			SnareTimeout=0;

			// Has the eventlog somehow overtaken us, or is this the first time we
			// have been run?

			if(dwOldestEventLogRecord > dwEventIDRead[EventTriggered]) {
				// Yes. Set our start counter to the first record.
				// This probably means that windows is overwriting old events,
				// and we have been overtaken. VERY doubtful that this will happen
				// within the one second timeout.
				//dwEventIDRead[EventTriggered]=dwOldestEventLogRecord;
				//dwEvLogStart = dwOldestEventLogRecord;
				
				// At the risk of missing a few events, jump to the most recent event.
				dwEventIDRead[EventTriggered]=dwNewestEventLogRecord;
				dwEvLogStart = dwNewestEventLogRecord;
				
				LogExtMsg(WARNING_LOG,"Acceleration problem: I have lost my old event pointer. Recalculating"); 
			}
			
			// No data in the current log file? Break out.
			if(dwEventLogRecords == 0) {
				LogExtMsg(WARNING_LOG,"No events in the current file. Popping back out to the main loop."); 
				continue;
			}

			for(dwEvLogCounter=dwEvLogStart; dwEvLogCounter <= dwNewestEventLogRecord; dwEvLogCounter++) {
				// First, check to see if we should save off a log position
				if (MessageCounter >= MSG_COUNT_SAVE_POS) {
					MyWriteProfileDWORD("Status",EventLogStatusName[EventTriggered],dwEvLogCounter);
					LogExtMsg(WARNING_LOG,"Saving position for log: %d", EventTriggered); 
					MessageCounter = 0;
				} else {
					MessageCounter++;
				}
				// Has the user requested that we exit here?
				// This may be called if the user has multiple megabytes of
				// data to send and they didn't realise it.
				if(g_Info.bTerminate) {
					m_bIsRunning=0;
					break;
				}

				// NOTE: THIS WILL POTENTIALLY READ MULTIPLE RECORDS INTO THE BUFFER!
				// Ignore any after the first, and iterate through the file.
				// Read the Event Log records we have not yet seen
				// NOTE 2: These events can be BIG - 78k in one case. (DrWatson dump)
				bRetVal = ReadEventLog( hEventLog[EventTriggered], EVENTLOG_BACKWARDS_READ|EVENTLOG_SEEK_READ, dwEvLogCounter, EventLogRecordBuffer,
						  MAX_EVENT,&dwBytesRead,&dwMinNumberOfBytesNeeded );
				
				if(!bRetVal) {
					// Problem encountered.
					g_dwLastError = GetLastError();
				}
				// I would like to filter out events that have been caused by Safed here,
				// but there seems to be no way to correalate the process ID reported in
				// the event with real process ID of Safed

				pELR=(PEVENTLOGRECORD)EventLogRecordBuffer;
				
				if(!pELR) {
					continue;
				}

				if(bRetVal) {
					// ZAP out out last eventlog record to a file.
					// DEBUGDumpEventLog(EventTriggered,dwBytesRead,pELR);

					LogExtMsg(WARNING_LOG,"pELR Len: %d RecordNum: %d TimeGen: %ld TimeWr: %ld EventID: %d EventType: %d NumStrings: %d EventCat: %d StringOff: %d UserSidLen: %d UserSidOff: %d DataLen: %d DataOff: %d",
						pELR->Length,pELR->RecordNumber,pELR->TimeGenerated,pELR->TimeWritten,pELR->EventID,
						pELR->EventType,pELR->NumStrings,pELR->EventCategory,pELR->StringOffset,pELR->UserSidLength,pELR->UserSidOffset,pELR->DataLength,pELR->DataOffset);
				}
				
				if(!bRetVal) {
					if(g_dwLastError == ERROR_INSUFFICIENT_BUFFER) {
						LogExtMsg(WARNING_LOG,"Not enough buffer available for a event log record. Dropped event."); 
						LogExtMsg(WARNING_LOG,"loop info: dwEvLogStart: %d - dwEvLogCounter: %d - dwNewestEventLogRecord: %d",dwEvLogStart,dwEvLogCounter,dwNewestEventLogRecord); 
						LogExtMsg(WARNING_LOG,"Minimum number of bytes needed is aparently %ld. Bytes read is %ld",dwMinNumberOfBytesNeeded,dwBytesRead); 
						// Buffer is not large enough? An event greater than 8k? You're joking.
						// For the moment, drop this event.
						// We may wish to consider malloc'ing some extra RAM
						// to retrieve the event (Like we did in the old backlog)
						// but I don't think it's worthwhile, due to the risk of memory leaks.
						
						// NOTE: User report of a 78k!!! log message (drwatson dump)

						// Maybe we should print out some raw stats here.

						
						continue; // to the next event.
					}  else if(g_dwLastError == ERROR_EVENTLOG_FILE_CORRUPT) {
						LogExtMsg(ERROR_LOG,"%s has been corrupted!! Sending warning message and going to sleep",EventLogSourceName[EventTriggered]);
													
						char CurrentDate[16]="";
						DWORD ShortEventID=0;
						char header[256];
					
						int criticality=4;

						static char szTempString[MAX_EVENT]="SAFED-ERROR: The event log is corrupted and requires immediate attention"; // Approximately the maximum we could reasonably expect to transfer over UDP

						struct tm ptmTime;
						time_t ttime;

						ttime=time(NULL);
						localtime_s(&ptmTime,&ttime);
						strftime(SubmitTime, _countof(SubmitTime),"%a %b %d %H:%M:%S %Y", &ptmTime);

						if(dwSyslogHeader || usefile) {
							resetSafedCounter(&newtime);
						}else{
							time(&currenttime);
							localtime_s(&newtime,&currenttime);

						}
						BOOL DataSent=0;
						DWORD dwWaitCount = WaitForSingleObject(hMutexCount,1000);
						if(dwWaitCount == WAIT_OBJECT_0) {

							if(dwSyslogHeader) {
								DWORD tdwSyslog;
								syslogdate(CurrentDate,&newtime);
								tdwSyslog=(3 & 7) | ((dwSyslog >> 3) << 3);
								_snprintf_s(header,_countof(header),_TRUNCATE,"<%ld>%s %s Safed[%d][%d]:",tdwSyslog,CurrentDate,Hostname,pid,SafedCounter);
							} else {
								_snprintf_s(header,_countof(header),_TRUNCATE,"%s%sSafed[%d][%d]:",Hostname,DELIM,pid,SafedCounter);
							}
							_snprintf_s(szSendString,dwMaxMsgSize*sizeof(char),_TRUNCATE,"%s%s%s%seventid=%ld%s%s%suser=%s%s%s%s%s%s%s%s%s%s%s%s%s%s%d\0",header,DELIM,SubmitTime,DELIM,ShortEventID,DELIM,EventLogSourceName[EventTriggered],DELIM,"SYSTEM",DELIM,SIDType,DELIM,EventLogType,DELIM,ComputerName,DELIM,"Event Log Corruption",DELIM,EventLogSourceName[EventTriggered],DELIM,szTempString,DELIM,EventLogCounter[EventTriggered]);
							// Add in an MD5 if appropriate
							if(ActivateChecksum) {
								char CryptString[64];
								strncpy_s(CryptString,_countof(CryptString),MD5String(szSendString),_TRUNCATE);
								_snprintf_s(szSendString,dwMaxMsgSize*sizeof(char),_TRUNCATE,"%s%s%s",szSendString,DELIM,CryptString);
							}
							
							// Ok, now add a newline.
							if (strlen(szSendString) >= dwMaxMsgSize*sizeof(char) -1) {
								szSendString[strlen(szSendString) - 1]='\n';
							} else {
								strncat_s(szSendString,dwMaxMsgSize*sizeof(char),"\n",_TRUNCATE);
							}
									
							if(strlen(szSendString)) { LogExtMsg(INFORMATION_LOG,"DEBUG: Sending the following string to the server: %s",szSendString); }
							

							hostcurrentnode=getHostHead();
							while(hostcurrentnode) {
								//LogExtMsg(WARNING_LOG,"sending data to %s", hostcurrentnode->HostName);
								if(hostcurrentnode->Socket == INVALID_SOCKET) {
									// Try to reestablish here.
									// Since socket connects use a fair bit of system resources, try and do it nicely.
									LogExtMsg(INFORMATION_LOG,"Socket is toast for %s. Trying to reestablish.",hostcurrentnode->HostName); 
									
									hostcurrentnode->Socket = ConnectToServer( hostcurrentnode, szError, _countof(szError) );
									
									if(hostcurrentnode->Socket == INVALID_SOCKET) {
										// Hmm. Try again later.
										// Jump to the next socket
										hostcurrentnode=hostcurrentnode->next;
										LogExtMsg(ERROR_LOG,"Failed to reconnect socket");
										continue;
									}
								}
								if(SafedCounter == 1){
									recovery = 0;//avoid to send backuped message from yesterday to the log of today
								}
								if(recovery == 1){// try to send the backuped message
									if( !SendToSocket(hostcurrentnode, szSendStringBkp, (int)strlen(szSendStringBkp), szError, _countof(szError)) )
									{
										if(szError) { LogExtMsg(INFORMATION_LOG,szError); } 
										LogExtMsg(INFORMATION_LOG,"Socket for %s is toast. Breaking out - will reestablish next time.",hostcurrentnode->HostName); 
										// Close the socket. Restablish it on the next cycle, if we can.
										CloseSocket(hostcurrentnode->Socket,hostcurrentnode->tlssession);
										hostcurrentnode->Socket=INVALID_SOCKET;

									} else {
										recovery = -1; //backuped message has been sent
									}

								} 


								if(recovery != 1){// try to send the current message only if no backuped message exists
									if( !SendToSocket(hostcurrentnode, szSendString, (int)strlen(szSendString), szError, _countof(szError)) )
									{
										if(szError) { LogExtMsg(INFORMATION_LOG,szError); }
										LogExtMsg(INFORMATION_LOG,"Socket for %s is toast. Breaking out - will reestablish next time.",hostcurrentnode->HostName); 
										// Close the socket. Restablish it on the next cycle, if we can.
										CloseSocket(hostcurrentnode->Socket, hostcurrentnode->tlssession);
										hostcurrentnode->Socket=INVALID_SOCKET;
										if(recovery == 0)recovery = 1;//if backuped message is sent , it will not be sent again
									} else {
										strcpy(szSendStringBkp, szSendString);
										DataSent=1;
										recovery = 0;
										//seqnum++;
									}
								}
								hostcurrentnode=hostcurrentnode->next;
							}
							if(DataSent){
								SafedCounter++;
								if(SafedCounter >= MAXDWORD) {
									SafedCounter=1;
								}

							}
							ReleaseMutex(hMutexCount);	
							if(DataSent){
								// Write the data out to a disk, if requested.
								if(usefile) {
									dwWaitFile = WaitForSingleObject(hMutexFile,500);
									if(dwWaitFile == WAIT_OBJECT_0) {
										fopen_s(&OutputFile,filename,"a");
										fputs(szSendString,OutputFile);
										fflush(OutputFile);
										fclose(OutputFile);
									}
									ReleaseMutex(hMutexFile);	
								}
							}

						}
						g_Info.bTerminate = TRUE;
						failure_exit = TRUE;
						break;
					}  else if(g_dwLastError == ERROR_EVENTLOG_FILE_CHANGED) {
						// Someone cleared the file, close and reread!
						LogExtMsg(WARNING_LOG,"%s has been cleared. Reopening eventlog file.",EventLogSourceName[EventTriggered]); 
						dwEventLogCleared[EventTriggered] = 1;
						for(int i=0;i<10;i++) {
							if(!CloseEventLog(hEventLog[EventTriggered])) {
								LogExtMsg(WARNING_LOG,"2: Closure of eventlog failed! Error is %d.",GetLastError());
								if( i==9) { LogExtMsg(WARNING_LOG,"Bailing out! Cannot seem to close this eventlog. Name is %s, hEventLog[EventTriggered] is %ld, EventTriggered is %d",EventLogSourceName[EventTriggered],hEventLog[EventTriggered],EventTriggered); }
								Sleep(1000);
							} else {
								LogExtMsg(INFORMATION_LOG,"Closure of eventlog succeeded"); 
								break;
							}
						}
						

						int count=0;
						do {
							hEventLog[EventTriggered] = OpenEventLog( NULL, EventLogSourceName[EventTriggered] );
							if(hEventLog[EventTriggered] != NULL) {
								break;
							}
							LogExtMsg(WARNING_LOG,"2: Could not re-open event log.. EventTriggered is %d, log name is %s - sleeping for 5 seconds (Error code was %d)",EventTriggered,EventLogSourceName[EventTriggered],GetLastError()); 
							Sleep(5000);
							count++;
							if(count > 20) {
								hEventLog[EventTriggered]=NULL;
								LogExtMsg(WARNING_LOG,"%s wont reopen after 20 attempts. Bailing out.",EventLogSourceName[EventTriggered]);
								break;
							}
						} while(hEventLog[EventTriggered] == NULL);

						if(hEventLog[EventTriggered]==NULL) {
							continue;
						}

						while((nRet = NotifyChangeEventLog( hEventLog[EventTriggered], m_hEventList[EventTriggered] )) == NULL) {
							LogExtMsg(WARNING_LOG,"2: Could not re-bind to event log.. sleeping for 5 seconds");
							Sleep(5000);
						}
						
						// Grab these details just in case.
						// They should persist, but read them again anyway.
						GetOldestEventLogRecord(hEventLog[EventTriggered], &dwOldestEventLogRecord);
						dwEventIDOldest[EventTriggered]=dwOldestEventLogRecord;
						// The total number of eventlog records.
						GetNumberOfEventLogRecords(hEventLog[EventTriggered], &dwEventLogRecords);
						// The last eventlog record number
						dwNewestEventLogRecord = (dwEventLogRecords + dwOldestEventLogRecord) -1;

						dwEventIDRead[EventTriggered]=dwOldestEventLogRecord;
						dwEvLogStart = dwOldestEventLogRecord;
						
						LogExtMsg(WARNING_LOG,"Eventlog has been cleared. Re-created pointers to log"); 
						
						// Jump out of the for/next loop, and try again.
						dwNewestEventLogRecord=dwOldestEventLogRecord;
						::SetEvent(m_hEventList[EventTriggered]);
						break;
						
					} else if(g_dwLastError == ERROR_INVALID_PARAMETER || g_dwLastError == ERROR_HANDLE_EOF || g_dwLastError == RPC_S_UNKNOWN_IF) {
						// This error generally means that the user has a small
						// audit buffer set to overwrite old audit events.
						// We have not been quick enough to catch the old event before
						// it is overwritten, so Continue on to the next one and try to
						// catch up again.
						
						// Add one to our catchup variable - this should help us if we get into an endless loop here.
						dwCatchUpCount++;
						
						if(dwCatchUpCount > 100) {
							// Hmm.. we have problems, we can't seem to catch up to the audit record
							// pointer. Lets try and sleep for a moment in the hope that the system
							// stabilises. Note: This will mean that we lose a few records (potentially)
							// but at least we won't grind the system to a halt..
							dwCatchUpCount=0;
							LogExtMsg(WARNING_LOG,"Acceleration problem: Small audit buffer means that I cannot catch up to the most recent audit event. Sleeping for a moment."); 
							
							Sleep(1000);
							
							GetOldestEventLogRecord(hEventLog[EventTriggered], &dwOldestEventLogRecord);
							dwEventIDOldest[EventTriggered]=dwOldestEventLogRecord;
							// The total number of eventlog records.
							GetNumberOfEventLogRecords(hEventLog[EventTriggered], &dwEventLogRecords);
							// The last eventlog record number
							dwNewestEventLogRecord = (dwEventLogRecords + dwOldestEventLogRecord) -1;
							dwEventIDRead[EventTriggered]=dwNewestEventLogRecord;
						}
						// We may want to continue here instead.
						break; // Break out of the for loop. Note that this will send us to the newest event.
					} else {
						// Unknown error. Windows is  doing something very strange.
						// We sometimes receive a 998 here (ERROR_NOACCESS). Not sure what the cause is.

						LogExtMsg(WARNING_LOG,"An unknown error occurred - g_dwLastError is %d. Continuing.",g_dwLastError); 
						// m_bIsRunning=0;
						
						// Sleep for a second, since we do NOT want to get into an endless loop
						// here, and eat CPU.
						Sleep(1000);
						
						// IF the event is a log-related one:
						// Close and reopen the offending log file, just in case.
						if(EventTriggered <= MAX_LOG_TYPE) {
							for(int i=0;i<10;i++) {

								if(!CloseEventLog(hEventLog[EventTriggered])) {
									LogExtMsg(WARNING_LOG,"3: Closure of eventlog failed! Error is %d.",GetLastError()); 
									if(i==9) { LogExtMsg(WARNING_LOG,"Bailing out! Cannot seem to close this eventlog. Name is %s, hEventLog[EventTriggered] is %ld, EventTriggered is %d",EventLogSourceName[EventTriggered],hEventLog[EventTriggered],EventTriggered); }
									Sleep(1000);
								} else {
									LogExtMsg(INFORMATION_LOG, "Closure of eventlog succeeded"); 
									break;
								}
							}

							int count=0;
							do {
								hEventLog[EventTriggered] = OpenEventLog( NULL, EventLogSourceName[EventTriggered] );
								if(hEventLog[EventTriggered] != NULL) {
									break;
								}
								LogExtMsg(WARNING_LOG,"3: Could not re-open event log.. EventTriggered is %d, log name is %s - sleeping for 5 seconds (Error code was %d)",EventTriggered,EventLogSourceName[EventTriggered],GetLastError()); 
								Sleep(5000);
								count++;
								if(count > 20) {
									hEventLog[EventTriggered]=NULL;
									LogExtMsg(WARNING_LOG,"%s wont reopen after 20 attempts. Bailing out.",EventLogSourceName[EventTriggered]); 
									break;
								}
							} while(hEventLog[EventTriggered] == NULL);

							if(hEventLog[EventTriggered]==NULL) {
								continue;
							}

							while((nRet = NotifyChangeEventLog( hEventLog[EventTriggered], m_hEventList[EventTriggered] )) == NULL) {
								LogExtMsg(WARNING_LOG,"3: Could not re-bind to event log.. sleeping for 5 seconds"); 
								Sleep(5000);
							}
						
							GetOldestEventLogRecord(hEventLog[EventTriggered], &dwOldestEventLogRecord);
							dwEventIDOldest[EventTriggered]=dwOldestEventLogRecord;
							// The total number of eventlog records.
							GetNumberOfEventLogRecords(hEventLog[EventTriggered], &dwEventLogRecords);
							// The last eventlog record number
							dwNewestEventLogRecord = (dwEventLogRecords + dwOldestEventLogRecord) -1;
							dwEventIDRead[EventTriggered]=dwNewestEventLogRecord;
						}
						break; // Break out of the for loop.
					}
				}
				
				// We received a good event. Clear our catch-up variable.
				dwCatchUpCount=0;
				if(bRetVal)
				{

					if(EventTriggered==1) { // SYSTEM
						// For some wierd reason, MS mangles the system eventIDs!
						if(pELR->EventID > 1073741824) {
							EventID = pELR->EventID & 65535;
						} else {
							EventID = pELR->EventID;
						}
					} else {
						EventID = pELR->EventID;
					}
				
					if(dwObjectiveCount) {
						// I was considering doing a quick eventid match here,
						// to see whether we should continue or not, but there's no real point
						// if users are going to have at least ONE '*' match for eventid..
						
						switch(pELR->EventType)	{
						case EVENTLOG_SUCCESS:
							etype=TYPE_INFO;
							break;
						case EVENTLOG_ERROR_TYPE:
							etype=TYPE_ERROR;
							break;
						case EVENTLOG_WARNING_TYPE:
							etype=TYPE_WARN;
							break;
						case EVENTLOG_INFORMATION_TYPE:
							etype=TYPE_INFO;
							break;
						case EVENTLOG_AUDIT_SUCCESS:
							etype=TYPE_SUCCESS;
							break;
						case EVENTLOG_AUDIT_FAILURE:
							etype=TYPE_FAILURE;
							break;
						default:
							LogExtMsg(WARNING_LOG,"pELR->EventType looks to be corrupted. Set to TYPE_INFO"); 
							etype=TYPE_INFO;
							break;
						}
						
						LogExtMsg(DEBUG_LOG,"FastCheckObjective: Starting checks"); 
						
						MatchCount=0;
						MatchPointer=MatchList; // Start of the list
						ResetCurrentNode();

						if(!MatchPointer) {
							// Something seriously wierd is happening if MatchPointer is null.
							LogExtMsg(DEBUG_LOG,"Match Pointer has gone away");
							continue;
						}
						
						do {
							try {
								*MatchPointer=FastCheckObjective(EventID,etype,stype);
							} catch(...) {
								LogExtMsg(DEBUG_LOG,"FastCheckObjective: Error encountered!");
								LogExtMsg(DEBUG_LOG,"MatchPointer is %ld, EventID is %d, etype is %d, stype is %d",*MatchPointer,EventID,etype,stype);
								*MatchPointer=NULL;
							}
							
							if(*MatchPointer) {
								MatchFound=1;
								MatchCount++;
								MatchPointer++;
							} else {
								MatchFound=0;
							}
						} while(MatchFound && (MatchCount < dwObjectiveCount) && g_Info.bTerminate==0); // Guard against overflows

						if(g_Info.bTerminate) {
							m_bIsRunning=0;
							break;
						}

						// No matches? Not much point in expanding strings and so on.
						// Jump out now.
						if(!MatchCount) {
							LogExtMsg(INFORMATION_LOG,"Match Checker: No matches found"); 

							continue;
						}
						LogExtMsg(INFORMATION_LOG,"FastCheckObjective: found matches (%d)",MatchCount); 
					}
					// OK, we have at least one probable match. Expand our strings
					// so that we can continue looking.
		
					// No error. Proceed.
					Offset = sizeof(EVENTLOGRECORD);
					// Grab the source name, the start of which is eventlogrecordbuffer + _countof(eventlogrecord)
					strncpy_s(SourceName, _countof(SourceName), (LPTSTR)((LPBYTE)pELR + Offset), _TRUNCATE);
					// Just in case
					SourceName[_countof(SourceName)-1]='\0';

					LogExtMsg(DEBUG_LOG,"SourceName is %s",SourceName); 
					
					// Jump to the next element of the eventlog record
					Offset += (DWORD)strlen(SourceName) +1; // length + \0 character
					// Note that there is a chance that the sourcename is longer than 1024.
					// If this is the case, then this event is probably corrupted.
					
					strncpy_s(ComputerName,_countof(ComputerName), (LPTSTR)((LPBYTE)pELR + Offset), _TRUNCATE);
					
					if(ComputerName) { LogExtMsg(DEBUG_LOG,"Received event from computer %s",ComputerName); } 
	
					if(pELR->UserSidLength > 0 && pELR->UserSidLength < 8192)	{
						LogExtMsg(DEBUG_LOG,"UserSidLength is > 0 and less than 8k.."); 
						SID_NAME_USE SidNameUse=SidTypeUser;
						LogExtMsg(DEBUG_LOG,"Getting event user name"); 
						bRetVal=GetEventUserName(pELR,UserName,_countof(UserName),&SidNameUse);
						LogExtMsg(DEBUG_LOG,"User name grabbed. Getting Sid type"); 

						if(bRetVal && SidNameUse) {
							GetSIDType(SidNameUse,SIDType,_countof(SIDType));
						} else {
							SIDType[0]='\0';
						}
						
						LogExtMsg(DEBUG_LOG,"Grabbed Sidtype"); 
					} else {
						LogExtMsg(DEBUG_LOG,"UserSidLength problem. Event is corrupt - size is %ld !!!!!!!!!!!!!!!!!!!!!!!!!! Consider dumping this event.",pELR->UserSidLength); 
						UserName[0]='\0';
						// Consider dumping this event!
						// continue;
					}
					
					LogExtMsg(DEBUG_LOG,"Getting Event Log Type"); 
					
					// Some of the MS System calls used in GetEventLogType are prone to error.
					try {
						GetEventLogType(EventLogType, pELR->EventType, _countof(EventLogType));
					} catch(...) {
						LogExtMsg(DEBUG_LOG,"GetEventLogType error caught. EventType is %ld. Continuing.",pELR->EventType);
						strncpy_s(EventLogType,_countof(EventLogType),"Success Audit",_TRUNCATE);
						//continue;
					}
					
					LogExtMsg(DEBUG_LOG,"Ok, checking times"); 
					if(pELR->TimeGenerated && pELR->TimeWritten) {
						struct tm ptmTime;
						time_t ttime;
						errno_t err;
						
						ttime=(time_t)pELR->TimeGenerated;
						err=localtime_s(&ptmTime,&ttime);
						if(!err) {
							strftime(SubmitTime, _countof(SubmitTime),"%a %b %d %H:%M:%S %Y", &ptmTime);
						} else {
							// Could not pull back date/time from the event. Use current time.
							ttime=time(NULL);
							localtime_s(&ptmTime,&ttime);
							strftime(SubmitTime, _countof(SubmitTime),"%a %b %d %H:%M:%S %Y", &ptmTime);
						}
						ttime=(time_t)pELR->TimeWritten;
						err=localtime_s(&ptmTime,&ttime);
						if(!err) {
							strftime(WriteTime, _countof(WriteTime),"%a %b %d %H:%M:%S %Y", &ptmTime);
						} else {
							ttime=time(NULL);
							localtime_s(&ptmTime,&ttime);
							strftime(WriteTime, _countof(WriteTime),"%a %b %d %H:%M:%S %Y", &ptmTime);
						}
						
						//lstrcpyn(SubmitTime, asctime(localtime((time_t *)&(pELR->TimeGenerated))), _countof(SubmitTime));
						// lstrcpyn(WriteTime, asctime(localtime((time_t *)&(pELR->TimeWritten))), _countof(WriteTime));
						// May need to chomp off the last character - asctime return a newline!
						// SubmitTime[strlen(SubmitTime)-1]='\0';
						// WriteTime[strlen(WriteTime)-1]='\0';
					} else {
						SubmitTime[0]='\0';
						WriteTime[0]='\0';
					}
					
					if(SubmitTime) { LogExtMsg(DEBUG_LOG,"Date and Time grabbed: %s.",SubmitTime); } 
					try {
						ExpandStrings(pELR,EventLogSourceName[EventTriggered],ExpandedString,_countof(ExpandedString));
					} catch (...) {
						int size;
						size=pELR->DataOffset - pELR->StringOffset;
						if(size >= _countof(ExpandedString)) {
							size=_countof(ExpandedString)-1;
						}
						
						LogExtMsg(DEBUG_LOG,"CRASH: ExpandStrings Failure Caught"); 
						
						strncpy_s(ExpandedString,_countof(ExpandedString),"N/A",_TRUNCATE);
						memcpy(ExpandedString, (LPBYTE)pELR + pELR->StringOffset, size);
						ExpandedString[size]='\0';
					}
					LogExtMsg(DEBUG_LOG,"Strings Expanded"); 
					
					try {
						GetDataString(pELR,DataString,_countof(DataString));
					} catch (...) {
						LogExtMsg(DEBUG_LOG,"CRASH: GetDataString Failure Caught"); 
						strncpy_s(DataString,_countof(DataString),"N/A",_TRUNCATE);
					}
					LogExtMsg(DEBUG_LOG,"DataStrings Grabbed"); 
					Category = pELR->EventCategory;
					
					// Some of the MS system calls use by GetCategoryString are buggy.
					try {
						GetCategoryString(pELR,EventLogSourceName[EventTriggered],SourceName,szCategoryString,_countof(szCategoryString));
					} catch (...) {
						LogExtMsg(DEBUG_LOG,"CRASH: GetCategoryString Failure Caught"); 
						strncpy_s(szCategoryString,_countof(szCategoryString),"N/A",_TRUNCATE);
					}
					if(szCategoryString) { LogExtMsg(DEBUG_LOG,"Category String grabbed: %s.",szCategoryString); } 
					
					// Send out to network
					// First set the separator in the strings area to use tabs instead.

					static char szTempString[MAX_EVENT]=""; // Approximately the maximum we could reasonably expect to transfer over UDP

					UINT counter=0;
				
					// Chop down the ExpandedString into nice easy bits.
					if(strlen(ExpandedString))
					{
						UINT stringsize=0;
						BOOL bDelim=0;
						BOOL bNewLine=0;
						
						LogExtMsg(DEBUG_LOG,"Expanding Strings..."); 
						
						if(strlen(ExpandedString) >= MAX_EVENT) {
							stringsize=MAX_EVENT;
						} else {
							stringsize=(UINT)strlen(ExpandedString);
						}
						
						// Within the "Extra strings" section of a windows log,
						// get rid of newlines (cr / lf), and change any multiple-tabs to a single tab.
						strncpy_s(szTempString,_countof(szTempString),"",_TRUNCATE);
						while(counter < stringsize) {
							// Replace any delimiter characters (usually tab)
							// with spaces.
							// Also, if the ClearTabs registry key is set, kill off the tabs.
							if(ExpandedString[counter]==DELIM[0] || (ExpandedString[counter]==9 && ClearTabs==1))
							{
								bNewLine=0;
								if(!bDelim) {
									if((strlen(szTempString) + 1) < MAX_EVENT) {
										strncat_s(szTempString,_countof(szTempString)," ",_TRUNCATE);
									}
									bDelim=1;
								}
							}
							else if(ExpandedString[counter]==10 || ExpandedString[counter]==13)
							{
								// CR/LF - substitute a space instead.
								if((strlen(szTempString) + 1) < MAX_EVENT) {
									strncat_s(szTempString,_countof(szTempString)," ",_TRUNCATE);
								}
								
								bDelim=0;
								bNewLine=1;
							} else if(ExpandedString[counter]==' ' && bNewLine==1) {
								// Lots of spaces after newlines. Trim them down.
								1;
							} else {
								char szTempString2[2]="";
								
								bNewLine=0;
								bDelim=0;
								szTempString2[0]=(char)ExpandedString[counter];
								szTempString2[1]='\0';
								if((strlen(szTempString) + strlen(szTempString2)) < MAX_EVENT) {
									strncat_s(szTempString,_countof(szTempString),szTempString2,_TRUNCATE);
								}
							}
							counter++;
						}
					} else {
						// Could not expand the strings.
						strncpy_s(szTempString,_countof(szTempString),"",_TRUNCATE);
					}

					if(UserName && strstr(UserName,"SYSTEM")){
						char* uname = strstr(szTempString,"Target User Name: ");
						char* euname = NULL;
						int lenuname = _countof(UserName);
						if(uname){
							uname = uname + 18;
							euname = strstr(uname," ");
							if(euname){
								lenuname = lenuname> euname-uname +1? euname-uname +1:lenuname;
								strncpy_s(UserName,lenuname,uname,_TRUNCATE);
							}							
						}else{
							uname = strstr(szTempString,"User Name: ");
							if(uname){
								uname = uname + 11;
								euname = strstr(uname," ");
								if(euname){
									lenuname = lenuname> euname-uname +1? euname-uname +1:lenuname;
									strncpy_s(UserName,lenuname,uname,_TRUNCATE);
								}	
							}else{
								uname = strstr(szTempString,"Logon account: ");
								if(uname){
									uname = uname + 15;
									euname = strstr(uname," ");
									if(euname){
										lenuname = lenuname> euname-uname +1? euname-uname +1:lenuname;
										strncpy_s(UserName,lenuname,uname,_TRUNCATE);
									}
									
								}
							}
						}
						euname = strstr(UserName,"@");
						if(euname){//remove the domain name if any   -> user@domain
							UserName[euname - UserName] = '\0';
						}
					}


					char CurrentDate[16]="";
					// Check that we have all the data that we need.
					// Note: DataString may not exist, but everything else should.
					// Removed this bit: && strlen(UserName) && strlen(SIDType)
					
					// Sanitise some of the data if it's not available.
					if(!strlen(EventLogSourceName[EventTriggered]))
						strncpy_s(EventLogSourceName[EventTriggered],_countof(EventLogSourceName[EventTriggered]),"Unknown",_TRUNCATE);
					if(!strlen(SubmitTime))
						strncpy_s(SubmitTime,_countof(SubmitTime),"Unknown",_TRUNCATE);
					if(!strlen(SourceName))
						strncpy_s(SourceName,_countof(SourceName),"Unknown",_TRUNCATE);
					if(!strlen(EventLogType))
						strncpy_s(EventLogType,_countof(EventLogType),"Unknown",_TRUNCATE);
					if(!strlen(ComputerName))
						strncpy_s(ComputerName,_countof(ComputerName),"Unknown",_TRUNCATE);
					if(!strlen(szTempString))
						strncpy_s(szTempString,_countof(szTempString),"Unknown",_TRUNCATE);
					if(!strlen(szCategoryString))
						strncpy_s(szCategoryString,_countof(szCategoryString),"Unknown",_TRUNCATE);
					PreUSBEventTriggered = EventTriggered;

					do {

						if(strlen(EventLogSourceName[EventTriggered]) && strlen(SubmitTime) && strlen(SourceName) && strlen(EventLogType) && strlen(ComputerName) && DataString && strlen(szTempString) && strlen(szCategoryString))
						{

							LogExtMsg(DEBUG_LOG,"Event is ready, checking objectives");
							char *stringp;
							if(!strlen(UserName)) {
								strncpy_s(UserName,_countof(UserName),"Unknown User",_TRUNCATE);
								strncpy_s(SIDType,_countof(SIDType),"N/A",_TRUNCATE);
							}
							
							// This is the point at which we integrate our regular expression handling
							// and event filtering facilities.
							// NOTE:
							// Was going to implement a regular expression matching capability,
							// - but based on the limitations of the NT Audit subsystem, it's probably
							//   better that we use dos wildcards instead.
							//
							
							DWORD ShortEventID=0;
							// Cut off the severity, flags, and  facility data
							// Just leave the real event ID.
							ShortEventID = EventID & 65535;
							LogExtMsg(INFORMATION_LOG,"ShortEventID: %d", ShortEventID);
							char header[256];
							
							BOOL nodematch=0;
							int criticality=0;
							int tcriticality=0;
							char matchedstr[512]="";
							
							LogExtMsg(INFORMATION_LOG,"dwObjectiveCount: %d", dwObjectiveCount);
							// Check objectives
							// NOTE: If there are no objectives, send nothng?
							if(!dwObjectiveCount) {
								nodematch=0;
							} else {
								MatchCount=0;
								MatchPointer=MatchList; // Start of the list
								ResetCurrentNode();
								
								do {
									LogExtMsg(INFORMATION_LOG,"begin MatchCount: %d", MatchCount);
									// Some of the MS System calls used in CheckObjective are buggy.
									try {
										tcriticality=CheckObjective(*MatchPointer,ShortEventID,UserName,szTempString,matchedstr);
									} catch(...) {
										LogExtMsg(DEBUG_LOG,"CheckObjective CRASH");
										tcriticality=0;
									}
									if(tcriticality >= 0) {
										if ((*MatchPointer)->excludeidflag || (*MatchPointer)->excludeflag || (*MatchPointer)->excludematchflag) {
											LogExtMsg(INFORMATION_LOG,"Excluding this event");
											nodematch=0;
											break;
										}
										nodematch=1;
										LogExtMsg(INFORMATION_LOG,"Checkobjective: node found"); 
										if(criticality < tcriticality) {
											criticality = tcriticality;
										}
										if(!dwCritAudit) {
											// break here if we just want the FIRST match.
											break;
										}
									}
									MatchPointer++;
									MatchCount++;

									LogExtMsg(INFORMATION_LOG,"end MatchCount: %d", MatchCount);
								} while(*MatchPointer && (MatchCount < dwObjectiveCount) && g_Info.bTerminate==0); // Guard against overflows
								
								if(g_Info.bTerminate) {
									m_bIsRunning=0;
									goto endmsg;
								}
								if (!*MatchPointer) LogExtMsg(INFORMATION_LOG,"Check Objective finished: MatchPointer has gone away");
								if (MatchCount >= dwObjectiveCount) LogExtMsg(INFORMATION_LOG,"Check Objective finished: no objectives left to check");
							}
							// END
							LogExtMsg(INFORMATION_LOG,"nodematch: %d", (nodematch?1:0));
							if(nodematch) {
								time(&currenttime);
								if(dwSyslogHeader || usefile) {
									resetSafedCounter(&newtime);
								}else{
									time(&currenttime);
									localtime_s(&newtime,&currenttime);
								}
								
								if(usefile) {
									// Check to see whether we need to rotate our log file.
									if(changeCacheFileName(newtime)){
										usefile=GetOutputFile(filename, NULL);
									}

								}
								BOOL DataSent=0;
								DWORD tmpCounter=0;
								DWORD dwWaitCount = WaitForSingleObject(hMutexCount,1000);
								if(dwWaitCount == WAIT_OBJECT_0) {
								
									if(dwSyslogHeader) {
										DWORD tdwSyslog;
										
										syslogdate(CurrentDate,&newtime);
										
										// HERE: Split out criticality.
										if(dwSyslogDynamic) {
											tdwSyslog=((7-criticality) & 7) | ((dwSyslog >> 3) << 3);
										} else {
											tdwSyslog=dwSyslog;
										}
										_snprintf_s(header,_countof(header),_TRUNCATE,"<%ld>%s %s Safed[%d][%d]:",tdwSyslog,CurrentDate,Hostname,pid,SafedCounter);
									} else {
										_snprintf_s(header,_countof(header),_TRUNCATE,"%s%sSafed[%d][%d]:",Hostname,DELIM,pid,SafedCounter);
									}
									char* checkpos=strstr(UserName,"SYSTEM");
									if(checkpos){
										_snprintf_s(szSendString,dwMaxMsgSize*sizeof(char),_TRUNCATE,"%s%s%s%seventid=%ld%s%s%suser=%s%s%s%s%s%s%s%s%s%s%s%s%s%s%d\0",header,DELIM,SubmitTime,DELIM,ShortEventID,DELIM,SourceName,DELIM,matchedstr,DELIM,SIDType,DELIM,EventLogType,DELIM,ComputerName,DELIM,szCategoryString,DELIM,DataString,DELIM,szTempString,DELIM,EventLogCounter[EventTriggered]);
									}else{
										_snprintf_s(szSendString,dwMaxMsgSize*sizeof(char),_TRUNCATE,"%s%s%s%seventid=%ld%s%s%suser=%s%s%s%s%s%s%s%s%s%s%s%s%s%s%d\0",header,DELIM,SubmitTime,DELIM,ShortEventID,DELIM,SourceName,DELIM,UserName,DELIM,SIDType,DELIM,EventLogType,DELIM,ComputerName,DELIM,szCategoryString,DELIM,DataString,DELIM,szTempString,DELIM,EventLogCounter[EventTriggered]);
									}
									if(DataString) { LogExtMsg(INFORMATION_LOG,"DataString: %s",DataString); }
									if(szTempString) { LogExtMsg(INFORMATION_LOG,"szTempString: %s",szTempString); }

									// Jump through szSendString, and remove any newline characters.
									stringp=szSendString;
									while(*stringp) {
										// CR or LF
										if(*stringp==10 || *stringp==13) {
											*stringp=' ';
										}
										stringp++;
									}
									
									// Add in an MD5 if appropriate
									if(ActivateChecksum) {
										char CryptString[64];
										strncpy_s(CryptString,_countof(CryptString),MD5String(szSendString),_TRUNCATE);
										_snprintf_s(szSendString,dwMaxMsgSize*sizeof(char),_TRUNCATE,"%s%s%s",szSendString,DELIM,CryptString);
									}
									
									
									// Ok, now add a newline.
									if (strlen(szSendString) >= dwMaxMsgSize*sizeof(char) - 1 ) {
										szSendString[strlen(szSendString) - 1]='\n';
									} else {
										strncat_s(szSendString,dwMaxMsgSize*sizeof(char),"\n",_TRUNCATE);
									}
											
									if(strlen(szSendString)) { 
										LogExtMsg(INFORMATION_LOG,"DEBUG: Sending the following string to the server: %s",szSendString); 
									}
									hostcurrentnode=getHostHead();
									while(hostcurrentnode) {
										//LogExtMsg(WARNING_LOG,"sending data to %s", hostcurrentnode->HostName);
										if(hostcurrentnode->Socket == INVALID_SOCKET) {
											// Try to reestablish here.
											// Since socket connects use a fair bit of system resources, try and do it nicely.
											LogExtMsg(INFORMATION_LOG,"Socket is toast for %s. Trying to reestablish.",hostcurrentnode->HostName); 
											
											hostcurrentnode->Socket = ConnectToServer( hostcurrentnode , szError, _countof(szError) );
											
											if(hostcurrentnode->Socket == INVALID_SOCKET) {
												// Hmm. Try again later.
												// Jump to the next socket
												hostcurrentnode=hostcurrentnode->next;
												LogExtMsg(ERROR_LOG,"Failed to reconnect socket");
												continue;
											}
										}
										if(SafedCounter == 1){
											recovery = 0;//avoid to send backuped message from yesterday to the log of today
										}
										if(recovery == 1){// try to send the backuped message
											if( !SendToSocket(hostcurrentnode, szSendStringBkp, (int)strlen(szSendStringBkp), szError, _countof(szError)) )
											{
												if(szError) { LogExtMsg(INFORMATION_LOG,szError); }
												LogExtMsg(INFORMATION_LOG,"Socket for %s is toast. Breaking out - will reestablish next time.",hostcurrentnode->HostName); 
												// Close the socket. Restablish it on the next cycle, if we can.
												CloseSocket(hostcurrentnode->Socket, hostcurrentnode->tlssession);
												hostcurrentnode->Socket=INVALID_SOCKET;
											} else {
												recovery = -1; //backuped message has been sent
											}

										} 
										if(recovery != 1){// try to send the current message only if no backuped message exists
											BOOL FailFromCache = 0;
											dwWaitFile = WaitForSingleObject(hMutexFile,500);
											if(dwWaitFile == WAIT_OBJECT_0) {
												if(sentIndex && strlen(sentFile)){
													FailFromCache=SendFailedCache(hostcurrentnode, sentFile, _countof(sentFile),&sentIndex, dwMaxMsgSize);
												}
												SetSentIndex(sentFile,sentIndex);
											}
											ReleaseMutex(hMutexFile);
											if(!FailFromCache){
												if( !SendToSocket(hostcurrentnode, szSendString, (int)strlen(szSendString), szError, _countof(szError)) )
												{
													if(szError) { LogExtMsg(INFORMATION_LOG,szError); } 
													LogExtMsg(INFORMATION_LOG,"Socket for %s is toast. Breaking out - will reestablish next time.",hostcurrentnode->HostName); 
													// Close the socket. Restablish it on the next cycle, if we can.
													CloseSocket(hostcurrentnode->Socket, hostcurrentnode->tlssession);
													hostcurrentnode->Socket=INVALID_SOCKET;
													if(recovery == 0)recovery = 1;//if backuped message is sent , it will not be sent again
												} else {
													strcpy(szSendStringBkp, szSendString);
													DataSent=1;
													recovery = 0;
													//seqnum++;
												}
											}
										}
										hostcurrentnode=hostcurrentnode->next;
									}
									if(DataSent){
										SafedCounter++;
										if(SafedCounter >= MAXDWORD) {
											SafedCounter=1;
										}
									}
								}
								tmpCounter = SafedCounter;
								ReleaseMutex(hMutexCount);	
								// Did we push out at least one record?
								if(!DataSent) {
									dwEvLogCounter--;
									dwNewestEventLogRecord=dwEvLogCounter;
									LogExtMsg(ERROR_LOG,"Failed to send message, holding position in event log");
									// Break out of the for/next loop.
									goto endmsg;
								} else {

									MCCurrent = (MsgCache *)malloc(sizeof(MsgCache));
									if (MCCurrent) {
										memset(MCCurrent,0,sizeof(MsgCache));
										strncpy_s(MCCurrent->Hostname,_countof(Hostname),Hostname,_TRUNCATE);
										MCCurrent->criticality = criticality;
										MCCurrent->SafedCounter = tmpCounter;
										strncpy_s(MCCurrent->SubmitTime, 26, SubmitTime,_TRUNCATE);
										MCCurrent->ShortEventID = ShortEventID;
										strncpy_s(MCCurrent->SourceName, 100, SourceName,_TRUNCATE);
										strncpy_s(MCCurrent->UserName, 256, UserName,_TRUNCATE);
										strncpy_s(MCCurrent->SIDType, 100, SIDType,_TRUNCATE);
										strncpy_s(MCCurrent->EventLogType, 60, EventLogType,_TRUNCATE);
										strncpy_s(MCCurrent->szCategoryString, 256, szCategoryString,_TRUNCATE);
										strncpy_s(MCCurrent->DataString, MAX_EVENT, DataString,_TRUNCATE);
										strncpy_s(MCCurrent->szTempString, MAX_EVENT, szTempString,_TRUNCATE);
										MCCurrent->EventLogCounter = EventLogCounter[EventTriggered];
										MCCurrent->seenflag=0;
										MCCurrent->next = NULL;
										MCCurrent->prev = NULL;
										dwWaitRes = WaitForSingleObject(hMutex,500);
										if(dwWaitRes == WAIT_OBJECT_0) {
											if (MCCount >= WEB_CACHE_SIZE) {
												//Lock Mutex and drop the oldest record
												MsgCache *temp;
												temp = MCTail;
												MCTail = MCTail->prev;
												MCTail->next = NULL;
												memset(temp,0,sizeof(MsgCache));
												free(temp);
												MCCount--;
											}
											if (MCHead) {
												MCHead->prev = MCCurrent;
												MCCurrent->next = MCHead;
											}
											MCHead = MCCurrent;
											if (!MCTail) MCTail = MCCurrent;
											MCCount++;
										} else {
											LogExtMsg(ERROR_LOG,"EVENT CACHE FAILED!\n");
											if(MCCurrent)free(MCCurrent);
										}
										ReleaseMutex(hMutex);
										
									} else {
										LogExtMsg(ERROR_LOG,"Unable to allocate latest event cache\n");
									}
									// Increment the Safed internal event counter
									// Note: Maxdword is 4294967295
									// Dont overflow our array either.
									EventLogCounter[EventTriggered]++;
									if(EventLogCounter[EventTriggered] >= MAXDWORD) {
										EventLogCounter[EventTriggered]=1;
									}

								}
								// Write the data out to a disk, if requested.
								if(usefile) {
									dwWaitFile = WaitForSingleObject(hMutexFile,500);
									if(dwWaitFile == WAIT_OBJECT_0) {
										fopen_s(&OutputFile,filename,"a");
										fputs(szSendString,OutputFile);
										fflush(OutputFile);
										fclose(OutputFile);
									}
									ReleaseMutex(hMutexFile);	
								}
							}
								
	#ifdef MEMDEBUG
							_CrtDumpMemoryLeaks();
	#endif
								
						} else {							
							LogExtMsg(WARNING_LOG,"DEBUG: I received an event that I could not process! Details are as follows:");
							LogExtMsg(WARNING_LOG,"dwSyslog: ");
							if(dwSyslog) { LogExtMsg(WARNING_LOG,"%d\n",dwSyslog);} else { LogExtMsg(WARNING_LOG,"NO DATA\n");}
							LogExtMsg(WARNING_LOG,"CurrentDate: ");
							if(CurrentDate) { LogExtMsg(WARNING_LOG,"%s\n",CurrentDate);} else { LogExtMsg(WARNING_LOG,"NO DATA\n");}
							LogExtMsg(WARNING_LOG,"Hostname: ");
							if(Hostname) {LogExtMsg(WARNING_LOG,"%s\n",Hostname);} else { LogExtMsg(WARNING_LOG,"NO DATA\n");}
							LogExtMsg(WARNING_LOG,"EventTriggered: ");
							if(EventTriggered) { LogExtMsg(WARNING_LOG,"%d\n",EventTriggered);} else { LogExtMsg(WARNING_LOG,"NO DATA\n");}
							LogExtMsg(WARNING_LOG,"EventLogSourceName[EventTriggered]: ");
							if(EventLogSourceName[EventTriggered]) {LogExtMsg(WARNING_LOG,"%s\n",EventLogSourceName[EventTriggered]);} else {LogExtMsg(WARNING_LOG,"NO DATA\n");}
							LogExtMsg(WARNING_LOG,"dwEvLogCounter: ");
							if(dwEvLogCounter) { LogExtMsg(WARNING_LOG,"%d\n",dwEvLogCounter);} else { LogExtMsg(WARNING_LOG,"NO DATA\n");}
							LogExtMsg(WARNING_LOG,"SubmitTime: ");
							if(SubmitTime) { LogExtMsg(WARNING_LOG,"%s\n",SubmitTime);} else { LogExtMsg(WARNING_LOG,"NO DATA\n");}
							LogExtMsg(WARNING_LOG,"EventID: ");
							if(EventID) { LogExtMsg(WARNING_LOG,"%d\n",EventID);} else { LogExtMsg(WARNING_LOG,"NO DATA\n");}
							LogExtMsg(WARNING_LOG,"SourceName: ");
							if(SourceName) { LogExtMsg(WARNING_LOG,"%s\n",SourceName);} else { LogExtMsg(WARNING_LOG,"NO DATA\n");}
							LogExtMsg(WARNING_LOG,"UserName: ");
							if(UserName) { LogExtMsg(WARNING_LOG,"%s\n",UserName);} else { LogExtMsg(WARNING_LOG,"NO DATA\n");}
							LogExtMsg(WARNING_LOG,"SIDType: ");
							if(SIDType) { LogExtMsg(WARNING_LOG,"%s\n",SIDType);} else { LogExtMsg(WARNING_LOG,"NO DATA\n");}
							LogExtMsg(WARNING_LOG,"EventLogType: ");
							if(EventLogType) { LogExtMsg(WARNING_LOG,"%s\n",EventLogType);} else { LogExtMsg(WARNING_LOG,"NO DATA\n");}
							LogExtMsg(WARNING_LOG,"ComputerName: ");
							if(ComputerName) { LogExtMsg(WARNING_LOG,"%s\n",ComputerName);} else { LogExtMsg(WARNING_LOG,"NO DATA\n");}
							LogExtMsg(WARNING_LOG,"DataString: ");
							if(DataString) { LogExtMsg(WARNING_LOG,"%s\n",DataString);} else { LogExtMsg(WARNING_LOG,"NO DATA\n");}
							LogExtMsg(WARNING_LOG,"szTempString: ");
							if(szTempString) { LogExtMsg(WARNING_LOG,"%s\n",szTempString);} else { LogExtMsg(WARNING_LOG,"NO DATA\n");}
						}
						USBMsgFlag=0;
						while (USB_ENABLED && USBMsgHead) {
							DWORD usbwait = 0;
							// first run through fastcheck to establish the MatchList
							LogExtMsg(INFORMATION_LOG,"Looping through available USB messages");
							MatchCount=0;
							MatchPointer=MatchList; // Start of the list
							ResetCurrentNode();
							EventTriggered = LOG_TYPE_SYSTEM;
							etype = TYPE_INFO;
							stype = LOG_SYS;
							EventID = USBMsgHead->ShortEventID;
							if (EventID != USB_ARRIVAL && EventID != USB_REMOVAL) {
								//This is a pretty serious error, we can't free USBMsgHead since we don't know where it is pointing
								// just set it to null and keep going.
								LogExtMsg(INFORMATION_LOG,"MAJOR ERROR in USB auditing, invalid event pointer found");
								USBMsgHead=NULL;
								USBMsgTail=NULL;
								break;
							}
							if(!MatchPointer) {
								// Something seriously wierd is happening if MatchPointer is null.
								LogExtMsg(INFORMATION_LOG,"USB Match Pointer has gone away");
								goto endmsg;
							}
							do {
								LogExtMsg(INFORMATION_LOG,"USB fast checking");
								try {
									*MatchPointer=FastCheckObjective(EventID,etype,stype);
								} catch(...) {
									LogExtMsg(INFORMATION_LOG,"FastCheckObjective: Error encountered!");
									LogExtMsg(INFORMATION_LOG,"MatchPointer is %ld, EventID is %d, etype is %d, stype is %d",*MatchPointer,EventID,etype,stype);
									*MatchPointer=NULL;
								}
								
								if(*MatchPointer) {
									MatchFound=1;
									MatchCount++;
									MatchPointer++;
								} else {
									MatchFound=0;
								}
							} while(MatchFound && (MatchCount < dwObjectiveCount) && g_Info.bTerminate==0); // Guard against overflows

							usbwait = WaitForSingleObject(hUSBMutex,500);
							//this should never time out there is nothing else that could be holding it for that long
							//so we might have to go ahead and use it even on a timeout.
							if(usbwait == WAIT_OBJECT_0) {
								USBCache *usbtemp = USBMsgHead;
								if (MatchCount) {
									LogExtMsg(INFORMATION_LOG,"USB event found, processing");
									strncpy_s(SubmitTime,_countof(SubmitTime),USBMsgHead->SubmitTime, _TRUNCATE);
									_snprintf_s(SourceName, _countof(SourceName),_TRUNCATE,"Removable Storage Service");
									_snprintf_s(EventLogType,_countof(EventLogType),_TRUNCATE,"Information");
									strncpy_s(DataString,_countof(DataString),"",_TRUNCATE);
									strncpy_s(szTempString,_countof(szTempString),USBMsgHead->szTempString, _TRUNCATE);
									strncpy_s(szCategoryString,_countof(szCategoryString),"N/A",_TRUNCATE);
									strncpy_s(UserName,_countof(UserName),"Unknown User",_TRUNCATE);
									strncpy_s(SIDType,_countof(SIDType),"N/A",_TRUNCATE);
									//strncpy_s(Hostname,_countof(Hostname),USBMsgHead->Hostname, _TRUNCATE);
									LogExtMsg(INFORMATION_LOG,"USB event processed, deleting");
									USBMsgFlag = 1;
								}
								LogExtMsg(INFORMATION_LOG,"USB next");
								USBMsgHead = usbtemp->next;
								LogExtMsg(INFORMATION_LOG,"USB zeroing");
								memset(usbtemp,0,sizeof(USBCache));
								LogExtMsg(INFORMATION_LOG,"USB freeing");
								free(usbtemp);
								if (!USBMsgHead) {
									USBMsgTail=NULL;
								}
								LogExtMsg(INFORMATION_LOG,"USB releasing");
							} else if(usbwait == WAIT_ABANDONED) {
								LogExtMsg(WARNING_LOG,"Found abandoned mutex, releasing");
								ReleaseMutex(hUSBMutex);
							} else {
								USBMsgFlag = 0;
								break;
							}
							if (!ReleaseMutex(hUSBMutex)) {
								LogExtMsg(WARNING_LOG,"Failed to release mutex: [%d]",GetLastError());
							}
							if (USBMsgFlag) break;
						}
					} while (USB_ENABLED && USBMsgFlag);
					EventTriggered = PreUSBEventTriggered;
				}

				//firstly, check to see if the web server needs resetting:
				if (WebResetFlag) {
					LogExtMsg(INFORMATION_LOG,"HandleWebThread: resetting the web thread"); 
									//While we are here, may as well record the value
					MyWriteProfileDWORD("Status",EventLogStatusName[EventTriggered],dwEvLogCounter);
					DWORD WebResetFlagTmp = WebResetFlag;
					WebResetFlag = 0;//change the value before starting the web server
					if (WebResetFlagTmp == FULL_WEB_RESET) {
						if(retThread > 0 ){
							retThread = 0;
							CloseSafedE();
						}	
						DestroyList();
						if(WEBSERVER_ACTIVE) {
							CloseWebServer();
						}

						// cancel blocking calls, if any
						WSACancelBlockingCall();

						// Close all active sockets.
						HostNode * temphostnode;

						hostcurrentnode=getHostHead();
						while(hostcurrentnode) {
							if(hostcurrentnode->Socket != INVALID_SOCKET) {
								CloseSocket(hostcurrentnode->Socket, hostcurrentnode->tlssession);
								hostcurrentnode->Socket=INVALID_SOCKET;
							}
							temphostnode=hostcurrentnode->next;

							// Free the RAM associated with this node. We don't need it any more.
							free(hostcurrentnode);
							hostcurrentnode=temphostnode;
							// Just in case
							setHostHead(hostcurrentnode);
						}
						setHostHead(NULL);
						//stop sda process before reinitializing isVBA
						TerminateSAProcess(&piProcessInfo);
						if(MatchList) {
							free(MatchList);
							MatchList=NULL;
						}
						// READ in our data
						if(!InitFromRegistry(&dwTimesADay, &dwNextTimeDiscovery, &dwForceNextTime, &dwSysAdminEnable, &ActivateChecksum, &dwCritAudit, &ClearTabs, &szSendString, &szSendString))goto nomemory;;
						if(!InitEvents(&m_hEventList, &hEventLog, m_hRestartEventList))goto nomemory;;
						// Open our outgoing sockets.
						OpenSockets();

						// Ok, we have finished our general configuration reads.
						if(WEBSERVER_ACTIVE) {
							LogExtMsg(INFORMATION_LOG,"Starting web thread."); 
							if(InitWebServer((unsigned short)dwPortNumber,lpszPassword,lpszIPAddress) >0) {
								StartWebThread(m_hEventList[dwNumEventLogs + dwNumCustomEventLogs]);
							} else {
								//sleep and try again
								Sleep(2000);
								if(InitWebServer((unsigned short)dwPortNumber,lpszPassword,lpszIPAddress) >0) {
									StartWebThread(m_hEventList[dwNumEventLogs + dwNumCustomEventLogs]);
								} else {
									LogExtMsg(ERROR_LOG,"Unable to start web server [2], disabling."); 
									WEBSERVER_ACTIVE = 0;
								}
							}
						}
						if(dwSysAdminEnable){
							SAOBJ = LoadSAObjective(dwForceNextTime,dwTimesADay, dwNextTimeDiscovery, &piProcessInfo, &SADStrt);
							dwForceNextTime = 0;
						}
						
						// Load the objective data here.
						dwObjectiveCount=ReadObjectives();
						if(dwObjectiveCount) {
							// Malloc a array for our FastCheckObjective process
							MatchList = (Node **)malloc(dwObjectiveCount * sizeof(Node *));
							if(!MatchList) {
								LogExtMsg(ERROR_LOG,"Cannot allocate memory for our internal Objective match list");
								dwObjectiveCount=0;
							}
						}
						ResetCurrentNode();
						break;
					} else if (WebResetFlagTmp == BASIC_WEB_RESET) {
						if(WEBSERVER_ACTIVE) {
							LogExtMsg(INFORMATION_LOG,"Restarting web thread."); 
							CloseWebServer();
							if(InitWebServer((unsigned short)dwPortNumber,lpszPassword,lpszIPAddress) >0) {
								StartWebThread(m_hEventList[dwNumEventLogs + dwNumCustomEventLogs]);
							} else {
								//sleep and try again
								Sleep(2000);
								if(InitWebServer((unsigned short)dwPortNumber,lpszPassword,lpszIPAddress) >0) {
									StartWebThread(m_hEventList[dwNumEventLogs + dwNumCustomEventLogs]);
								} else {
									LogExtMsg(ERROR_LOG,"Unable to start web server [2], disabling."); 
									WEBSERVER_ACTIVE = 0;
								}
							}
						}
						hostcurrentnode=getHostHead();
						while(hostcurrentnode) {
							//if(hostcurrentnode->Socket != INVALID_SOCKET) {
							if(hostcurrentnode->Socket != INVALID_SOCKET) {
								CloseSocket(hostcurrentnode->Socket, hostcurrentnode->tlssession);
								hostcurrentnode->Socket=INVALID_SOCKET;
							}
							hostcurrentnode=hostcurrentnode->next;
						}
					}
					break;
				}
				
			} // End for loop
			endmsg: dwEventIDRead[EventTriggered]=dwNewestEventLogRecord;
		}
    }
	nomemory:;
	LogExtMsg(INFORMATION_LOG,"NetEye Safed Closing"); 

	TerminateSAProcess(&piProcessInfo);

	// Save off our current position in each of our log files.
	for (DWORD i=0;i<dwNumEventLogs + dwNumCustomEventLogs;i++) {
		MyWriteProfileDWORD("Status",EventLogStatusName[i],dwEventIDRead[i]);
	}
	if (szSendString) free(szSendString);
	if (szSendStringBkp) free(szSendStringBkp);

	if(MatchList) {
		free(MatchList);
	}

	if(retThread > 0 ){
		CloseSafedE();
		dwWaitRes=WaitForSingleObject(m_hEventList[dwNumEventLogs + dwNumCustomEventLogs + 1],5000);
		if(dwWaitRes != WAIT_FAILED)
		{
			if(dwWaitRes == WAIT_OBJECT_0) {
					ResetEvent(m_hEventList[dwNumEventLogs + dwNumCustomEventLogs+ 1]);
			}
		}
	}
	CloseWebServer();
	
	deinitSAD();	

	// Save off our current position in each of our log files.
	for (DWORD i=0;i<dwNumEventLogs +  dwNumCustomEventLogs;i++) {
		MyWriteProfileDWORD("Status",EventLogStatusName[i],dwEventIDRead[i]);
	}

	if(sentIndex && strlen(sentFile)){
		SetSentIndex(sentFile,sentIndex);
	}
	HostNode * temphostnode;
	// Free our host linked list.
	hostcurrentnode=getHostHead();
	while(hostcurrentnode) {
		if(hostcurrentnode->Socket != INVALID_SOCKET) {
			TerminateWinsock(hostcurrentnode->Socket, hostcurrentnode->tlssession);
		}
		temphostnode=hostcurrentnode;
		hostcurrentnode=hostcurrentnode->next;
		free(temphostnode);
	}
	setHostHead(NULL);

	cleanEventLogStructures(&m_hEventList, &hEventLog);
	if( m_hRestartEventList[0] ) ::CloseHandle(m_hRestartEventList[0]);
	if( m_hRestartEventList[1] ) ::CloseHandle(m_hRestartEventList[1]);
	if( web_hEventList[0] ) ::CloseHandle(web_hEventList[0]);
	if( web_hEventList[1] ) ::CloseHandle(web_hEventList[1]);
	if( web_hEventList[2] ) ::CloseHandle(web_hEventList[2]);



	// Free memory used by the objectives lists
	DestroyList();
	
	if(hMutex)CloseHandle(hMutex);
	if(hUSBMutex)CloseHandle(hUSBMutex);
	if(hMutexFile)CloseHandle(hMutexFile);
	if(hMutexCount)CloseHandle(hMutexCount);

	deinitSocketMutex();
	deinitLog();
	if(failure_exit)exit(1);
}


BOOL changeCacheFileName(struct tm newtime){
	return changeFileName( newtime, &savedtime, hMutexFile,dwNumberFiles, TRUE);
}
BOOL resetSafedCounter(struct tm *newtime){
	BOOL ret = TRUE;
	time_t currenttime;
	DWORD dwWaitCount = WaitForSingleObject(hMutexCount,500);
	time(&currenttime);
	localtime_s(newtime,&currenttime);
	if(dwWaitCount == WAIT_OBJECT_0) {
		if(newtime->tm_year != cnttime.tm_year ||
			newtime->tm_mon != cnttime.tm_mon ||
			newtime->tm_mday != cnttime.tm_mday) {
			
			SafedCounter = 1;
			cnttime.tm_year=newtime->tm_year;
			cnttime.tm_mon=newtime->tm_mon;
			cnttime.tm_mday=newtime->tm_mday;
		}
	}else ret = FALSE;
	ReleaseMutex(hMutexCount);	
	return ret;
}





void GetFQDN(char *string, const int length)
{
	struct hostent *phostent;
	
	if(!string) return;

	// Now, grab fully qualified hostname here.
	// Get the normal name.
	if(gethostname(string, length)) {		
		strncpy_s(string,length,"localhost.unknown",_TRUNCATE);
		return;
	}
	
	// Now perform a lookup on that name.
	phostent=gethostbyname(string);

	if(phostent) {
		while(phostent->h_aliases && *phostent->h_aliases) {
			if(strlen(*(phostent->h_aliases)) > strlen(string) && !strncmp(string,*(phostent->h_aliases),strlen(string))) {
				strncpy_s(string,length,*(phostent->h_aliases),_TRUNCATE);
			}
			phostent->h_aliases++;
		}
		if(strlen(phostent->h_name) > strlen(string) && !strncmp(string,phostent->h_name,strlen(string))) {
			strncpy_s(string,length,phostent->h_name,_TRUNCATE);
		}
	}
}

BOOL GetEventUserName(EVENTLOGRECORD *pELR, char * lpszUser, int length, SID_NAME_USE *snu)
{
    PSID lpSid;
    char szName[257]="";
    char szDomain[257]="";
    DWORD dwRC=0;
    DWORD cbName = 256;
    DWORD cbDomain = 256;

	if(!lpszUser || length<=0 || !pELR) {
		LogExtMsg(DEBUG_LOG,"GetEventUserName: Input Variables incorrect. Length, lpszUser or pELR are null "); 
		return(FALSE);
	}
	strncpy_s(lpszUser,length,"",_TRUNCATE);

	if(!pELR->UserSidOffset) {
		LogExtMsg(DEBUG_LOG,"GetEventUserName: UserSidOffset is Null");
		return(FALSE);
	}

	LogExtMsg(DEBUG_LOG,"GetEventUserName: pUserSID length is %d",pELR->UserSidLength);

	if(pELR->UserSidLength <= 0) {
		LogExtMsg(DEBUG_LOG,"GetEventUserName: UserSidLength is Null");
		return(FALSE);
	} else if(pELR->UserSidLength > 8192) {
		// Sanity check. An 8k sid? You've got to be kidding me.
		LogExtMsg(DEBUG_LOG,"GetEventUserName: UserSidLength is > 8k. This event looks corrupt to me.");
		return(FALSE);
	}

    // Point to the SID.
    lpSid = (PSID)((LPBYTE) pELR + pELR->UserSidOffset);

	try {
		if(IsValidSid(lpSid)) {
			dwRC=LookupAccountSid(NULL, lpSid, szName, &cbName, szDomain, &cbDomain, snu);
			if(szName) {
				strncpy_s(lpszUser,length,szName,_TRUNCATE);
			}
		} else {
			LogExtMsg(DEBUG_LOG,"GetEventUserName: IsValidSid returned FALSE! Not much I can do with an invalid SID.\n");
		}
	} catch (...) {
		LogExtMsg(DEBUG_LOG,"LookupAccountSid Failed in GetEventUserName");
		GetTextualSid(lpSid,lpszUser,(LPDWORD)&length);
		
		LogExtMsg(DEBUG_LOG,"GetEventUserName: Dumping details of the event....");
		LogExtMsg(DEBUG_LOG,"    UserSidLength is %d, offset is %d",pELR->UserSidLength,pELR->UserSidOffset);
		LogExtMsg(DEBUG_LOG,"    DataLength is %d, DataOffset is %d",pELR->DataLength,pELR->DataOffset);
		LogExtMsg(DEBUG_LOG,"    Length is %d, string count is %d",pELR->Length,pELR->NumStrings);
		LogExtMsg(DEBUG_LOG,"    StringOffset is %d",pELR->StringOffset);
		LogExtMsg(DEBUG_LOG,"    SID: %s",lpszUser);
	
		dwRC=0;
	}
    if (dwRC) {
		strncpy_s(lpszUser,length,szName,_TRUNCATE);
	} else {
		return(FALSE);
	}

			




	return TRUE;
}

BOOL GetCategoryString(PEVENTLOGRECORD pELR, char *Trigger, char *SourceName, char *StringBuffer, DWORD length)
{
	TCHAR szKeyName[MAX_STRING]="";
	HKEY   hk = (HKEY)0;
	long Category;
	int CatMsgFile=0;

	DWORD dwMaxPath = _MAX_PATH + 1;
	DWORD dwType; // Temporary variable.
	TCHAR szExeFile[_MAX_PATH + 1]="", szExeFilePath[_MAX_PATH+1]="";
	HMODULE hModule = 0;
	TCHAR TStringBuffer[_MAX_PATH + 1];

	if(!Trigger || !StringBuffer || !pELR || !length) return(0);

	strncpy_s(StringBuffer,length,"None",_TRUNCATE);
	StringBuffer[length-1]='\0';
	
	Category=pELR->EventCategory;

	if(!Category) {
		LogExtMsg(DEBUG_LOG,"The current event has no category string.");
		return(FALSE);
	}

	//Check if there is an source specific category message first
	_snprintf_s(szKeyName, _countof(szKeyName),_TRUNCATE,_T("SYSTEM\\CurrentControlSet\\Services\\EventLog\\%s\\%s"), Trigger, SourceName);
	if(RegOpenKeyEx(HKEY_LOCAL_MACHINE, szKeyName, 0L, KEY_QUERY_VALUE, &hk) == NOERROR) {
		if(RegQueryValueEx(hk, _T("CategoryMessageFile"), 0, &dwType, (LPBYTE)szExeFile, &dwMaxPath) == NOERROR) {
			CatMsgFile=1;
		} else {
			RegCloseKey(hk);
			LogExtMsg(DEBUG_LOG,"Could not query Source categorymessagefile, returning just the ID");
			_snprintf_s(StringBuffer,length,_TRUNCATE,"%d",Category);
			return(TRUE);
		}
	} else {
		LogExtMsg(DEBUG_LOG,"Could not open specific Event Source Registry Key, attempting to open generic categorymessagefile");
	}

	if (!CatMsgFile) {
		_snprintf_s(szKeyName, _countof(szKeyName),_TRUNCATE,_T("SYSTEM\\CurrentControlSet\\Services\\EventLog\\%s\\%s"), Trigger, Trigger);
		if(RegOpenKeyEx(HKEY_LOCAL_MACHINE, szKeyName, 0L, KEY_QUERY_VALUE, &hk) != NOERROR) {
			LogExtMsg(DEBUG_LOG,"Could not open eventlog category string registry information");
			return(FALSE);
		}
		if(RegQueryValueEx(hk, _T("CategoryMessageFile"), 0, &dwType, (LPBYTE)szExeFile, &dwMaxPath) != NOERROR) {
			RegCloseKey(hk);
			LogExtMsg(DEBUG_LOG,"Could not query categorymessagefile.");
			return(FALSE);
		}
	}

	if(ExpandEnvironmentStrings(szExeFile, szExeFilePath, _MAX_PATH + 1) == 0)
	{
		strncpy_s(szExeFilePath,_countof(szExeFilePath),szExeFile,_TRUNCATE);
		szExeFilePath[_MAX_PATH]='\0';

	}

	
	// Jump through our DLL references, and try to expand our strings.
	char * DLLStart;
	char * DLLEnd;
	char * StringEnd;

	DLLStart=szExeFilePath;
	StringEnd=DLLStart+strlen(szExeFilePath);

	DLLEnd=strstr(szExeFilePath,";");
	if(!DLLEnd) {
		DLLEnd=StringEnd;
	}

	do {
		*DLLEnd='\0';
	
		hModule = LoadLibraryEx(DLLStart, 0, DONT_RESOLVE_DLL_REFERENCES);
		
		DLLEnd++;
		DLLStart=DLLEnd;

		if(!hModule) {
			LogExtMsg(DEBUG_LOG,"LoadLibraryEx failed for %s",DLLStart);
			continue;
		}


		BOOL HasContent=0;

		try {
			if(!FormatMessage(
				FORMAT_MESSAGE_FROM_HMODULE | 
				FORMAT_MESSAGE_FROM_SYSTEM |
				FORMAT_MESSAGE_IGNORE_INSERTS,
				hModule, Category,
				MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // Default language
				(LPTSTR)TStringBuffer, _countof(TStringBuffer),
				NULL))
			{
				LogExtMsg(DEBUG_LOG,"Could not format message");
				//FreeLibrary(hModule);
				continue;
			} else {
				if(TStringBuffer != NULL) {
					// Ok, we have resolved a string. Add it to our buffer.
					if(HasContent) {
						_snprintf_s(StringBuffer,length,_TRUNCATE,"%s %s",StringBuffer,TStringBuffer);
					} else {
						HasContent=1;
						strncpy_s(StringBuffer,length,TStringBuffer,_TRUNCATE);
					}
				}
			}
		} catch(...) {
			//FreeLibrary(hModule);
			LogExtMsg(DEBUG_LOG,"CRASH: Could not format message in GetCategoryString");
			continue;
		}

		//FreeLibrary(hModule);
	} while(DLLEnd < StringEnd);



	// Kill off those annoying CR/LF chars on the end of this string.
	char *pSB;
	pSB=StringBuffer;
	while(*pSB) {
		if(*pSB==13 || *pSB == 10) {
			*pSB='\0'; //DMM updated 090329
			break;
		}
		pSB++;
	}

	RegCloseKey(hk);

	return(TRUE);
}


// Match a DOS wildcard against a string.
// eg: wildmatch("c:\blah\abc???.*","c:\blah\abc123.txt");
int wildmatch(char *pattern, char *source)
{
	if(!pattern || !source) {
		return(0);
	}
    if(*pattern == 0)
        return (*source == 0);

    // special case
    if(strspn(pattern, "*") == strlen(pattern))
        return 1;

    if(*source == 0)
        return 0;

    switch(*pattern){
    case '*':
        return wildmatch(pattern, source+1) || wildmatch(pattern+1, source) || wildmatch(pattern+1, source+1);
    case '?':
        return wildmatch(pattern+1, source+1);
    default:
        return (*pattern == *source) && wildmatch(pattern+1, source+1);
    }
}

// Match a DOS wildcard against a string.
// eg: wildmatch("C:\blah\abc???.*","c:\blah\abc123.txt");
int wildmatchi(char *pattern, char *source)
{
	if(!pattern || !source) {
		return(0);
	}
    if(*pattern == 0)
        return (*source == 0);

    // special case
    if(strspn(pattern, "*") == strlen(pattern))
        return 1;

    if(*source == 0)
        return 0;

    switch(*pattern){
    case '*':
        return wildmatchi(pattern, source+1) || wildmatchi(pattern+1, source) || wildmatchi(pattern+1, source+1);
    case '?':
        return wildmatchi(pattern+1, source+1);
    default:
		char lpattern,lsource;
		lpattern = tolower(*pattern);
		lsource = tolower(*source);
		
        return (lpattern == lsource) && wildmatchi(pattern+1, source+1);
    }
}




// Find the nth entry in the tab-delimited string 'search'.
// NOTE: may need to take into account the user delimiter
void splitstrings(char *store, int field, char *search, int size)
{
	int count;
	char *start=search;
	char *end=search;

	if(!store || !search) return;

	strncpy_s(store,1,"",_TRUNCATE);

	for(count=1;count<=field;count++) {
		end=strstr(start,"	");
		if(!end) {
			if(count < field) {
				return;
			} else {
				strncpy_s(store,size,start,_TRUNCATE);
				store[size]='\0';
				return;
			}
		} else {
			int nsize;

			if((end-start) >= size) {
				nsize=size-1;
			} else {
				nsize=(int)(end-start);
			}

			if(count == field) {
				strncpy_s(store,nsize+1,start,_TRUNCATE);
				store[nsize]='\0';
				return;
			}

			start=end+1;
			end=start;
		}
	}
}




BOOL GetDataString(PEVENTLOGRECORD pELR, char *DataString, DWORD length)
{
	register UINT x;
	LPBYTE			pData = 0;

	if(!DataString) {
		return(0);
	}

	DataString[0]='\0';
	if(pELR->DataLength <= 0)
		return(FALSE);

	// pData = (LPBYTE)GlobalAlloc(GPTR, pELR->DataLength * sizeof(BYTE));
	pData = (LPBYTE)malloc(pELR->DataLength * sizeof(BYTE));
	if(pData == NULL) {
		LogExtMsg(DEBUG_LOG,"Could not allocate memory in GetDataString");
		LogExtMsg(ERROR_LOG,"Could not allocate memory in GetDataString");
		return(FALSE);
	}

	memcpy(pData, (LPBYTE)((LPBYTE)pELR + pELR->DataOffset), pELR->DataLength);

	for(x = 0; x < pELR->DataLength; x += 8)
	{
		TCHAR DataStringAux[MAX_STRING];
		register UINT y;

		_snprintf_s(DataStringAux,_countof(DataStringAux),_TRUNCATE,"%.4x: ", x);
		if((strlen(DataString) + strlen(DataStringAux)) < length) {
			_tcscat_s(DataString,length, DataStringAux);
		} 
									
		for(y = x; y < x + 8; y++)
		{
			_snprintf_s(DataStringAux, _countof(DataStringAux),_TRUNCATE, "%.2x ", pData[y]);
			if((strlen(DataString) + strlen(DataStringAux)) < length) {
				_tcscat_s(DataString,length, DataStringAux);
			}
		}
		if((strlen(DataString) + 2) < length) {
			_tcscat_s(DataString,length, _T("  "));
		}
									
		for(y = x; y < x + 8; y++)
		{
			if(!isprint((int)pData[y]))
				if((strlen(DataString) + 1) < length) {
					_tcscat_s(DataString,length, _T("."));
				}
			else
			{
				TCHAR s[2];
				s[0] = (TCHAR)pData[y];
				s[1] = '\0';
				if((strlen(DataString) + 1) < length) {
					_tcscat_s(DataString,length, s);
				}
			}
		}
		if((strlen(DataString) + 2) < length) {
			_tcscat_s(DataString,length, _T("\r\n"));
		}
	}
						
	if(pData) {
		//GlobalFree(pData);
		free(pData);
	}

	return(TRUE);
}

BOOL ExpandStrings(PEVENTLOGRECORD pELR, char *Trigger, char *StringBuffer, DWORD length)
{
	TCHAR szKeyName[MAX_STRING]="";
	LPVOID lpszBuffer = 0;
	LPBYTE pSourceName=0;
	HKEY   hk = (HKEY)0;
	LPBYTE pStrings = 0;

	DWORD dwMaxPath = _MAX_PATH + 1;
	DWORD dwType; // Temporary variable.
	TCHAR szExeFile[_MAX_PATH + 1]="", szExeFilePath[_MAX_PATH+1]="";
	HMODULE hModule = 0;
	LPTSTR *Args = NULL;
	LPTSTR *SArgs = NULL; // Save off any RAM that has been allocated.
	BOOL returncode=FALSE;
	
	DWORD ShortEventID=pELR->EventID;

	LogExtMsg(DEBUG_LOG,"Inside ExpandStrings");
	
	if(!pELR || !StringBuffer) { return(FALSE); }
	
	StringBuffer[0]='\0';
	if(!pELR->DataOffset || !pELR->StringOffset) {
		LogExtMsg(DEBUG_LOG,"ExpandStrings: Event looks to have been corrupted.");
		return(FALSE);
	}

	if(!Trigger) {
		DWORD size=0;

		// No trigger? Send back the input value.
		size=pELR->DataOffset - pELR->StringOffset;
		// Something strange with this audit event. Try and just send back the raw string
		// if it is available.
		if(size) {
			if(size > (length-1)) {
					size=length-1;
			}
			memcpy(StringBuffer, (LPBYTE)pELR + pELR->StringOffset, size);
			StringBuffer[size+1]='\0';
			return(TRUE);
		} else {
			_snprintf_s(StringBuffer,length,_TRUNCATE,"N/A");
		}
	}

	pSourceName = (LPBYTE) pELR + sizeof(EVENTLOGRECORD);
	if(pELR->DataOffset != pELR->StringOffset) {
		pStrings = (LPBYTE)malloc(pELR->DataOffset - pELR->StringOffset);

		// Malloc failed. Dump this event, try the next.
		if(pStrings == NULL) 
		{
			LogExtMsg(DEBUG_LOG,"Could not malloc in ExpandStrings");
			return(FALSE);
		}

		// Grab the strings (located between stringoffset and dataoffset.
		memcpy(pStrings, (LPBYTE)pELR + pELR->StringOffset, pELR->DataOffset - pELR->StringOffset);
	}
	
	// NOTE that pStrings is null-terminated.

	_snprintf_s(szKeyName, _countof(szKeyName),_TRUNCATE, _T("SYSTEM\\CurrentControlSet\\Services\\EventLog\\%s\\%s"), Trigger, pSourceName);
	//LogExtMsg(WARNING_LOG,"KEY: %s",szKeyName);

	if(RegOpenKeyEx(HKEY_LOCAL_MACHINE, szKeyName, 0L, KEY_QUERY_VALUE, &hk) != NOERROR) {
		DWORD slen=pELR->DataOffset - pELR->StringOffset;
		if(slen >= (length)) {
			slen=length-1;
		}
		if(pStrings) {
			strncpy_s(StringBuffer,slen+1,(char *)pStrings,_TRUNCATE);
			StringBuffer[slen+1]='\0';

			free(pStrings);
		} else {
			_snprintf_s(StringBuffer,length,_TRUNCATE,"N/A");
		}
		LogExtMsg(DEBUG_LOG,"Could not open registry data in expandstrings");
		return(FALSE);
	}

	if(RegQueryValueEx(hk, _T("EventMessageFile"), 0, &dwType, (LPBYTE)szExeFile, &dwMaxPath) != NOERROR)
	{
		DWORD slen=pELR->DataOffset - pELR->StringOffset;
		if(slen >= (length)) {
			slen=length-1;
		}

		if(pStrings) {
			strncpy_s(StringBuffer,slen+1,(char *)pStrings,_TRUNCATE);
			StringBuffer[slen+1]='\0';

			free(pStrings);
		} else {
			_snprintf_s(StringBuffer,length,_TRUNCATE,"N/A");
		}
		
		RegCloseKey(hk);
		LogExtMsg(DEBUG_LOG,"Could not queryvalue in expandstrings");
		return(FALSE);
	}


	// Establish a loop for those eventlog entries that use more than one
	// DLL to retrieve audit data from. Loop through each until we find a
	// valid bit of info.

	TCHAR szExeFile2[_MAX_PATH + 1];
	char * pszExeFile2;
	char * semipos;
	int shortened=0;
	
	DWORD ArgCount;
	DWORD NewStringsCount=0;
	DWORD AllocCount=0;
	char * tempArg=NULL;
	
	strncpy_s(szExeFile2,_countof(szExeFile2),szExeFile,_TRUNCATE);
	pszExeFile2=szExeFile2;
	
	if(pELR->NumStrings) {
		// Allocate memory and split up string arguments
		// Note: We are only allocating RAM here for the pointer list. The actual string
		// RAM is allocated from within GetParameterMsg
		Args = (LPTSTR *)malloc((pELR->NumStrings) * sizeof(TCHAR *));
		if(Args == NULL)
		{
			//FreeLibrary(hModule);
			LogExtMsg(DEBUG_LOG,"Could not allocate memory for the appropriate number of strings.");
			return(FALSE);
		}
		
		SArgs = (LPTSTR *)malloc((pELR->NumStrings) * sizeof(TCHAR *));
		if(SArgs == NULL)
		{
			free(Args);
			//FreeLibrary(hModule);
			LogExtMsg(DEBUG_LOG,"Could not allocate memory for the appropriate number of strings.");
			return(FALSE);
		}
	}

	LogExtMsg(DEBUG_LOG,"ExpandStrings: Getting Args");
	// No need to free anything after this call. We are just constructing a pointer list to
	// data within pELR
	if(pELR->NumStrings) {
		GetArgs(pELR,(char **)Args);
						
		for(ArgCount=0; ArgCount<pELR->NumStrings; ArgCount++) {
			NewStringsCount++;
			tempArg=GetParameterMsg(Args[ArgCount],szKeyName);
			// Save off the location of the allocated RAM
			// So we can free it later.
			if(tempArg) {
				Args[ArgCount]=tempArg;
				SArgs[ArgCount]=tempArg;

				AllocCount++;
			} else {
				SArgs[ArgCount]=NULL;
			}
		}
	}

	// Loop through the available libary options until we actually get
	// something useful.  Try all available files first, then clip the eventID if we still don't have anything.
	do {
		if (!pszExeFile2 && !shortened) {
			// Use the shortened event ID to deal with buggy software that
			// does not fill out the whole DWORD.

			// Some buggy software does not write out a full dword eventid.
			//       However: By 'shortening' the eventid, it kills many legitimate
			//                event logs. *sigh*
			pszExeFile2=szExeFile2;
			ShortEventID=ShortEventID &0x0000FFF;
			shortened = 1;
		}
		semipos=strstr(pszExeFile2,";");
		if(semipos) {
			if(semipos-pszExeFile2 < _MAX_PATH) {
				strncpy_s(szExeFile,(semipos-pszExeFile2)+1,pszExeFile2,_TRUNCATE);
				szExeFile[semipos-pszExeFile2]='\0';
			} else {
				strncpy_s(szExeFile,_countof(szExeFile),pszExeFile2,_TRUNCATE);
			}
			pszExeFile2=semipos+1;
		} else {
			strncpy_s(szExeFile,_countof(szExeFile),pszExeFile2,_TRUNCATE);
			pszExeFile2=(char *)NULL;
		}
		
		// If someone has added a semi-colon without actually putting info after it, break out.
		if(!strlen(szExeFile)) {
			continue;
		}
				
		if(ExpandEnvironmentStrings(szExeFile, szExeFilePath, _MAX_PATH + 1) == 0)
		{
			strncpy_s(szExeFilePath,_countof(szExeFilePath),szExeFile,_TRUNCATE);
			szExeFilePath[_MAX_PATH]='\0';
		}
		// NOTE: Windows 2000 SP2 introduces a bug here, because it
		// adds another DLL after the normal msaudite.dll (after a semicolon)
		// Have changed this routine to cover this problem. We are now in a do..while loop.
		hModule=NULL;
		hModule = LoadLibraryEx(szExeFilePath, 0, DONT_RESOLVE_DLL_REFERENCES);
		if(!hModule) {
			LogExtMsg(DEBUG_LOG,"LoadLibraryEx failed in expandstrings");
			continue;
		}
		
		LogExtMsg(DEBUG_LOG,"ExpandStrings: Allocating Args");
		
		LogExtMsg(DEBUG_LOG,"ExpandStrings: Jumping through params");
		// Now, jump through the parametermessage stuff.
		// Basically: jump through each of the strings,
		// if it contains a %%, then send it through
		
		if(pELR->NumStrings) {			
			LogExtMsg(DEBUG_LOG,"ExpandStrings: NumStrings is NOT zero");
			if(Args) {
				LogExtMsg(DEBUG_LOG,"ExpandStrings: Args exist, now formatting for %d...", ShortEventID);
				// This FORMATMESSAGE call is causing a DrWATSON in some strange circumstances
				// principally on exchange boxes... (eg: eventid 287, and 1292)
				// Not sure why yet.
				// I'll encase this in a try/catch block.
				
				try {
					if(!FormatMessage(
						FORMAT_MESSAGE_ALLOCATE_BUFFER | 
						FORMAT_MESSAGE_FROM_HMODULE | 
						FORMAT_MESSAGE_FROM_SYSTEM | 
						FORMAT_MESSAGE_ARGUMENT_ARRAY,
						hModule, ShortEventID,
						MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // Default language
						(LPTSTR)&lpszBuffer, 0,
						(va_list *)Args))	{
							if (!shortened) LogExtMsg(DEBUG_LOG,"FormatMessage failed (with strings) - Event ID was %d",ShortEventID);
							else LogExtMsg(DEBUG_LOG,"FormatMessage failed (with strings) on second try - Event ID was %d",ShortEventID);
					}
				} catch(...) {
					LogExtMsg(DEBUG_LOG,"FormatMessage Died - handling catch");
					
					// No characters stored in buffer.
					
					//if(hModule) {	FreeLibrary(hModule);	}
					LogExtMsg(DEBUG_LOG,"FormatMessage failure cleanup complete");
					continue;
				}
			} else {
				// ARGS - null pointer.
				LogExtMsg(DEBUG_LOG,"Args has mysteriously disappeared");
				
				// No characters stored in buffer.
				
				//if(hModule) {	FreeLibrary(hModule);	}
				LogExtMsg(DEBUG_LOG,"Cleaning up after args dissappearance");
				continue;
			}
		} else {
			LogExtMsg(DEBUG_LOG,"ExpandStrings: NumStrings is zero");
			// No Strings! Try and format it anyway.
			DWORD size=0;
		
			// Note: There are some events (eg: the one generated by Safed!)
			// That do not seem to fit this (StringOffset = DataOffset) - where do we get strings
			// from????
			pSourceName = (LPBYTE) pELR + sizeof(EVENTLOGRECORD);

			LogExtMsg(DEBUG_LOG,"ExpandStrings: Now formatting for %d...", ShortEventID);
			try {
				if(!FormatMessage(
					FORMAT_MESSAGE_ALLOCATE_BUFFER | 
					FORMAT_MESSAGE_FROM_HMODULE | 
					FORMAT_MESSAGE_FROM_SYSTEM | 
					FORMAT_MESSAGE_IGNORE_INSERTS,
					hModule, ShortEventID,
					MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // Default language
					(LPTSTR)&lpszBuffer, 0,
					(va_list *)NULL))	{
						if (!shortened) LogExtMsg(DEBUG_LOG,"FormatMessage failed (with no strings) - Event ID was %d - trying shorter ID",ShortEventID);
						else LogExtMsg(DEBUG_LOG,"FormatMessage failed (with no strings) on second try - Event ID was %d",ShortEventID);

				}
			} catch(...) {
				LogExtMsg(DEBUG_LOG,"ExpandStrings: Format message failed...");
				//if(hModule) {	FreeLibrary(hModule);	}
				continue;
			}
		}
		LogExtMsg(DEBUG_LOG,"ExpandStrings: pELR OK");
			
		if(!lpszBuffer)
		{
			//if(hModule) { FreeLibrary(hModule); }
			LogExtMsg(DEBUG_LOG,"No lpszBuffer");
			continue;
		}
		
		strncpy_s(StringBuffer,length,(const char *)lpszBuffer,_TRUNCATE);
	
		LocalFree(lpszBuffer);
			
		//if(hModule) { FreeLibrary(hModule); }
	
		returncode=TRUE;
		// We have some data! Break out of our loop. No point in investigating the other
		// locations for data.
		break;

	} while(pszExeFile2 || !shortened);

	LogExtMsg(DEBUG_LOG,"ExpandStrings: About to free SArgs");

	if(AllocCount) {
		for(ArgCount=0;ArgCount<AllocCount;ArgCount++) {
			free(SArgs[ArgCount]);
		}
	}
	LogExtMsg(DEBUG_LOG,"ExpandStrings: About to free Args");

	if(Args) { free(Args); }
	if(SArgs) { free(SArgs); }

	if(hk) { RegCloseKey(hk); }

	if(pStrings) {
		// If we have been unable to push anything into the string buffer.
		if(!strlen(StringBuffer)) {
			LogExtMsg(DEBUG_LOG,"ExpandStrings: Nothing in StringBuffer");
			DWORD slen=pELR->DataOffset - pELR->StringOffset;
			if(slen >= (length)) {
				slen=length-1;
			}
			strncpy_s(StringBuffer,slen+1,(char *)pStrings,_TRUNCATE);
			StringBuffer[slen+1]='\0';
			LogExtMsg(DEBUG_LOG,"ExpandStrings: Returning with pStrings in stringbuffer");
			returncode=FALSE;
		}
		free(pStrings);
	} else if(!strlen(StringBuffer)) {
		LogExtMsg(DEBUG_LOG,"ExpandStrings: Setting StringBuffer to unknown");
		strncpy_s(StringBuffer,length,"Unknown",_TRUNCATE);
		returncode=FALSE;
	}
	return(returncode);
}


char * GetParameterMsg(char *message, char *szKeyName)
{
	int		I, StringId, FileNameModuleSize = MAX_STRING;
	char    *EndPtr;
	HKEY	nKeyHandle=0;
	BYTE	FileNameModule[MAX_STRING+1],expbuffer[MAX_STRING+1];
	HMODULE hModule = 0;

	char	lpBuffer[MAX_STRING+1], tmpStr[MAX_STRING+2], *StartPtr;
	static char *DescrStr;

	if(!message || !szKeyName) {
		return((char *)NULL);
	}

	if(!strstr(message,"%%")) {
		DescrStr = (char *)malloc(strlen(message) + 1);
		if(DescrStr) {
			strncpy_s(DescrStr,strlen(message) + 1, message,_TRUNCATE);
			return DescrStr;
		} else {
			return((char *)NULL);
		}
	}

	if(strlen(message) < 3) {
		return((char *)NULL);
	}

	if(!strlen(szKeyName)) {
		return((char *)NULL);
	}

	if(RegOpenKeyEx(HKEY_LOCAL_MACHINE, (LPTSTR) szKeyName, 0L, KEY_QUERY_VALUE, &nKeyHandle) != NOERROR) {
		LogExtMsg(DEBUG_LOG,"Could not open key in getparametermsg");
		return((char *)NULL);	
	}

	if (RegQueryValueEx(nKeyHandle,
				"ParameterMessageFile",
				NULL,
				NULL,
				FileNameModule,
				(unsigned long *)&FileNameModuleSize) != ERROR_SUCCESS) {
		LogExtMsg(DEBUG_LOG,"Could not regqueryvalueex in getparametermsg");
	    if(nKeyHandle) { RegCloseKey(nKeyHandle); }
		return((char *)NULL);
	}

	ExpandEnvironmentStrings(
				(const char *)FileNameModule,	// pointer to string with environment variables
				(char *)expbuffer,      		// pointer to string with expanded environment variables
				MAX_STRING);					// maximum characters in expanded string

	
	if(nKeyHandle) { RegCloseKey(nKeyHandle); }

	hModule=LoadLibraryEx((const char *)expbuffer,NULL,DONT_RESOLVE_DLL_REFERENCES);
	//DMMhModule=LoadLibraryEx((const char *)expbuffer,NULL,LOAD_LIBRARY_AS_DATAFILE|DONT_RESOLVE_DLL_REFERENCES);
	if(!hModule) {
		return((char *)NULL);
	}

	EndPtr = message;
	StartPtr = message;
	tmpStr[0] = '\0';
	while (*EndPtr) {
		StringId = 0;

		// HMMM... this could be an issue? REDRED - TODO / FIXME
		StringId = strtol(StartPtr + 2 ,&EndPtr,10);
		if (StringId == 0) {
			strncat_s(tmpStr, _countof(tmpStr)," ",_TRUNCATE);
			EndPtr++;
			StartPtr++;
			continue;
		}
		StartPtr = EndPtr;

		int csize=0;	// current size
		int ssize=0;	// target string size
		int copysize=0;	// amount to copy
		int overflow=0;	// did we overflow?

		try {
			I=FormatMessage(
				FORMAT_MESSAGE_FROM_HMODULE|
				FORMAT_MESSAGE_IGNORE_INSERTS,
				hModule,
				StringId,
				0,  // Default language
				(LPTSTR) &lpBuffer,
				MAX_STRING,
				(LPTSTR *) NULL
			);
		} catch(...) {
			LogExtMsg(DEBUG_LOG,"FormatMessage crash in GetParameterMsg");
			I=0;
		}

		if (I==0)
		{
			//FreeLibrary(hModule);
			// return (message);
			return((char *)NULL);
		}
		
		csize=(int)strlen(tmpStr);
		ssize=(int)strlen((char *)lpBuffer);
		if((csize + ssize) >= MAX_STRING) {
			// Overflow. Copy what we can.
			copysize=MAX_STRING - csize;
		} else {
			copysize=csize+ssize;
		}

		strncat_s(tmpStr, _countof(tmpStr),(char *)lpBuffer,_TRUNCATE);
	}

	//FreeLibrary(hModule);

	// NOTE: the calling routine REALLY needs to free this string once it's grabbed.
	// C sucks sometimes.
	DescrStr = (char *)malloc(strlen(tmpStr) + 1);
	if(DescrStr) {
		strncpy_s(DescrStr,strlen(tmpStr) + 1, tmpStr,_TRUNCATE);

		return DescrStr;
	}
	return((char *)NULL);
}




void GetArgs(const EVENTLOGRECORD *pELR, char **Args)
{
	DWORD ArgCount;
	char * cpointer;

	if(!pELR || !Args) return;
	if(pELR->NumStrings == 0) return;

	cpointer = (char *)pELR + (pELR->StringOffset);

	for(ArgCount=0; ArgCount<pELR->NumStrings; ArgCount++) {
		Args[ArgCount] = cpointer;
		cpointer += strlen(cpointer) + 1;
	}
}

BOOL GetEventLogType(TCHAR *sz, unsigned short uEventType, DWORD length)
{
	if(!sz || !length)
		return FALSE;

	switch(uEventType)
	{
		case EVENTLOG_SUCCESS:
			strncpy_s(sz, length, _T("Success"),_TRUNCATE);
			break;
		case EVENTLOG_ERROR_TYPE:
			strncpy_s(sz, length, _T("Error"),_TRUNCATE);
			break;
		case EVENTLOG_WARNING_TYPE:
			strncpy_s(sz, length, _T("Warning"),_TRUNCATE);
			break;
		case EVENTLOG_INFORMATION_TYPE:
			strncpy_s(sz, length, _T("Information"),_TRUNCATE);
			break;
		case EVENTLOG_AUDIT_SUCCESS:
			strncpy_s(sz, length, _T("Success Audit"),_TRUNCATE);
			break;
		case EVENTLOG_AUDIT_FAILURE:
			strncpy_s(sz, length, _T("Failure Audit"),_TRUNCATE);
			break;
		default:
			strncpy_s(sz, length, _T("Unknown"),_TRUNCATE);
			break;
	}

	return TRUE;
}

BOOL Check64(){
	BOOL f64 = FALSE;
#ifdef _M_X64
	f64 = TRUE;
#elif _M_IA64
	f64 = TRUE;
#else
	typedef BOOL (WINAPI *LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);
	LPFN_ISWOW64PROCESS fnIsWow64Process;

    fnIsWow64Process = (LPFN_ISWOW64PROCESS) GetProcAddress(GetModuleHandle(TEXT("kernel32")),"IsWow64Process");
  
    if (NULL != fnIsWow64Process) {
        if (!fnIsWow64Process(GetCurrentProcess(),&f64)) {
            // handle error
			f64 = FALSE;
        }
    }
#endif
	return f64;
}

BOOL CheckLogExists(TCHAR *LogName, int LeaveRetention)
{
	TCHAR szKeyName[MAX_STRING]="";
	LPBYTE pSourceName=0;
	HKEY   hk = (HKEY)0;
	LPBYTE pStrings = 0;

	DWORD dwMaxString;			
	DWORD dwType; // Temporary variable.
	TCHAR szKeyValue[MAX_STRING+1]="";
	TCHAR szFileName[MAX_STRING+1]="";

	if(!LogName) return(0);
	wsprintf(szKeyName, _T("SYSTEM\\CurrentControlSet\\Services\\EventLog\\%s"), LogName);

	if(RegOpenKeyEx(HKEY_LOCAL_MACHINE, szKeyName, 0L, KEY_READ|KEY_SET_VALUE, &hk) != ERROR_SUCCESS) {
		if(LogName) { LogExtMsg(WARNING_LOG,"Cannot determine if log %s exists - openkey failed",LogName); } 
		return(FALSE);
	}

	dwMaxString=MAX_STRING-1;
	if(RegQueryValueEx(hk, _T("File"), 0, &dwType, (LPBYTE)szKeyValue, &dwMaxString) != ERROR_SUCCESS)
	{
		if(LogName) { LogExtMsg(WARNING_LOG,"Cannot determine if log %s exists - queryvalueex failed",LogName); }
		RegCloseKey(hk);
		return(FALSE);
	}

	ExpandEnvironmentStrings(szKeyValue,szFileName,_countof(szFileName));
	if(!strlen(szFileName)) {
		if(LogName) { LogExtMsg(WARNING_LOG,"String just wont expand in checklogexists. Log %s probably doesnt exist",LogName); }
		RegCloseKey(hk);
		return(FALSE);
	}
	if(!Check64()){
		struct _stat buf;
		if(_stat(szFileName, &buf)) {
			RegCloseKey(hk);
			return(FALSE);
		}
	}

	
	// Verify that log retention settings are set to 'overwrite as needed'.
	// Also verify that log size settings are set to requested values.
	// Not sure if we need to restart the audit service if this succeeds..

	DWORD RetentionValue=0;
	DWORD RetentionSize=sizeof(RetentionValue);

	// Verify that the user is overwriting as required
	if(RegQueryValueEx(hk, _T("Retention"), 0, &dwType, (unsigned char *)&RetentionValue, &RetentionSize) != ERROR_SUCCESS)
	{
		if(LogName) {
			LogExtMsg(WARNING_LOG,"Cannot check log retention settings - queryvalueex failed for log %s",LogName);
		}
	}

	LogExtMsg(ERROR_LOG,"Log retention settings are set to %d for log %s",RetentionValue,LogName); 
	
	if(!LeaveRetention && RetentionValue != 0) {
		RetentionValue=0;
		if(RegSetValueEx(hk, _T("Retention"), 0, REG_DWORD, (unsigned char *)&RetentionValue, sizeof(DWORD)) != ERROR_SUCCESS)
		{
			if(LogName) { LogExtMsg(WARNING_LOG,"Cannot set log retention settings - regsetvalueex failed for log %s",LogName); }
		}
	}

	RegCloseKey(hk);
	return(TRUE);
}




BOOL GetSIDType(SID_NAME_USE _SidNameUse, TCHAR *szSIDType, DWORD length)
{
	if(!szSIDType || length <=1 || !_SidNameUse) {
		return FALSE;
	}

	szSIDType[0] = '\0';
	switch(_SidNameUse)
	{
		case SidTypeUser:
			strncpy_s(szSIDType,length,"User",_TRUNCATE);
			break;
		case SidTypeGroup:
			strncpy_s(szSIDType,length,"Group",_TRUNCATE);
			break;
		case SidTypeDomain:
			strncpy_s(szSIDType,length,"Domain",_TRUNCATE);
			break;
		case SidTypeAlias:
			strncpy_s(szSIDType,length,"Alias",_TRUNCATE);
			break;
		case SidTypeWellKnownGroup:
			strncpy_s(szSIDType,length,"Well Known Group",_TRUNCATE);
			break;
		case SidTypeDeletedAccount:
			strncpy_s(szSIDType,length,"Deleted Account",_TRUNCATE);
			break;
		case SidTypeInvalid:
			strncpy_s(szSIDType,length,"Invalid SID",_TRUNCATE);
			break;
		case SidTypeUnknown:
			strncpy_s(szSIDType,length,"Unknown",_TRUNCATE);
			break;
		case SidTypeComputer:
			strncpy_s(szSIDType,length,"Computer",_TRUNCATE);
			break;
		default:
			strncpy_s(szSIDType,length,"Out of Type",_TRUNCATE);
			break;
	}						

	return TRUE;
}





static Node * FastCheckObjective(int eventnumber, int etype, int stype)
{
	static Node *tnode;
	int ShortEventID=0;
	// No objectives?
	if(!head) {
			return(NULL);
	}
	
	do {
		if(!currentnode) {
			return(NULL);
		}
		tnode = currentnode;
		
		ShortEventID=eventnumber & 65535;

		//if(eventnumber == tnode->event_number || tnode->event_number == AUDIT_ALL) {
		if((ShortEventID >= tnode->event_bottom && ShortEventID <= tnode->event_top)|| tnode->event_bottom == AUDIT_ALL) {
			LogExtMsg(DEBUG_LOG,"FCO: Checking event %d against %d, and etype %d against %d, and stype %d against %d",eventnumber,tnode->event_top,etype,tnode->eventlogtype,stype,tnode->sourcename); 
			if((etype & tnode->eventlogtype) && (stype & tnode->sourcename)) {
				// Are we including users, or excluding.
				currentnode = currentnode->next;
				return(tnode);
			}
		}
		currentnode = currentnode->next;
	} while(currentnode);
	// Will probably never get here.
	ResetCurrentNode();

	return(NULL);
}

int CheckObjective(Node * Match, int eventnumber, char *username, char *match, char* matched)
{

	if(!username || !match) {
		LogExtMsg(DEBUG_LOG,"CheckObjective: No Username or Match Term supplied"); 
		return(-1);
	}

	if(!Match) {
		LogExtMsg(DEBUG_LOG,"CheckObjective: No Objective supplied"); 
		return(-1);
	}

	if(Match->regexpError){
		LogExtMsg(DEBUG_LOG,"CheckObjective: RegExp not correct:%s", Match->match);
		return(-1);
	}
	LogExtMsg(INFORMATION_LOG,"CheckObjective ([%s,%d,%d,%d,%s],%d,%s,%s)", Match->match, Match->excludematchflag,Match->excludeidflag, Match->excludeflag, Match->username, eventnumber, username, match);

	int usermatch=0;
	char * spoint;
	char tuser[256];
			
	// This could do with some optimisation.. FIXME
	// NOTE: Cannot split out into separate objectives, due to exclusion stuff.
	if(Match->muserflag) {
		if(strlen(Match->sysadmin) > 0)//sys administrator discovery
			spoint=Match->sysadmin;
		else
			spoint=Match->username;
		usermatch=0;
		do {
			spoint=string_split(',',spoint,tuser,_countof(tuser));
			usermatch=wildmatchi(tuser,username);
			if(usermatch) {
				break;
			}
		} while(spoint);
	} else {
		usermatch=wildmatchi(Match->username,username);
	}
	

	LogExtMsg(INFORMATION_LOG,"Match->excludeflag: %d, Match->excludeidflag: %d, Match->excludematchflag %d", Match->excludeflag, Match->excludeidflag, Match->excludematchflag); 
	regmatch_t pm[1];
	//if((Match->excludeflag || usermatch) && !(Match->excludeflag && usermatch)) {
	if(usermatch) {
		int res= regexec(&Match->regexpCompiled, match, (size_t) 1, pm, 0);
		//if((Match->excludematchflag || !res) && !(Match->excludematchflag && !res)){
		if(!res){
			if(!strcmp(Match->match,".*") || (pm[0].rm_eo - pm[0].rm_so >= 512))
				sprintf(matched,"UNKNOWN");
			else
				sprintf(matched,"%.*s", pm[0].rm_eo - pm[0].rm_so, &match[pm[0].rm_so]);

			return(Match->criticality);
		}
	} 
	LogExtMsg(INFORMATION_LOG,"Match failed"); 

	return(-1);
}

char * string_split(char divider,char *string,char *destination,int destlength)
{
	int destsize=0;

	if(!string || !destination) {
		return((char *)NULL);
	}

	while(*string && *string != divider) {
		if(destsize < destlength) {
			*destination=*string;
			destination++;
			destsize++;
		}

		string++;
	}
	*destination='\0';
	if(*string == divider) {
		string++;
	} else {
		return((char *)NULL);
	}
	return(string);
}





int ReadObjectivesFrom(int from, BOOL onlySYSADMIN, DWORD SetAudit){
	Reg_Objective reg_objective;
	DWORD dw_objective_error;
	int i_objective_count=from;
	char *eventpointer,*eventpointer2;
	char eventnumber[11];
	int eventid;
	int criticality;
	int etype=0;
	int stype=0;
	int userflag=0; // include by default
	int eventflag=0; // include by default
	int generalflag=0; // include by default
	int muserflag=0; // multiple users, comma separated?

	while((dw_objective_error = Read_Objective_Registry(i_objective_count,&reg_objective))==0) {
		// For each event number defined.
		int ecount=0,eventbottom=0,eventtop=0;
		int *eventidlist=NULL, *templist=NULL;
		eventpointer=reg_objective.str_unformatted_eventid_match;
		eventpointer2=reg_objective.str_unformatted_eventid_match;

		userflag=reg_objective.dw_user_match_type;
		eventflag=reg_objective.dw_event_match_type;
		generalflag=reg_objective.dw_general_match_type;

		if(!strcmp(reg_objective.str_critic,CRITICAL_TOKEN)) {
			criticality=EVENT_CRITICAL;
		} else if(!strcmp(reg_objective.str_critic,PRIORITY_TOKEN)) {
			criticality=EVENT_PRIORITY;
		} else if(!strcmp(reg_objective.str_critic,WARNING_TOKEN)) {
			criticality=EVENT_WARNING;
		} else if(!strcmp(reg_objective.str_critic,INFORMATION_TOKEN)) {
			criticality=EVENT_INFORMATION;
		} else if(!strcmp(reg_objective.str_critic,CLEAR_TOKEN)) {
			criticality=EVENT_CLEAR;
		}

		etype=reg_objective.dw_event_type;
		if(!etype) etype=TYPE_SUCCESS|TYPE_FAILURE|TYPE_INFO|TYPE_WARN|TYPE_ERROR;

		stype=reg_objective.dw_eventlog_type;
		if(!stype) stype=LOG_CUS|LOG_SEC|LOG_SYS|LOG_APP|LOG_DIR|LOG_DNS|LOG_REP;
		
		// Just in case the general match is empty.
		char tempmatch[SIZE_OF_GENERALMATCH];

		if(!strlen(reg_objective.str_general_match)) {
			// NOTE: general_match is > 1, so strcpy is safe here.
			//strncpy_s(tempmatch,_countof(tempmatch),"*",_TRUNCATE);
			strncpy_s(tempmatch,_countof(tempmatch),"",_TRUNCATE);
		} else {
			//_snprintf_s(tempmatch,_countof(tempmatch),_TRUNCATE,"*%s*",reg_objective.str_general_match);
			_snprintf_s(tempmatch,_countof(tempmatch),_TRUNCATE,"%s",reg_objective.str_general_match);
		}

		if(strstr(reg_objective.str_user_match,",")) {
			muserflag=1;
		} else {
			muserflag=0;
		}

		
		// While there are no more commas
		while(eventpointer2) {
			eventpointer2=strstr(eventpointer,",");
			if(eventpointer2 == (char *)NULL) {
				// No commas left. Just copy to the end of the line.
				strncpy_s(eventnumber,_countof(eventnumber),eventpointer,_TRUNCATE);
				eventnumber[10]='\0'; // just in case
			} else {
				int size=9;
				if(eventpointer2-eventpointer < 10) {
					size=(int)(eventpointer2-eventpointer);
				}
				strncpy_s(eventnumber,size+1,eventpointer,_TRUNCATE);
				// Make sure we have a null on the end of the line.
				eventnumber[size]='\0';
			}
			if(eventpointer2) {
				// Skip the comma
				eventpointer=eventpointer2+1;
			}
			
			if(!strcmp(eventnumber,"*")) {
				eventid=AUDIT_ALL;
			} else {
				eventid=atoi(eventnumber);
			}
			if((eventid >=0 && eventid <= 65535) || eventid==AUDIT_ALL) {
				// valid event ID. Continue.

				// HERE: Turn on the appropriate audit.
				// Does the user want us to change the audit settings?
				// Only do this for SECURITY log events
				if(SetAudit && (reg_objective.dw_eventlog_type & LOG_SEC)) {
					if((etype & TYPE_SUCCESS) || (etype & TYPE_FAILURE)) {
						TurnOnEvent(eventid,etype);
					} else {
						// The user didn't specify whether to audit success or failures.
						// TURN ON SUCCESS AUDITING AND FAILURE AUDITING
						TurnOnEvent(eventid,TYPE_SUCCESS|TYPE_FAILURE);
					}
				}
				if (eventid==AUDIT_ALL) {
					eventbottom=eventtop=AUDIT_ALL;
					break;
				}
				ecount++;
				templist = new int[ecount];
				//keep the list ordered
				if (ecount > 1) {
					int found =0;
					for (int i=ecount-1; i > 0;i--) {
						if (found) {
							templist[i] = eventidlist[i];
							continue;
						}
						if (eventid == eventidlist[i-1]) {
							//leave everything the same, delete templist and break out
							delete [] templist; templist=NULL;
							break;
						} else if (eventid > eventidlist[i-1]) {
							templist[i]=eventid;
							found=1;
						} else {
							templist[i]=eventidlist[i-1];
						}
					}
					if (found) {
						templist[0] = eventidlist[0];
					} else {
						templist[0]=eventid;
					}
					if (templist) {
						delete [] eventidlist;
						eventidlist=NULL;
					}
				} else {
					templist[0]=eventid;
				}
				eventidlist = templist;
			}
		}
		//if audit_all, just addtolist
		if (eventbottom == AUDIT_ALL) {
			AddToList(eventbottom, eventtop, reg_objective.str_user_match,
				  tempmatch,
				  criticality, generalflag, eventflag, userflag, muserflag, etype,
				  stype,i_objective_count);
		} else {
			//look for sequential numbers
			eventbottom = eventidlist[0];
			if (!eventtop) eventtop = eventidlist[0];
			for (int i=1;i<ecount;i++) {
				if (eventidlist[i] == eventidlist[i-1] + 1) {
					//still in sequence
					eventtop = eventidlist[i];
				} else {
					//new sequence, add old sequence
					AddToList(eventbottom, eventtop, reg_objective.str_user_match,
					  tempmatch,
					  criticality, generalflag, eventflag, userflag, muserflag, etype,
					  stype,i_objective_count);
					//reset bottom
					eventbottom=eventtop=eventidlist[i];
				}
			}
			eventtop = eventidlist[ecount-1];
			AddToList(eventbottom, eventtop, reg_objective.str_user_match,
					  tempmatch,
					  criticality, generalflag, eventflag, userflag, muserflag, etype,
					  stype,i_objective_count);
		}
		if (eventidlist) delete [] eventidlist;
		i_objective_count++;
		if(onlySYSADMIN && (i_objective_count >= 0))break;//read only Sysadmin part of objectives if onlySYSADMIN == true
	}
	if(from < 0){
		i_objective_count = i_objective_count - from;
	}
	return i_objective_count;
}


int ReadObjectives()
{
	int i_objective_count=0;

	DWORD SetAudit=0;
	int totasobjects = 0;
	int last = 0;
	
	if(SAOBJ){
		totasobjects = MyGetProfileDWORD("SysAdmin","TotalASObjectives",0);
		last = MyGetProfileDWORD("SysAdmin","LastSA",0);
		i_objective_count = totasobjects*(-1);
	}
	SetAudit=MyGetProfileDWORD("Config","Audit",0);
	// HERE: Turn off all auditing, unless there are NO objectives to read.
	if(SetAudit) {
		ClearAuditFlags();
	}
	
	if(SAOBJ && last){
			i_objective_count=ReadObjectivesFrom(0, FALSE,SetAudit) + ReadObjectivesFrom(totasobjects*(-1),TRUE ,SetAudit);
	}else{
		i_objective_count=ReadObjectivesFrom(i_objective_count,FALSE, SetAudit);
	}

	if(SetAudit) {
		ApplyAudit();
	}
	if(SAOBJ)i_objective_count = i_objective_count + totasobjects;
	return(i_objective_count);
}

BOOL TurnOnEvent(DWORD EventID,DWORD SuccessFailure)
{
	if(IS_PRIVILEGE_USE(EventID)) {
		SetAuditFlag(AuditCategoryPrivilegeUse,SuccessFailure);
	}
	if(IS_PROCESS_TRACKING(EventID)) {
		SetAuditFlag(AuditCategoryDetailedTracking,SuccessFailure);
	}
	if(IS_SYSTEM_EVENTS(EventID)) {
		SetAuditFlag(AuditCategorySystem,SuccessFailure);
	}
	if(IS_LOGON_EVENTS(EventID)) {
		SetAuditFlag(AuditCategoryLogon,SuccessFailure);
	}
	if(IS_ACCOUNT_LOGON_EVENTS(EventID)) {
		SetAuditFlag(AuditCategoryAccountLogon,SuccessFailure);
	}
	if(IS_ACCOUNT_MANAGEMENT_EVENTS(EventID)) {
		SetAuditFlag(AuditCategoryAccountManagement,SuccessFailure);
	}
	if(IS_OBJECT_ACCESS(EventID)) {
		SetAuditFlag(AuditCategoryObjectAccess,SuccessFailure);
	}
	if(IS_POLICY_CHANGE(EventID)) {
		SetAuditFlag(AuditCategoryPolicyChange,SuccessFailure);
	}
	if(IS_DIRECTORY_SERVICE_ACCESS(EventID)) {
		SetAuditFlag(AuditCategoryDirectoryServiceAccess,SuccessFailure);
	}

	return(1);
}

// New routines to cope with win2003 PDC replication issues.
// Rather than clear, and re-set all auditing (which causes lots of replication traffic)
// we will just establish a 'flag' array, and then apply it all at the end.

void ClearAuditFlags()
{
	// Uses global flag array "int AuditFlags[9]"
	int i=0;
	for(i=0;i<9;i++) {
		AuditFlags[i]=0;
	}
}

// Make sure you clear audit flags before building this array up.
int SetAuditFlag(POLICY_AUDIT_EVENT_TYPE AuditCategory, DWORD SuccessFailure)
{
	// Uses global flag array "int AuditFlags[9]"
	// Note: expand AuditFlags to max(POLICY_AUDIT_EVENT_TYPE)
	AuditFlags[AuditCategory] |= SuccessFailure;

	return(0);
}

BOOL ApplyAudit()
{
	// AuditCategorySystem, AuditCategoryLogon, AuditCategoryObjectAccess,
	// AuditCategoryPrivilegeUse, AuditCategoryDetailedTracking,
	// AuditCategoryPolicyChange, AuditCategoryAccountManagement,
	// AuditCategoryDirectoryServiceAccess, AuditCategoryAccountLogon
	LPWSTR wComputerName = NULL; 
    LSA_HANDLE PolicyHandle; 
    NTSTATUS Status; 
	PPOLICY_AUDIT_EVENTS_INFO AuditEvents;
	LSA_OBJECT_ATTRIBUTES ObjectAttributes; 
	DWORD Flag=0;
	int i=0;
	DWORD SuccessFailure;
	POLICY_AUDIT_EVENT_TYPE AuditCategory;
	int AuditChanged=0;

	ZeroMemory(&ObjectAttributes, sizeof(ObjectAttributes));

	Status = LsaOpenPolicy(NULL, &ObjectAttributes, POLICY_VIEW_AUDIT_INFORMATION | POLICY_SET_AUDIT_REQUIREMENTS, &PolicyHandle);

	if(Status == 0) {

		Status = LsaQueryInformationPolicy(PolicyHandle, PolicyAuditEventsInformation, 
                (void **) &AuditEvents); 
 
		if(Status != 0) {
			LsaClose(PolicyHandle);
			return 0; 
		}
		// 
		// successfully obtained AuditEventsInformation. 
		// 

		// If audit is not turned on
		if(AuditEvents->AuditingMode == 0) {
			// In theory, we need to turn on auditing.
			AuditEvents->AuditingMode = 1;
			Status = LsaSetInformationPolicy(PolicyHandle, PolicyAuditEventsInformation, 
				(PVOID) AuditEvents); 

		}

		// For each element in the AuditFlags array:
		for(i=0;i<9;i++) {
			AuditCategory=(POLICY_AUDIT_EVENT_TYPE)i;
			SuccessFailure=AuditFlags[AuditCategory];
			Flag=0;
			
			if(SuccessFailure & TYPE_SUCCESS) {
				Flag |= POLICY_AUDIT_EVENT_SUCCESS;
			}
			
			if(SuccessFailure & TYPE_FAILURE) {
				Flag |= POLICY_AUDIT_EVENT_FAILURE;
			}
			
			// If the current settings mirror what we want, don't change anything.
			if((Flag == 0 && (AuditEvents->EventAuditingOptions[AuditCategory] &
				(POLICY_AUDIT_EVENT_SUCCESS | POLICY_AUDIT_EVENT_FAILURE)) == 0) ||
				Flag == (AuditEvents->EventAuditingOptions[AuditCategory] &
				(POLICY_AUDIT_EVENT_SUCCESS | POLICY_AUDIT_EVENT_FAILURE))) {
				Flag=POLICY_AUDIT_EVENT_UNCHANGED;
			} else if(Flag==0) {
				Flag=POLICY_AUDIT_EVENT_NONE;
			}
			
			if(Flag != POLICY_AUDIT_EVENT_UNCHANGED) {
				Status = SetAuditEvent(PolicyHandle,AuditCategory,Flag);
				AuditChanged=1;
			}
		}
		if(AuditChanged) {
			// 
			// enable audits 
			// 
			if( Status == 0 ) {
				Status = SetAuditMode(PolicyHandle, TRUE);

			}
		}

		LsaClose(PolicyHandle);
	}
 
	return(1);
}

int SetAuditEvent(LSA_HANDLE PolicyHandle, POLICY_AUDIT_EVENT_TYPE EventType,
					   POLICY_AUDIT_EVENT_OPTIONS EventOption)
{ 
    PPOLICY_AUDIT_EVENTS_INFO pae; 
    NTSTATUS Status; 
    DWORD i; // index into EventAuditingOptions 
 
    // 
    // obtain AuditEvents 
    // 
    Status = LsaQueryInformationPolicy( 
                PolicyHandle, 
                PolicyAuditEventsInformation, 
                (void **)&pae 
                ); 
    if(Status != 0) return Status; 

    // 
    // ensure we were passed a valid EventType and EventOption 
    // 
    if((ULONG)EventType > pae->MaximumAuditEventCount) {
		LsaFreeMemory(pae);
		LogExtMsg(DEBUG_LOG,"Invalid eventtype.");
        return -1; 
	}
		
	if(!(EventOption & POLICY_AUDIT_EVENT_MASK)) { 
        LsaFreeMemory(pae); 
		LogExtMsg(DEBUG_LOG,"Invalid eventoption");
        return -1; 
    } 
 
    // 
    // set all auditevents to the unchanged status... 
    // 
    for(i = 0 ; i < pae->MaximumAuditEventCount ; i++) { 
        pae->EventAuditingOptions[i] = POLICY_AUDIT_EVENT_UNCHANGED; 
    } 
 
    // 
    // ...and update only the specified EventType 
    // 
    pae->EventAuditingOptions[EventType] = EventOption; 
 
    // 
    // set the new AuditEvents 
    // 
    Status = LsaSetInformationPolicy( 
                PolicyHandle, 
                PolicyAuditEventsInformation, 
                pae 
                ); 

    // 
    // free allocated memory 
    // 
    LsaFreeMemory(pae); 
 
    return Status; 
} 

int SetAuditMode(LSA_HANDLE PolicyHandle, BOOL bEnable)
{ 
    PPOLICY_AUDIT_EVENTS_INFO AuditEvents; 
    NTSTATUS Status; 
    DWORD i; 
 
    // 
    // obtain current AuditEvents 
    // 
    Status = LsaQueryInformationPolicy( 
                PolicyHandle, 
                PolicyAuditEventsInformation, 
                (void **)&AuditEvents 
                ); 
 
    if(Status != 0) return Status; 

    // 
    // update the relevant member 
    // 
    AuditEvents->AuditingMode = bEnable; 
 
    // 
    // set all auditevents to the unchanged status... 
    // 
    for(i = 0 ; i < AuditEvents->MaximumAuditEventCount ; i++) { 
        AuditEvents->EventAuditingOptions[i] = POLICY_AUDIT_EVENT_UNCHANGED; 
    } 
 
    // 
    // set the new auditing mode (enabled or disabled) 
    // 
    Status = LsaSetInformationPolicy( 
                PolicyHandle, 
                PolicyAuditEventsInformation, 
                AuditEvents 
                ); 

    LsaFreeMemory(AuditEvents); 
 
    return Status; 
} 

char* replaceSAMacro(char* sa){
	char* p = strstr(sa, SYSADMINMACRO);
	if(p && getSAStr()){
		int size = strlen(getSAStr()) + strlen(sa) - strlen(SYSADMINMACRO) + 1;
		char* tmp = (char*)malloc(size);
		if(tmp){
			strncpy_s(tmp,size,sa,p-sa);
			strncat_s(tmp,size,getSAStr(),_TRUNCATE);
			strncat_s(tmp,size,p + strlen(SYSADMINMACRO),_TRUNCATE);
			LogExtMsg(DEBUG_LOG,"SA substitution in General Search Term: %s\n", tmp);
			return tmp;
		}else{
			LogExtMsg(DEBUG_LOG,"SA substitution in General Search Term failed: %s\n", sa);
			return NULL;
		}
	}
	return NULL;
}
// Linked List Functions

void AddToList(int eventbottom, int eventtop, char *username, char *match, int criticality, int excludematchflag, int excludeidflag, int excludeflag,
				 int muserflag, int eventlogtype, int sourcename, int objectivecount)
{
   Node *newNode=NULL;

	LogExtMsg(INFORMATION_LOG,"AddToList(), bottom:%d, top:%d",eventbottom, eventtop);

	if(!username || !match) {
		return;
	}

    newNode = (Node *) malloc(sizeof(Node));
	//memset(newNode,0,sizeof(Node));

    if (newNode == NULL) {
        LogExtMsg(ERROR_LOG,"AddToList(): error in dynamic memory allocation\nCould not add a new objective into our linked list. You may be low on memory.\n");
        return;
    }

	newNode->event_top = eventtop;
	newNode->event_bottom = eventbottom;
	newNode->criticality=criticality;
	newNode->excludematchflag=excludematchflag;
	newNode->excludeflag=excludeflag;
	newNode->excludeidflag=excludeidflag;
	newNode->muserflag=muserflag;
	newNode->eventlogtype=eventlogtype;
	newNode->sourcename=sourcename;
	newNode->next=NULL;

	strncpy_s(newNode->username,_countof(newNode->username),username,_TRUNCATE);
	strncpy_s(newNode->match,_countof(newNode->match),match,_TRUNCATE);
	if((objectivecount < 0) && (strlen(newNode->match) > 0)){//Only for sys admin users
		strncpy_s(newNode->sysadmin,_countof(newNode->sysadmin),newNode->match,_TRUNCATE);
		int len = strlen(newNode->sysadmin);
		for(int i = 0; i < len; i++){
			if(newNode->sysadmin[i] == '|')
				newNode->sysadmin[i] = ',';
		}
		strncat_s(newNode->sysadmin,_countof(newNode->sysadmin),",SYSTEM",_TRUNCATE);
		newNode->muserflag=1;
	}
	char* matchR = replaceSAMacro(match);
	if(matchR){
		newNode->regexpError = regcomp(&newNode->regexpCompiled, matchR, REG_EXTENDED|REG_ICASE);
		free(matchR);
	}else{
		newNode->regexpError = regcomp(&newNode->regexpCompiled, match, REG_EXTENDED|REG_ICASE);
	}

	if (newNode->regexpError != 0) {
		char errorMsg[8192];
		char tmpMsg[9216];
		regerror(newNode->regexpError, &newNode->regexpCompiled, errorMsg, 8192);
		LogExtMsg(DEBUG_LOG,"Error compiling the regular expression: %s\n", match);
		_snprintf_s(tmpMsg,_countof(tmpMsg),_TRUNCATE,"Error compiling the regular expression: %s ", match);
		strncat_s(initStatus,_countof(initStatus),tmpMsg,_TRUNCATE);
		LogExtMsg(DEBUG_LOG,"Error compiling the regular expression: %s\n", match);
		_snprintf_s(tmpMsg,_countof(tmpMsg), _TRUNCATE,"Error code = %d ", newNode->regexpError);
		strncat_s(initStatus,_countof(initStatus),tmpMsg,_TRUNCATE);
		LogExtMsg(DEBUG_LOG,"Error message = %s\n", errorMsg);
		_snprintf_s(tmpMsg,_countof(tmpMsg), _TRUNCATE,"Error message = %s<p>", errorMsg);
		strncat_s(initStatus,_countof(initStatus),tmpMsg,_TRUNCATE);

	}

    if (tail != NULL) {
		tail->next = newNode;
	}
	tail = newNode;
	if (head == NULL) {
		head = newNode;
	}

    return;
}

void ResetCurrentNode(void)
{
    currentnode = head;
	LogExtMsg(DEBUG_LOG,"re-initialising currentnode to head"); 
}
void freeMatchLists(){
	currentnode=NULL;
    while (NULL != head) {
        Node *tempPtr = head;
        head = head->next;
		regfree(&tempPtr->regexpCompiled);
        free(tempPtr);
    }
	head = NULL;
	tail = NULL;

}
void DestroyList(void)
{
	DWORD dwWaitRes=0;
	MsgCache *temp;
    if (NULL == head) {
        return;
    }
	MCCount=0;
	deinitSockets();
	hostcurrentnode=NULL;
	freeMatchLists();
	dwWaitRes = WaitForSingleObject(hMutex,1000);
	//We should be the only ones, so success or fail, we need to get rid of this list
	while (MCHead) {
		temp = MCHead;
		MCHead = MCHead->next;
		free(temp);
	}
	MCHead=NULL;
	MCTail=NULL;
	MCCurrent=NULL;
	MCCount=0;

	ReleaseMutex(hMutex);


	if(WEBSERVER_ACTIVE && WEBSERVER_TLS){
		if(!TLSSERVERFAIL)deinitSTLS();
	}
}


void CSafedService::OnShutdown() {
	// Audit: Set that global variable to TRUE so that the threads
	// receive the terminate message

	g_Info.bTerminate=TRUE;
	
	LogExtMsg(WARNING_LOG,"NetEye Safed Shutdown request received"); 

	// Save off our current position in each of our log files.
	for (DWORD i=0;i<dwNumEventLogs + dwNumCustomEventLogs;i++) {
		MyWriteProfileDWORD("Status",EventLogStatusName[i],dwEventIDRead[i]);
	}
	// Call a fake event so that the subroutine	gets the shutdown message
	// through the setting of g_Info.bTerminate
	if(m_hEventList[0])
		::SetEvent(m_hEventList[0]);
}

void CSafedService::OnStop() {
	g_Info.bTerminate=TRUE;
	
	LogExtMsg(WARNING_LOG,"NetEye Safed Stop request received"); 
	
	// Save off our current position in each of our log files.
	for (DWORD i=0;i<dwNumEventLogs + dwNumCustomEventLogs;i++) {
		MyWriteProfileDWORD("Status",EventLogStatusName[i],dwEventIDRead[i]);
	}
	// Call a fake event so that the subroutine	gets the shutdown message
	// through the setting of g_Info.bTerminate
	if(m_hEventList[0])
		::SetEvent(m_hEventList[0]);
}

void CSafedService::OnSignal() {
	// Save off our current position in each of our log files.
	for (DWORD i=0;i<dwNumEventLogs + dwNumCustomEventLogs;i++) {
		MyWriteProfileDWORD("Status",EventLogStatusName[i],dwEventIDRead[i]);
	}
}

// Process user control requests
BOOL CSafedService::OnUserControl(DWORD dwOpcode)
{
    switch (dwOpcode) {
    case SERVICE_CONTROL_USER + 0:

        // Save the current status in the registry
        SaveStatus();
        return TRUE;

    default:
        break;
    }
    return FALSE; // say not handled
}

// Save the current status in the registry
void CSafedService::SaveStatus()
{
	// Save off our current position in each of our log files.
	for (DWORD i=0;i<dwNumEventLogs + dwNumCustomEventLogs;i++) {
		MyWriteProfileDWORD("Status",EventLogStatusName[i],dwEventIDRead[i]);
	}
}


// Configuration reading routines

void GetHostname(char * Hostname,int size)
{
	// Grab the fully qualified hostname
	// Note: if the user has explicitly set a hostname in the registry, use that instead.

	if(!Hostname) return;
	if(!size) return;

	Hostname[0]='\0';
	MyGetProfileString("Config","Clientname",Hostname,size);
	if(Hostname[0]=='\0') {
		GetFQDN(Hostname,size);
	}
}





void GetDNSCheckTime(DWORD * dwDNSCheckTime)
{
	if(!dwDNSCheckTime) return;
	// time in seconds between DNS checks for remote access and event transmission
	*dwDNSCheckTime=MyGetProfileDWORD("Network","DestPort",600);
}
void GetCrit(DWORD * dwCrit)
{
	if(!dwCrit) return;
	*dwCrit=MyGetProfileDWORD("Config","CritAudit",0);
}

void GetSyslog(DWORD * dwSyslog)
{
	if(!dwSyslog) return;
	*dwSyslog=MyGetProfileDWORD("Network","SyslogDest",13);
}

void GetSyslogDynamic(DWORD * dwSyslogDynamic)
{
	if(!dwSyslogDynamic) return;
	*dwSyslogDynamic=MyGetProfileDWORD("Network","SyslogDynamicCritic",0);
}

void GetSyslogHeader(DWORD * dwSyslogHeader)
{
	if(!dwSyslogHeader) return;
	*dwSyslogHeader=MyGetProfileDWORD("Network","Syslog",0);
}

void GetWEBSERVER_ACTIVE(DWORD * WEBSERVER_ACTIVE)
{
	//if(!WEBSERVER_ACTIVE) return;
	*WEBSERVER_ACTIVE=MyGetProfileDWORD("Remote","Allow",0);
}

void GetWEBSERVER_TLS(DWORD * WEBSERVER_TLS)
{
	*WEBSERVER_TLS=MyGetProfileDWORD("Remote","TLS",0);
}

void GetPortNumber(DWORD * dwPortNumber)
{
	DWORD dwUsePort;

	if(!dwPortNumber) return;
	*dwPortNumber=6161;
	dwUsePort=MyGetProfileDWORD("Remote","WebPortChange",0);
	if(dwUsePort) {
		*dwPortNumber=MyGetProfileDWORD("Remote","WebPort",6161);
	}
}

void GetSysAdminEnable(DWORD * dwSAE)
{
	*dwSAE=0;
	*dwSAE=MyGetProfileDWORD("SysAdmin","SysAdministrators",0);
}
void GetTimesADay(int * dwTAD)
{	//Every multiple by 5s seconds.
	//Once a day = 17280 x 5 secs.
	*dwTAD=1;
	DWORD tad = MyGetProfileDWORD("SysAdmin","TimesADay",1);
	if(tad == 0)
		*dwTAD=0;
	else
		*dwTAD=(24*60*60)/tad;
}

void GetNextTimeDiscovery(DWORD * dwNT)
{	
	//Get the next scheduled time (in seconds).
	*dwNT = MyGetProfileDWORD("SysAdmin","NextTimeDiscovery",0);
}

void GetForceSysAdmin(DWORD * dwFSA)
{	
	//Get the forcing flag.
	*dwFSA = MyGetProfileDWORD("SysAdmin","ForceSysAdmin",0);
	MyWriteProfileDWORD("SysAdmin","ForceSysAdmin",0);
}

DWORD GetVBS()
{	
	//Get the vb script flag.
	return MyGetProfileDWORD("SysAdmin","VBS",0);
}


void GetChecksum(BOOL *ActivateChecksum)
{
	DWORD Check=0;
	Check=MyGetProfileDWORD("Config","Checksum",0);
	*ActivateChecksum = (BOOL)Check;
}

void	GetLeaveRetention		(BOOL * LeaveRetention)
{
	DWORD leaveret=0;
	leaveret=MyGetProfileDWORD("Config","LeaveRetention",0);
	*LeaveRetention = (BOOL)leaveret;
}


void GetDelim(char * DELIM,int size)
{
	if(!DELIM) return;
	if(size < 2) return;

	DELIM[0]=9;	// TAB character
	DELIM[1]='\0';
	// Only use a different character for delimiters if we're sending data via syslog.
	MyGetProfileString("Config","Delimiter",DELIM,size);
}

void GetPassword(char * lpszPassword,int size)
{
	DWORD dwUsePassword;

	if(!lpszPassword) return;
	if(!size) return;

	strncpy_s(lpszPassword,size,"",_TRUNCATE);
	dwUsePassword=MyGetProfileDWORD("Remote","AccessKey",0);
	if(dwUsePassword) {
		if(!MyGetProfileString("Remote","AccessKeySet",lpszPassword,size))
		{
			// Problem. Couldn't retrieve the destination from the registry.
			// Default it to something harmless.
			strncpy_s(lpszPassword,size,"",_TRUNCATE);
		}
	}
}
void GetSentIndex(char * sfile,int size, int *sindex)
{

	if(!sfile) return;
	if(!size) return;
	strncpy_s(sfile,size,"",_TRUNCATE);
	*sindex = 0;
	
	TCHAR sendIndex[255] = "";
	strncpy_s(sendIndex,size,"",_TRUNCATE);
	if(MyGetProfileString("Status","SentIndex",sendIndex,size))
	{
		char* pos=strstr(sendIndex,"|");
		if(pos){
			strncpy_s(sfile,size,sendIndex,(pos - sendIndex));
			sfile[pos - sendIndex]='\0';
			pos++;
			*sindex = atoi(pos);
		}
	}
}
void SetSentIndex(char * sfile,int sindex)
{
	if(!sfile) return;
	TCHAR sendIndex[255] = "";
	_snprintf_s(sendIndex,255, _TRUNCATE,"%s|%d",sfile, sindex);
	MyWriteProfileString("Status","SentIndex",sendIndex);
}







void GetIPAddress(char * lpszIPAddress,int size)
{
	DWORD dwRestrictIP;

	if(!lpszIPAddress) return;
	if(!size) return;

	strncpy_s(lpszIPAddress,size,"",_TRUNCATE);
	dwRestrictIP=MyGetProfileDWORD("Remote","Restrict",0);

	if(dwRestrictIP) {
		if(!MyGetProfileString("Remote","RestrictIP",lpszIPAddress,SIZE_OF_RESTRICTIP))
		{
			// Problem. Couldn't retrieve the destination from the registry.
			// Default it to something harmless.
			strncpy_s(lpszIPAddress,size,"127.0.0.1",_TRUNCATE);
		}
	}
}

void GetClearTabs(DWORD * ClearTabs)
{
	if(!ClearTabs) return;
	// If the user SPECIFICALLY does not want TABS in the output,
	// even IF the delimiter is not a TAB:
	*ClearTabs=MyGetProfileDWORD("Config","ClearTabs",0);
}

void check_usb_enabled()
{
	USB_ENABLED=MyGetProfileDWORD("Config","EnableUSB",0);
}

DWORD GetTotalSavedLogs(FILE * fp){
	DWORD cnt = 0;
	char* line = (char*)malloc(dwMaxMsgSize*sizeof(char)); 
	if (line)line[0]='\0';
	else{ 
		LogExtMsg(DEBUG_LOG,"NO MEMORY LEFT!!!");
		LogExtMsg(ERROR_LOG,"NO MEMORY LEFT!!!");
		return cnt;
	
	}	
	
	if(fp) {
		while (fgets(line, dwMaxMsgSize, fp)) {
			cnt++;
		}
	}
	if (line) free(line);
	return cnt;
}

void GetSavedLogsAt(FILE * fp, char* line, int position){
	int cnt = 0;
	if(fp) {
		while ((cnt <= position) && fgets(line, dwMaxMsgSize, fp)) {
			cnt++;
		}
		if(cnt <= position)
			*line = '\0'; 
	}
}





void GetNumberFiles(DWORD * dwNumberFiles)
{
	if(!dwNumberFiles) return;
	*dwNumberFiles=MyGetProfileDWORD("Config","NumberFiles",2);
}
void GetMaxMsgSize()
{
	if(!dwMaxMsgSize) return;
	dwMaxMsgSize=MyGetProfileDWORD("Network","MaxMessageSize",MAXMSGSIZE);
}

// END Configuration Reading Routines

int StartWebThread(HANDLE event)
{

	int threadid=0;
	threadid=(int)_beginthread( HandleWebThread, 0, event );
	LogExtMsg(INFORMATION_LOG,"DEBUG: Starting web thread %d..",threadid); 
	if(threadid==-1)
	{
		LogExtMsg(ERROR_LOG,"Error in web thread creation");
		return(-1);
	}
	return(1);
}

void HandleWebThread(HANDLE event)
{
	time_t currenttime,lasttime;
	DWORD dwWaitRes=0;
	DWORD dwWaitReset=0;
	
	time(&lasttime);

	
	if(web_hEventList[0] == NULL) {
		LogExtMsg(ERROR_LOG,"CreateEvent() Web Server failed"); 
		_endthread();
	}
	if(web_hEventList[1] == NULL) {
		LogExtMsg(ERROR_LOG,"CreateEvent() Web Server Reset failed"); 
		_endthread();
	}
	if(web_hEventList[2] == NULL) {
		LogExtMsg(ERROR_LOG,"CreateEvent() Web Server Exit failed"); 
		_endthread();
	}

	LogExtMsg(INFORMATION_LOG,"Starting HandleWebThread."); 
	StartThread(web_hEventList[0]);
	//while (m_bIsRunning) {
	while (1) {
		dwWaitRes=WaitForMultipleObjects(3,web_hEventList,FALSE,500);
		if(dwWaitRes != WAIT_FAILED) {
			if(dwWaitRes == WAIT_OBJECT_0) {
				// Web server has data to read.
				ResetEvent(web_hEventList[0]);
				LogExtMsg(INFORMATION_LOG,"HandleWebThread: WEB Server Connect."); 

				if(WEBSERVER_ACTIVE) {
					// Let handleconnect have the eventlist pointer, in case it needs
					// to signal a restart
					LogExtMsg(INFORMATION_LOG,"HandleWebThread: About to HandleConnect");
					HandleConnect(web_hEventList[1]);
					LogExtMsg(INFORMATION_LOG,"HandleWebThread: Running thread again."); 
					StartThread(web_hEventList[0]);
				}
			} else if (dwWaitRes == WAIT_OBJECT_0+1) {
			// We need to re-read our configuration file.
				LogExtMsg(INFORMATION_LOG,"HandleWebThread: WEB Server Reset."); 
				ResetEvent(web_hEventList[1]);
				WebResetFlag=FULL_WEB_RESET;
				//don't end straight away, we need to finish handling any other connections, just sleep for now
				//Sleep(10);
		
				break;
			} else if (dwWaitRes == WAIT_OBJECT_0+2) {
				// We need to exit, now
				LogExtMsg(INFORMATION_LOG,"HandleWebThread: WEB Server exitting.."); 
				ResetEvent(web_hEventList[2]);
				break;
			} else if (dwWaitRes == WAIT_TIMEOUT) {
				// For the time being, we want to reset the web server every 20 mins
				// This is done using the last values that were grabbed
				time(&currenttime);

				if ((currenttime - lasttime) > dwDNSCheckTime) {
					lasttime=currenttime;
					LogExtMsg(INFORMATION_LOG,"HandleWebThread: WEB Server Timeout Reset."); 
					WebResetFlag=BASIC_WEB_RESET;
					
					//Sleep(10);
					break;
				}
			}
		}
	}
	SetEvent(event);
	_endthread();
}



// Dump the current eventlog record to a file.
void DEBUGDumpEventLog(DWORD EventTriggered,DWORD dwBytesRead,PEVENTLOGRECORD pELR)
{
	FILE *fp;
	errno_t err;
	err = fopen_s(&fp, "SNAREEvt.log","w");
	if(!err) {
		
		fwrite(&EventTriggered,sizeof(EventTriggered),1,fp);
		fwrite(pELR,dwBytesRead,1,fp);
		fflush(fp);
		fclose(fp);
	}
}
















