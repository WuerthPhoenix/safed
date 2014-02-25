// SAFED for Windows
// Author: Wuerth-Phoenix s.r.l.,
//  made starting from:
// SNARE - Audit / EventLog analysis and forwarding
// Copyright 2001-2010 InterSect Alliance Pty Ltd
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
#include <winevt.h>
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
//////////////////////DEBUG////////////////// 0xc0000417 STATUS_INVALID_CRUNTIME_PARAMETER
#include <stdlib.h>
#include <crtdbg.h>
#include <eh.h>
#include "Version.h"
//////////////////////DEBUG////////////////// 0xc0000417 STATUS_INVALID_CRUNTIME_PARAMETER


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



// Pull this from registry
DWORD			WEBSERVER_ACTIVE = 0;
//////////////////////DEBUG////////////////// 0xc0000417 STATUS_INVALID_CRUNTIME_PARAMETER
DWORD			HANDLER_ACTIVE = 0;
//////////////////////DEBUG////////////////// 0xc0000417 STATUS_INVALID_CRUNTIME_PARAMETER
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
DWORD			dwEventIDSize;
EVT_HANDLE		*hEvtBookmark;
DWORD			dwNumEventLogs=6;
DWORD			dwNumCustomEventLogs = 0;
WCHAR			(* EventLogStatusName)[_MAX_PATH + 1]=NULL;
TCHAR			(* EventLogSourceName)[_MAX_PATH + 1]=NULL;
TCHAR			(* OtherEventLogSourceNames)[_MAX_PATH + 1]=NULL;
char			CustomLogName[10*SIZE_OF_EVENTLOG]="";// max 10 objectives with custom event logs are supported

DWORD			*EventLogCounter;

TCHAR			DELIM[2]="	";					// TAB

char			sentFile[255]="";
int				sentIndex=0;

int				AuditFlags[9];					// Array of audit flags to set.
												// Note: Increase this if the POLICY_AUDIT_EVENTTYPE grows in ntsecapi.h
AuditSubCat		ObjectAuditFlags[11];			// Array of Object Access SubCategory audit flags to set.
GUID			guidObjectAccess;

Node *head=NULL, *tail=NULL, *currentnode=NULL;

static HostNode *hostcurrentnode;

int MCCount=0;
MsgCache *MCHead=NULL;
MsgCache *MCTail=NULL;
MsgCache *MCCurrent=NULL;

int EventCount=0;
MsgCache *EventHead=NULL;
MsgCache *EventTail=NULL;
MsgCache *EventCurrent=NULL;


// Locker
HANDLE hMutex;
HANDLE hMutexFile=NULL;
HANDLE hMutexCount=NULL;
HANDLE web_hEventList[3]; // list of events to control web actions.
HANDLE m_hCollectEvent[2]; // CollectionThread events.
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

wchar_t* towchar(char* orig){
    size_t origsize = strlen(orig) + 1;
    const size_t newsize = 4*SIZE_OF_EVENTLOG;
    size_t convertedChars = 0;
    wchar_t wcstring[newsize];
    mbstowcs_s(&convertedChars, wcstring, origsize, orig, _TRUNCATE);
    wcscat_s(wcstring, L" (wchar_t *)");
	return wcstring;
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

void cleanEventLogStructures(){

	if(hEvtBookmark){
		for(int i = 0 ; i<dwNumEventLogs + dwNumCustomEventLogs;i++){
			if(hEvtBookmark[i]) EvtClose(hEvtBookmark[i]);
		}
		delete [] hEvtBookmark;
		hEvtBookmark = NULL;
	}

	if(EventLogCounter){
		delete[] EventLogCounter;
		EventLogCounter = NULL;
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

BOOL InitEvents(){
	dwNumCustomEventLogs = ReadCustomEventLogs();

	cleanEventLogStructures();

	//Resize all the necessary fields
	EventLogSourceName = new TCHAR[dwNumEventLogs + dwNumCustomEventLogs][_MAX_PATH + 1];
	EventLogStatusName = new WCHAR[dwNumEventLogs + dwNumCustomEventLogs][_MAX_PATH + 1];
	hEvtBookmark = new EVT_HANDLE[dwNumEventLogs + dwNumCustomEventLogs];

	EventLogCounter = new DWORD[dwNumEventLogs + dwNumCustomEventLogs];

	strncpy_s(EventLogSourceName[LOG_TYPE_SECURITY],_countof(EventLogSourceName[LOG_TYPE_SECURITY]),"Security",_TRUNCATE);
	strncpy_s(EventLogSourceName[LOG_TYPE_SYSTEM],_countof(EventLogSourceName[LOG_TYPE_SYSTEM]),"System",_TRUNCATE);
	strncpy_s(EventLogSourceName[LOG_TYPE_APPLICATION],_countof(EventLogSourceName[LOG_TYPE_APPLICATION]),"Application",_TRUNCATE);
	strncpy_s(EventLogSourceName[LOG_TYPE_DS],_countof(EventLogSourceName[LOG_TYPE_DS]),"Directory Service",_TRUNCATE);
	strncpy_s(EventLogSourceName[LOG_TYPE_DNS],_countof(EventLogSourceName[LOG_TYPE_DNS]),"DNS Server",_TRUNCATE);
	strncpy_s(EventLogSourceName[LOG_TYPE_FRS],_countof(EventLogSourceName[LOG_TYPE_FRS]),"DFS Replication",_TRUNCATE);

	wcsncpy_s(EventLogStatusName[LOG_TYPE_SECURITY],_countof(EventLogStatusName[LOG_TYPE_SECURITY]),L"LOG_TYPE_SECURITY",_TRUNCATE);
	wcsncpy_s(EventLogStatusName[LOG_TYPE_SYSTEM],_countof(EventLogStatusName[LOG_TYPE_SYSTEM]),L"LOG_TYPE_SYSTEM",_TRUNCATE);
	wcsncpy_s(EventLogStatusName[LOG_TYPE_APPLICATION],_countof(EventLogStatusName[LOG_TYPE_APPLICATION]),L"LOG_TYPE_APPLICATION",_TRUNCATE);
	wcsncpy_s(EventLogStatusName[LOG_TYPE_DS],_countof(EventLogStatusName[LOG_TYPE_DS]),L"LOG_TYPE_DS",_TRUNCATE);
	wcsncpy_s(EventLogStatusName[LOG_TYPE_DNS],_countof(EventLogStatusName[LOG_TYPE_DNS]),L"LOG_TYPE_DNS",_TRUNCATE);
	wcsncpy_s(EventLogStatusName[LOG_TYPE_FRS],_countof(EventLogStatusName[LOG_TYPE_FRS]),L"LOG_TYPE_FRS",_TRUNCATE);




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
		wcsncpy_s(EventLogStatusName[dwNumEventLogs + i],_countof(EventLogStatusName[dwNumEventLogs + i]),L"LOG_TYPE_",_TRUNCATE);
		char* toupchars = toup(tmp);

		if(toupchars){
			wcsncpy_s(EventLogStatusName[dwNumEventLogs + i],_countof(EventLogStatusName[dwNumEventLogs + i]),towchar(toupchars),_TRUNCATE);
			free(toupchars);
		}

	}
	for (DWORD i=0;i<(dwNumEventLogs + dwNumCustomEventLogs);i++) {
		EventLogCounter[i]=0;
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

	m_hEventList = new HANDLE[2];
	m_hEventList[0] = CreateEvent(NULL, TRUE, FALSE, NULL);
	m_hEventList[1] = CreateEvent(NULL, TRUE, FALSE, NULL);

	// Web server
	web_hEventList[0] = CreateEvent(NULL, TRUE, FALSE, NULL);
	// Web server reset
	web_hEventList[1] = CreateEvent(NULL, TRUE, FALSE, NULL);
	// Web server exit
	web_hEventList[2] = CreateEvent(NULL, TRUE, FALSE, NULL);

	//CollectionThread shutdown
	m_hCollectEvent[0] = CreateEvent(NULL, TRUE, FALSE, NULL);
	//CollectionThread shutdown and restart web
	m_hCollectEvent[1] = CreateEvent(NULL, TRUE, FALSE, NULL);
	
	if(m_hEventList[0] == NULL)
	{	LogExtMsg(ERROR_LOG,"CreateEvent() Web notification failed");	return FALSE;	}
	if(m_hEventList[1] == NULL)
	{	LogExtMsg(ERROR_LOG,"CreateEvent() Log notification failed");	return FALSE;	}

	if(m_hCollectEvent[0] == NULL)
	{	LogExtMsg(ERROR_LOG,"CreateEvent() Thread 0 notification failed");	return FALSE;	}
	if(m_hCollectEvent[1] == NULL)
	{	LogExtMsg(ERROR_LOG,"CreateEvent() Thread 1 notification failed");	return FALSE;	}

	hMutex = CreateMutex(NULL,FALSE,"Global\\SnareAgentLock");
	if(hMutex == NULL) {
		LogExtMsg(ERROR_LOG,"I cannot create the NetEye Safed Agent 'Mutex' lock. This probably means that you already have another instance of the NetEye Safed Agent running.\nPlease stop the other incarnation of the NetEye Safed Agent (eg: net stop NetEye Safed) before continuing.");
		return FALSE;
	}
	hMutexFile = CreateMutex(NULL,FALSE,"Global\\FileLock");
	if(hMutexFile == NULL) {
		LogExtMsg(ERROR_LOG,"I cannot create the Safed Agent File 'Mutex' lock. This probably means that you already have another instance of the Safed Agent running.\nPlease stop the other incarnation of the Safed Agent (eg: net stop safed) before continuing.");
		return FALSE;
	}	
	hMutexCount = CreateMutex(NULL,FALSE,"Global\\CountLock");
	if(hMutexCount == NULL) {
		LogExtMsg(ERROR_LOG,"I cannot create the Safed Agent Count 'Mutex' lock. This probably means that you already have another instance of the Safed Agent running.\nPlease stop the other incarnation of the Safed Agent (eg: net stop safed) before continuing.");
		return FALSE;
	}

	if(!InitEvents())return FALSE;


	StartCollectThread(m_hEventList[0]);

	LogExtMsg(INFORMATION_LOG,"NetEye Safed Initialisation complete");
#ifdef DEBUG_TO_FILE
	setSAFEDDEBUG(4);
#endif
	LogExtMsg(INFORMATION_LOG,"SAFEDDEBUG: %d", getSAFEDDEBUG());
	// return FALSE here if initialization failed & the service shouldn't start
	return TRUE;
}

void CollectionThread(HANDLE event)
{
	//-------------- thread --------------
	EVT_HANDLE *m_hEventLog;   // Handle to the event subscriber.
	m_hEventLog = new EVT_HANDLE[dwNumEventLogs + dwNumCustomEventLogs];
	wchar_t *szQuery = L"*";   // XPATH Query to specify which events to subscribe to.
	static BOOL LeaveRetention=0;
	GetLeaveRetention(&LeaveRetention);

	for (unsigned int i=0;i<dwNumEventLogs + dwNumCustomEventLogs;i++) {
		if (CheckLogExists(EventLogSourceName[i],LeaveRetention)) {
			//turn the sourcename into a wchar
			DWORD Flags=EvtSubscribeToFutureEvents;
			EVT_HANDLE Bookmark=NULL;
			wchar_t sourcename[256]=L"";
			size_t numChars=0;
			hEvtBookmark[i] = NULL;
			wchar_t	szEventIDRead[SIZE_EVENTREAD];
			mbstowcs_s(&numChars,sourcename,_countof(sourcename),EventLogSourceName[i],_TRUNCATE);
			// this call will initialise szEventIDRead
			if (MyGetProfileWString("Status",EventLogStatusName[i],szEventIDRead,_countof(szEventIDRead))) {
				hEvtBookmark[i] = EvtCreateBookmark(szEventIDRead);
				if (hEvtBookmark[i]) {
					Bookmark = hEvtBookmark[i];
					Flags = EvtSubscribeStartAfterBookmark;
				}
			}
			// Register the subscription.
			m_hEventLog[i] = EvtSubscribe( 
				NULL,					 //Session
				NULL,                    // Used for pull subscriptions.
				sourcename,    // Channel.
				szQuery,                 // XPath query.
				Bookmark,         // Bookmark.
				NULL,                    // CallbackContext.
				(EVT_SUBSCRIBE_CALLBACK) EventSubCallBack,  // Callback.
				Flags   // Flags.
				);
		} else {
			hEvtBookmark[i] = NULL;
		}
	}

	if( !m_hEventLog[0]  || !m_hEventLog[1]  || !m_hEventLog[2]) {
		LogExtMsg(INFORMATION_LOG,"Couldn't Subscribe to Core Events!. Error = 0x%x", GetLastError());
		return;
	}
	DWORD dwWaitRes=0;
	while (1) {
		//dwWaitRes=WaitForSingleObject(event,2000);
		//two event types, one to shutdown and restart the web server, the other to just shutdown
		dwWaitRes=WaitForMultipleObjects(2,m_hCollectEvent,FALSE,500);
		if(dwWaitRes != WAIT_FAILED && dwWaitRes != WAIT_TIMEOUT) {
			//Reset the event, just in case we're only restarting the web interface.
			if(dwWaitRes == WAIT_OBJECT_0) {
				ResetEvent(m_hCollectEvent[0]);
				//shutdown
			} else if(dwWaitRes == WAIT_OBJECT_0+1) {
				ResetEvent(m_hCollectEvent[1]);
				//restart the web interface
				SetEvent(event);
			}
			break;
		}
		//Sleep(1000);
	}
	// Close the subscriber handle.
	for (unsigned int i=0; i < dwNumEventLogs + dwNumCustomEventLogs;i++) {
		EvtClose(m_hEventLog[i]);
	}
	//-------------- thread --------------
	_endthread();
}

DWORD WINAPI EventSubCallBack(EVT_SUBSCRIBE_NOTIFY_ACTION Action, PVOID Context, EVT_HANDLE Event)
{
	WCHAR *pBuff = NULL;
	DWORD dwBuffSize = 0;
	DWORD dwBuffUsed = 0;
	DWORD dwRes = 0;
	DWORD dwWaitRes =0;
	DWORD dwPropertyCount = 0;
	UINT EventTriggered=0;
	char SubmitTime[26];

	if (EventCount > 500) {
		//LogExtMsg(INFORMATION_LOG,"##################### Slowing message collection...");//DMM
		Sleep(1500); //DMM
	}
	// Create a context for rendering all event system properties to values.
	EVT_HANDLE renderContext = EvtCreateRenderContext(
		NULL, 0, EvtRenderContextSystem);

	PEVT_VARIANT pValues = NULL;      
	DWORD dwValueSize = 0;
	// Get the XML EventSize to allocate the buffer size.
	BOOL bRet = EvtRender(  
		renderContext,       // Session.
		Event,               // HANDLE.
		EvtRenderEventValues,   // Flags.                                              
		dwValueSize,          // BufferSize.
		pValues,               // Buffer.
		&dwValueSize,         // Buffersize that is used or required.
		&dwPropertyCount);

	if (!bRet) {
		dwRes = GetLastError();
		if( dwRes == ERROR_INSUFFICIENT_BUFFER ) {
			// Allocate the buffer size needed to for the XML event.
			//dwBuffSize = dwBuffUsed;
			//pBuff = new WCHAR[dwBuffSize/sizeof(WCHAR)];
			pValues = new EVT_VARIANT[dwValueSize];
            
			//Get the Event XML
			bRet = EvtRender(   
				renderContext,        // Session.
				Event,                // HANDLE.
				EvtRenderEventValues,    // Flags.                                              
				dwValueSize,           // BufferSize.
				pValues,                // Buffer.
				&dwValueSize,          // Buffer size that is used or required.
				&dwPropertyCount);

			if( !bRet ) {
				LogExtMsg(INFORMATION_LOG,"Couldn't Render Events!. Error = 0x%x", GetLastError());
				delete[] pValues;
				EvtClose(renderContext);
				return dwRes;
            }
		} else {
			LogExtMsg(INFORMATION_LOG,"Couldn't Render Events!. Error = 0x%x", dwRes);
			delete[] pValues;
			EvtClose(renderContext);
			return dwRes;
		}
    }    
    //Display the Event XML on console

	//------------------------------
	WORD EventID = pValues[EvtSystemEventID].UInt16Val;
    if (EvtVarTypeNull != pValues[EvtSystemQualifiers].Type)
    {
        EventID = MAKELONG(pValues[EvtSystemEventID].UInt16Val, pValues[EvtSystemQualifiers].UInt16Val);
    }

    //printf("EventID: %lu\n", EventID);

    //printf("Version: %u\n", (EvtVarTypeNull == pValues[EvtSystemVersion].Type) ? 0 : pValues[EvtSystemVersion].ByteVal);
    //printf("Level: %u\n", (EvtVarTypeNull == pValues[EvtSystemLevel].Type) ? 999 : pValues[EvtSystemLevel].ByteVal);
    //printf("Task: %hu\n", (EvtVarTypeNull == pValues[EvtSystemTask].Type) ? 0 : pValues[EvtSystemTask].UInt16Val);
    //printf("Opcode: %u\n", (EvtVarTypeNull == pValues[EvtSystemOpcode].Type) ? 0 : pValues[EvtSystemOpcode].ByteVal);
    //printf("Keywords: 0x%I64x\n", pValues[EvtSystemKeywords].UInt64Val);
	//------------------------------

	/*SYSTEMTIME st;
	FILETIME ft;
	FileTimeToLocalFileTime((FILETIME *)&pValues[EvtSystemTimeCreated].FileTimeVal,&ft);
	FileTimeToSystemTime(&ft,&st);
	char subtime[32];
	
	GetDateFormat(LOCALE_SYSTEM_DEFAULT,0,&st,"ddd MMM dd ",subtime,_countof(subtime));
	strncpy_s(SubmitTime,_countof(SubmitTime),subtime,_TRUNCATE);
	GetTimeFormat(LOCALE_SYSTEM_DEFAULT,0,&st,"HH':'mm':'ss ",subtime,_countof(subtime));
	strncat_s(SubmitTime,_countof(SubmitTime),subtime,_TRUNCATE);
	GetDateFormat(LOCALE_SYSTEM_DEFAULT,0,&st,"yyyy",subtime,_countof(subtime));
	strncat_s(SubmitTime,_countof(SubmitTime),subtime,_TRUNCATE);
*/

	struct tm ptmTime;
	time_t ttime;
	ttime=time(NULL);
	localtime_s(&ptmTime,&ttime);
	strftime(SubmitTime, _countof(SubmitTime),"%a %b %d %H:%M:%S %Y", &ptmTime);



	EVT_HANDLE hPubConfig = EvtOpenPublisherMetadata( NULL, pValues[EvtSystemProviderName].StringVal, NULL, NULL, 0);

	if (hPubConfig == NULL) {
		LogExtMsg(INFORMATION_LOG,"Bad publisher: %d", GetLastError());
		EVT_HANDLE hProviders = NULL;
		LPWSTR pwcsProviderName = NULL;
		LPWSTR pTemp = NULL;
		DWORD dwBufferSize = 0;
		DWORD dwBufferUsed = 0;
		DWORD status = ERROR_SUCCESS;

		// Get a handle to the list of providers.
		hProviders = EvtOpenPublisherEnum(NULL, 0);
		if (NULL == hProviders)
		{
			wprintf(L"EvtOpenPublisherEnum failed with %lu\n", GetLastError());
			goto cleanup;
		}

		wprintf(L"List of registered providers:\n\n");

		// Enumerate the providers in the list.
		while (true)
		{
			// Get a provider from the list. If the buffer is not big enough
			// to contain the provider's name, reallocate the buffer to the required size.
			if  (!EvtNextPublisherId(hProviders, dwBufferSize, pwcsProviderName, &dwBufferUsed))
			{
				status = GetLastError();
				if (ERROR_NO_MORE_ITEMS == status)
				{
					break;
				}
				else if (ERROR_INSUFFICIENT_BUFFER == status)
				{
					dwBufferSize = dwBufferUsed;
					pTemp = (LPWSTR)realloc(pwcsProviderName, dwBufferSize * sizeof(WCHAR));
					if (pTemp)
					{
						pwcsProviderName = pTemp;
						pTemp = NULL;
						EvtNextPublisherId(hProviders, dwBufferSize, pwcsProviderName, &dwBufferUsed);
					}
					else
					{
						wprintf(L"realloc failed\n");
						goto cleanup;
					}
				}

				if (ERROR_SUCCESS != (status = GetLastError()))
				{
					wprintf(L"EvtNextPublisherId failed with %d\n", status);
					goto cleanup;
				}
			}

			wprintf(L"%s\n", pwcsProviderName);

			RtlZeroMemory(pwcsProviderName, dwBufferUsed * sizeof(WCHAR));
		}

	cleanup:

		if (pwcsProviderName)
			free(pwcsProviderName);

		if (hProviders)
			EvtClose(hProviders);

	}

	bRet = EvtFormatMessage(hPubConfig, Event, NULL, dwPropertyCount, pValues, 9, dwBuffSize, pBuff, &dwBuffUsed);
	LogExtMsg(INFORMATION_LOG,"got message");

	//pBuff = new WCHAR[4096];

	//keyword = audit success,classic
	//Task = category
	//opcode = info
	//Level = information
	//<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
	//<System>
	//	<Provider Name='VMTools'/>
	//	<EventID Qualifiers='0'>108</EventID>
	//	<Level>4</Level>
	//	<Task>0</Task>
	//	<Keywords>0x80000000000000</Keywords>
	//	<TimeCreated SystemTime='2007-03-07T04:23:08.000Z'/>
	//	<EventRecordID>1256</EventRecordID><
	//	<Channel>Application</Channel>
	//	<Computer>vista</Computer>
	//	<Security/>
	//</System>
	//<EventData></EventData>
	//<RenderingInfo Culture='en-AU'>
	//	<Message>The service was stopped.</Message>
	//	<Level>Information</Level>
	//	<Opcode>Info</Opcode>
	//	<Keywords><Keyword>Classic</Keyword></Keywords>
	//</RenderingInfo>
	//</Event>

	//EventLogSourceName	= XML Channel
	//SubmitTime			= XML TimeCreated
	//EventID				= XML EventID
	//Source				= XML Provider Name
	// Username				= XML Security UserID
	// UserType				= NA
	//Hostname			= XML Computer
	//category				= XML 
	//data
	//Strings				= EvtFormatMessageEvent

	if (!bRet) {
		dwRes = GetLastError();
		LogExtMsg(DEBUG_LOG,"EvtFormatMessage Error: %d", dwRes);
		//regardless of the error, try again anyway
		//if( dwRes == ERROR_INSUFFICIENT_BUFFER ) {
			// Allocate the buffer size needed to for the XML event.
			dwBuffSize = dwBuffUsed;
			pBuff = new WCHAR[dwBuffSize/sizeof(WCHAR)];
			bRet = EvtFormatMessage(hPubConfig, Event, NULL, dwPropertyCount, pValues, 9, dwBuffSize, pBuff, &dwBuffUsed);
		//}
		if (!bRet) {
			dwRes = GetLastError();
			LogExtMsg(INFORMATION_LOG,"EvtFormatMessage Error 2: %d", dwRes);
			delete[] pBuff;
			delete[] pValues;
			EvtClose(renderContext);
			EvtClose(hPubConfig);
			return dwRes;
		}
	}

	MsgCache *ecur;
	ecur = (MsgCache *)malloc(sizeof(MsgCache));
	if (ecur) {
		strncpy_s(ecur->Hostname,_countof(ecur->Hostname),"unknown",_TRUNCATE);
		ecur->criticality=0;
		ecur->SafedCounter=0;
		strncpy_s(ecur->SubmitTime,_countof(ecur->SubmitTime),"not yet",_TRUNCATE);
		ecur->ShortEventID;
		strncpy_s(ecur->SourceName, 100, "Unknown",_TRUNCATE);
		strncpy_s(ecur->EventLogSourceName, _countof(ecur->EventLogSourceName), "System",_TRUNCATE);
		strncpy_s(ecur->UserName, 256, "N/A",_TRUNCATE);
		strncpy_s(ecur->SIDType, 100, "N/A",_TRUNCATE);
		strncpy_s(ecur->szCategoryString, 256, "None",_TRUNCATE);
		ecur->DataString[0] = '\0';
		ecur->szTempString[0] = '\0';
		ecur->EventLogCounter=0;
		ecur->seenflag=0;
		ecur->next=NULL;
		ecur->prev=NULL;
		char tempevent[8192];
		char *start,*end;
		WideCharToMultiByte(CP_ACP,0,pBuff,-1,tempevent,8192,NULL,NULL);
		//DMM LogExtMsg(INFORMATION_LOG,"%s",tempevent);
		//Hostname			= XML Computer
		start = strstr(tempevent,"<Computer");
		if (start) {
			start = strstr(start,">");
			if (start) {
				start = start+1;
				end = strstr(start,"<");
				if (end) {
					strncpy_s(ecur->Hostname,_countof(ecur->Hostname),start,end-start);
				}
			}
		}
		ecur->criticality = 0;
		ecur->SafedCounter = 0;
		////SubmitTime			= XML TimeCreated
		strncpy_s(ecur->SubmitTime, 26,SubmitTime,_TRUNCATE);
		////EventID				= XML EventID
		ecur->ShortEventID = EventID; 

		////EventLogSourceName				= XML Channel
		start = strstr(tempevent,"<Channel");
		if (start) {
			start = strstr(start,">");
			if (start) {
				start = start+1;
				end = strstr(start,"<");
				if (end) {
					strncpy_s(ecur->EventLogSourceName, _countof(ecur->EventLogSourceName), start,end-start);
					for (DWORD i=0; i < dwNumEventLogs + dwNumCustomEventLogs; i++) {
						if (strcmp(ecur->EventLogSourceName,EventLogSourceName[i]) == 0) {
							EventTriggered = i;
							break;
						}
					}
					if (!hEvtBookmark[EventTriggered]) hEvtBookmark[EventTriggered] = EvtCreateBookmark(NULL);
					if (EvtUpdateBookmark(hEvtBookmark[EventTriggered], Event)) {
						//render the bookmark straight away and pop it in the node
						EvtRender(NULL, hEvtBookmark[EventTriggered], EvtRenderBookmark, SIZE_EVENTREAD, ecur->Bookmark, &dwEventIDSize, NULL);
					} else {
						LogExtMsg(INFORMATION_LOG,"Error in bookmark: %d",GetLastError());
					}
				}
			}
		}

		////Source				= XML Provider Name
		start = strstr(tempevent,"<Provider");
		if (start) {
			start = strstr(start,"'");
			start = start+1;
			if (start) {
				end = strstr(start,"'");
				if (end) {
					strncpy_s(ecur->SourceName, 100, start,end-start);
				}
			}
		}

		//// Username				= XML Security UserID
		start = strstr(tempevent,"<Security");
		if (start) {
			end = strstr(start,">");
			start = strstr(start,"'");
			if (start && end && start < end) {
				start = start+1;
				end = strstr(start,"'");
				if (end) {
					strncpy_s(ecur->UserName, 256, start,end-start);
				}
			} else {
				//fall back on the TargetUserName, then the SubjectUserId
				start = strstr(tempevent,"<Data Name='TargetUserName'");
				if (start) {
					start = strstr(start,">");
					end = strstr(start,"<");
					if (start && end && start < end) {
						start = start+1;
						strncpy_s(ecur->UserName, 256, start,end-start);
					}
				} else {
					start = strstr(tempevent,"<Data Name='SubjectUserName'");
					if (start) {
						start = strstr(start,">");
						end = strstr(start,"<");
						if (start && end && start < end) {
							start = start+1;
							strncpy_s(ecur->UserName, 256, start,end-start);
						}
					} else {
						start = strstr(tempevent,"<Data Name='AccountName'");
						if (start) {
							start = strstr(start,">");
							end = strstr(start,"<");
							if (start && end && start < end) {
								start = start+1;
								strncpy_s(ecur->UserName, 256, start,end-start);
							}
						}
					}
				}
			}
		}
		char* euname = strstr(ecur->UserName,"@");
		if(euname){//remove the domain name if any   -> user@domain
			ecur->UserName[euname - (ecur->UserName)] = '\0';
		}

		////EventLogKeywords		= XML Keywords
		ecur->EventLogKeyword=pValues[EvtSystemKeywords].UInt64Val;

		////EventLogType			= XML Level
		//4 - information
		//3 - warning
		//2 - error
		//0 - information (USE KEYWORDS)
		int EventLogLevel=(EvtVarTypeNull == pValues[EvtSystemLevel].Type) ? 0 : pValues[EvtSystemLevel].ByteVal;
		ecur->EventLogLevel=0;
		strncpy_s(ecur->EventLogType,_countof(ecur->EventLogType),"Unknown",_TRUNCATE);
		if (EventLogLevel == 4) {
			ecur->EventLogLevel=TYPE_INFO;
			strncpy_s(ecur->EventLogType,_countof(ecur->EventLogType),"Information",_TRUNCATE);
		} else if (EventLogLevel == 3) {
			ecur->EventLogLevel=TYPE_WARN;
			strncpy_s(ecur->EventLogType,_countof(ecur->EventLogType),"Warning",_TRUNCATE);
		} else if (EventLogLevel == 2) {
			ecur->EventLogLevel=TYPE_ERROR;
			strncpy_s(ecur->EventLogType,_countof(ecur->EventLogType),"Error",_TRUNCATE);
		} else if (EventLogLevel == 0) {
			//DMM
			if (ecur->EventLogKeyword & 0x10000000000000) {
				//Audit Failure
				ecur->EventLogLevel=TYPE_FAILURE;
				strncpy_s(ecur->EventLogType,_countof(ecur->EventLogType),"Failure Audit",_TRUNCATE);
			} else if (ecur->EventLogKeyword & 0x20000000000000) {
				//Audit Success
				ecur->EventLogLevel=TYPE_SUCCESS;
				strncpy_s(ecur->EventLogType,_countof(ecur->EventLogType),"Success Audit",_TRUNCATE);
			}
		}

		//######## TEST
		//Keywords are resolved using the provider metadata
		//TIME -					0x8000000000000010
		//<blank> -					0x8000000000000000
		//Classic -					0x80000000000000
		//Failure/Installation -	0x8000000000000028 (32 + 8)
		//Reboot -					0x8000000000000040
		//State -					0x8000000000000080
		//Success/Download -		0x8000000000000014 (16 + 4)
		//Success/Installation -	0x8000000000000018 (16 + 8)
		//Time-						0x8000000000000010
		//Audit Success-			0x8020000000000000
		//Audit Failure-			0x8010000000000000


//$ grep EVENTKEYS SNAREDebug.log | cut -d" " -f7 | sort | uniq -c
//    106 <keywords>:<EventLogKeyword>|0:
// 107528 <keywords>:<EventLogKeyword>|0:<Keyword>Classic</Keyword>
//     12 <keywords>:<EventLogKeyword>|128:<Keyword>State</Keyword>
//    221 <keywords>:<EventLogKeyword>|16:<Keyword>Time</Keyword>
//    128 <keywords>:<EventLogKeyword>|20:<Keyword>Download</Keyword><Keyword>Success</Keyword>
//     77 <keywords>:<EventLogKeyword>|24:<Keyword>Installation</Keyword><Keyword>Success</Keyword>
//    441 <keywords>:<EventLogKeyword>|36028797018963968:<Keyword>Classic</Keyword>
//     42 <keywords>:<EventLogKeyword>|40:<Keyword>Installation</Keyword><Keyword>Failure</Keyword>
//     29 <keywords>:<EventLogKeyword>|4503599627370496:<Keyword>Audit
//     11 <keywords>:<EventLogKeyword>|64:<Keyword>Reboot</Keyword>
// 238080 <keywords>:<EventLogKeyword>|9007199254740992:<Keyword>Audit
//
//$ grep EVENTLEVEL SNAREDebug.log | cut -d" " -f7 | sort | uniq -c
// 238143 <level>:<EventLogLevel>|0:Information
//  48374 <level>:<EventLogLevel>|2:Error
//   4922 <level>:<EventLogLevel>|3:Warning
//  55238 <level>:<EventLogLevel>|4:Information
		//######## /TEST

		////category				= XML 
		////Strings				= XML Message
		start = strstr(tempevent,"<Message");
		if (start) {
			start = strstr(start,">");
			start = start+1;
			if (start) {
				end = strstr(start,"<");
				if (end) {
					strncpy_s(ecur->szTempString, MAX_EVENT, start,end-start);
				}
			}
		}

		dwWaitRes = WaitForSingleObject(hMutex,1000);
		if (dwWaitRes == WAIT_OBJECT_0) {
			if (EventTail) {
				ecur->prev = EventTail;
				EventTail->next = ecur;
			}
			EventTail = ecur;
			if (!EventHead) EventHead = ecur;
		} else {
			LogExtMsg(INFORMATION_LOG,"FAILED WAIT");
		}
		EventCount++;
		ReleaseMutex(hMutex);
	} else {
		LogExtMsg(INFORMATION_LOG,"Unable to allocate latest VistaEvent cache\n");
	}

	LogExtMsg(INFORMATION_LOG,"Message Complete\n");
    //Cleanup
    delete[] pBuff;
    delete[] pValues;
	EvtClose(hPubConfig);
	EvtClose(renderContext);
    return dwRes;

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
	GetHANDLER_ACTIVE(&HANDLER_ACTIVE);
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
	else {LogExtMsg(ERROR_LOG,"NO MEMORY LEFT!!!"); return false;}
	if (*szSendStringBkp)*szSendStringBkp[0]='\0';
	else {LogExtMsg(ERROR_LOG,"NO MEMORY LEFT!!!"); return false;}
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

//////////////////////DEBUG////////////////// 0xc0000417 STATUS_INVALID_CRUNTIME_PARAMETER
void myInvalidParameterHandler(const wchar_t* expression,
   const wchar_t* function, 
   const wchar_t* file, 
   unsigned int line, 
   uintptr_t pReserved)
{
	LogExtMsg(ERROR_LOG,"Invalid parameter detected in function %s.File: %s Line: %d\n", function, file, line);
    LogExtMsg(ERROR_LOG,"Expression: %s\n", expression);
  
}
int seh_filter(unsigned int code, struct _EXCEPTION_POINTERS* ep)
{
	LogExtMsg(ERROR_LOG,"SEH:EXCEPTION %d\n at 0x%08x", code, ep->ExceptionRecord->ExceptionAddress);
	// Structured Exception Handling
    // Generate error report
    // Execute exception handler
    return EXCEPTION_EXECUTE_HANDLER;
}

LONG WINAPI MyUnhandledExceptionFilter(PEXCEPTION_POINTERS pExceptionPtrs)
{
  // Do something, for example generate error report
  //..
  // Execute default exception handler next
  return EXCEPTION_EXECUTE_HANDLER; 
} 
void my_terminate_handler()
{
  // Abnormal program termination (terminate() function was called)
  // Do something here
  // Finally, terminate program

#ifdef _M_X64
	LogExtMsg(ERROR_LOG,"SafedAgent Version %s for Windows x86-64 is currently active.</font></CENTER><P>",SAFED_VERSION);
#elif _M_IA64
	LogExtMsg(ERROR_LOG,"SafedAgent Version %s for Windows x86-64 is currently active.</font></CENTER><P>",SAFED_VERSION);
#else
	BOOL f64 = FALSE;
	typedef BOOL (WINAPI *LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);
	LPFN_ISWOW64PROCESS fnIsWow64Process;

    fnIsWow64Process = (LPFN_ISWOW64PROCESS) GetProcAddress(GetModuleHandle(TEXT("kernel32")),"IsWow64Process");
  
    if (NULL != fnIsWow64Process) {
        if (!fnIsWow64Process(GetCurrentProcess(),&f64)) {
            // handle error
			f64 = FALSE;
        }
    }

	LogExtMsg(ERROR_LOG,"SafedAgent Version %s for Windows x86-32 is currently active" ,SAFED_VERSION);
#endif
    LogExtMsg(ERROR_LOG,"ERROR HANDLER IS ACTIVE.!!!!!!");
	LogExtMsg(ERROR_LOG,"TERMINATE:LAST ERROR %d\n", GetLastError());

    exit(1); 
}


//////////////////////DEBUG////////////////// 0xc0000417 STATUS_INVALID_CRUNTIME_PARAMETER

void CSafedService::Run()
{
	DWORD dwEventLogRecords = 0, dwOldestEventLogRecord = 0, dwNewestEventLogRecord = 0,
		dwEvLogStart = 0, dwEvLogCounter = 0, dwNumberOfBytesToRead = 0, 
		dwBytesRead = 0, dwMinNumberOfBytesNeeded = 0, dwCancel = 0, dwClose = 0;

	static int recovery = 0;
	static int CollectorThreadStopped = 0;
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
	TCHAR ExpandedString[MAX_EVENT]="";
	TCHAR DataString[MAX_EVENT]="";
	TCHAR UserName[256]="";
	TCHAR szCategoryString[256]=""; // "Detailed Tracking"

  	TCHAR szError[MAX_STRING]="";

	TCHAR SubmitTime[26]="None Yet";

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

	int etype=0;	// eventlog type
	int stype=0;	// source type
	UINT EventTriggered=0;

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
	time_t currenttime,lasttime;
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

	LogExtMsg(INFORMATION_LOG,"The page size for this system is %u bytes.\n", si.dwPageSize);

 //    Retrieve the working set size of the process.
	if (!GetProcessMemoryInfo(hProcess,&memCounters,sizeof(PROCESS_MEMORY_COUNTERS))) {
        LogExtMsg(WARNING_LOG,"GetProcessMemoryInfo failed (%d)", GetLastError() );
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
        LogExtMsg(WARNING_LOG,"SetProcessWorkingSetSize failed (%d)", GetLastError());
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


	LogExtMsg(INFORMATION_LOG,"NetEye Safed is Running");

	//discovery process !!
	PROCESS_INFORMATION piProcessInfo;
	piProcessInfo.dwProcessId = 0;
	//Start discovery process timestamp
	DWORD SADStrt = 0;
	// READ in our data
	if(!InitFromRegistry(&dwTimesADay, &dwNextTimeDiscovery, &dwForceNextTime, &dwSysAdminEnable, &ActivateChecksum, &dwCritAudit, &ClearTabs, &szSendString, &szSendStringBkp))goto nomemory;;
	//if(!InitEvents())goto nomemory;;
	if(WEBSERVER_ACTIVE) {
		if(InitWebServer((unsigned short)dwPortNumber,lpszPassword,lpszIPAddress) >0) {
			StartWebThread(m_hCollectEvent[1]);
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

	retThread = StartSafedEThread(m_hEventList[1]);



	// Monitor the pipe
	// Set the terminate flag to zero.
	// setting this value to TRUE will terminate the service,
	// and ask it to save it's current status.
	g_Info.bTerminate = FALSE;

	//////////////////////DEBUG////////////////// 0xc0000417 STATUS_INVALID_CRUNTIME_PARAMETER
   if(HANDLER_ACTIVE){
        _invalid_parameter_handler oldHandler, newHandler;
        newHandler = myInvalidParameterHandler;
        oldHandler = _set_invalid_parameter_handler(newHandler);
        // Disable the message box for assertions.
        _CrtSetReportMode(_CRT_ASSERT, 0);

		SetUnhandledExceptionFilter(MyUnhandledExceptionFilter);
		set_terminate(my_terminate_handler);
	}
//////////////////////DEBUG////////////////// 0xc0000417 STATUS_INVALID_CRUNTIME_PARAMETER

 __try {
//////////////////////DEBUG////////////////// 0xc0000417 STATUS_INVALID_CRUNTIME_PARAMETER
//   // Call printf_s with invalid parameters.
//   char* formatString;
//   formatString = NULL;
//   printf(formatString);
//////////////////////DEBUG////////////////// 0xc0000417 STATUS_INVALID_CRUNTIME_PARAMETER

	
	LogExtMsg(INFORMATION_LOG,"Entering main loop SafedAgent Version %s.", SAFED_VERSION); 
	// This is the service's main run loop.
	int lastwait = 0,lastblockcount=0;
    while (m_bIsRunning) 
	{
		int wait = 0, blockcount = 0;
		// TODO: Add code to perform processing here  
		// If we have been asked to terminate, do so.
		if(g_Info.bTerminate)
		{
			m_bIsRunning=0;
			break;
		}

		//while (EventHead && blockcount < 200) {//DMM
		while (EventHead) {
			LogExtMsg(INFORMATION_LOG,"VISTA: Checking VISTA Events..");
			static char szTempString[MAX_EVENT]=""; // Approximately the maximum we could reasonably expect to transfer over UDP
			MsgCache *CurrentEvent;
			dwWaitRes = WaitForSingleObject(hMutex,1000);
			if (dwWaitRes == WAIT_OBJECT_0) {
				CurrentEvent = EventHead;
				EventHead = EventHead->next;
				if (EventHead) EventHead->prev = NULL;
				else EventTail = NULL;
				CurrentEvent->prev=NULL;
				CurrentEvent->next=NULL;
			} else {
				LogExtMsg(INFORMATION_LOG,"FAILED WAIT 2");
			}
			EventCount--;
			ReleaseMutex(hMutex);
			//DMM

			if (!CurrentEvent->EventLogSourceName) {
				LogExtMsg(INFORMATION_LOG,"FAILED message!!");
			}
			LogExtMsg(INFORMATION_LOG,"VISTA: Event found, processing data for VISTA event");
			if (strstr(CurrentEvent->EventLogSourceName,"Security") != NULL) {
				stype = LOG_SEC;
				EventTriggered = 0;
			} else if (strstr(CurrentEvent->EventLogSourceName,"System") != NULL) {
				stype = LOG_SYS;
				EventTriggered = 1;
			} else if (strstr(CurrentEvent->EventLogSourceName,"Application") != NULL) {
				stype = LOG_APP;
				EventTriggered = 2;
			} else if (strstr(CurrentEvent->EventLogSourceName,"Directory Service") != NULL) {
				stype = LOG_DIR;
				EventTriggered = 3;
			} else if (strstr(CurrentEvent->EventLogSourceName,"DNS Server") != NULL) {
				stype = LOG_DNS;
				EventTriggered = 4;
			} else if (strstr(CurrentEvent->EventLogSourceName,"DFS Replication") != NULL) {
				stype = LOG_REP;
				EventTriggered = 5;
			}

			etype = CurrentEvent->EventLogLevel;

			EventID = CurrentEvent->ShortEventID;

			if (dwObjectiveCount){
				MatchCount=0;
				MatchPointer=MatchList; // Start of the list
				ResetCurrentNode();
				if(!MatchPointer) {
					// Something seriously wierd is happening if MatchPointer is null.
					// Leave the messages as they are and try again later.
					LogExtMsg(INFORMATION_LOG,"Match Pointer has gone away");
					dwWaitRes = WaitForSingleObject(hMutex,1000);
					if (dwWaitRes == WAIT_OBJECT_0) {
						if (EventTail) {
							CurrentEvent->prev = EventTail;
							EventTail->next = CurrentEvent;
						}
						EventTail = CurrentEvent;
						if (!EventHead) EventHead = CurrentEvent;
					} else {
						LogExtMsg(INFORMATION_LOG,"FAILED WAIT 3");
					}
					EventCount++;
					ReleaseMutex(hMutex);
					break;
				}
				do {
					__try {
					//try {
						*MatchPointer=FastCheckObjective(EventID,etype,stype);
					} __except(seh_filter(GetExceptionCode(), GetExceptionInformation())){
					//catch(...) {
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
				
				if(g_Info.bTerminate) {
					m_bIsRunning=0;
					free(CurrentEvent);
					break;
				}
				if(!MatchCount) {
					LogExtMsg(INFORMATION_LOG,"Match Checker: No matches found, clearing data for VISTA event");
					free(CurrentEvent);
					continue;
				}
			}
			if (!CurrentEvent) {
				//strncpy_s(SubmitTime,_countof(SubmitTime),"",_TRUNCATE);
				//free(CurrentEvent);
				break;
			}
			LogExtMsg(INFORMATION_LOG,"FastCheckObjective: found matches (%d)",MatchCount);
			LogExtMsg(INFORMATION_LOG,"VISTA: done");
			//DMM
			if(strlen(CurrentEvent->EventLogSourceName) && strlen(CurrentEvent->SubmitTime) && strlen(CurrentEvent->SourceName) && CurrentEvent->EventLogLevel && strlen(CurrentEvent->Hostname) && strlen(CurrentEvent->szTempString) && strlen(CurrentEvent->szCategoryString))
			{
				LogExtMsg(INFORMATION_LOG,"Event is ready, checking objectives");
				char *stringp;
				
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
				int tcriticality=0;
				char matchedstr[512]="";
				
				LogExtMsg(INFORMATION_LOG,"dwObjectiveCount: %d", dwObjectiveCount);
				// Check objectives
				// NOTE: If there are no objectives, send nothing?
				if(!dwObjectiveCount) {
					nodematch=0;
				} else {
					MatchCount=0;
					MatchPointer=MatchList; // Start of the list
					
					do {
						LogExtMsg(INFORMATION_LOG,"begin MatchCount: %d", MatchCount);
						// Some of the MS System calls used in CheckObjective are buggy.
						__try {
						//try {
							tcriticality=CheckObjective(*MatchPointer,ShortEventID,CurrentEvent->UserName,CurrentEvent->szTempString,matchedstr);
						} __except(seh_filter(GetExceptionCode(), GetExceptionInformation())){
						//} catch(...) {
							LogExtMsg(INFORMATION_LOG,"CheckObjective CRASH");
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
							if(CurrentEvent->criticality < tcriticality) {
								CurrentEvent->criticality = tcriticality;
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
						free(CurrentEvent);
						break;
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
		
					char CurrentDate[16]="";
					BOOL DataSent=0;
					DWORD tmpCounter=0;
					DWORD dwWaitCount = WaitForSingleObject(hMutexCount,1000);
					if(dwWaitCount == WAIT_OBJECT_0) {

						if(dwSyslogHeader) {
							DWORD tdwSyslog;
							
							syslogdate(CurrentDate,&newtime);
							
							// HERE: Split out criticality.
							if(dwSyslogDynamic) {
								tdwSyslog=((7-CurrentEvent->criticality) & 7) | ((dwSyslog >> 3) << 3);
							} else {
								tdwSyslog=dwSyslog;
							}
							
							_snprintf_s(header,_countof(header),_TRUNCATE,"<%ld>%s %s Safed[%d][%d]:",tdwSyslog,CurrentDate,Hostname,pid,SafedCounter);
						} else {
							_snprintf_s(header,_countof(header),_TRUNCATE,"%s%sSafed[%d][%d]:",Hostname,DELIM,pid,SafedCounter);
						}
						stringp=CurrentEvent->szTempString;
						while(*stringp) {
							// TAB
							if(*stringp==9) {
								*stringp=' ';
							}
							stringp++;
						}

						char UserStr[514];
						if(CurrentEvent->UserName && !strstr(CurrentEvent->UserName,"N/A")){
							char* checkpos=strstr(CurrentEvent->UserName," ");
							if(checkpos){// in case of space in user name put it in ""
								_snprintf_s(UserStr,_countof(UserStr),_TRUNCATE,"\"%s\"",CurrentEvent->UserName);
							}else{
								_snprintf_s(UserStr,_countof(UserStr),_TRUNCATE,"%s",CurrentEvent->UserName);
							}
							//_snprintf_s(szSendString,dwMaxMsgSize*sizeof(char),_TRUNCATE,"%s%s%s%seventid=%ld%s%s%suser=%s%s%s%s%s%s%s%s%s%s%s%s%d\n",header,DELIM,CurrentEvent->SubmitTime,DELIM,ShortEventID,DELIM,CurrentEvent->EventLogSourceName,DELIM,CurrentEvent->UserName,DELIM,CurrentEvent->SIDType,DELIM,CurrentEvent->EventLogType,DELIM,CurrentEvent->Hostname,DELIM,CurrentEvent->EventLogSourceName,DELIM,CurrentEvent->szTempString,DELIM,EventLogCounter[EventTriggered]);
						}else{//if user field = SYSTEM then check matchet in the payload of the event
							char* checkpos=strstr(matchedstr," ");
							if(checkpos){// in case of space in user name put it in ""
								_snprintf_s(UserStr,_countof(UserStr),_TRUNCATE,"\"%s\"",matchedstr);
							}else{
								_snprintf_s(UserStr,_countof(UserStr),_TRUNCATE,"%s",matchedstr);
							}
							//_snprintf_s(szSendString,dwMaxMsgSize*sizeof(char),_TRUNCATE,"%s%s%s%seventid=%ld%s%s%suser=%s%s%s%s%s%s%s%s%s%s%s%s%d\n",header,DELIM,CurrentEvent->SubmitTime,DELIM,ShortEventID,DELIM,CurrentEvent->EventLogSourceName,DELIM,matchedstr,DELIM,CurrentEvent->SIDType,DELIM,CurrentEvent->EventLogType,DELIM,CurrentEvent->Hostname,DELIM,CurrentEvent->EventLogSourceName,DELIM,CurrentEvent->szTempString,DELIM,EventLogCounter[EventTriggered]);
						}
						_snprintf_s(szSendString,dwMaxMsgSize*sizeof(char),_TRUNCATE,"%s%s%s%seventid=%ld%s%s%suser=%s%s%s%s%s%s%s%s%s%s%s%s%d\n",header,DELIM,CurrentEvent->SubmitTime,DELIM,ShortEventID,DELIM,CurrentEvent->EventLogSourceName,DELIM,UserStr,DELIM,CurrentEvent->SIDType,DELIM,CurrentEvent->EventLogType,DELIM,CurrentEvent->Hostname,DELIM,CurrentEvent->EventLogSourceName,DELIM,CurrentEvent->szTempString,DELIM,EventLogCounter[EventTriggered]);

						if(CurrentEvent->DataString) { LogExtMsg(INFORMATION_LOG,"DataString: %s",CurrentEvent->DataString); }
						if(CurrentEvent->szTempString) { LogExtMsg(INFORMATION_LOG,"szTempString: %s",CurrentEvent->szTempString); }
						
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
						if (strlen(szSendString) >= dwMaxMsgSize*sizeof(char) -1) {
							szSendString[strlen(szSendString)-1]='\n';
						} else {
							strncat_s(szSendString,dwMaxMsgSize*sizeof(char),"\n",_TRUNCATE);
						}
						
						if(szSendString) { LogExtMsg(INFORMATION_LOG,"DEBUG: Sending the following string to the server: %s",szSendString); }
						//LogExtMsg(INFORMATION_LOG,"sending...\n");//DMM
						hostcurrentnode=getHostHead();
						while(hostcurrentnode) {
							//LogExtMsg(DEBUG_LOG,"sending data to %s", hostcurrentnode->HostName);//DMM
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
						//LogExtMsg(INFORMATION_LOG,"socket...\n");//DMM
							if(SafedCounter == 1){
								recovery = 0;//avoid to send backuped message from yesterday to the log of today
							}
							if(recovery == 1){// try to send the backuped message
								if( !SendToSocket(hostcurrentnode, szSendStringBkp, (int)strlen(szSendStringBkp), szError, _countof(szError)) )
								{
									if(szError) { LogExtMsg(ERROR_LOG,szError); } 
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
										if(szError) { LogExtMsg(ERROR_LOG,szError); } 
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
							if(CollectorThreadStopped) {
								//if collection thread has been stoped due to send error.
								StartCollectThread(m_hEventList[0]);
								CollectorThreadStopped = 0;
							}
						}
					}
					tmpCounter = SafedCounter;
					ReleaseMutex(hMutexCount);	
					//LogExtMsg(INFORMATION_LOG,"sent!\n");//DMM

					// Did we push out at least one record?
					if(!DataSent) {
						dwEvLogCounter--;
						dwNewestEventLogRecord=dwEvLogCounter;
						LogExtMsg(ERROR_LOG,"Failed to send message, holding position in event log");
						// Break out of the while loop.
						dwWaitRes = WaitForSingleObject(hMutex,1000);
						if (dwWaitRes == WAIT_OBJECT_0) {
							if (EventTail) {
								CurrentEvent->prev = EventTail;
								EventTail->next = CurrentEvent;
							}
							EventTail = CurrentEvent;
							if (!EventHead) EventHead = CurrentEvent;
						}
						EventCount++;
						ReleaseMutex(hMutex);
						//collection thread will been stoped due to send error.
						if(recovery == 1 && !CollectorThreadStopped){
							SetEvent(m_hCollectEvent[0]);
							CollectorThreadStopped = 1;
						}
						break;
					} else {
						//Msg Sent! Update the status and log the event to the webcache
						MyWriteProfileWString("Status",EventLogStatusName[EventTriggered],CurrentEvent->Bookmark);//DMM
						MCCurrent = CurrentEvent;
						strncpy_s(MCCurrent->Hostname,_countof(MCCurrent->Hostname),Hostname,_TRUNCATE);
						MCCurrent->EventLogCounter = EventLogCounter[EventTriggered];
						MCCurrent->SafedCounter = tmpCounter;
						MCCurrent->next = NULL;
						MCCurrent->prev = NULL;
						dwWaitRes = WaitForSingleObject(hMutex,500);
						//LogExtMsg(INFORMATION_LOG,"Loading event into Web cache\n");//DMM
						if(dwWaitRes == WAIT_OBJECT_0) {
							if (MCCount >= WEB_CACHE_SIZE) {
								//Lock Mutex and drop the oldest record
								MsgCache *temp;
								temp = MCTail;
								MCTail = MCTail->prev;
								free(temp);
								MCCount--;
								if (!MCTail) {
									//Something is wrong, recalculate the tail
									MCHead=NULL;
									MCCount = 0;
									MCTail = NULL;
								} else {
									MCTail->next = NULL;
								}
							}
							if (MCHead) {
								MCHead->prev = MCCurrent;
								MCCurrent->next = MCHead;
							}
							MCHead = MCCurrent;
							if (!MCTail) MCTail = MCCurrent;
							MCCount++;
						} else {
							LogExtMsg(WARNING_LOG,"VISTA: EVENT CACHE FAILED!\n");
							if(MCCurrent)free(MCCurrent);
						}
						ReleaseMutex(hMutex);
						
						//LogExtMsg(INFORMATION_LOG,"Increment counter\n");//DMM
						// Increment the NetEye Safed internal event counter
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
				} else {
					free(CurrentEvent);
				}
#ifdef MEMDEBUG
				_CrtDumpMemoryLeaks();
#endif
			} else {
				LogExtMsg(INFORMATION_LOG,"ERROR: Invalid VISTA event.");
				LogExtMsg(INFORMATION_LOG,"%d %d %d %d %d %d %d", strlen(CurrentEvent->EventLogSourceName), strlen(CurrentEvent->SubmitTime), strlen(CurrentEvent->SourceName), CurrentEvent->EventLogLevel, strlen(CurrentEvent->Hostname), strlen(CurrentEvent->szTempString), strlen(CurrentEvent->szCategoryString));
				free(CurrentEvent);
			}
			//LogExtMsg(INFORMATION_LOG,loop\n");//DMM

			blockcount++;
			//free(CurrentEvent);

		}
		// The service performs one check per 2 seconds. This should not be
		// a significant drain on resources.
		LogExtMsg(INFORMATION_LOG,"WaitForSingle - EventList[%d:%d]\n",blockcount,EventCount);
		//in times of heavy load, try to minimise the wait times
		//use the average of this and the last block count
		if (lastblockcount) blockcount = (blockcount + lastblockcount) / 2;
		if (blockcount > 400) wait=0;
		if (blockcount > 200) wait=200;
		else if (blockcount > 150) wait=400;
		else if (blockcount > 100) wait=750;
		else if (blockcount > 50) wait=1250;
		else wait=2000;
		lastblockcount=blockcount;
		lastwait=wait;
		dwWaitRes=WaitForMultipleObjects(2,m_hEventList,FALSE,wait);

		// if(dwWaitRes != WAIT_FAILED && dwWaitRes != WAIT_TIMEOUT)
		if(dwWaitRes != WAIT_FAILED)
		{
			EventTriggered=0;
			stype = LOG_APP;	 // Assume application log if no valid source provided.
			if(dwWaitRes == WAIT_OBJECT_0 + 1) {
				ResetEvent(m_hEventList[1]);
				retThread = StartSafedEThread(m_hEventList[1]);
				if(retThread <= 0 )goto nomemory;
			}else if(dwWaitRes == WAIT_OBJECT_0) {
				//do nothing, this means there has been a web reset event, it will be handled below.
				// this is just to prevent a delay
				ResetEvent(m_hEventList[0]);
				LogExtMsg(INFORMATION_LOG,"HandleWebThread: WEB Server Reset event received");
			} else if (dwWaitRes == WAIT_TIMEOUT) {
 				LogExtMsg(DEBUG_LOG,"Timeout hit");
				if(dwSysAdminEnable && dwTimesADay){
					if( piProcessInfo.dwProcessId && (checkEndOfASDiscoveryProcess(&piProcessInfo) > 0)){
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
								LogExtMsg(WARNING_LOG,"Cannot allocate memory for our internal Objective match list");
								dwObjectiveCount=0;
							}
						}
						ResetCurrentNode();
					}
				}
			} else {
				LogExtMsg(DEBUG_LOG,"Warning: An event occured that I am not programmed to deal with. Continuing");
				continue;
			}
			//firstly, check to see if the web server needs resetting:
			if (WebResetFlag) {
				LogExtMsg(INFORMATION_LOG,"HandleWebThread: resetting the web thread");
//DMM Old Status Save
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
					if(!InitEvents())goto nomemory;;
					// Open our outgoing sockets.
					OpenSockets();

					// Ok, we have finished our general configuration reads.

					if(WEBSERVER_ACTIVE) {
						LogExtMsg(INFORMATION_LOG,"Starting web thread.");
						if(InitWebServer((unsigned short)dwPortNumber,lpszPassword,lpszIPAddress) >0) {
							StartWebThread(m_hCollectEvent[1]);
							StartCollectThread(m_hEventList[0]); //DMM potential for duplication
						} else {
							//sleep and try again
							Sleep(2000);
							if(InitWebServer((unsigned short)dwPortNumber,lpszPassword,lpszIPAddress) >0) {
								StartWebThread(m_hCollectEvent[1]);
								StartCollectThread(m_hEventList[0]); //DMM potential for duplication
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
							LogExtMsg(WARNING_LOG,"Cannot allocate memory for our internal Objective match list");
							dwObjectiveCount=0;
						}
					}
					ResetCurrentNode();


				} else if (WebResetFlagTmp == BASIC_WEB_RESET) {
					if(WEBSERVER_ACTIVE) {
						LogExtMsg(INFORMATION_LOG,"Restarting web thread.");
						CloseWebServer();
						if(InitWebServer((unsigned short)dwPortNumber,lpszPassword,lpszIPAddress) >0) {
							StartWebThread(m_hCollectEvent[1]);
							StartCollectThread(m_hEventList[0]); //DMM potential for duplication
						} else {
							//sleep and try again
							Sleep(2000);
							if(InitWebServer((unsigned short)dwPortNumber,lpszPassword,lpszIPAddress) >0) {
								StartWebThread(m_hCollectEvent[1]);
								StartCollectThread(m_hEventList[0]); //DMM potential for duplication
							} else {
								LogExtMsg(ERROR_LOG,"Unable to start web server [2], disabling.");
								WEBSERVER_ACTIVE = 0;
							}
						}
					}
					hostcurrentnode=getHostHead();
					while(hostcurrentnode) {
						if(hostcurrentnode->Socket != INVALID_SOCKET) {
							CloseSocket(hostcurrentnode->Socket, hostcurrentnode->tlssession);
							hostcurrentnode->Socket=INVALID_SOCKET;
						}
						hostcurrentnode=hostcurrentnode->next;
					}
				}

			}
		}
		//Possible that EvtRender on a non-existent bookmark might return with "<BookmarkList Direction='backward'>\n</BookmarkList>" if an event log is uninitialised.
		//To avoid this condition, hEvtBookmark is left as null so we can easily skip unwanted bookmarks
//DMM Old Status Save
		//LogExtMsg(INFORMATION_LOG,"WaitForSingle Complete\n");//DMM
    }
	/////////////////////DEBUG//////////
  }__except(seh_filter(GetExceptionCode(), GetExceptionInformation())){
	LogExtMsg(ERROR_LOG,"Safed EXCEPTION");
  }
	/////////////////////DEBUG//////////
	nomemory:;
	LogExtMsg(INFORMATION_LOG,"NetEye Safed Closing");

	TerminateSAProcess(&piProcessInfo);

	if (szSendString) free(szSendString);
	if (szSendStringBkp) free(szSendStringBkp);
//DMM Old Status Save
	if(retThread > 0 ){
		if(MatchList) {
			free(MatchList);
		}
		CloseSafedE();
		dwWaitRes=WaitForSingleObject(m_hEventList[1],5000);
		if(dwWaitRes != WAIT_FAILED)
		{
			if(dwWaitRes == WAIT_OBJECT_0) {
					ResetEvent(m_hEventList[dwNumEventLogs + 1]);
			}
		}
	}
	CloseWebServer();

	deinitSAD();	

	if(sentIndex && strlen(sentFile)){
		SetSentIndex(sentFile,sentIndex);
	}
//DMM Old Status Save

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

	cleanEventLogStructures();
	if( m_hEventList[0] ) ::CloseHandle(m_hEventList[0]);
	if( m_hEventList[1] ) ::CloseHandle(m_hEventList[1]);
	if( m_hCollectEvent[0] )	::CloseHandle(m_hCollectEvent);
	if( m_hCollectEvent[1] )	::CloseHandle(m_hCollectEvent);
	if( web_hEventList[0] ) ::CloseHandle(web_hEventList[0]);
	if( web_hEventList[1] ) ::CloseHandle(web_hEventList[1]);
	if( web_hEventList[2] ) ::CloseHandle(web_hEventList[2]);

//DMM OLD Close subscriber handle

	// Free memory used by the objectives lists
	DestroyList();

	if(hMutex)CloseHandle(hMutex);
	if(hMutexFile)CloseHandle(hMutexFile);
	if(hMutexCount)CloseHandle(hMutexCount);

	deinitSocketMutex();
	deinitLog();
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

//a simple wild match is = one or more stars, a word, then one or more stars (i.e. /\*+[^*?]*\*+/ )
BOOL IsSimpleWildMatch(char *pattern)
{
	char *c;
	int seq=0; //0 - opening star, 1 - star sequence, 2 - word, 3 - closing star sequence
	//bad pointer
	if (!pattern) return(0);
	//empty string
	if (*pattern == 0) return(0);
	c=pattern;
	while (*c) {
		if (*c == '?') {
			//definitely not simple
			return FALSE;
		} else if (*c == '*') {
			if (seq == 0) {
				//found the opening star
				seq = 1;
			} else if (seq == 2) {
				//found the closing star
				seq = 3;
			} else if (seq == 1 || seq == 3) {
				//star sequence
//				continue;
			}
		} else {
			if (seq == 1) {
				//start word
				seq = 2;
			} else if (seq == 2) {
				//word collection
				//continue;
			} else {
				// not simple
				return FALSE;
			}
		}
		c++;
	}
	//if we made it to the final sequence, return true
	if (seq == 3) return TRUE;
	else return FALSE;
}

void ExtractSimpleWildMatch(char *pattern,char *newpat,int size)
{
	char *c,*n;
	int seq=0;
	//bad pointer
	if (!pattern) return;
	//empty string
	if (*pattern == 0) return;
	c = pattern;
	n = newpat;
	while (*c && size > 1) {
		if (*c == '*') {
			//continue;
		} else {
			*n=*c;
			n++;
			size--;
		}
		c++;
	}
	*n='\0';
}

// Match a DOS wildcard against a string.
// eg: wildmatch("c:\blah\abc???.*","c:\blah\abc123.txt");
int wildmatch(char *pattern, char *source, int top = 1)
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

	//check if we're using a simple pattern
	if (top && IsSimpleWildMatch(pattern)) {
		//extract the simple match
		char newpat[512]="";
		ExtractSimpleWildMatch(pattern,newpat,512);
		if (strstr(source,newpat) == NULL) return 0;
		else return 1;
	}

    switch(*pattern){
    case '*':
        return wildmatch(pattern, source+1,0) || wildmatch(pattern+1, source,0) || wildmatch(pattern+1, source+1,0);
    case '?':
        return wildmatch(pattern+1, source+1,0);
    default:
        return (*pattern == *source) && wildmatch(pattern+1, source+1,0);
    }
}

char *stristr(const char *String, const char *Pattern)
{
      char *pptr, *sptr, *start;

      for (start = (char *)String; *start != NULL; start++)
      {
            /* find start of pattern in string */
            for ( ; ((*start!=NULL) && (toupper(*start) != toupper(*Pattern))); start++)
                  ;
            if (NULL == *start)
                  return NULL;

            pptr = (char *)Pattern;
            sptr = (char *)start;

            while (toupper(*sptr) == toupper(*pptr) || ( (*sptr == ' ' || *sptr == '	' || *sptr == '\n' || *sptr == '\r') && (*pptr == ' ' || *pptr == '	' || *pptr == '\n' || *pptr == '\r') ) )
            {
                  sptr++;
                  pptr++;

                  /* if end of pattern then pattern was found */

                  if (NULL == *pptr)
                        return (start);
            }
      }
      return NULL;
}

// Match a DOS wildcard against a string.
// eg: wildmatch("C:\blah\abc???.*","c:\blah\abc123.txt");
int wildmatchi(char *pattern, char *source, int top = 1)
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

	//check if we're using a simple pattern
	if (top && IsSimpleWildMatch(pattern)) {
		//extract the simple match
		char newpat[512]="";
		ExtractSimpleWildMatch(pattern,newpat,512);
		if (stristr(source,newpat) == NULL) return 0;
		else return 1;
	}

    switch(*pattern){
    case '*':
        return wildmatchi(pattern, source+1,0) || wildmatchi(pattern+1, source,0) || wildmatchi(pattern+1, source+1,0);
    case '?':
        return wildmatchi(pattern+1, source+1,0);
    default:
		char lpattern,lsource;
		lpattern = tolower(*pattern);
		lsource = tolower(*source);
		
        return (lpattern == lsource) && wildmatchi(pattern+1, source+1,0);
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



BOOL CheckLogExists(TCHAR *LogName, int LeaveRetention)
{
	TCHAR szKeyName[MAX_STRING]="";
	LPBYTE pSourceName=0;
	HKEY   hk = (HKEY)0;
	LPBYTE pStrings = 0;

	DWORD dwType; // Temporary variable.

	if(!LogName) return(0);
			
	wsprintf(szKeyName, _T("SYSTEM\\CurrentControlSet\\Services\\EventLog\\%s"), LogName);

	if(RegOpenKeyEx(HKEY_LOCAL_MACHINE, szKeyName, 0L, KEY_READ|KEY_SET_VALUE, &hk) != ERROR_SUCCESS) {
		if(LogName) { LogExtMsg(WARNING_LOG,"Cannot determine if log %s exists - openkey failed",LogName); } 
		return(FALSE);
	}

	//No need to check for "File" under 2008/Vista

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
	LogExtMsg(WARNING_LOG,"Log retention settings are set to %d for log %s",RetentionValue,LogName);
	
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
			//LogExtMsg(DEBUG_LOG,"FCO: Event number looks good..");
		if((ShortEventID >= tnode->event_bottom && ShortEventID <= tnode->event_top)|| tnode->event_bottom == AUDIT_ALL) {
			LogExtMsg(INFORMATION_LOG,"FCO: Checking event %d against %d, and etype %d against %d, and stype %d against %d",eventnumber,tnode->event_top,etype,tnode->eventlogtype,stype,tnode->sourcename);
			if((etype & tnode->eventlogtype) && (stype & tnode->sourcename)) {
				//LogExtMsg(DEBUG_LOG,"FCO: etype/stype looks good!");
				// Are we including users, or excluding.
				currentnode = currentnode->next;
				return(tnode);
			}
		}
		currentnode = currentnode->next;
	} while(currentnode);
	//LogExtMsg(DEBUG_LOG,"FCO: Out. No more valid items.");
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
	

	LogExtMsg(DEBUG_LOG,"Match->excludeflag: %d, Match->excludeidflag: %d, Match->excludematchflag: %d ", Match->excludeflag, Match->excludeidflag, Match->excludematchflag);
	regmatch_t pm[1];

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


	LogExtMsg(DEBUG_LOG,"Match failed");

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
	//Grab the Object Access GUID
	AuditLookupCategoryGuidFromCategoryId(AuditCategoryObjectAccess,&guidObjectAccess);
	
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
		GUID *list;
		ULONG numcat;
		PSTR pszName;
		AuditEnumerateSubCategories(&guidObjectAccess,FALSE,&list,&numcat);
		for (UINT i=0; i<numcat; i++) {
			AuditLookupSubCategoryName(&list[i],&pszName);
			if (!strncmp(pszName,"File System",strlen("File System")+1)) {
				SetObjectAuditFlag(OBJACCESS_FILE_SYS,list[i],pszName,SuccessFailure);
			} else if (!strncmp(pszName,"Registry",strlen("Registry")+1)) {
				SetObjectAuditFlag(OBJACCESS_REG,list[i],pszName,SuccessFailure);
			} else if (!strncmp(pszName,"Kernel Object",strlen("Kernel Object")+1)) {
				SetObjectAuditFlag(OBJACCESS_KERN_OBJ,list[i],pszName,SuccessFailure);
			} else if (!strncmp(pszName,"SAM",strlen("SAM")+1)) {
				SetObjectAuditFlag(OBJACCESS_SAM,list[i],pszName,SuccessFailure);
			} else if (!strncmp(pszName,"Certification Services",strlen("Certification Services")+1)) {
				SetObjectAuditFlag(OBJACCESS_CERT_SRV,list[i],pszName,SuccessFailure);
			} else if (!strncmp(pszName,"Application Generated",strlen("Application Generated")+1)) {
				SetObjectAuditFlag(OBJACCESS_APP_GEN,list[i],pszName,SuccessFailure);
			} else if (!strncmp(pszName,"Handle Manipulation",strlen("Handle Manipulation")+1)) {
				SetObjectAuditFlag(OBJACCESS_HANDLE_MANIP,list[i],pszName,SuccessFailure);
			} else if (!strncmp(pszName,"File Share",strlen("File Share")+1)) {
				SetObjectAuditFlag(OBJACCESS_FILE_SHARE,list[i],pszName,SuccessFailure);
			} else if (!strncmp(pszName,"Other Object Access Events",strlen("Other Object Access Events")+1)) {
				SetObjectAuditFlag(OBJACCESS_OTHER,list[i],pszName,SuccessFailure);
			}
			AuditFree(pszName);
		}
		AuditFree(list);
	}
	if(IS_FILTERING_EVENTS(EventID)) {
		GUID *list;
		ULONG numcat;
		PSTR pszName;
		AuditEnumerateSubCategories(&guidObjectAccess,FALSE,&list,&numcat);
		for (UINT i=0; i<numcat; i++) {
			AuditLookupSubCategoryName(&list[i],&pszName);
			if (!strncmp(pszName,"Filtering Platform Packet Drop",strlen("Filtering Platform Packet Drop")+1)) {
				SetObjectAuditFlag(OBJACCESS_FP_PACKET_DROP,list[i],pszName,SuccessFailure);
			} else if (!strncmp(pszName,"Filtering Platform Connection",strlen("Filtering Platform Connection")+1)) {
				SetObjectAuditFlag(OBJACCESS_FP_CONNECTION,list[i],pszName,SuccessFailure);
			}
			AuditFree(pszName);
		}
		AuditFree(list);
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
	// Uses global flag array "int ObjectAuditFlags[9]"
	for(i=0;i<11;i++) {
		ObjectAuditFlags[i].Flags=0;
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

// Make sure you clear audit flags before building this array up.
int SetObjectAuditFlag(int ObjectSubCategory, GUID SubCatID, char *SubCatName, DWORD SuccessFailure)
{
	// Uses global flag array "AuditSubCat ObjectAuditFlags[9]"
	ObjectAuditFlags[ObjectSubCategory].SubCatGuid = SubCatID;
	strncpy_s(ObjectAuditFlags[ObjectSubCategory].SubCatName,_countof(ObjectAuditFlags[ObjectSubCategory].SubCatName),SubCatName,_TRUNCATE);
	ObjectAuditFlags[ObjectSubCategory].Flags |= SuccessFailure;

	return(0);
}

BOOL ApplyAudit()
{
	// AuditCategorySystem, AuditCategoryLogon, AuditCategoryObjectAccess,
	// AuditCategoryPrivilegeUse, AuditCategoryDetailedTracking,
	// AuditCategoryPolicyChange, AuditCategoryAccountManagement,
	// AuditCategoryDirectoryServiceAccess, AuditCategoryAccountLogon

	LPWSTR wHostname = NULL;
    LSA_HANDLE PolicyHandle;
    NTSTATUS Status;
	PPOLICY_AUDIT_EVENTS_INFO AuditEvents;
	LSA_OBJECT_ATTRIBUTES ObjectAttributes;
	DWORD Flag=0;
	DWORD SuccessFailure;
	POLICY_AUDIT_EVENT_TYPE AuditCategory;
	int AuditChanged=0;
	ULONG pCount=0;
	GUID SubCatList[11];
	int SubCatID[11];
	AUDIT_POLICY_INFORMATION *pAuditPol;
	DWORD err;
	char *apCmd[6];

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
		for(int i=0;i<9;i++) {
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

	for(ULONG i=0;i<11;i++) {
		if (ObjectAuditFlags[i].SubCatGuid != GUID_NULL) {
			SubCatList[pCount]=ObjectAuditFlags[i].SubCatGuid;
			SubCatID[pCount]=i;
			pCount++;
		}
	}

	Status = AuditQuerySystemPolicy((GUID *)SubCatList,pCount,&pAuditPol);
	if (!Status) {
		err = GetLastError();
		LogExtMsg(WARNING_LOG,"Audit Policy Configuration Query Failed: %lu",err);
	} else {
		apCmd[0] = "auditpol";
		apCmd[1] = "/set";
		apCmd[2] = (char *)malloc(SIZE_OF_AUDITPOL_ARG * sizeof(char));
		apCmd[3] = (char *)malloc(SIZE_OF_AUDITPOL_ARG * sizeof(char));
		apCmd[4] = (char *)malloc(SIZE_OF_AUDITPOL_ARG * sizeof(char));
		apCmd[5]=NULL;
		// For each element in the ObjectAuditFlags array:
		for(ULONG i=0;i<pCount;i++) {
			SuccessFailure=ObjectAuditFlags[SubCatID[i]].Flags;
			Flag=0;
			
			if(SuccessFailure & TYPE_SUCCESS) {
				Flag |= POLICY_AUDIT_EVENT_SUCCESS;
			}

			if(SuccessFailure & TYPE_FAILURE) {
				Flag |= POLICY_AUDIT_EVENT_FAILURE;
			}
			
			// If the current settings mirror what we want, don't change anything.
			if((Flag == 0 && (pAuditPol[i].AuditingInformation &
				(POLICY_AUDIT_EVENT_SUCCESS | POLICY_AUDIT_EVENT_FAILURE)) == 0) ||
				Flag == (pAuditPol[i].AuditingInformation &
				(POLICY_AUDIT_EVENT_SUCCESS | POLICY_AUDIT_EVENT_FAILURE))) {
				Flag=POLICY_AUDIT_EVENT_UNCHANGED;
			} else if(Flag==0) {
				Flag=POLICY_AUDIT_EVENT_NONE;
			}

			_snprintf_s(apCmd[2],SIZE_OF_AUDITPOL_ARG,_TRUNCATE, "/subcategory:\"%s\"",ObjectAuditFlags[SubCatID[i]].SubCatName);
			if(Flag != POLICY_AUDIT_EVENT_UNCHANGED) {
				pAuditPol[i].AuditingInformation=Flag;
				if (Flag & POLICY_AUDIT_EVENT_SUCCESS) {
					strncpy_s(apCmd[3],SIZE_OF_AUDITPOL_ARG, "/success:enable",_TRUNCATE);
				} else {
					strncpy_s(apCmd[3],SIZE_OF_AUDITPOL_ARG, "/success:disable",_TRUNCATE);
				}	
				if (Flag & POLICY_AUDIT_EVENT_FAILURE) {
					strncpy_s(apCmd[4],SIZE_OF_AUDITPOL_ARG, "/failure:enable",_TRUNCATE);
				} else {
					strncpy_s(apCmd[4],SIZE_OF_AUDITPOL_ARG, "/failure:disable",_TRUNCATE);
				} 
				Status = _spawnvp(_P_WAIT,"auditpol.exe",apCmd);
				if (Status != 0) {
					LogExtMsg(WARNING_LOG,"Audit Policy Configuration Failed: %lu",errno);
				}
				//DMM - this is the correct API, but it doesn't utilise the SeSecurityPrivilege correctly
				// and will always fail with the error 1314 - a required privilege is not held by the client.
				//Status = AuditSetSystemPolicy((PCAUDIT_POLICY_INFORMATION)&pAuditPol[i],1);
				//if (Status != TRUE) {
				//	err = GetLastError();
				//	LogExtMsg(WARNING_LOG,"Audit Policy Configuration Failed: %lu",err);
				//} else {
				//	AuditChanged=1;
				//}
			}
		}
		AuditFree(pAuditPol);
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
        LogExtMsg(WARNING_LOG,"AddToList(): error in dynamic memory allocation\nCould not add a new objective into our linked list. You may be low on memory.\n");
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
		strncat_s(newNode->sysadmin,_countof(newNode->sysadmin),",N/A",_TRUNCATE);
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
		LogExtMsg(ERROR_LOG,"Error compiling the regular expression: %s\n", match);
		_snprintf_s(tmpMsg,_countof(tmpMsg),_TRUNCATE,"Error compiling the regular expression: %s ", match);
		strncat_s(initStatus,_countof(initStatus),tmpMsg,_TRUNCATE);
		LogExtMsg(ERROR_LOG,"Error code = %d\n", newNode->regexpError);
		_snprintf_s(tmpMsg,_countof(tmpMsg), _TRUNCATE,"Error code = %d ", newNode->regexpError);
		strncat_s(initStatus,_countof(initStatus),tmpMsg,_TRUNCATE);
		LogExtMsg(ERROR_LOG,"Error message = %s\n", errorMsg);
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
	//EventCurrent = EventHead;
	//while (EventCurrent) {
	//	temp = EventCurrent;
	//	EventCurrent = EventCurrent->next;
	//	free(temp);
	//}
	//EventHead=NULL;
	//EventTail=NULL;
	//EventCurrent=NULL;
	//EventCount=0;
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

//DMM Old Status Save

	// Call a fake event so that the subroutine	gets the shutdown message
	// through the setting of g_Info.bTerminate
	if(m_hEventList[0])
		::SetEvent(m_hEventList[0]);

	if(m_hCollectEvent)
		::SetEvent(m_hCollectEvent);
}

void CSafedService::OnStop() {
	g_Info.bTerminate=TRUE;
	
	LogExtMsg(WARNING_LOG,"NetEye Safed Stop request received"); 
	
//DMM Old Status Save

	// Call a fake event so that the subroutine	gets the shutdown message
	// through the setting of g_Info.bTerminate
	if(m_hEventList[0])
		::SetEvent(m_hEventList[0]);
	
	if(m_hCollectEvent)
		::SetEvent(m_hCollectEvent);
}

void CSafedService::OnSignal() {
	LogExtMsg(WARNING_LOG,"NetEye Safed Signal request received"); 
//DMM Old Status Save
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
//DMM Old Status Save
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
//////////////////////DEBUG////////////////// 0xc0000417 STATUS_INVALID_CRUNTIME_PARAMETER
void GetHANDLER_ACTIVE(DWORD * HANDLER_ACTIVE)
{
	if(!HANDLER_ACTIVE) return;
	*HANDLER_ACTIVE=MyGetProfileDWORD("Config","Handler",0);
}
//////////////////////DEBUG////////////////// 0xc0000417 STATUS_INVALID_CRUNTIME_PARAMETER

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
{	*dwTAD=1;
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

DWORD GetTotalSavedLogs(FILE * fp){
	DWORD cnt = 0;
	char* line = (char*)malloc(dwMaxMsgSize*sizeof(char)); 
	if (line)line[0]='\0';
	else {
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
int StartCollectThread(HANDLE event)
{
	int threadid=0;
	
	threadid = (int)_beginthread(CollectionThread,0,event);
	LogExtMsg(INFORMATION_LOG,"DEBUG: Starting collection thread %d..",threadid);
	if(threadid==-1) {
		LogExtMsg(ERROR_LOG,"Error in collection thread creation");
		return(0);
	}
	return(1);
}

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
		dwWaitRes=WaitForMultipleObjects(3,web_hEventList,FALSE,5000);
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
				LogExtMsg(INFORMATION_LOG,"HandleWebThread: WEB Server exiting..");
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

