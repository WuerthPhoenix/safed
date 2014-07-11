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
#include <io.h>


#include "LogUtils.h"
#include "Communication.h"
#include "SafedLog.h"
#include "Safed.h"
#include "NTServApp.h"





extern int wildmatchi(char *pattern, char *source, int top);

extern char			Hostname[100];
extern DWORD dwSyslogHeader; // Send the Syslog header?
extern DWORD dwPortNumber;
extern DWORD dwRestrictIP;
extern DWORD dwUsePassword;
extern TCHAR lpszIPAddress[SIZE_OF_RESTRICTIP];
extern TCHAR lpszPassword[256];
extern DWORD dwSyslog;
// Destination for log events. Default it to something safe.
extern TCHAR lpszDestination[SIZE_OF_DESTINATION];
extern TCHAR DELIM[2];
extern HANDLE hMutex;
extern HANDLE hMutexFile;
extern HANDLE hMutexCount;
extern DWORD SafedCounter;
extern DWORD dwMaxMsgSize;
extern int pid;

static HostNode *e_hostcurrentnode;

extern BOOL usefile;
extern FILE * OutputFile;
extern char filename[1024];

extern char sentFile[255];
extern int sentIndex;


ThreadStruct	e_g_Info;

int				PROCESS_WATCHES_EXIT=0;

//Message cache
int LCCount=0;
E_MsgCache *LCHead=NULL;
E_MsgCache *LCTail=NULL;
E_MsgCache *LCCurrent=NULL;

LogNode *lhead=NULL;
LogNode *ltail=NULL;
LogNode *lcurrent=NULL;


//Shared between web thread log thread and main
extern int MCCount;
extern MsgCache *MCHead;
extern MsgCache *MCTail;
extern MsgCache *MCCurrent;


char e_initStatus[16384] = "";


static E_Node *e_head=NULL, *e_tail=NULL, *e_currentnode=NULL;

HANDLE *e_m_hEventList; // 1  event for epilog


int CloseSafedE(){
	e_g_Info.bTerminate = TRUE;
	while(e_g_Info.bTerminate){
		Sleep(100);
	}
	return(1);
}	

BOOL isNotClosed(){
	return e_g_Info.bTerminate;
}

int StartSafedEThread(HANDLE event)
{
	int threadid=0;
	_snprintf_s(e_initStatus,_countof(e_initStatus),_TRUNCATE,"");
	e_m_hEventList = new HANDLE[1]; // 1 epilog event
	e_m_hEventList[0] = CreateEvent(NULL, TRUE, FALSE, NULL);
	if(e_m_hEventList[0] == NULL) {
		LogExtMsg(ERROR_LOG,"CreateEvent() for Safed Log Thread failed");
		return 0;
	}
	threadid=(int)_beginthread( RunSafedE, 0, event);
	LogExtMsg(INFORMATION_LOG,"DEBUG: Starting Safed Log  thread %d..",threadid); 
	if(threadid==-1)
	{
		LogExtMsg(ERROR_LOG,"Error in Safed Log thread creation");
		return(-1);
	}
	return(1);
}



void RunSafedE(HANDLE event)
{

	// Define a log buffer of 8k.
	// Should be enough for an overwhelming majority of circumstances.
	TCHAR logbuffer[MAX_EVENT]="";

  	TCHAR szError[MAX_STRING]="";
	
	static int recovery = 0;

	short nEventCount=1; // epilog event
	char* szSendString = NULL; // Nice big memory buffer - just in case.
	szSendString = (char*)malloc(dwMaxMsgSize*sizeof(char)); // Nice big memory buffer - just in case.
	if (szSendString)szSendString[0]='\0';
	else {
		LogExtMsg(ERROR_LOG,"NO MEMORY LEFT!!!"); 		
		goto e_nomemory;
	}

	char* szSendStringBkp = NULL; // Nice big memory buffer - just in case.
	szSendStringBkp = (char*)malloc(dwMaxMsgSize*sizeof(char)); // Nice big memory buffer - just in case.
	if (szSendString)szSendStringBkp[0]='\0';
	else {
		LogExtMsg(ERROR_LOG,"NO MEMORY LEFT!!!");
		goto e_nomemory;
	}




	HCRYPTPROV hProv = 0;
	HCRYPTKEY hSessionKey = 0;
	DWORD dwWaitRes=0,dwWaitFile=0;
	DWORD dwObjectiveCount=0;
	BOOL MatchFound=0;
	BOOL m_bIsRunning=1;

	// Syslog, and output log time variables.
	time_t currenttime;
	struct tm *newtime;
	newtime = (struct tm *)malloc(sizeof(struct tm));

	LogExtMsg(INFORMATION_LOG,"Epilog is Running"); 

	// READ in our data
	ReadLogs();
	// Load the objective data here.
	dwObjectiveCount=E_ReadObjectives();


	LogExtMsg(INFORMATION_LOG,"Sockets opened/connected");


	// Set the terminate flag to zero.
	// setting this value to TRUE will terminate the service,
	// and ask it to save it's current status.
	e_g_Info.bTerminate = FALSE;

	LogExtMsg(DEBUG_LOG,"Entering main loop.");
	// This is the service's main run loop.
	while (m_bIsRunning) {
		// TODO: Add code to perform processing here  
		// If we have been asked to terminate, do so.

		if(e_g_Info.bTerminate) {
			m_bIsRunning=0;
			break;
		}	
		
		// The service performs one check per 5 seconds. This should not be
		// a significant drain on resources.
		dwWaitRes=WaitForMultipleObjects(nEventCount,e_m_hEventList,FALSE,1000);

		// if(dwWaitRes != WAIT_FAILED && dwWaitRes != WAIT_TIMEOUT)
		if(dwWaitRes != WAIT_FAILED) {

			if (dwWaitRes == WAIT_OBJECT_0) {
				ResetEvent(e_m_hEventList[0]);
				LogExtMsg(INFORMATION_LOG,"Sending Logs"); 
				E_MsgCache *mymsg;
				errno_t err;

				mymsg = LCHead;
				//while (mymsg && !caught_kill) {
				int hasCash = 0;
				while (mymsg) {

					char header[256];
					char CurrentDate[16]="";
					
					// Check objectives
					// NOTE: If there are no objectives, send nothing?
					if(dwObjectiveCount) {
						if(e_g_Info.bTerminate) {
							m_bIsRunning=0;
							break;
						}
					}

					if(dwSyslogHeader || usefile) {
						resetSafedCounter(newtime);
						syslogdate(CurrentDate,newtime);
					}else{
						time(&currenttime);
						err=localtime_s(newtime,&currenttime);
					}

					BOOL DataSent=0;
					BOOL FailFromCache=0;
					DWORD tmpCounter=0;
					DWORD dwWaitCount = WaitForSingleObject(hMutexCount,5000);
					if(dwWaitCount == WAIT_OBJECT_0) {
						DWORD TheCounter = SafedCounter;

						if(usefile) {
							// Check to see whether we need to rotate our log file.
							if(changeCacheFileName(*newtime)){
								usefile=GetOutputFile(filename, NULL);
							}
						}
						if(mymsg->counter){
							TheCounter = mymsg->counter;
						}
						if(dwSyslogHeader) {
							_snprintf_s(header,_countof(header),_TRUNCATE,"<%ld>%s %s Safed[%d][%d]:%s",dwSyslog,CurrentDate,Hostname,pid,TheCounter,DELIM);
						} else {
							if (strncmp("GenericLog",mymsg->type,10))
								_snprintf_s(header,_countof(header),_TRUNCATE,"%s%sSafed[%d][%d]:%s",Hostname,DELIM,pid,TheCounter,DELIM);
							else
								_snprintf_s(header,_countof(header),_TRUNCATE,"%s%sSafed[%d][%d]:%s0%s0%s0%s",Hostname,DELIM,pid,TheCounter,DELIM,DELIM,DELIM,DELIM);
						}
						
						_snprintf_s(szSendString,dwMaxMsgSize*sizeof(char),_TRUNCATE,"%s%s\n",header,mymsg->msg);

						if(szSendString) { LogExtMsg(INFORMATION_LOG,"DEBUG: Sending the following string to the server: %s",szSendString); }

						e_hostcurrentnode=getHostHead();

						while(e_hostcurrentnode) {
							if(e_hostcurrentnode->Socket == INVALID_SOCKET) {
								// Try to reestablish here.
								// Since socket connects use a fair bit of system resources, try and do it nicely.
								LogExtMsg(ERROR_LOG,"Socket is toast for %s. Trying to reestablish.",e_hostcurrentnode->HostName); 
								
								e_hostcurrentnode->Socket = ConnectToServer( e_hostcurrentnode, szError, _countof(szError) );
								
								if(e_hostcurrentnode->Socket == INVALID_SOCKET) {
									// Hmm. Try again later.
									// Jump to the next socket
									e_hostcurrentnode=e_hostcurrentnode->next;
									LogExtMsg(ERROR_LOG,"Failed to reconnect socket");
									continue;
								}
							}
							if(!hasCash){
								if(recovery == 1){// try to send the backuped message

									if( !SendToSocket(e_hostcurrentnode, szSendStringBkp, (int)strlen(szSendStringBkp), szError, _countof(szError)) )
									{

										if(szError) { LogExtMsg(INFORMATION_LOG,szError); } 
										LogExtMsg(INFORMATION_LOG,"Socket for %s is toast. Breaking out - will reestablish next time.",e_hostcurrentnode->HostName); 
										// Close the socket. Restablish it on the next cycle, if we can.
										CloseSocket(e_hostcurrentnode->Socket, e_hostcurrentnode->tlssession);
										e_hostcurrentnode->Socket=INVALID_SOCKET;
									} else {
										recovery = -1; //backuped message has been sent
										LogExtMsg(ERROR_LOG,"sending recovered log msg  ......>: %s",szSendStringBkp); 
									}

								} 


								if(recovery != 1){// try to send the current message only if no backuped message exists
									dwWaitFile = WaitForSingleObject(hMutexFile,500);
									if(dwWaitFile == WAIT_OBJECT_0) {
										GetSentIndex(sentFile,_countof(sentFile), &sentIndex);
										if(sentIndex && strlen(sentFile)){
											FailFromCache=SendFailedCache(e_hostcurrentnode, sentFile, _countof(sentFile),&sentIndex, dwMaxMsgSize);
											SetSentIndex(sentFile,sentIndex);
										}
									}
									ReleaseMutex(hMutexFile);
									if(!FailFromCache){
										if( !SendToSocket(e_hostcurrentnode, szSendString, (int)strlen(szSendString), szError, _countof(szError)) )
										{
											if(szError) LogExtMsg(DEBUG_LOG,szError); 
											LogExtMsg(INFORMATION_LOG,"Socket for %s is toast. Breaking out - will reestablish next time.",e_hostcurrentnode->HostName); 
											// Close the socket. Restablish it on the next cycle, if we can.
											CloseSocket(e_hostcurrentnode->Socket, e_hostcurrentnode->tlssession);
											e_hostcurrentnode->Socket=INVALID_SOCKET;
											if(recovery == 0)recovery = 1;//if backuped message is sent , it will not be sent again
										} else {
											strcpy(szSendStringBkp, szSendString);
											DataSent=1;
											recovery = 0;
										}
									}
								}

							}

							e_hostcurrentnode=e_hostcurrentnode->next;
						}
						if(!mymsg->counter){
							SafedCounter++;
							if(SafedCounter >= MAXDWORD) {
								SafedCounter=1;
							}
						}
					
					}
					tmpCounter = SafedCounter;
					ReleaseMutex(hMutexCount);	

					// Write the data out to a disk, if requested.
					if(usefile && !mymsg->cached) {
						dwWaitFile = WaitForSingleObject(hMutexFile,500);
						if(dwWaitFile == WAIT_OBJECT_0) {
							fopen_s(&OutputFile,filename,"a");
							fputs(szSendString,OutputFile);
							fflush(OutputFile);
							fclose(OutputFile);
						}
						if(!FailFromCache){//in case not failed to send cached data
							char* posslash = strstr(filename,"\\");
							char* tmpslash = posslash;
							while(posslash){
								tmpslash = posslash + 1;
								posslash = strstr(tmpslash,"\\");
							}
							if(tmpslash){
								int lastSentIndex = 0;
								char lastSentFile[255];
								GetSentIndex(lastSentFile,_countof(lastSentFile), &lastSentIndex);
								if(!DataSent && ((!lastSentIndex || (strlen(lastSentFile) == 0)) || !strcmp(lastSentFile, tmpslash))){
									//if send fails and no index has been set yet or a greater value for the same file log has been set by onother thread
									strncpy_s(sentFile,_countof(sentFile),tmpslash,_TRUNCATE);
									if(SafedCounter > 1 ){
										sentIndex = SafedCounter -1;
										if(!lastSentIndex || lastSentIndex > sentIndex){
											SetSentIndex(sentFile,sentIndex);//in case failed to send data and no cache toll now
										}else{
											sentIndex = lastSentIndex;
										}
									}
								}
							}
						}
						ReleaseMutex(hMutexFile);	
					}
					FailFromCache = 0;

					// Did we push out at least one record?
					/*cache in local file
					if(!DataSent) {
						// Break out of the for/next loop.
						LogExtMsg(ERROR_LOG,"ERROR: Failed to send msg");
						mymsg->cached = 1;
						mymsg->counter = TheCounter;
						mymsg = mymsg->next;
						hasCash=1;
						continue;
					}
					*/
					//Msg Sent! Update the status and log the event to the webcache
					MCCurrent = (MsgCache *)malloc(sizeof(MsgCache));
					if (MCCurrent) {
						memset(MCCurrent,0,sizeof(MsgCache));
						strncpy_s(MCCurrent->Hostname,_countof(Hostname),Hostname,_TRUNCATE);
						time_t ttime=time(NULL);
						struct tm *ptmTime;
						errno_t err;
						ptmTime = (struct tm *)malloc(sizeof(struct tm));
						err = localtime_s(ptmTime,&ttime);
						strftime(MCCurrent->SubmitTime, _countof(MCCurrent->SubmitTime),"%a %b %d %H:%M:%S %Y", ptmTime);
						free(ptmTime);
						char * bufmsg = NULL;
						htmlspecialchars(mymsg->msg,&bufmsg,ENT_COMPAT); 
						strncpy_s(MCCurrent->szTempString, MAX_EVENT, bufmsg,_TRUNCATE);
						if(bufmsg)free(bufmsg);
						MCCurrent->criticality = 0;
						MCCurrent->SafedCounter = tmpCounter;
						MCCurrent->ShortEventID = 0;
						MCCurrent->SourceName[0]='\0';
						MCCurrent->UserName[0]='\0';
						strncpy_s(MCCurrent->SIDType, 100, mymsg->type,_TRUNCATE);
						MCCurrent->EventLogType[0]='\0';
						MCCurrent->szCategoryString[0]='\0';
						MCCurrent->DataString[0]='\0';
						MCCurrent->EventLogCounter =0;
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
					

					LCHead = mymsg->next;
					if(mymsg->msg)free(mymsg->msg);
					free(mymsg);
					//DMMVirtualFree(mymsg,sizeof(E_MsgCache),MEM_RELEASE);
					LCCount--;
					mymsg = LCHead;
					if (!mymsg) {
						LCTail=NULL;
					}
				}
			}  else if (dwWaitRes == WAIT_TIMEOUT) {
				//check if we are just doing a single run
				if (PROCESS_WATCHES_EXIT >= 2) {
					LogExtMsg(DEBUG_LOG,"Finished processing %d", PROCESS_WATCHES_EXIT);
					break;
				}
				if (PROCESS_WATCHES_EXIT) PROCESS_WATCHES_EXIT++;
 				//LogExtMsg(INFORMATION_LOG,"Timeout hit"); }
			} else {
				LogExtMsg(DEBUG_LOG,"Warning: An event occured that I am not programmed to deal with. Continuing"); 
				continue;
			}

			lcurrent = lhead;
			while (lcurrent) {
				LogExtMsg(INFORMATION_LOG,"Checking for changes in: %s", lcurrent->name);
				int ret,length;
				int big_msg=0;
				int grab_count=0;
				int fh = 0;
				lcurrent->fs = _fsopen(lcurrent->name, "rb", _SH_DENYNO);
				if (lcurrent->fs == NULL) {
					LogExtMsg(ERROR_LOG,"Failed to get file pointer %s", lcurrent->name);
					ret = -1;
				}else{
					fh = fileno(lcurrent->fs);
					ret = file_has_changed(lcurrent, fh);
				}
				if (ret > 0) {
					LogExtMsg(INFORMATION_LOG,"Found a change, grabbing and sending");
					_lseeki64(fh,lcurrent->size,SEEK_SET);

					lcurrent->old_size = lcurrent->size;
					int block = lcurrent->multiline == ML_BLOCK?1:0;
					int max = block?lcurrent->linecount:MAX_EVENT;
					while ((length = GetLine(lcurrent->fs, logbuffer, max, block)) > 0) {
						//if (!strncmp(logbuffer,"          ",10)) break;
						lcurrent->size=lcurrent->size + length;
						if (!lcurrent->send_comments && logbuffer[0] == '#') continue;
						if (!lcurrent->multiline || lcurrent->multiline == ML_BLOCK) {
							if (logbuffer[0] == '\n') continue;
							if (big_msg) {
								if (logbuffer[strlen(logbuffer) - 1] == '\n') {
									big_msg = 0;
								}
								continue;
							}
							if (lcurrent->pmsg && strlen(lcurrent->pmsg)) {
								strncat_s(lcurrent->pmsg, MAX_EVENT, logbuffer,_TRUNCATE);
								strncpy_s(logbuffer, MAX_EVENT, lcurrent->pmsg,_TRUNCATE);
								lcurrent->pmsg[0]='\0';
							}
							if (logbuffer[strlen(logbuffer) - 1] != '\n') {
								if (strlen(logbuffer) >= MAX_EVENT -1) {
									logbuffer[MAX_EVENT]='\0';
									big_msg = 1;
								} else {
									strncpy_s(lcurrent->pmsg, MAX_EVENT, logbuffer,_TRUNCATE);
									continue;
								}
							}
						} else {
							if (lcurrent->multiline == ML_FIXED) {
								if (lcurrent->lines < lcurrent->linecount) {
									lcurrent->lines++;
									if (logbuffer[strlen(logbuffer) - 1] == '\n') logbuffer[strlen(logbuffer) - 1]='\t';
									strncat_s(lcurrent->pmsg, MAX_EVENT, logbuffer,_TRUNCATE);
									continue;
								} else {
									strncat_s(lcurrent->pmsg, MAX_EVENT, logbuffer,_TRUNCATE);
									strncpy_s(logbuffer, MAX_EVENT, lcurrent->pmsg,_TRUNCATE);
									strncpy_s(lcurrent->pmsg, MAX_EVENT, "",_TRUNCATE);
									lcurrent->lines=1;
								}
							} else if (lcurrent->multiline == ML_SEP) {
								if (!strcmp(logbuffer,lcurrent->separator)) {
									strncat_s(lcurrent->pmsg, MAX_EVENT, logbuffer,_TRUNCATE);
									strncpy_s(logbuffer, MAX_EVENT, lcurrent->pmsg,_TRUNCATE);
									strncpy_s(lcurrent->pmsg, MAX_EVENT, "",_TRUNCATE);
								} else {
									if (logbuffer[strlen(logbuffer) - 1] == '\n') logbuffer[strlen(logbuffer) - 1]='\t';
									strncat_s(lcurrent->pmsg, MAX_EVENT, logbuffer,_TRUNCATE);
									continue;
								}
							}
						}
						if (logbuffer[strlen(logbuffer) - 1] == '\n') logbuffer[strlen(logbuffer) - 1]='\0';
						if (logbuffer && E_CheckObjective(logbuffer)) {

							//#######################################
							if (LCCount > DEFAULT_CACHE) {
								LogExtMsg(INFORMATION_LOG,"Log Cache FULL - deleting oldest message");
								LCCurrent = LCHead;
								LCHead = LCCurrent->next;
								free(LCCurrent->msg);
								free(LCCurrent);
							}
							int size_msg_cache = sizeof(E_MsgCache);
							//DMMLCCurrent = (E_MsgCache *)VirtualAlloc((LPSTR)lpMem + grab_count * MsgCacheBytes,MsgCacheBytes,MEM_COMMIT,PAGE_READWRITE);
							LCCurrent = (E_MsgCache *)malloc(sizeof(E_MsgCache));
							if (LCCurrent) {
								memset(LCCurrent,0,sizeof(E_MsgCache));
								LCCurrent->msg = (char*)malloc(dwMaxMsgSize*sizeof(char)); // Nice big memory buffer - just in case.
								if (LCCurrent->msg){
									LCCurrent->msg[0]='\0';
									LCCurrent->msglen=strlen(logbuffer);
									strncpy_s(LCCurrent->msg, dwMaxMsgSize*sizeof(char), logbuffer,_TRUNCATE);
									LCCurrent->msg[LCCurrent->msglen]='\0';
									LCCurrent->next=NULL;
									LCCurrent->cached=0;
									LCCurrent->counter=0;
									strncpy_s(LCCurrent->type, MAX_TYPE, lcurrent->type,_TRUNCATE);
								}else{
									LogExtMsg(ERROR_LOG,"Unable to allocate cache");
								}
							} else {
								LogExtMsg(ERROR_LOG,"Unable to allocate cache");
							}
							LCCount++;
							if (LCTail) {
								LCTail->next=LCCurrent;
							}
							LCTail=LCCurrent;
							if (!LCHead) {
								LCHead=LCCurrent;
							}

							LogExtMsg(INFORMATION_LOG,"About to set event");
							::SetEvent(e_m_hEventList[0]);
							//#######################################
						}
						grab_count++;
						if (grab_count >= MAX_LINE_GRAB) {
						//if (grab_count >= 1) {
							LogExtMsg(INFORMATION_LOG,"Breaking out to allow events to send");
							break;
						}
					}
				} else {
					// The file hasn't changed OR
					// there was an error that we can't do anything about
					LogExtMsg(INFORMATION_LOG,"No changes found");
				}
				if(lcurrent->fs)fclose(lcurrent->fs);
				lcurrent = lcurrent->next;
			}
		}
	}

	e_nomemory:;
	LogExtMsg(INFORMATION_LOG,"Safed Log Thread Closing"); 
	if (szSendString) free(szSendString);
	if (szSendStringBkp) free(szSendStringBkp);
	if(newtime)free(newtime);

	// Free memory used by the objectives lists
	E_DestroyList();

	if( e_m_hEventList[0] ) ::CloseHandle(e_m_hEventList[0]);
	delete [] e_m_hEventList;
	SetEvent(event);

	e_g_Info.bTerminate = FALSE;
	_endthread();

}


int E_CheckObjective(char *searchterm)
{
	if(!searchterm) {
		LogExtMsg(INFORMATION_LOG,"E_CheckObjective: No Search Term supplied"); 
		return(-1);
	}

	e_currentnode=e_head;
	//If there are no filter terms, match nothing
	if (e_currentnode == NULL) {
		return(0);
	}

	while (e_currentnode != NULL) {
		//if (wildmatchi(e_currentnode->match,searchterm)) {
		if(!e_currentnode->regexpError && !regexec(&e_currentnode->regexpCompiled, searchterm, (size_t) 0, NULL, 0)) {
			if (e_currentnode->excludematchflag) {
				return(0);
			} else {
				return(1);
			}
		}
		e_currentnode = e_currentnode->next;
	}

	e_currentnode=e_head;
	return(0);
}

int E_ReadObjectives()
{
	E_Reg_Objective reg_objective;
	DWORD dw_objective_error;
	int i_objective_count=0;
	// HERE: Turn off all auditing, unless there are NO objectives to read.

	while((dw_objective_error = E_Read_Objective_Registry(i_objective_count,&reg_objective))==0) {	
		E_AddToList(reg_objective.str_match, reg_objective.dw_match_type);
		i_objective_count++;
	}

	return(i_objective_count);
}

// Linked List Functions

void E_AddToList(char *match, int excludematchflag)
{
	static E_Node *newE_Node=NULL;

	if(!match) {
		return;
	}

	newE_Node = (E_Node *) malloc(sizeof(E_Node));

	if (newE_Node == NULL) {
		LogExtMsg(ERROR_LOG,"E_AddToList(): error in dynamic memory allocation\nCould not add a new objective into our linked list. You may be low on memory.\n");
		return;
    }
	memset(newE_Node,0,sizeof(E_Node));

	newE_Node->excludematchflag=excludematchflag;
	strncpy_s(newE_Node->match,_countof(newE_Node->match),match,_TRUNCATE);
	newE_Node->next = NULL;


	newE_Node->regexpError = regcomp(&newE_Node->regexpCompiled, match, REG_EXTENDED | REG_NOSUB);
	if (newE_Node->regexpError != 0) {
		char errorMsg[8192];
		char tmpMsg[9216];
		regerror(newE_Node->regexpError, &newE_Node->regexpCompiled, errorMsg, 8192);
		LogExtMsg(NULL,"Error compiling the regular expression: %s\n", match);
		_snprintf_s(tmpMsg,_countof(tmpMsg),_TRUNCATE,"Error compiling the regular expression: %s ", match);
		strncat_s(e_initStatus,_countof(e_initStatus),tmpMsg,_TRUNCATE);
		LogExtMsg(NULL,"Error code = %d\n", newE_Node->regexpError);
		_snprintf_s(tmpMsg,_countof(tmpMsg), _TRUNCATE,"Error code = %d ", newE_Node->regexpError);
		strncat_s(e_initStatus,_countof(e_initStatus),tmpMsg,_TRUNCATE);
		LogExtMsg(NULL,"Error message = %s\n", errorMsg);
		_snprintf_s(tmpMsg,_countof(tmpMsg), _TRUNCATE,"Error message = %s<p>", errorMsg);
		strncat_s(e_initStatus,_countof(e_initStatus),tmpMsg,_TRUNCATE);

	}



	if (e_tail != NULL) {
		e_tail->next = newE_Node;
	}
	e_tail = newE_Node;
	if (e_head == NULL) {
		e_head = newE_Node;
	}
	return;
}

void E_DestroyList(void)
{
	while (NULL != e_head) {
		E_Node *tempPtr = e_head;
		e_head = e_head->next;
		regfree(&tempPtr->regexpCompiled);
		free(tempPtr);
	}
	e_head = NULL;
	e_tail = NULL;
	e_currentnode = NULL;

	LCCurrent=LCHead;
	while(LCCurrent) {
		LCHead=LCCurrent->next;
		free(LCCurrent->msg);
		free(LCCurrent);
		LCCurrent=LCHead;
	}
	LCTail = NULL;
	LCHead = NULL;
	LCCurrent = NULL;
	LCCount = 0;

	lcurrent=lhead;
	while(lcurrent) {
		lhead=lcurrent->next;
		free(lcurrent);
		lcurrent=lhead;
	}
	ltail = NULL;
	lhead = NULL;
	lcurrent = NULL;

}




// Configuration reading routines


int ReadLogs()
{
	Reg_Log reg_log;
	DWORD dw_log_error;
	int i_log_count=0;

	LogExtMsg(INFORMATION_LOG,"Reading Log entries");
	while((dw_log_error = Read_Log_Registry(i_log_count,&reg_log))==0) {	
		AddLogWatch(&reg_log);
		i_log_count++;
	}
	LogExtMsg(INFORMATION_LOG,"Found %d logs [return code: %d]", i_log_count, dw_log_error);
	return(i_log_count);
}

// END Configuration Reading Routines




// Dump the current eventlog record to a file.

int AddLogWatch(Reg_Log *rl)
{
	struct stat stats;
	int length;
	char logbuffer[MAX_EVENT], c;
	lcurrent = (LogNode *)malloc(sizeof(LogNode));
	if (lcurrent) {
		memset(lcurrent,0,sizeof(LogNode));
		lcurrent->next=NULL;
		lcurrent->send_comments = rl->send_comments;
		lcurrent->multiline = rl->multiline;
		lcurrent->linecount = rl->log_ml_count;
		lcurrent->lines=1;
		_snprintf_s(lcurrent->separator, SIZE_OF_SEP,_TRUNCATE,"%s\n", rl->log_ml_sep);
		strncpy_s(lcurrent->type, MAX_TYPE, rl->type,_TRUNCATE);
		strncpy_s(lcurrent->format, SIZE_OF_LOGNAME, rl->format,_TRUNCATE);
		// Firstly check if the entry is a directory
		if (validate_file_or_directory(rl->name) == 2) {
			LogExtMsg(INFORMATION_LOG,"FOUND A DIRECTORY: %s", rl->name);
			strncpy_s(lcurrent->dir_name, SIZE_OF_LOGNAME, rl->name,_TRUNCATE);
			if (rl->name[strlen(rl->name)-1] != '\\') strncat_s(lcurrent->dir_name, SIZE_OF_LOGNAME, "\\",_TRUNCATE);
			lcurrent->dir=1;
			lcurrent->dir_check = 0;
			lcurrent->name[0]='\0';
			// this function will create all the necessary log watchers
			FindDirFile(lcurrent);
			strncpy_s(lcurrent->old_name,_countof(lcurrent->old_name),lcurrent->name,_TRUNCATE);
		} else {
			strncpy_s(lcurrent->name, SIZE_OF_LOGNAME, rl->name,_TRUNCATE);
			strncpy_s(lcurrent->old_name,_countof(lcurrent->old_name),lcurrent->name,_TRUNCATE);
			lcurrent->dir = 0;
			lcurrent->dir_check = 0;
			lcurrent->dir_name[0]='\0';
		}
		LogExtMsg(INFORMATION_LOG,"Watching '%s' at location: %s", lcurrent->type, lcurrent->name);
		// Grab and record the current stats
		if (stat(lcurrent->name, &stats) < 0) {
			LogExtMsg(ERROR_LOG,"Failed to find stats for %s\n", lcurrent->name);
			lcurrent->last_error=time(&lcurrent->last_error);
		} else {
			lcurrent->mtime = stats.st_mtime;
			//Before we set the size, we need to find the true end of the file
			lcurrent->fs = _fsopen(lcurrent->name, "rb", _SH_DENYNO);
			if (lcurrent->fs != NULL && !PROCESS_WATCHES_EXIT) {
				int fh = fileno(lcurrent->fs);
				__int64 sizeoffile = _lseeki64(fh,0,SEEK_END);
				lcurrent->old_size = sizeoffile;
				if((int)sizeoffile < 0) 
					_lseeki64(fh,sizeoffile-1,SEEK_SET);
				else 
					_lseeki64(fh,-1,SEEK_END);

				c=fgetc(lcurrent->fs);
				if (c == '\0' || c == ' ') {
					//Possibly SMTP or old IIS format, start searching for the true end of the file
					_lseeki64(fh,0,SEEK_SET);
					lcurrent->size = 0;
					int block = lcurrent->multiline == ML_BLOCK?1:0;
					int max = block?lcurrent->linecount:MAX_EVENT;
					while ((length = GetLine(lcurrent->fs, logbuffer, max, block)) > 0) {
						//if (!strncmp(logbuffer,"          ",10)) break;
						lcurrent->size=lcurrent->size + length;
					}
				} else {
					//looks like we are ok to watch the file from the end.
					lcurrent->size = sizeoffile;
				}
				fclose(lcurrent->fs);
			} else {
				// This shouldn't happen at this point, but if it does, just use the file size
				LogExtMsg(ERROR_LOG,"Failed to open %s\n", lcurrent->name);
				lcurrent->last_error=time(&lcurrent->last_error);
			}
			if (PROCESS_WATCHES_EXIT) {
				lcurrent->size = 0;
				lcurrent->old_size = 0;
				if (lcurrent->fs != NULL) {
					fclose(lcurrent->fs);
				}
			}
			lcurrent->dev = stats.st_dev;
			lcurrent->ino = stats.st_ino;
			lcurrent->mode = stats.st_mode;
			lcurrent->last_error=0;
		}
		lcurrent->next=NULL;
		lcurrent->pmsg[0]='\0';
		// Now that the file is ready, seek to the end of the file
		// and prepare to capture further output

		if (ltail) {
			ltail->next=lcurrent;
			ltail=lcurrent;
		}
		if (!lhead) {
			lhead=lcurrent;
			ltail=lcurrent;
		}
	} else {
		LogExtMsg(ERROR_LOG,"Failed to allocate memory for log file\n");
		return(0);
	}
	return(0);
}


int file_has_changed (LogNode *f, int fh) {
	// Grab the new set of stats
	struct _stat stats;
	if (f->dir) f->dir_check++;
	if (f->dir && f->last_error) {
		if (f->dir_check < 20) return(0);
		if (FindDirFile(f)) {
			f->last_error = 0;
		}
		f->dir_check = 0;
	}
	if (_stat(f->name, &stats) < 0) {
		if (!f->last_error ) LogExtMsg(INFORMATION_LOG,"Failed to find log file: %s\n", f->name);
		f->last_error=time(&f->last_error);
		return(-1);
	}
	__int64 sizeoffile =_lseeki64(fh,f->size,SEEK_SET);
	if (f->size == stats.st_size &&
	    f->mtime == stats.st_mtime) {
		// Everything else is exactly the same
		// so do nothing for now
		LogExtMsg(INFORMATION_LOG,"Size and mtime are the same");
		// return straight away if not a directory, or if under 20
		// seconds has passed, this should minimise any resource
		// impacts
		if (!f->dir) return(0);
		if (f->dir_check < 20) return(0);
		f->dir_check = 0;
		//just make sure that there is no new file to watch yet
		if (FindDirFile(f) == DIR_NEW_FILE) return(1);
		else return(0);
	} else {
		int change=0;
		// Something has changed, find out what and take action
		if (strcmp(f->old_name,f->name)) {
			// This is the replacement for the rotation check
			LogExtMsg(INFORMATION_LOG,"File name has changed\nOLD NAME:[%s]\nNEW NAME:[%s]", f->old_name, f->name);
			strncpy_s(f->old_name,_countof(f->old_name),f->name,_TRUNCATE);
			change = 1;
		} else if (stats.st_size < f->size) {
			LogExtMsg(INFORMATION_LOG,"%s: File truncated\n", f->name);
			change = 1;
		} else if (f->mtime > stats.st_mtime) {
			LogExtMsg(INFORMATION_LOG,"%s: Modified in the past\n", f->name);
			change = 1;
		}

		// Reset the descriptors
		//f->size = stats.st_size;
		f->mtime = stats.st_mtime;
		f->dev = stats.st_dev;
		f->ino = stats.st_ino;
		f->mode = stats.st_mode;
		if (change) {
			// Something went wrong, so ditch the old descriptor and
			// keep the new one.  However, since it was not a rotation,
			// i.e. we still have the same dev and inode numbers, then
			// seek to the beginning of the file and only return a change
			// if the file is larger than zero.
			f->size = 0;
			if (stats.st_size == (off_t) 0)
				return(0);
			else
				return(1);
		} else {
			// return straight away if not a directory, or if under 20
			// seconds has passed, this should minimise any resource
			// impacts
			if (!f->dir) return(1);
			if (f->dir_check > 20) {
				f->dir_check = 0;
				//just make sure that there is no new file to watch yet
				FindDirFile(f);
			}
		}
		return(1);
	}
}

char * getdate(char *date, BOOL ytday)
{
   time_t t;
   struct tm *tm;
   errno_t err;

   char year[3],month[3],day[3];
   int tempyear,tempmonth,tempday;

   t = time(NULL);
   if (ytday) t = t - (24 * 60 * 60);
   tm = (struct tm *)malloc(sizeof(struct tm));
   err=gmtime_s(tm,&t);

   tempyear = tm->tm_year;
   if(tempyear > 100) {
	tempyear -= 100;
   }

   if(tempyear >=10) {
	_snprintf_s(year,3,_TRUNCATE,"%d",tempyear);
   } else {
	_snprintf_s(year,3,_TRUNCATE,"0%d",tempyear);
   }

   tempmonth=tm->tm_mon+1;
   if(tempmonth >=10) {
	_snprintf_s(month,3,_TRUNCATE,"%d",tempmonth);
   } else {
	_snprintf_s(month,3,_TRUNCATE,"0%d",tempmonth);
   }

   tempday=tm->tm_mday;
   if(tempday >=10) {
	_snprintf_s(day,3,_TRUNCATE,"%d",tempday);
   } else {
	_snprintf_s(day,3,_TRUNCATE,"0%d",tempday);
   }

   _snprintf_s(date,7,_TRUNCATE,"%s%s%s",year,month,day);

   return(date);
}

int FindDirFile(LogNode *f)
{
	HANDLE handle=INVALID_HANDLE_VALUE;
	WIN32_FIND_DATA firstData;
	char currentdate[7]; // YYMMDD
	char filespec[132]="";
	char fmt[SIZE_OF_LOGNAME]="";
	char *pos, *pos2;
	getdate(currentdate);
	strncpy_s(f->old_name,_countof(f->old_name),f->name,_TRUNCATE);
	if (strlen(f->format)) {
		strncpy_s(fmt,_countof(fmt),f->format,_TRUNCATE);
		pos = strstr(fmt,"%");
		if (pos) {
			pos2 = pos + 1;
			*pos = '\0';
			_snprintf_s(filespec,_countof(filespec),_TRUNCATE,"%s%s%s%s",f->dir_name,fmt,currentdate,pos2);
		} else {
			_snprintf_s(filespec,_countof(filespec),_TRUNCATE,"%s%s",f->dir_name,fmt);
		}
	} else {
		_snprintf_s(filespec,_countof(filespec),_TRUNCATE,"%s*%s*.*",f->dir_name,currentdate);
	}
	LogExtMsg(INFORMATION_LOG,"+++++++++++++++ checking today: %s", filespec);
	handle = FindFirstFile(filespec, &firstData);
	if (handle != INVALID_HANDLE_VALUE) {
		//Make sure we have the last file instead
		while (FindNextFile(handle,&firstData)) continue;
		LogExtMsg(INFORMATION_LOG,"+++++++++++++++ Found file: %s", firstData.cFileName);
		//LogExtMsg(INFORMATION_LOG,"Checking for other files");
		//while (FindNextFile(handle, &findData)) {
		//	LogExtMsg(INFORMATION_LOG,"+++++++++++++++ Found file: %s", findData.cFileName);
		//	_snprintf_s(f->name,SIZE_OF_LOGNAME,_TRUNCATE,"%s%s",f->dir_name,findData.cFileName);
		//	//AddLogWatch(name,type);
		//}
	} else {
		//check to see if we are still logging to yesterday
		getdate(currentdate, true);
		if (strlen(f->format)) {
			strncpy_s(fmt,SIZE_OF_LOGNAME,f->format,_TRUNCATE);
			pos = strstr(fmt,"%");
			if (pos) {
				pos2 = pos + 1;
				*pos = '\0';
				_snprintf_s(filespec,_countof(filespec),_TRUNCATE,"%s%s%s%s",f->dir_name,fmt,currentdate,pos2);
			} else {
				_snprintf_s(filespec,_countof(filespec),_TRUNCATE,"%s%s",f->dir_name,fmt);
			}
		} else {
			_snprintf_s(filespec,_countof(filespec),_TRUNCATE,"%s*%s*.*",f->dir_name,currentdate);
		}
		LogExtMsg(INFORMATION_LOG,"Could not find a file for today, checking yesterday: %s", filespec);
		handle = FindFirstFile(filespec, &firstData);
		if (handle == INVALID_HANDLE_VALUE) {
			if (strlen(f->name)) {
				LogExtMsg(INFORMATION_LOG,"#Could not find a file for yesterday either, continuing to watch %s.", f->name);
				return(0);
			} else {
				LogExtMsg(INFORMATION_LOG,"Could not find a file for yesterday either, will continue watching %s.", filespec);
				_snprintf_s(f->name,_countof(f->name),_TRUNCATE,"%s",filespec);
				FindClose(handle);
				return(0);
			}
		}
		LogExtMsg(INFORMATION_LOG,"+++++++++++++++ Found file: %s", firstData.cFileName);
		//while (FindNextFile(handle, &findData)) {
		//	LogExtMsg(INFORMATION_LOG,"+++++++++++++++ Found file: %s", findData.cFileName);
		//	_snprintf_s(f->name,SIZE_OF_LOGNAME,_TRUNCATE,"%s%s",f->dir_name,findData.cFileName);
		//	//AddLogWatch(f->name,f->type);
		//}
	}
	_snprintf_s(f->name,_countof(f->name),_TRUNCATE,"%s%s",f->dir_name,firstData.cFileName);
	FindClose(handle);
	if (strstr(firstData.cFileName,f->name)) return(1);
	else return(DIR_NEW_FILE);
}


 
int htmlspecialchars(char *src,char **ret,int type){ 
 
    int len=0; 
    int entity_len=0; 
    int size=0; 
    char *tmp; 
 
    len=strlen(src); 
    tmp=src; 
 
    while(*src!='\0'){ 
 
        switch(*src){ 
 
 
            case '&'://     
                entity_len+=basic_entities[0].entitylen; 
                break; 
 
            case '"'://    " 
 
                if((type==ENT_COMPAT)||(type=ENT_QUOTES)) entity_len+=basic_entities[1].entitylen; 
                break; 
 
            case '\''://    ' 
 
                if((type!=ENT_COMPAT)||(type==ENT_QUOTES)) entity_len+=basic_entities[2].entitylen; 
                break; 
 
            case '<'://    < 
 
                entity_len+=basic_entities[3].entitylen; 
                break; 
 
            case '>'://    > 
 
                entity_len+=basic_entities[4].entitylen; 
                break; 
 
        } 
 
        ++src; 
 
    } 
 
    src=tmp; 
    size=len+entity_len; 
 
    if(((*ret)=(char *)malloc(sizeof(char)*size+1))==NULL) return 1; 
    memset((*ret),0x0,sizeof(char)*size+1); 
 
    tmp=(*ret); 
 
    while(*src!='\0'){ 
 
        switch(*src){ 
 
 
            case '&'://     
                memcpy((*ret),basic_entities[0].entity,basic_entities[0].entitylen); 
                (*ret)+=basic_entities[0].entitylen; 
                break; 
 
            case '"'://    " 
 
                if((type==ENT_COMPAT)||(type=ENT_QUOTES)){ 
                    memcpy((*ret),basic_entities[1].entity,basic_entities[1].entitylen); 
                    (*ret)+=basic_entities[1].entitylen; 
                } 
                break; 
 
            case '\''://    ' 
 
                if((type!=ENT_COMPAT)||(type==ENT_QUOTES)){
                    memcpy((*ret),basic_entities[2].entity,basic_entities[2].entitylen);
                    (*ret)+=basic_entities[2].entitylen;
                } 
                break;
 
            case '<'://    <

                memcpy((*ret),basic_entities[3].entity,basic_entities[3].entitylen);
                (*ret)+=basic_entities[3].entitylen;
                break; 
 
            case '>'://    >

                memcpy((*ret),basic_entities[4].entity,basic_entities[4].entitylen);
                (*ret)+=basic_entities[4].entitylen;
                break;

            default:

                *(*ret)=*src;
                ++(*ret);

        }
 
        ++src;
 
    }
	(*ret)=tmp;
	return 0;
} 
