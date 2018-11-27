
#include <stdio.h>
#include <stdlib.h>
#include <winsock2.h>
#include <windows.h>

#include "support.h"
#include "RegKeyUtilities.h"
#include "LogUtils.h"
#include "Communication.h"



int TLSFAIL = 0;

HANDLE hMutexSend;
HostNode *hosthead; 
char socketStatus[600] = "";
DWORD SocketType=SOCKETTYPE_UDP;	// 0 for UDP
DWORD dwDestPort=514;
// Destination for log events. Default it to something safe.
TCHAR lpszDestination[SIZE_OF_DESTINATION]="127.0.0.1";



HostNode * getHostHead(){
	return hosthead;
}

void setHostHead(HostNode* h){
	hosthead = h;
}

void GetDestination(char * lpszDestination,int size)
{
	if(!lpszDestination) return;
	if(!size) return;
	
	strncpy_s(lpszDestination,size,"127.0.0.1",_TRUNCATE);
	if(!MyGetProfileString("Network","Destination",lpszDestination,size))
	{
		// Problem. Couldn't retrieve the destination from the registry.
		// Default it to something harmless.
		MyWriteProfileString("Network","Destination",lpszDestination);
	}
}


BOOL initSocketMutex(){
	SECURITY_ATTRIBUTES MutexOptions;
	MutexOptions.bInheritHandle = true;
	MutexOptions.nLength = sizeof(SECURITY_ATTRIBUTES);
	MutexOptions.lpSecurityDescriptor = NULL;
	hMutexSend = CreateMutex(&MutexOptions,FALSE,"SendLock");
	if(hMutexSend == NULL) {
		LogExtOnlyDebugMsg(ERROR_LOG,"I cannot create the Safed Agent Send 'Mutex' lock. This probably means that you already have another instance of the Safed Agent running.\nPlease stop the other incarnation of the Safed Agent (eg: net stop safed) before continuing."); 
		return FALSE;
	}
	return TRUE;
}
void deinitSocketMutex(){
	if(hMutexSend)CloseHandle(hMutexSend);
}

void deinitSockets(){
	while(hosthead) {
		HostNode *th;
		th = hosthead;
		hosthead = th->next;
		if (th->Socket != INVALID_SOCKET) {
			closesocket(th->Socket);
			if(isTLS()){
				deinitTLSSocket(th->tlssession, TRUE);
			}
		}
		free(th);
	}
	hosthead = NULL;
	if(isTLS()){
		if(!TLSFAIL)deinitTLS();
	}
}
BOOL isTLS(){
	if(SocketType == SOCKETTYPE_TCP_TLS) return TRUE;
	return FALSE;
}
void initSocket(){
	socketStatus[0] = '\0';
	SocketType=MyGetProfileDWORD("Network","SocketType",SOCKETTYPE_UDP);
	dwDestPort=MyGetProfileDWORD("Network","DestPort",514);
	GetDestination(lpszDestination,_countof(lpszDestination));
	if(isTLS()){
		TLSFAIL = initTLS();
	}
}


char* getSocketType(int type){
	if(type == SOCKETTYPE_TCP) return "TCP";
	if(type == SOCKETTYPE_TCP_TLS) return "TLS";
	return "UDP";

}
///////////////////////////////////////////////////////////////////
// InitWinsock
//              starts up winsock.dll or wsock32.dll
BOOL InitWinsock( char *szError, int size )
{
	WSAData wsData;

	if(!szError) return(FALSE);
	
	WORD wVersionRequested = WINSOCK_VERSION;
	
	if(WSAStartup(wVersionRequested, &wsData) != 0)
	{
		// :( error
		if( szError )
		{
			sprintf_s(szError,size,"WSAStartup failed: WSA ERROR: %d\r\n",
				WSAGetLastError());
			LogExtMsg(ERROR_LOG,szError); 
		}
		return FALSE;
	}
	
	// all is well
	return TRUE;
}

//////////////////////////////////////////////////////////////////////////////
// TerminateWinsock
//      call this function with the current socket or INVALID_SOCKET
void TerminateWinsock( SOCKET hSocket, gnutls_session session )
{
	// cancel blocking calls, if any
	WSACancelBlockingCall();
	
	// close socket
	if( hSocket != INVALID_SOCKET ) {
		closesocket(hSocket);
		if(isTLS()){
			deinitTLSSocket(session, TRUE);
		}
		hSocket=INVALID_SOCKET;
	}
		
	// unload winsock
	WSACleanup();
}

// Note that hosthead is a global.
void OpenSockets()
{

	HostNode * headnode=NULL;
	char szError[MAX_STRING];

	headnode=(HostNode *)malloc(sizeof(HostNode));
	if(!headnode) {
		// Oh dear.. out of RAM?
		hosthead = headnode;
		return;
	}

	headnode->next=NULL;
	strncpy_s(headnode->HostName,511,lpszDestination,_TRUNCATE);
	headnode->Socket=ConnectToServer( headnode, szError,_countof(szError) );
	if(headnode->Socket == INVALID_SOCKET) {
		LogExtMsg(ERROR_LOG,"Problem opening Socket to %s: %s",lpszDestination,szError);
	}
	hosthead = headnode;
}




//////////////////////////////////////////////////////////////
// ConnectToServer:
//    connects to a server on a specified port number
//    returns the connected socket
SOCKET ConnectToServer(HostNode *hcn, char *szError, int size)
{

	SOCKET hSocket;
	struct hostent far *hp;
	time_t ctime;
	struct tm ntime;
	char thedate[25] = "";
	
	time(&ctime);                
	localtime_s(&ntime,&ctime);
	_snprintf_s(thedate,_countof(thedate),_TRUNCATE,"[%04d/%02d/%02d - %02d:%02d:%02d]",ntime.tm_year+1900,ntime.tm_mon+1,ntime.tm_mday,ntime.tm_hour,ntime.tm_min,ntime.tm_sec);

	LogExtMsg(INFORMATION_LOG,"ConnectToServer");
	if(!hcn->HostName) return INVALID_SOCKET;
	if(!szError || !size) return INVALID_SOCKET;
	if(!*hcn->HostName) return INVALID_SOCKET;

	DWORD dwWaitSend = WaitForSingleObject(hMutexSend,500);
	if(dwWaitSend == WAIT_OBJECT_0) {
		hcn->SocketType = SocketType;
		// Should use something nicer to check for IP addresses...
		if( isdigit(hcn->HostName[0])) {
			ZeroMemory((char *) &hcn->server, sizeof(hcn->server));
			hcn->server.sin_family      = AF_INET;
			hcn->server.sin_addr.s_addr = inet_addr(hcn->HostName);
			hcn->server.sin_port        = htons((UINT)dwDestPort);
		} else {
			if ( (hp = (struct hostent far *) gethostbyname(hcn->HostName)) == NULL)	{
				_snprintf_s(szError,size,_TRUNCATE,"Error: gethostbyname failed: %s.",hcn->HostName);
				ReleaseMutex(hMutexSend);
				_snprintf_s(socketStatus,_countof(socketStatus),_TRUNCATE,"The connection %s to %s is down! %s\n",getSocketType(hcn->SocketType), hcn->HostName,thedate);
				return INVALID_SOCKET;
			}
			
			ZeroMemory((char *)&hcn->server, sizeof(hcn->server));
			CopyMemory((char *) &hcn->server.sin_addr,hp->h_addr,hp->h_length);
			hcn->server.sin_family = hp->h_addrtype;
			hcn->server.sin_port = htons((UINT)dwDestPort);
		}

		// create socket
		//MM
		if(SocketType == SOCKETTYPE_UDP){
			if((hSocket = socket(AF_INET, SOCK_DGRAM, 0)) == INVALID_SOCKET) {
				_snprintf_s(szError,size,_TRUNCATE,"socket failed to create datagram socket: %d\n",WSAGetLastError());
				ReleaseMutex(hMutexSend);
				_snprintf_s(socketStatus,_countof(socketStatus),_TRUNCATE,"The connection %s to %s is down! %s\n",getSocketType(hcn->SocketType), hcn->HostName, thedate);
				return INVALID_SOCKET;
			}
			LogExtMsg(ERROR_LOG,"Created datagram socket");
		}else{
			if((hSocket = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET) {
				_snprintf_s(szError,size,_TRUNCATE,"socket failed to create stream socket: %d\n",WSAGetLastError());
				ReleaseMutex(hMutexSend);
				_snprintf_s(socketStatus,_countof(socketStatus),_TRUNCATE,"The connection %s to %s is down! %s\n", getSocketType(hcn->SocketType), hcn->HostName, thedate);

				return INVALID_SOCKET;
			}
			if ( connect( hSocket, (SOCKADDR *)&hcn->server, sizeof(hcn->server) ) == SOCKET_ERROR ){
				_snprintf_s(szError,size,_TRUNCATE,"socket failed to connect: %d\n",WSAGetLastError());
				closesocket(hSocket);
				ReleaseMutex(hMutexSend);
				_snprintf_s(socketStatus,_countof(socketStatus),_TRUNCATE,"The connection %s to %s is down! %s\n",getSocketType(hcn->SocketType), hcn->HostName, thedate);
				return INVALID_SOCKET;
			}
			if(SocketType == SOCKETTYPE_TCP_TLS){
				if(!TLSFAIL)hcn->tlssession = initTLSSocket(hSocket, inet_ntoa(hcn->server.sin_addr));
				else hcn->tlssession = NULL;
				if (!hcn->tlssession){
					closesocket(hSocket);
					ReleaseMutex(hMutexSend);
					if(TLSFAIL)_snprintf_s(socketStatus,_countof(socketStatus),_TRUNCATE,"The connection %s to %s is down! TLS initialization failed! %s\n",getSocketType(hcn->SocketType), hcn->HostName, thedate);
					else _snprintf_s(socketStatus,_countof(socketStatus),_TRUNCATE,"The connection %s to %s is down! %s\n",getSocketType(hcn->SocketType), hcn->HostName, thedate);
					return INVALID_SOCKET;
				}
				
			}
			LogExtMsg(INFORMATION_LOG,"Created stream socket");
		}
	}

	ReleaseMutex(hMutexSend);
	_snprintf_s(socketStatus,_countof(socketStatus),_TRUNCATE,"The connection %s to %s is up! %s\n", getSocketType(hcn->SocketType) ,hcn->HostName, thedate);

	return hSocket;
}


void  SendToAll(char *buf, int nSize){

	HostNode *currentnode;
  	TCHAR szErrorBuff[MAX_STRING]="";
	DWORD dwDestPort=6161;
	currentnode = hosthead;
	while(currentnode) {
		if(currentnode->Socket == INVALID_SOCKET) {
			// Try to reestablish here.
			// Since socket connects use a fair bit of system resources, try and do it nicely.
			LogExtMsg(INFORMATION_LOG,"Socket is toast for %s. Trying to reestablish.",currentnode->HostName); 
			
			currentnode->Socket = ConnectToServer( currentnode, szErrorBuff, _countof(szErrorBuff) );
			
			if(currentnode->Socket == INVALID_SOCKET) {
				// Hmm. Try again later.
				// Jump to the next socket
				currentnode=currentnode->next;
				LogExtMsg(ERROR_LOG,"Failed to reconnect socket");
				continue;
			}
		}


		if(currentnode){
			if( !SendToSocket(currentnode, buf, nSize, szErrorBuff, _countof(szErrorBuff)) )
			{
				LogExtMsg(INFORMATION_LOG,szErrorBuff);
				LogExtMsg(INFORMATION_LOG,"Socket for %s is toast. Breaking out - will reestablish next time.",currentnode->HostName); 
				// Close the socket. Restablish it on the next cycle, if we can.
				CloseSocket(currentnode->Socket, currentnode->tlssession);
				currentnode->Socket=INVALID_SOCKET;
			} 
		}

		
		currentnode=currentnode->next;
	}
}

int CloseSocket(SOCKET sock, gnutls_session session){
	int ret = 0;
	DWORD dwWaitSend = WaitForSingleObject(hMutexSend,500);
	if(dwWaitSend == WAIT_OBJECT_0) {
		ret = closesocket(sock);
		if(SocketType == SOCKETTYPE_TCP_TLS){
			ret = deinitTLSSocket(session, TRUE);
		}
	}else ret = -1;
	ReleaseMutex(hMutexSend);	
	return ret;

}

//////////////////////////////////////////////////////////////////
// SendToSocket
//              sends a buffer (buf) of size size to the specified socket
//              returns TRUE or FALSE.
BOOL  SendToSocket(HostNode *hcn, char *buf, int nSize, char *szError, int eSize)
{
	time_t ctime;
	struct tm ntime;
	char thedate[25] = "";
	BOOL ret = TRUE;
	DWORD dwWaitSend = WaitForSingleObject(hMutexSend,500);
	if(dwWaitSend == WAIT_OBJECT_0) {
		int bytessent=0;

		if(!buf || !szError || !eSize || !hcn || hcn->Socket == INVALID_SOCKET) return(0);

		do {
			if(SocketType == SOCKETTYPE_TCP_TLS){
				bytessent = sendTLS(buf,hcn->tlssession);
				if(bytessent < 0) {
					LogExtMsg(ERROR_LOG,"error sending to SSL server. WSA ERROR: %d",getTLSError(bytessent));
					ret = FALSE;
					break;
				}
			}else{
				LogExtMsg(ERROR_LOG,"sending to server......>: %s",buf); 
				bytessent = sendto(hcn->Socket,buf,nSize,0,(SOCKADDR *)&hcn->server,sizeof(hcn->server));
				LogExtMsg(ERROR_LOG,"sent to server......>: %d = ",bytessent,WSAGetLastError());
				if(bytessent==-1) {
					LogExtMsg(ERROR_LOG,"error sending to server. WSA ERROR: %d",WSAGetLastError()); 
					ret = FALSE;
					break;
				}
			}
			buf+= bytessent;
			nSize -= bytessent;
		} while(nSize > 0);
	}else ret = FALSE;
	ReleaseMutex(hMutexSend);	
	time(&ctime);                
	localtime_s(&ntime,&ctime);
	_snprintf_s(thedate,_countof(thedate),_TRUNCATE,"[%04d/%02d/%02d - %02d:%02d:%02d]",ntime.tm_year+1900,ntime.tm_mon+1,ntime.tm_mday,ntime.tm_hour,ntime.tm_min,ntime.tm_sec);

	if(ret) _snprintf_s(socketStatus,_countof(socketStatus),_TRUNCATE,"The connection %s to %s is up! %s\n",getSocketType(hcn->SocketType), hcn->HostName, thedate);
	else _snprintf_s(socketStatus,_countof(socketStatus),_TRUNCATE,"The connection %s to %s is down! %s\n", getSocketType(hcn->SocketType), hcn->HostName, thedate);
	return ret;
}



int SendFailedCache(HostNode *hcn, char *sFile, int size, int* sIndex, DWORD dwMaxMsgSize){
	char dir[MAX_PATH];
	char tempdir[MAX_PATH];
	char tempfile[MAX_PATH];
	HANDLE hFind = INVALID_HANDLE_VALUE;
	WIN32_FIND_DATA ffd;
	char *list[100];
	DWORD dwError=0;
	int error = 0;
	TCHAR szError[MAX_STRING]="";
	char* line = (char*)malloc(dwMaxMsgSize*sizeof(char)); 
	if (line){
		line[0]='\0';
	}else{ 
		LogExtMsg(ERROR_LOG,"NO MEMORY LEFT!!!");
		return 1;
	
	}	

	ExpandEnvironmentStrings("%SystemRoot%\\system32\\LogFiles\\Safed",tempdir,MAX_PATH);
	strcpy(dir, tempdir);
	strcat_s(tempdir, MAX_PATH, "\\*");
	hFind = FindFirstFile(tempdir, &ffd);

	if (INVALID_HANDLE_VALUE == hFind){
		 LogExtMsg(ERROR_LOG,"Error opening: %s\n", tempdir);
		 return 1;
	 } 
    LogExtMsg(ERROR_LOG,"sending from cache ......>: %s  from index %d",sFile,*sIndex); 
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
	  LogExtMsg(ERROR_LOG,"Error opening files: %d\n", dwError);
	}
	for(int j =0; j<i; j++){
		int cmp =strcmp(list[j], sFile);
		if(cmp >= 0){
			if(cmp > 0)*sIndex = 1;
			strcpy(tempfile, dir);
			strcat_s(tempfile, MAX_PATH, "\\");
			strcat_s(tempfile, MAX_PATH, list[j]);
			FILE* cache = NULL;
			fopen_s(&cache,tempfile,"r");
			if(cache) {
				int cnt = 0;
				while (fgets(line, dwMaxMsgSize, cache)) {
					cnt++;
					if(cnt >= *sIndex){
						 if(!SendToSocket(hcn, line, (int)strlen(line), szError, _countof(szError))){
							error = 1;
							strncpy_s(sFile,size,list[j],_TRUNCATE);
							*sIndex = cnt;
							break;
						}			
					}
					line[0]='\0';
				}
				fclose(cache);
				if(error)break;

			}		
		}
		free(list[j]);
	}
	FindClose(hFind);
	if (line) free(line);
	if(!error){ 
		*sIndex = 0;	
		strncpy_s(sFile,size,"",_TRUNCATE);
	}
	return error;

}