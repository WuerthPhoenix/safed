#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <process.h>

#include "LogUtils.h"
#include "NTService.h"
#include "webserver.h"
#include "WebPages.h"
#include "MD5.h"



// extern int getSAFEDDEBUG();

#define MAX_HTTPBUFFER 200000//40960//32768
#define MAX_RESTRICTIP 10 //max 10 restrict ip

// Socket for our pseudo-httpd server
SOCKET http_listen_socket = INVALID_SOCKET;
SOCKET http_message_socket = INVALID_SOCKET;
gnutls_session session_https = NULL;
char fromServer[25] = "";


extern int TLSSERVERFAIL;
extern DWORD WEBSERVER_TLS;
extern HANDLE web_hEventList[3];
extern TCHAR lpszDestination[SIZE_OF_DESTINATION];

// NOTE: This password sits in RAM.
// A user with appropriate access could pull it out.
// .. they could also grab it from the registry.
// Note: Despite the fact that we set the string, this does NOT represent a default password.
char SnarePass[256]="Admin";
char SnareIP[MAX_RESTRICTIP][17];
int SnareIP_count=0;

int InitWebServer(unsigned short port,char *password, char *ip)
{
	LogExtMsg(INFORMATION_LOG,"InitWebServer: configuring listening port");
	struct sockaddr_in local;
	struct hostent *phostent;
	struct in_addr in;
	char rsip[SIZE_OF_RESTRICTIP];
	char* current = ip;

	if(password) {
		strncpy_s(SnarePass,_countof(SnarePass),password,_TRUNCATE);
	}
	SnareIP_count = 0;			
	if(ip && strlen(ip)) {
		int end = 0;
		for(int i = 0; i < 17 ; i++) {
			char* currentIP = strstr(current,";");
			if(currentIP){
				strncpy(rsip,current,currentIP - current);
				rsip[currentIP - current]='\0';
				current = currentIP + 1;
			}else{
				strcpy(rsip,current);
				end = 1;
			}
			phostent=gethostbyname(rsip);
			if(phostent) {
				// strncpy_s(lpszIPAddress,size,phostent->h_addr_list[0],_TRUNCATE);
				memcpy(&in.s_addr, *(phostent->h_addr_list), sizeof(in.s_addr));
				strncpy_s(SnareIP[SnareIP_count],_countof(SnareIP[SnareIP_count]),inet_ntoa(in),_TRUNCATE);
			} else {
				strncpy_s(SnareIP[SnareIP_count],_countof(SnareIP[SnareIP_count]),rsip,_TRUNCATE);
			}
			SnareIP_count++;
			if(end)break;
		}
	}
		
	local.sin_family = AF_INET;
	local.sin_addr.s_addr = INADDR_ANY; 
	local.sin_port = htons(port);

	http_listen_socket = socket(AF_INET, SOCK_STREAM,0); // TCP socket
	
	if (http_listen_socket == INVALID_SOCKET){
		LogExtMsg(INFORMATION_LOG,"bind() failed: INVALID_SOCKET");
		return -1;
	}
	if (setsockopt(http_listen_socket,SOL_SOCKET,SO_DONTLINGER,"0",1)) {
		LogExtMsg(INFORMATION_LOG,"setsockopt(DONTLINGER) failed: SOCKET_ERROR");
		//return -1;
	}
	if (bind(http_listen_socket,(struct sockaddr*)&local,sizeof(local) ) 
		== SOCKET_ERROR) {
		LogExtMsg(INFORMATION_LOG,"bind() failed: SOCKET_ERROR");
		// give it another few chances to bind
		for (int i=0;;i++) {
			Sleep(1000);
			if (bind(http_listen_socket,(struct sockaddr*)&local,sizeof(local) ) != SOCKET_ERROR) break;
			if (i == 4) return -1;
		}
		
	}

	if (listen(http_listen_socket,5) == SOCKET_ERROR) {
		LogExtMsg(INFORMATION_LOG,"listen() failed: SOCKET_ERROR");
		return -1;
	}

	return(1);
}

int CloseWebServer()
{
	closesocket(http_listen_socket);
	//SetEvent(web_hEventList[2]);
	return(1);
}


int HandleConnect(HANDLE event)
{	
	int retval;
	// 8k buffer for input and output. Suggest we may need more for output.
	char HTTPBuffer[MAX_HTTPBUFFER];
	char HTTPBufferTemp[MAX_HTTPBUFFER];
	char HTTPOutputBuffer[MAX_HTTPBUFFER];
	char *pos;
	int size=0;
	int header=1;
	struct timeval tv;
	fd_set webread;

	tv.tv_sec = 1;
	tv.tv_usec = 0;
	FD_ZERO(&webread);
	FD_SET(http_message_socket,&webread);

	if(WEBSERVER_TLS){
		retval = recvTLS (HTTPBuffer,_countof (HTTPBuffer), session_https);
	}else{
		retval = recv(http_message_socket,HTTPBuffer,_countof (HTTPBuffer),0 );
	}
	// NOTE: Should probably do something about requests that are bigger than
	// HTTPBuffer also..

	if (retval == 0){
		if(WEBSERVER_TLS)printf("- Peer has closed the TLS connection\n");
		else printf("recv() failed: error %d\n",WSAGetLastError());
		closesocket(http_message_socket);
		if(WEBSERVER_TLS)deinitTLSSocket(session_https, TRUE);
		return(1);
	}else if (retval < 0){
		if(WEBSERVER_TLS)printf("*** Error: %s\n", gnutls_strerror (retval));
		else printf("recv() failed: socket error %d\n",WSAGetLastError());
		closesocket(http_message_socket);
		if(WEBSERVER_TLS)deinitTLSSocket(session_https, TRUE);
		return(1);
	}


	HTTPBuffer[retval]='\0';


	LogExtMsg(INFORMATION_LOG,"Handling connection: [ %s ]\n",HTTPBuffer); 
	char* isPOST = strstr(HTTPBuffer,"POST");
	char* headerend = strstr(HTTPBuffer,"\r\n\r\n");
	if (!headerend || (isPOST && (strlen(headerend) == 4))) {
		int tempval;
		//fopen patch, sleep then check if there is anything left to grab
		Sleep(500);
		if (select(0,&webread,NULL,NULL,&tv) > 0) {
			if(WEBSERVER_TLS){

				tempval = recvTLS(HTTPBufferTemp,_countof (HTTPBufferTemp), session_https);

				/*if (tempval == 0){
					printf("- Peer has closed the TLS connection\n");
					closesocket(http_message_socket);
					deinitTLSSocket(session_https, TRUE);
					return(1);
				}else if (tempval < 0){
					printf("*** Error: %s\n", gnutls_strerror (tempval));
					closesocket(http_message_socket);
					deinitTLSSocket(session_https, TRUE);
					return(1);
				}*/
			}else{
				tempval = recv(http_message_socket,HTTPBufferTemp,_countof (HTTPBufferTemp),0 );
			}
			HTTPBufferTemp[tempval]='\0';
			strncat_s(HTTPBuffer,_countof(HTTPBuffer),HTTPBufferTemp,_TRUNCATE);
		} else {
			printf("recv() failed: Incomplete message [%d]\n",WSAGetLastError());
			closesocket(http_message_socket);
			if(WEBSERVER_TLS)deinitTLSSocket(session_https, TRUE);
			return(1);
		}
	}	



	// Hunt down the authentication string
	// Dont ask for authentication if the password is blank.
	pos=strstr(HTTPBuffer,"Authorization: Basic ");
	if(strlen(SnarePass) && !pos) {
		LogExtMsg(INFORMATION_LOG,"Requesting Auth: no password");
		RequestAuth(HTTPOutputBuffer,MAX_HTTPBUFFER);
		header=0;
	} else if(strlen(SnarePass) && !MatchAuth(pos + strlen("Authorization: Basic "))) {
		LogExtMsg(INFORMATION_LOG,"Requesting Auth: BAD password");
		RequestAuth(HTTPOutputBuffer,MAX_HTTPBUFFER);
		header=0;
	} else {
		char content[MAX_HTTPBUFFER] = "";
		if(isPOST){
			char boundary[100] = "";
			char* pos=strstr(HTTPBuffer,"boundary=");
			char* pos2;
			if(pos){
				pos = pos + 9;
				pos2=strstr(pos,"\r\n");
				if(pos2){
					strncpy(boundary,pos,(int)(pos2 - pos));
					pos = pos2 + 2;
				}
			}
			if(strlen(boundary) > 0){
				pos2 =strstr(pos,boundary);
				if(pos2){
					pos = pos2 + strlen(boundary) + 2; //\r\n
					pos2 =strstr(pos,boundary);
					if(pos2){
						int len = (int)(pos2 - pos -4);//\r\n\r\n
						if(len >= sizeof(content))len = sizeof(content) -1;
						strncpy(content,pos,len);
						content[len]='\0';
					}
				}
			}		

		}

		// Don't care about anything after the GET
		pos=strstr(HTTPBuffer,"\n");
		if(pos) {
			*pos='\0';
		}
		pos=strstr(HTTPBuffer,"\r");
		if(pos) {
			*pos='\0';
		}

		// Get rid of the "GET "
		pos=strstr(HTTPBuffer," ");
		if(pos) {
			strncpy_s(HTTPBuffer,MAX_HTTPBUFFER,pos+1,_TRUNCATE);
		}
			
		// and the HTTP/1.x
		pos=strstr(HTTPBuffer," ");
		if(pos) {
			*pos='\0';
		}

		LogExtMsg(INFORMATION_LOG,"DEBUG: DATA chopped, now decoding... [%s]",HTTPBuffer);

		decodeurl(HTTPBuffer);
		LogExtMsg(INFORMATION_LOG,"DEBUG: DATA IN is now [%s]",HTTPBuffer);
		if(isPOST){
			strcat(HTTPBuffer,"?");
			strncat(HTTPBuffer,content,MAX_HTTPBUFFER);
		}
		size=HandleWebPages(HTTPBuffer,HTTPOutputBuffer,MAX_HTTPBUFFER,http_message_socket, session_https, fromServer,event);

	}

	if(size == -1) {
		size = 0;
	} else if(size == 0 && HTTPOutputBuffer) {
		size=(int)strlen(HTTPOutputBuffer);
	}

	if(size) {
		LogExtMsg(INFORMATION_LOG,"Data back from handlewebpages..");
		// Overwrite HTTPBuffer with the header data.
		strncpy_s(HTTPBuffer, _countof(HTTPBuffer),"HTTP/1.0 200 OK\r\n" \
							"Server: NetEye Safed/1.0\r\n" \
							"MIME-version: 1.0\r\n" \
							"Content-type: text/html\r\n\r\n",
				_TRUNCATE);
		
		if(header) {
			if(WEBSERVER_TLS){
				retval = sendTLS(HTTPBuffer,session_https);
			}else{
				retval = send(http_message_socket,HTTPBuffer,(int)strlen(HTTPBuffer),0);
			}

			if (retval < 0) {
				if(WEBSERVER_TLS)LogExtMsg(INFORMATION_LOG,"sendTLS() failed: %s", getTLSError(retval));
				else  LogExtMsg(INFORMATION_LOG,"send() failed: SOCKET_ERROR");
			
				// force close and return
				closesocket(http_message_socket);
				if(WEBSERVER_TLS) deinitTLSSocket(session_https, TRUE);
				return(1);
			}
		}

		
		if(WEBSERVER_TLS){
			retval = sendTLS(HTTPOutputBuffer,session_https,size);
		}else{
			retval = send(http_message_socket,HTTPOutputBuffer,size,0);
		}

		if (retval < 0) {
			if(WEBSERVER_TLS)LogExtMsg(INFORMATION_LOG,"send() failed: %s", getTLSError(retval));
			else LogExtMsg(INFORMATION_LOG,"send() failed: SOCKET_ERROR"); 
		
			closesocket(http_message_socket);
			if(WEBSERVER_TLS)deinitTLSSocket(session_https, TRUE);
			return(1);
		}
	}
	
	LogExtMsg(INFORMATION_LOG,"Handling connection finished\n");

	// printf("DEBUG: Terminating connection\n");
	closesocket(http_message_socket);
	if(WEBSERVER_TLS)deinitTLSSocket(session_https, TRUE);
	
	return(1);
}

int StartThread(HANDLE event)
{
	int threadid=0;
	
	threadid=(int)_beginthread( ListenThread, 0, (HANDLE) event );
	LogExtMsg(INFORMATION_LOG,"DEBUG: Starting thread %d.. event is %d",threadid,event);
	if(threadid==-1)
	{
		LogExtMsg(INFORMATION_LOG,"Error in HTTPD thread creation");
		return(-1);
	}

	return(1);
}

void ListenThread(HANDLE event)
{
	struct sockaddr_in from;
	int fromlen;
	BOOL invalidrequest=1;
	char ip_address[16] = "";
	time_t ctime;
	struct tm ntime;
	

	LogExtMsg(INFORMATION_LOG,"Starting ListenThread");

	fromlen=sizeof(from);
	while(invalidrequest) {
		LogExtMsg(INFORMATION_LOG,"ListenThread - looping");

		http_message_socket = accept(http_listen_socket,(struct sockaddr*)&from, &fromlen);

		if (http_message_socket == INVALID_SOCKET) {


			LogExtMsg(INFORMATION_LOG,"Accept() Error - socket is invalid");
			Sleep(1000);
			break;
		}
		
		strncpy_s(ip_address,_countof(ip_address),inet_ntoa(from.sin_addr),_TRUNCATE);

		if(WEBSERVER_TLS){		
			if(!TLSSERVERFAIL)session_https = initSTLSSocket(http_message_socket,getNameFromIP(ip_address));
			else session_https = NULL;
			if (!session_https){
				closesocket(http_message_socket);
				LogExtMsg(INFORMATION_LOG,"Web Server Error - TLS session failed");
				continue;
			}
		}

		if(AuthorisedSource(ip_address)) {
			invalidrequest=0;
			LogExtMsg(INFORMATION_LOG,"ListenThread finished - telling main thread about the new connection ");
			// Notify the main thread
			if(!strcmp(ip_address,lpszDestination)){
				time(&ctime);                
				localtime_s(&ntime,&ctime);
				_snprintf_s(fromServer,_countof(fromServer),_TRUNCATE,"[%04d/%02d/%02d - %02d:%02d:%02d]",ntime.tm_year+1900,ntime.tm_mon+1,ntime.tm_mday,ntime.tm_hour,ntime.tm_min,ntime.tm_sec);
			}else{
				_snprintf_s(fromServer,_countof(fromServer),_TRUNCATE,"");
			}
			

			SetEvent(event);
		} else {
			invalidrequest=1;
			if(WEBSERVER_TLS){
				sendTLS("<HTML><BODY><CENTER>Authentication failed</CENTER></BODY></HTML>\r\n\0",session_https);
			}else{
				send(http_message_socket,"<HTML><BODY><CENTER>Authentication failed</CENTER></BODY></HTML>\r\n\0",66,0);		
			}
			closesocket(http_message_socket);
			if(WEBSERVER_TLS)deinitTLSSocket(session_https, TRUE);
		}
	}

	LogExtMsg(INFORMATION_LOG,"ListenThread terminating (explicitly).");
	// Terminate this thread.
	_endthread();
	
}

BOOL AuthorisedSource(char *address)
{
	if(!address) return(0);
	if(!strlen(address)) return(1);
	if(!SnareIP_count) return(1);
	for (int i=0;i<SnareIP_count;i++) {
		if(!strncmp(address,SnareIP[i],15)) {
			return(1);
		}
	}
	return(0);
}

void decodeurl(char *pEncoded)
{
	char *pDecoded;

	pDecoded=pEncoded;
	while (*pDecoded) {
		if (*pDecoded=='+') *pDecoded=' ';
		pDecoded++;
	};
	pDecoded=pEncoded;
	while (*pEncoded) {
		if (*pEncoded=='%') {
			pEncoded++;
			if(pEncoded[0]) {
				if(pEncoded[1]) {
					if (isxdigit(pEncoded[0])&&isxdigit(pEncoded[1])) {
						// *pDecoded++=(char)hex2int((char *)pEncoded);
						// Special Wuerth Phoenix - escape ampersands and slashes.
						// Note: hex characters are 3 bytes, we are only adding 2, so no
						// problems with buffer overflows.
						*pDecoded=(char)hex2int((char *)pEncoded);
						if(*pDecoded=='&') {
							*pDecoded++='\\';
							*pDecoded='&';
						} else if(*pDecoded=='\\') {
							*pDecoded++='\\';
							*pDecoded='\\';
						} else if(*pDecoded=='=') {
							*pDecoded++='\\';
							*pDecoded='=';
						}
						pDecoded++;
						// End changes

						pEncoded+=2;
					}
				} else {
					break;
				}
			} else {
				break;
			}
		} else {
			*pDecoded++=*pEncoded++;
		}
	}
	*pDecoded='\0';
}

// Find ampersand-delimited strings (but ignore escaped ampersands).
char * GetNextArgument(char *source,char *destvar,int varlength,char *destval,int vallength)
{
	char prevchar='\0';
	int destlen=0;

	if(!source || !destvar || !destval) {
		return((char *)NULL);
	}

	if(!*source) {
		return((char *)NULL);
	}

	*destvar='\0';
	*destval='\0';

	// length = maximum size of dest
	while(*source && !(*source == '&' && prevchar != '\\') && !(*source == '=' && prevchar != '\\') && destlen<varlength) {

		if(*source!='\\' || (*source == '\\' && prevchar == '\\')) {
			*destvar=*source;
			destvar++;
			destlen++;
		}

		if(*source == '\\' && prevchar == '\\') {
			prevchar=0;
		} else {
			prevchar=*source;
		}

		source++;
	}
	*destvar='\0';

	destlen=0;

	if(*source == '=') {
		// We have a value. Excellent.
		source++;
	
		while(*source && !(*source == '&' && prevchar != '\\') && destlen<vallength) {
			if(*source!='\\' || (*source == '\\' && prevchar == '\\')) {
				*destval=*source;
				destval++;
				destlen++;
			}

			if(*source == '\\' && prevchar == '\\') {
				prevchar=0;
			} else {
				prevchar=*source;
			}
			source++;
		}
		*destval='\0';
	}

	// Return our position in the new string, or null for end of string.
	if(*source) {
		source++;
	}

	return(source);
}


int hex2int(char *pChars)
{
	int Hi;
	int Lo;
	int Result;

	Hi=pChars[0];
	if ('0'<=Hi&&Hi<='9') {
		Hi-='0';
	} else if ('a'<=Hi&&Hi<='f') {
		Hi-=('a'-10);
	} else if ('A'<=Hi&&Hi<='F') {
		Hi-=('A'-10);
	}
	Lo = pChars[1];
	if ('0'<=Lo&&Lo<='9') {
		Lo-='0';
	} else if ('a'<=Lo&&Lo<='f') {
		Lo-=('a'-10);
	} else if ('A'<=Lo&&Lo<='F') {
		Lo-=('A'-10);
	}
	Result=Lo+(16*Hi);
	return (Result);
}

void RequestAuth(char *HTTPOutputBuffer,int size)
{
	strncpy_s(HTTPOutputBuffer,size,"HTTP/1.0 401 Unauthorized\r\n" \
		"Connection: close\r\n" \
		"Content-Type: text/html\r\n" \
		"Server: NetEye Safed\r\n" \
		"WWW-Authenticate: Basic realm=\"NetEye Safed\"\r\n\r\n" \
		"<HTML><HEAD>\r\n<TITLE>401 Authorization Required</TITLE>\r\n" \
		"</HEAD><BODY>\r\n<H2>Authorization Required</H2>\r\nNetEye Safed could not " \
		"verify that you.are authorized to access the remote control facility. " \
		"You may have supplied the wrong credentials<P>\r\n<HR>\r\n" \
		"<ADDRESS>NetEye Safed Remote Control facility</ADDRESS>\r\n</BODY></HTML>\r\n",_TRUNCATE);
}

/*void RequestAuth(char *HTTPOutputBuffer,int size)
{
	strncpy_s(HTTPOutputBuffer,size,"HTTP/1.0 401 Unauthorized\n" \
		"Connection: close\n" \
		"Content-Type: text/html\n" \
		"Server: NetEye Safed\n" \
		"WWW-Authenticate: Basic realm=\"NetEye Safed\"\n",_TRUNCATE);
}*/

BOOL MatchAuth(char *AuthStart)
{
	char AuthString[256]="";
	char AuthString2[256]="";
	char CryptString[256]="";
	char *pos;
	int length=0;

	// Hunt down end of line
	pos=AuthStart;

	while(isalpha(*pos) || (*pos >= '0' && *pos <= '9') || *pos == '+' || *pos == '=') {
		pos++;
	}

	if(!pos) return(0);

	length=(int)(pos-AuthStart);
	if(length<1) return(0);

	if(length >= _countof(AuthString)) {
		length=_countof(AuthString) - 1;
	}
	strncpy_s(AuthString,length+1,AuthStart,_TRUNCATE);
	AuthString[length]='\0';

	length=base64decode(AuthString2,AuthString);

	pos=strstr(AuthString2,":");

	if(!pos) return(0);

	*pos='\0';
	pos++;

	if(strcmp(AuthString2,"admin") && strcmp(AuthString2,"Admin") && strcmp(AuthString2,"ADMIN")) {
		// Username does not match
		return(0);
	}

	strncpy_s(CryptString,_countof(CryptString),MD5String(pos),_TRUNCATE);

	if(!strcmp(CryptString,SnarePass)) {
		return(1);
	}

	// Lets try and support non-encrypted passwords too.
	// Removed for 2.4.5
//	if(!strcmp(MD5String(SnarePass),CryptString)) {
//		return(1);
//	}

	return(0);

}

int base64encode(char *dest, char *src, int len)
{
        unsigned char *bin, *pBase64;
        int chars_left, count=0;
        static const char cb64[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        bin=(unsigned char *)src;
        pBase64=(unsigned char *)dest;

        chars_left = len;
        while (chars_left > 0) {
                pBase64[0] = cb64[ bin[0] >> 2 ];
                pBase64[1] = cb64[ ((bin[0] & 0x03) << 4) | ((bin[1] & 0xf0) >> 4) ];
                chars_left--;
                pBase64[2] = (unsigned char) (chars_left > 0? cb64[ ((bin[1] & 0x0f) << 2) | ((bin[2] & 0xc0) >> 6) ] : '=');
                chars_left--;
                pBase64[3] = (unsigned char) (chars_left > 0? cb64[ bin[2] & 0x3f ] : '=');
                chars_left--;

                bin += 3;
                pBase64 += 4;
                count++;
        }
        *pBase64 = '\0';
        return(count);
}

int base64decode(char *dest, char *src)
{
	char *ascii, *pBase64, *mBase64;
	char TopVal, BottomVal;
	int chars_left, i, padding, count=0;
	
	mBase64 = (char *) malloc(strlen(src) + 1);
	pBase64 = mBase64;
	if (pBase64 == NULL) {
		dest[0] = '\0';	// Returns null if there was a problem
		return(0);
	}
	
	strncpy_s(pBase64,strlen(src) + 1, src,_TRUNCATE);
	ascii = dest;
	
	chars_left = (int)strlen(pBase64);
	while (chars_left > 0) {
		padding = 0;
		for (i = 0; i < 4; i++) {
			if (pBase64[i] == '=') {
				padding++;
			} else if (pBase64[i] == '+') {
				pBase64[i] = 62;
			} else if (pBase64[i] == '/') {
				pBase64[i] = 63;
			} else if (pBase64[i] <= '9') {
				pBase64[i] = pBase64[i] + 52 - '0';
			} else if (pBase64[i] <= 'Z') {
				pBase64[i] = pBase64[i] - 'A';
			} else {
				pBase64[i] = pBase64[i] + 26 - 'a';
			}
		}
		TopVal = pBase64[0] << 2;
		BottomVal = pBase64[1] >> 4;
		ascii[0] = TopVal | BottomVal;
		count++;
		
		if (padding < 2) {
			TopVal = pBase64[1] << 4;
			BottomVal = pBase64[2] >> 2;
			ascii[1] = TopVal | BottomVal;
			count++;
			if (padding < 1) {
				TopVal = pBase64[2] << 6;
				ascii[2] = TopVal | pBase64[3];
				count++;
			} else {
				ascii[2] = '\0';
			}
		} else {
			ascii[1] = '\0';
		}
		
		ascii += 3;
		pBase64 += 4;
		chars_left -= 4;
	}
	*ascii = '\0';
	free(mBase64);
	return(count);
}

