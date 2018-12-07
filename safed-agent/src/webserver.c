#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <crypt.h>
#include <ctype.h>

#include <signal.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <strings.h>

#include <errno.h>

#include "safed.h"
#include "webserver.h"
#include "WebPages.h"
#include "webutilities.h"

#ifdef TLSPROTOCOL
	#include "SafedTLS.h"
#endif



// the server - listening socket
int http_listen_socket;
// the socket used to handle each client connection
int http_message_socket;
#ifdef TLSPROTOCOL
	gnutls_session_t session_https = NULL;
#endif
char fromServer[25] = "";

char agentPassword[256];
char allowedIP[MAX_RESTRICTIP][17];
int ip_count=0;


extern HostNode host;
extern int remoteControlHttps;
extern int TLSSERVERFAIL;

/*
 * Opens a listening server socket bound to the given port.
 * If an error occurs, it waits 10 seconds, and then tryes again to open, bind and listen on the socket.
 */
int openServerSocket(unsigned short port){
	int ready = 0;
	struct sockaddr_in local;
	int sockopt = 1;
	local.sin_family = AF_INET;
	local.sin_addr.s_addr = INADDR_ANY;
	local.sin_port = htons(port);

	while (!ready) {
		http_listen_socket = socket(AF_INET, SOCK_STREAM, 0);	// opening a TCP socket
		setsockopt(http_listen_socket, SOL_SOCKET, SO_REUSEADDR, &sockopt, sizeof(sockopt));

		if (http_listen_socket == -1) {
			perror("openServerSocket() - socket() failed");
		} else if (bind(http_listen_socket, (struct sockaddr *) &local, sizeof(local))) {
			perror("openServerSocket() - bind() failed");
		} else if (listen(http_listen_socket, 5)) {
			perror("openServerSocket() - listen() failed");
		} else {
			ready = 1;
		}

		if (!ready) {
			// something went wrong; waiting 10 seconds before trying again to open a listening socket on the given port
			close(http_listen_socket);
			sleep(10);
		}
	}
	return (1);
}

//public
/* sends to the agent the request to resend messages from - to */
void sendRequestToAgent(int from, int to) {
	char buffer[1024];
	snprintf(buffer, 1024, "%d %d", from, to);
	buffer[1023] = '\0';
	if (write(fds[1], buffer, strlen(buffer)) == -1) {
		perror("write");
	}
}


/**
 * Opens a server socket listening for incoming connections on the given port.
 * port: the port on which the http server listens;
 * ip: if specified, is the ip allowed to connect to the web server;
 * password: if specified, is the password to use to connect to the web server
 */
int initWebServer(unsigned short port, char *ip, char *password) {
	// agentPassword = ""; allowedIP = "";
	strncpy(agentPassword, "", 256);
	char rsip[SIZE_OF_RESTRICTIP];
	char* current = ip;

	http_listen_socket = 0;
	http_message_socket = 0;

	// ignore SIGPIPE
	signal(SIGPIPE, SIG_IGN);

	if (password) {
		strncpy(agentPassword, password, 256);
	}
	ip_count=0;
	if (ip && strlen(ip)) {
			int end = 0;
			int i = 0;
			for(i = 0; i < 17 ; i++) {
				char* currentIP = strstr(current,";");
				if(currentIP){
					strncpy(rsip,current,currentIP - current);
					rsip[currentIP - current]='\0';
					current = currentIP + 1;
				}else{
					strcpy(rsip,current);
					end = 1;
				}
				strncpy(allowedIP[ip_count],rsip,sizeof(allowedIP[ip_count]));
				ip_count++;
				if(end)break;
			}
	}

	openServerSocket(port);
	slog(LOG_NORMAL, "... web server init done!\n");
	return (1);
}

//public
int closeWebServer() {
	if(http_message_socket > 0) {
		shutdown(http_message_socket,SHUT_RDWR);
		close(http_message_socket);
#ifdef TLSPROTOCOL
		if(remoteControlHttps)deinitTLSSocket(session_https, 1);
#endif
		http_message_socket=-1;
	}

	if(http_listen_socket > 0) {
		shutdown(http_listen_socket,SHUT_RDWR);
		close(http_listen_socket);
		http_listen_socket=-1;
	}
	return (1);
}


void requestAuth(char *HTTPOutputBuffer, int size) {
	strncpy(HTTPOutputBuffer, "HTTP/1.0 401 Unauthorized\n"
		"Connection: close\r\n"
		"Content-Type: text/html\r\n"
		"Server: NetEye Safed\r\n"
		"WWW-Authenticate: Basic realm=\"NetEye Safed\"\r\n\r\n"
		"<HTML><HEAD>\r\n<TITLE>401 Authorization Required</TITLE>\r\n"
		"</HEAD><BODY>\r\n<CENTER><H2>Authorization Required</H2></CENTER>\r\n<CENTER>NetEye Safed could not "
		"verify that You are authorized to access the remote control facility. "
		"You may have supplied the wrong credentials</CENTER><P>\r\n<HR>\r\n", size);
}


void getHeader(char *HTTPBuffer, int size) {
	strncpy(HTTPBuffer, "HTTP/1.0 200 OK\r\n"
		"Server: NetEye Safed/1.0\r\n"
		"MIME-version: 1.0\r\n"
		"Content-type: text/html\r\n\r\n",
		size);
}


int matchAuth(char *AuthStart) {
	char AuthString[256]="";
	char AuthString2[256]="";
	char TempAuth[256]="";
	char *pos;
	char *crypttext;
	int length=0;

	// Hunt down end of line
	pos=AuthStart;

	while(isalpha((int)*pos) || (*pos >= '0' && *pos <= '9') || *pos == '+' || *pos == '=') {
		pos++;
	}

	if(!pos) return(0);

	length=pos-AuthStart;
	if(length<1) return(0);

	if(length >= sizeof(AuthString)) {
		length=sizeof(AuthString) - 1;
	}
	strncpy(AuthString,AuthStart,length);
	AuthString[length]='\0';

	length=base64decode(AuthString2,AuthString);

	pos=strstr(AuthString2,":");

	if(!pos) return(0);

	*pos='\0';
	pos++;
	strncpy(TempAuth,pos,sizeof(TempAuth));

	if(strcmp(AuthString2,"admin") && strcmp(AuthString2,"Admin") && strcmp(AuthString2,"ADMIN")) {
		// Username does not match
		return(0);
	}

	// Reuse authstring here.
	crypttext=crypt(TempAuth,SALT);
	if(crypttext) {
		strncpy(AuthString2,crypttext,sizeof(AuthString2));
	} else {
		strncpy(AuthString2,"",sizeof(AuthString2));
		// Hmm.. fall back to normal crypt.
		fprintf(stderr,"SNARE Warning: Your version of Solaris does not seem to support BSD MD5 Checksums in crypt.conf\n");
	}

	if(!strcmp(AuthString2,agentPassword)) {
		// Password matches
		return(1);
	}

	// Do we need a fallback here for plaintext passwords?
	// If so, how do we guard against a user just entering the md5
	// checksum as a password?

	// Lets md5 the SnarePass value, and check it against the crypted value.
	crypttext=crypt(agentPassword,SALT);
	if(crypttext) {
		if(!strcmp(AuthString2,crypttext)) {
			// fprintf(stderr,"SNARE Warning: Non-encrypted password used in epilog.conf file.\n");
			return(1);
		}
	}

	return(0);
}

void decodeurl(char *pEncoded) {
	char *pDecoded;

	pDecoded = pEncoded;
	while (*pDecoded) {
		if (*pDecoded == '+')
			*pDecoded = ' ';
		pDecoded++;
	};
	pDecoded = pEncoded;
	while (*pEncoded) {
		if(*pEncoded == '%') {
			pEncoded++;
			if(pEncoded[0]) {
				if(pEncoded[1]) {
					if(isxdigit((int)pEncoded[0])
					    && isxdigit((int)pEncoded[1])) {
						// *pDecoded++=(char)hex2int((char *)pEncoded);
						// Special InterSect Alliance - escape ampersands and slashes.
						// Note: hex characters are 3 bytes, we are only substituting 2, so no
						// problems with buffer overflows.
						*pDecoded =
						    (char) hex2int((char *)
								   pEncoded);
						if (*pDecoded == '&') {
							*pDecoded++ = '\\';
							*pDecoded = '&';
						} else if (*pDecoded ==
							   '\\') {
							*pDecoded++ = '\\';
							*pDecoded = '\\';
						} else if (*pDecoded ==
							   '=') {
							*pDecoded++ = '\\';
							*pDecoded = '=';
						}
						pDecoded++;

						pEncoded += 2;
					}
				} else {
					break;
				}
			} else {
				break;
			}
		} else {
			*pDecoded++ = *pEncoded++;
		}
	}
	*pDecoded = '\0';
}


void getURL(char *HTTPBuffer) {
	char* isPOST = strstr(HTTPBuffer,"POST");
	char *pos;

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
	pos = strstr(HTTPBuffer, "\n");
	if (pos) {
		*pos = '\0';
	}
	pos = strstr(HTTPBuffer, "\r");
	if (pos) {
		*pos = '\0';
	}
	// Get rid of the "GET "
	pos = strstr(HTTPBuffer, " ");
	if (pos) {
		strncpy(HTTPBuffer, pos + 1, MAX_HTTPBUFFER);
	}
	// and the HTTP/1.x
	pos = strstr(HTTPBuffer, " ");
	if (pos) {
		*pos = '\0';
	}
	decodeurl(HTTPBuffer);
	if(isPOST){
		strcat(HTTPBuffer,"?");
		strncat(HTTPBuffer,content,MAX_HTTPBUFFER);
	}

}

int checkAuthenticated(char *HTTPBuffer, char *HTTPOutputBuffer, int size) {
	// Hunt down the authentication string
	// Dont ask for authentication if the password is blank.

	char *pos;
	pos = strstr(HTTPBuffer, "Authorization: Basic ");
	if (strlen(agentPassword) && (!pos || !matchAuth(pos + strlen("Authorization: Basic ")))){
		requestAuth(HTTPOutputBuffer, size);
		return (0);
	}
	return (1);
}



/* POST CASE used for safed.conf and certs.

POST /setconfig HTTP/1.1
Host: prmlx004.rm.it.phoenix.wuerth.com:6161
User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.2.13) Gecko/20101203 Firefox/3.6.13
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,**;q=0.8
Accept-Language: en-us,en;q=0.5
Accept-Encoding: gzip,deflate
Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7
Keep-Alive: 115
Connection: keep-alive
Referer: http://prmlx004.rm.it.phoenix.wuerth.com:6161/config
Authorization: Basic YWRtaW46YWRtaW4=
Content-Type: multipart/form-data; boundary=---------------------------104948234121174534001138379537
Content-Length: 477

-----------------------------104948234121174534001138379537
Content-Disposition: form-data; name="cfgname"; filename="safed.conf"
Content-Type: application/octet-stream

[Output]
        network=192.168.1.252:514:tcp
        syslog=13
        days=2
        maxmsgsize=2048
        waittime=10000000
[Remote]
        allow=1
        listen_port=6161
        accesskey=$1$Auditor$NWNvifGLdfpSCwbYPKVD41
[End]

-----------------------------104948234121174534001138379537--

 */



/*
 * Handles the connection, getting the request from the client, and providing the answer.
 */
int handleConnect() {
	int retval;
	// 8k buffer for input and output. Suggest we may need more for output.
	char HTTPBuffer[MAX_HTTPBUFFER];
	char HTTPBufferTemp[MAX_HTTPBUFFER];
	char HTTPOutputBuffer[MAX_HTTPBUFFER];
	int size = 0;
	int header = 0;
	fd_set webread;
	FD_ZERO(&webread);
	FD_SET(http_message_socket, &webread);
	struct timeval tv;
	tv.tv_sec = 0;
	tv.tv_usec = 25000;

	struct timespec timeout;
	// setup the timeout values
	timeout.tv_sec = 0;
	timeout.tv_nsec = 500000000;


#ifdef TLSPROTOCOL
	if(remoteControlHttps)
		retval = recvTLS (HTTPBuffer,sizeof (HTTPBuffer), session_https);
	else
#endif
		retval = recv(http_message_socket, HTTPBuffer, sizeof(HTTPBuffer), 0);
	// NOTE: Should probably do something about requests that are bigger than HTTPBuffer also..

	if ((retval == -1) || (retval == 0)) {
		close(http_message_socket);
#ifdef TLSPROTOCOL
		if(remoteControlHttps)deinitTLSSocket(session_https, 1);
#endif
		return (1);
	}

	HTTPBuffer[retval] = '\0';
	char* headerend=strstr(HTTPBuffer,"\r\n\r\n");
	int boudaries = 0;
	if(headerend && strstr(HTTPBuffer,"POST")){
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
					boudaries = 1;
				}
			}
		}

	}
	if (!headerend || (strstr(HTTPBuffer,"POST") && !boudaries)) {
		int tempval;
		//fopen patch, sleep then check if there is anything left to grab
		nanosleep(&timeout,NULL);
		if (select(http_message_socket + 1,&webread,NULL,NULL,&tv) > 0) {

#ifdef TLSPROTOCOL
			if(remoteControlHttps){
			    tempval = recvTLS (HTTPBufferTemp,sizeof (HTTPBufferTemp), session_https);
			    if (tempval == 0){
				printf("- Peer has closed the TLS connection\n");
				close(http_message_socket);
				deinitTLSSocket(session_https, 1);
				return(1);
			    }else if (tempval < 0){
				printf("*** Error: %s\n", gnutls_strerror(tempval));
				close(http_message_socket);
				deinitTLSSocket(session_https, 1);
				return(1);
			    }
			}else
#endif
			    tempval = recv(http_message_socket,HTTPBufferTemp,sizeof(HTTPBufferTemp),0 );
			HTTPBufferTemp[tempval]='\0';
			strncat(HTTPBuffer,HTTPBufferTemp,sizeof(HTTPBuffer));
		} else {
			printf("recv() failed: Incomplete message \n");
			close(http_message_socket);
#ifdef TLSPROTOCOL
			if(remoteControlHttps)deinitTLSSocket(session_https, 1);
#endif
			return(1);
		}
	}


	if (checkAuthenticated(HTTPBuffer, HTTPOutputBuffer, MAX_HTTPBUFFER)) {
		getURL(HTTPBuffer);
#ifdef TLSPROTOCOL
		size = HandleWebPages(HTTPBuffer, HTTPOutputBuffer, MAX_HTTPBUFFER, http_listen_socket, http_message_socket , session_https, fromServer);
#else
		size = HandleWebPages(HTTPBuffer, HTTPOutputBuffer, MAX_HTTPBUFFER, http_listen_socket, http_message_socket, fromServer);
#endif
		header = 1;
	}

	if (size == 0) {
		size = strlen(HTTPOutputBuffer);
	}

	if (size > 0) {
		// Overwrite HTTPBuffer with the header data.
		if (header) {
			getHeader(HTTPBuffer, sizeof(HTTPBuffer));
#ifdef TLSPROTOCOL
			if(remoteControlHttps)
				retval = sendTLS(HTTPBuffer,session_https);
			else
#endif
				retval = send(http_message_socket, HTTPBuffer, strlen(HTTPBuffer), 0);
			if (retval == -1) {
				perror("send() failed");
			}
		}
#ifdef TLSPROTOCOL
			if(remoteControlHttps)
				retval = sendTLS2(HTTPOutputBuffer,session_https, size);
			else
#endif
				retval = send(http_message_socket, HTTPOutputBuffer, size, 0);

		if (retval == -1) {
			perror("send() failed");
		}
	}
	shutdown(http_message_socket,SHUT_RDWR);
	close(http_message_socket);
#ifdef TLSPROTOCOL
	if(remoteControlHttps)deinitTLSSocket(session_https, 1);
#endif


	return (1);
}

int authorisedSource(char *address) {
	if(!address) return(0);
	if(!strlen(address)) return(1);
	if(!ip_count) return(1);
	int i=0;
	for (i=0;i<ip_count;i++) {
		if(!strncmp(address,allowedIP[i],15)) {
			return(1);
		}
	}
	return (0);
}


/*
 * Acquires a connection from an authorized ip address.
 * It returns only when a new valid connection arrives.
 */
int nextConnect() {
	struct sockaddr_in from;
	int fromlen = sizeof (from);

	int requestNotValid = 1;
	char remoteIPAddress[16] = "";
	time_t ctime;
	struct tm *ntime;

	//TODO: this string can be defined and initialized only once! it can be a global variable.
	char HTTPBuffer[MAX_HTTPBUFFER] = "<HTML><BODY><CENTER>Authentication failed</CENTER></BODY></HTML>\n\0";

	while (requestNotValid) {
		http_message_socket = accept(http_listen_socket, (struct sockaddr *) &from, (socklen_t *)&fromlen);

        if (http_message_socket == -1) {
			perror("accept() error - The target TCP port looks to be currently in use");
			return (0);
		}
        // getting the remote peer address in a readable way
		strncpy(remoteIPAddress, inet_ntoa(from.sin_addr), 16);


#ifdef TLSPROTOCOL
	if(remoteControlHttps){
		if(!TLSSERVERFAIL)session_https = initSTLSSocket(http_message_socket,remoteIPAddress);
		else session_https = NULL;
		if (!session_https){
			close(http_message_socket);
			perror("Web Server Error - TLS session failed.Closing...");
			continue;
		}
	}
#endif
		if (authorisedSource(remoteIPAddress)) {
			if(!strcmp(remoteIPAddress,host.desthost)){
				time(&ctime);
				ntime = localtime(&ctime);
				snprintf(fromServer,sizeof(fromServer),"[%04d/%02d/%02d - %02d:%02d:%02d]",ntime->tm_year+1900,ntime->tm_mon+1,ntime->tm_mday,ntime->tm_hour,ntime->tm_min,ntime->tm_sec);
			}else{
				fromServer[0] = '\0';
			}
			requestNotValid = 0;
		} else {
			requestNotValid = 1;
			// sending the error message and closing the socket
#ifdef TLSPROTOCOL
			if(remoteControlHttps)
				sendTLS(HTTPBuffer,session_https);
			else
#endif
				send(http_message_socket, HTTPBuffer, strlen(HTTPBuffer),0);
			close(http_message_socket);
#ifdef TLSPROTOCOL
			if(remoteControlHttps)deinitTLSSocket(session_https, 1);
#endif

		}
	}

	return (1);
}

//public
/*
 * Acquires and handles new connections.
 * Actually, it never returns.
 */
int startWebServer() {
	while (nextConnect()) {
		handleConnect();
	}
	return (-1);
}

//public
// Find ampersand-delimited strings (but ignore escaped ampersands).
char *getNextArgument(char *source, char *destvar, int varlength, char *destval, int vallength) {
	char prevchar = '\0';
	int destlen = 0;

	if (!source || !destvar || !destval) {
		return ((char *) NULL);
	}

	if (!*source) {
		return ((char *) NULL);
	}

	*destvar = '\0';
	*destval = '\0';

	// length = maximum size of dest
	while (*source && !(*source == '&' && prevchar != '\\')
	       && !(*source == '=' && prevchar != '\\')
	       && destlen < (varlength - 1)) {

		if (*source != '\\'
		    || (*source == '\\' && prevchar == '\\')) {
			*destvar = *source;
			destvar++;
			destlen++;
		}

		prevchar = *source;
		source++;
	}
	*destvar = '\0';

	destlen = 0;

	if (*source == '=') {
		// We have a value. Excellent.
		source++;

		while (*source && !(*source == '&' && prevchar != '\\')
		       && destlen < (vallength-1)) {
			if (*source != '\\'
			    || (*source == '\\' && prevchar == '\\')) {
				*destval = *source;
				destval++;
				destlen++;
			}

			prevchar = *source;
			source++;
		}
		*destval = '\0';
	}
	// Return our position in the new string, or null for end of string.
	if (*source) {
		source++;
	}

	return (source);
}
