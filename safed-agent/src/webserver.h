//
// webserver.h
//
//

#ifndef _WEBSERVER_H_
#define _WEBSERVER_H_ 1

#define MAX_HTTPBUFFER 200000//40960

#ifdef __linux__
        #define SALT "$1$Auditor$"
#else
        // Solaris
        // #define SALT "$md5"
        #define SALT "$1"
#endif

extern int fds[2];

void sendRequestToAgent(int from, int to);
int	initWebServer(unsigned short, char *, char *);
int	startWebServer();
int	closeWebServer();
char *	getNextArgument(char *source,char *destvar,int varlength,char *destval,int vallength);


#endif // _WEBSERVER_H_ 1
