#include "SafedTLS.h"

struct _hostnode
{
	SOCKET Socket;
	struct sockaddr_in server;
	char HostName[512];
	DWORD SocketType;
	WOLFSSL* ssl;
	struct _hostnode *next;
};

typedef struct _hostnode HostNode;

BOOL isTLS();
void initSocket();
void deinitSockets();
BOOL initSocketMutex();
void deinitSocketMutex();
BOOL InitWinsock( char *szError, int size );
void TerminateWinsock( SOCKET hSocket, WOLFSSL* ssl);
void OpenSockets();
SOCKET ConnectToServer(HostNode *hcn, char *szError, int size);
void  SendToAll(char *buf, int nSize);
int CloseSafedSocket(SOCKET sock, WOLFSSL* ssl);
BOOL  SendToSocket(HostNode *hcn, char *buf, int nSize, char *szError, int eSize);
HostNode * getHostHead();
void setHostHead(HostNode* h);
int		SendFailedCache			(HostNode *hcn,char *sFile, int size, int* sIndex, DWORD dwMaxMsgSize);
