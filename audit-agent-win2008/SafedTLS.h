#include <wolfssl/ssl.h>

#ifndef ssize_t
#define ssize_t long
#endif

int initTLS();
int initSTLS();
WOLFSSL* initTLSSocket(SOCKET , char *);
WOLFSSL* initSTLSSocket(SOCKET, char *);
int deinitTLS();
int deinitSTLS(); 
int deinitTLSSocket(WOLFSSL*, BOOL);
int sendTLS(char* , WOLFSSL*,  int size = 0);
int recvTLS(char* , int , WOLFSSL* );
const char* getTLSError(WOLFSSL*, int);
char* getNameFromIP(char* ip);
char* getCAFILE();
char* getCERT_FILE();
char* getKEY_FILE();
void setCurrentDir();
