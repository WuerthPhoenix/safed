
#ifndef ssize_t
#define ssize_t long
#endif
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <gnutls/abstract.h>


int initTLS();
int initSTLS();
gnutls_session_t initTLSSocket(SOCKET , char *);
gnutls_session_t initSTLSSocket(SOCKET, char *);
int deinitTLS();
int deinitSTLS(); 
int deinitTLSSocket(gnutls_session_t, BOOL);
long sendTLS(char* msg, gnutls_session_t session, int size = 0);
long recvTLS(char* , int , gnutls_session_t );
const char* getTLSError(int ret);
char* getNameFromIP(char* ip);
char* getCAFILE();
char* getCERT_FILE();
char* getKEY_FILE();
void setCurrentDir();