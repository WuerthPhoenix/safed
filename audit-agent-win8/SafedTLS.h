
#ifndef ssize_t
#define ssize_t long
#endif
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <abstract.h>


int initTLS();
int initSTLS();
gnutls_session initTLSSocket(SOCKET , char *);
gnutls_session initSTLSSocket(SOCKET, char *);
int deinitTLS();
int deinitSTLS(); 
int deinitTLSSocket(gnutls_session, BOOL);
long sendTLS(char* msg, gnutls_session session, int size = 0);
long recvTLS(char* , int , gnutls_session );
const char* getTLSError(int ret);
char* getNameFromIP(char* ip);
char* getCAFILE();
char* getCERT_FILE();
char* getKEY_FILE();
void setCurrentDir();