
int initTLS();
int initSTLS();
gnutls_session initTLSSocket(int , const char *);
gnutls_session initSTLSSocket(int, const char *);
int deinitTLS();
int deinitSTLS();
int deinitTLSSocket(gnutls_session, int);
long sendTLS(char* , gnutls_session);
long sendTLS2(char* , gnutls_session,  int);
long recvTLS(char* , int , gnutls_session );
const char* getTLSError(int);
char* getNameFromIP(char*);
char* getCAFILE();
char* getCERT_FILE();
char* getKEY_FILE();
