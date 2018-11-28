
int initTLS();
int initSTLS();
gnutls_session_t initTLSSocket(int , char *);
gnutls_session_t initSTLSSocket(int, char *);
int deinitTLS();
int deinitSTLS();
int deinitTLSSocket(gnutls_session_t, int);
long sendTLS(char* , gnutls_session_t);
long sendTLS2(char* , gnutls_session_t,  int);
long recvTLS(char* , int , gnutls_session_t );
const char* getTLSError(int);
char* getNameFromIP(char*);
char* getCAFILE();
char* getCERT_FILE();
char* getKEY_FILE();
