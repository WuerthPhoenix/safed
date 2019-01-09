
int initTLS();
int initSTLS();
WOLFSSL* initTLSSocket(int , char *);
WOLFSSL* initSTLSSocket(int, char *);
int deinitTLS();
int deinitSTLS();
int deinitTLSSocket(WOLFSSL*, int);
long sendTLS(char* , WOLFSSL*);
long sendTLS2(char* , WOLFSSL*,  int);
long recvTLS(char* , int , WOLFSSL* );
int getTLSError(WOLFSSL*,int);
char* getNameFromIP(char*);
char* getCAFILE();
char* getCERT_FILE();
char* getKEY_FILE();
