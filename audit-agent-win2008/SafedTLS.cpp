


/* This example code is placed in the public domain. */
#ifdef HAVE_CONFIG_H

# include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <winsock2.h>
#include "LogUtils.h"
#include "SafedTLS.h"
#include <wolfssl/wolfcrypt/error-crypt.h>

/* A TLS client that loads the certificate and key.
 */
#define _CERT_FILE "cert.pem"
#define _KEY_FILE "key.pem"
#define _CAFILE "ca.pem"
#define _CRLFILE "crl.pem"

WOLFSSL_CTX* ctx;
WOLFSSL_CTX* ctx_server;
//could be used by web server and rsyslog socket
int TLSINIT = 0;

char CERT_FILE[MAX_PATH] = "";
char KEY_FILE[MAX_PATH] = "";
char CAFILE[MAX_PATH] = "";
char CRLFILE[MAX_PATH] = "";

char* getCAFILE(){
	return CAFILE;
}

char* getCERT_FILE(){
	return CERT_FILE;
}


char* getKEY_FILE(){
	return KEY_FILE;
}


void setCurrentDir(){
	char dir[MAX_PATH] = "" ;
	GetModuleFileName(NULL, dir, MAX_PATH);
	char* pos = strstr(dir,"Safed.exe");
	if(!pos){
		pos = strstr(dir,"SnareCore.exe");
	}
	dir[strlen(dir) - strlen(pos)]='\0';
	_snprintf_s(CERT_FILE,_countof(CERT_FILE),_TRUNCATE,"%s%s",dir,_CERT_FILE);
	_snprintf_s(KEY_FILE,_countof(KEY_FILE),_TRUNCATE,"%s%s",dir,_KEY_FILE);
	_snprintf_s(CAFILE,_countof(CAFILE),_TRUNCATE,"%s%s",dir,_CAFILE);
	_snprintf_s(CRLFILE,_countof(CRLFILE),_TRUNCATE,"%s%s",dir,_CRLFILE);

}

const char* getTLSError(WOLFSSL* ssl,int ret){
        int err = wolfSSL_get_error(ssl, 0);
        //char errorString[80];
        //wolfSSL_ERR_error_string(err, errorString);
        //return errorString;
		//return err;
        return wolfSSL_ERR_reason_error_string(err);
}


int init_global(){
        int ret = 0;
        if(!TLSINIT){
                ret = wolfSSL_Init();
                if(ret != WOLFSSL_SUCCESS) {
                       LogExtMsg(ERROR_LOG, "Error init_global %d.", ret);
                       return -1;
                }
				setCurrentDir();
        }
        TLSINIT++;
        return ret;
}

char* getNameFromIP(char* ip){
	struct hostent *he;
	struct in_addr addr;
	addr.s_addr = inet_addr(ip);
	he = gethostbyaddr((char *) &addr, 4, AF_INET);
	if( he == NULL ) return ip;
	return he->h_name;
}


//TLS Client
int initTLS() {
        LogExtMsg(INFORMATION_LOG,"initTLS starting.");
        int ret;
        ret = init_global();
        if(ret < 0){
                return -1;
        }


        //WOLFSSL_METHOD* method = wolfTLSv1_2_client_method(); /* use TLS v1.3 */
        WOLFSSL_METHOD* method = wolfSSLv23_client_method(); /* use TLS v1.3 */
        //WOLFSSL_METHOD* method = wolfTLSv1_3_client_method(); /* use TLS v1.3 */

        /* make new ssl context */
        if ( (ctx = wolfSSL_CTX_new(method)) == NULL) {
            LogExtMsg(ERROR_LOG,"Error: initTLS wolfSSL_CTX_new error");
            return -1;
        }

        /* Add cert to ctx */
        if (wolfSSL_CTX_load_verify_locations(ctx, CAFILE, 0) != SSL_SUCCESS) {
            LogExtMsg(ERROR_LOG,"Error: initTLS  loading %s\n",CAFILE);
            return -1;
        }

        LogExtMsg(INFORMATION_LOG,"initTLS done.");

        return 0;
}

WOLFSSL* initTLSSocket(SOCKET socketSafed, char *SERVER) {
        LogExtMsg(INFORMATION_LOG,"initTLSSocket for %s (%s) starting.",SERVER, getNameFromIP(SERVER));
        /* make new wolfSSL struct */
        WOLFSSL* ssl;
        if ( (ssl = wolfSSL_new(ctx)) == NULL) {
            LogExtMsg(ERROR_LOG,"Error: initTLSSocket wolfSSL_new error");
            return NULL;
        }
        if (wolfSSL_use_certificate_chain_file(ssl, CERT_FILE) != WOLFSSL_SUCCESS) {
            LogExtMsg(ERROR_LOG,"Eroor: initTLSSocket can't load client cert file, check file and run from %s", CERT_FILE);
            return NULL;
        }

        if (wolfSSL_use_PrivateKey_file(ssl, KEY_FILE, WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS) {
            LogExtMsg(ERROR_LOG,"Error: initTLSSocket can't load client private key file, check file %s",KEY_FILE);
            return NULL;
        }

        /* Connect wolfssl to the socket, server, then send message */
        wolfSSL_set_fd(ssl, (int)socketSafed);
        wolfSSL_connect(ssl);
        LogExtMsg(INFORMATION_LOG,"initTLSSocket done.");

        return ssl;
}

int sendTLS(char* msg, WOLFSSL* ssl,  int size){
        if(!size)size = strlen(msg);
        return wolfSSL_write(ssl,  msg, size);
}


int recvTLS(char* msg, int size, WOLFSSL* ssl){
        return wolfSSL_read(ssl, msg, size);
}

int deinitTLS() {
        TLSINIT--;
        if(ctx){
            wolfSSL_CTX_free(ctx);
            ctx = NULL;
        }
        wolfSSL_Cleanup();
        LogExtMsg(INFORMATION_LOG, "deinitTLS done.");
        return 0;
}

int deinitTLSSocket(WOLFSSL* ssl,BOOL bye) {
        /* frees all data before client termination */
        wolfSSL_free(ssl);
        LogExtMsg(INFORMATION_LOG, "deinitTLSSocket done.");
        return 0;
}

//TLS Server

int deinitSTLS() {
        TLSINIT--;
        if(ctx_server){
            wolfSSL_CTX_free(ctx_server);
            ctx_server = NULL;
        }
        if(!TLSINIT)wolfSSL_Cleanup();
        LogExtMsg(INFORMATION_LOG, "deinitTLS done.");
        return 0;
}


int initSTLS() {
        LogExtMsg(INFORMATION_LOG,"Web server initSTLS starting.");

        int ret;
        ret = init_global();
        if(ret < 0){
                return -1;
        }

        WOLFSSL_METHOD* method = wolfSSLv23_server_method(); /* use TLS v1.3 */

        /* make new ssl context */
        if ( (ctx_server = wolfSSL_CTX_new(method)) == NULL) {
            LogExtMsg(ERROR_LOG,"Error: initSTLS wolfSSL_CTX_new error");
            return -1;
        }

        if (wolfSSL_CTX_load_verify_locations(ctx_server, CAFILE, 0) != SSL_SUCCESS) {

            return -1;
        }
         /* Load server certs into ctx */
        if (wolfSSL_CTX_use_certificate_file(ctx_server, CERT_FILE, SSL_FILETYPE_PEM) != SSL_SUCCESS)
            LogExtMsg(ERROR_LOG,"Error initSTLS loading %s",CERT_FILE);

        /* Load server key into ctx */
        if (wolfSSL_CTX_use_PrivateKey_file(ctx_server, KEY_FILE, SSL_FILETYPE_PEM) != SSL_SUCCESS)
            LogExtMsg(ERROR_LOG,"Error initSTLS loading %s\n",KEY_FILE);


        LogExtMsg(INFORMATION_LOG,"Web server initSTLS done.");
        return 0;
}

WOLFSSL* initSTLSSocket(SOCKET socketSafed, char *SERVER) {
        LogExtMsg(INFORMATION_LOG,"Web server initSTLSSocket for %s (%s) starting.",SERVER, getNameFromIP(SERVER));
        /* Create wolfSSL object */
        WOLFSSL* ssl;
		int err,ret;
        if ( (ssl = wolfSSL_new(ctx_server)) == NULL)
            LogExtMsg(ERROR_LOG,"Error initSTLSSocket wolfSSL_new error");

        wolfSSL_set_fd(ssl, (int)socketSafed);
        do {
            err = 0; /* reset error */
            ret = wolfSSL_accept(ssl);
            if (ret != WOLFSSL_SUCCESS) {
                err = wolfSSL_get_error(ssl, ret);
            }
        } while (err == WC_PENDING_E);

        LogExtMsg(INFORMATION_LOG,"Web server initTLSSocket for %s done.",SERVER);
        return ssl;
}
