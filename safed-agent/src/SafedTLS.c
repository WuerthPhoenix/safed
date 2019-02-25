/* This example code is placed in the public domain. */
#ifdef HAVE_CONFIG_H

# include <config.h>
#endif


#include "SafedTLS.h"
#include "Misc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>


/* A TLS client that loads the certificate and key.
 */
#define CERT_FILE "/etc/safed/cert.pem"
#define KEY_FILE "/etc/safed/key.pem"
#define CAFILE "/etc/safed/ca.pem"
#define CRLFILE "/etc/safed/crl.pem"


WOLFSSL_CTX* ctx;
WOLFSSL_CTX* ctx_server;
int TLSINIT = 0;

char* getCAFILE(){
	return CAFILE;
}

char* getCERT_FILE(){
	return CERT_FILE;
}


char* getKEY_FILE(){
	return KEY_FILE;
}


int getTLSError(WOLFSSL* ssl,int ret){
        int err = wolfSSL_get_error(ssl, ret);
        //char errorString[80];
        //wolfSSL_ERR_error_string(err, errorString);
        return err;
}


int init_global(){
	int ret = 0;

	if(!TLSINIT){
                ret = wolfSSL_Init();
                if(ret != WOLFSSL_SUCCESS) {
                       slog(LOG_ERROR, "Error init_global %d.\n", ret);
                       return -1;
                }
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
	slog(LOG_NORMAL,"initTLS starting.\n");
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
            slog(LOG_ERROR,"Error: initTLS wolfSSL_CTX_new error\n");
            return -1;
        }

        /* Add cert to ctx */
        if (wolfSSL_CTX_load_verify_locations(ctx, CAFILE, 0) != SSL_SUCCESS) {
            slog(LOG_ERROR,"Error: initTLS  loading %s\n",CAFILE);
            return -1;
        }

        slog(LOG_NORMAL,"initTLS done.\n");

	return 0;
}

WOLFSSL* initTLSSocket(int socketSafed, char *SERVER) {
	slog(LOG_NORMAL,"initTLSSocket for %s (%s) starting.\n",SERVER, getNameFromIP(SERVER));
        /* make new wolfSSL struct */
        WOLFSSL* ssl;
        if ( (ssl = wolfSSL_new(ctx)) == NULL) {
            slog(LOG_ERROR,"Error: initTLSSocket wolfSSL_new error\n");
            return NULL;
        }
        if (wolfSSL_use_certificate_chain_file(ssl, CERT_FILE) != WOLFSSL_SUCCESS) {
            slog(LOG_ERROR,"Eroor: initTLSSocket can't load client cert file, check file and run from %s\n", CERT_FILE);
            return NULL;
        }

        if (wolfSSL_use_PrivateKey_file(ssl, KEY_FILE, WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS) {
            slog(LOG_ERROR,"Error: initTLSSocket can't load client private key file, check file %s\n",KEY_FILE);
            return NULL;
        }

        /* Connect wolfssl to the socket, server, then send message */
        wolfSSL_set_fd(ssl, socketSafed);
        wolfSSL_connect(ssl);
        slog(LOG_NORMAL,"initTLSSocket done.\n");
        
	return ssl;
}


long sendTLS(char* msg, WOLFSSL* ssl){
	return sendTLS2(msg, ssl,  0);
}
long sendTLS2(char* msg, WOLFSSL* ssl,  int size){
	if(!size)size = strlen(msg);
        return wolfSSL_write(ssl,  msg, size);
}


long recvTLS(char* msg, int size, WOLFSSL* ssl){
        return wolfSSL_read(ssl, msg, size);
}

int deinitTLS() {
	TLSINIT--;
	if(ctx){
            wolfSSL_CTX_free(ctx);
            ctx = NULL;
        }
        wolfSSL_Cleanup();
	slog(LOG_NORMAL, "deinitTLS done.\n");
	return 0;
}

int deinitTLSSocket(WOLFSSL* ssl,int bye) {
        /* frees all data before client termination */
        wolfSSL_free(ssl);
	slog(LOG_NORMAL, "deinitTLSSocket done.\n");
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
	slog(LOG_NORMAL, "deinitTLS done.\n");
	return 0;
}


int initSTLS() {
	slog(LOG_NORMAL,"Web server initSTLS starting.\n");

        int ret;
        ret = init_global();
        if(ret < 0){
                return -1;
        }

        WOLFSSL_METHOD* method = wolfSSLv23_server_method(); /* use TLS v1.3 */

        /* make new ssl context */
        if ( (ctx_server = wolfSSL_CTX_new(method)) == NULL) {
            slog(LOG_ERROR,"Error: initSTLS wolfSSL_CTX_new error\n");
            return -1;
        }

        if (wolfSSL_CTX_load_verify_locations(ctx_server, CAFILE, 0) != SSL_SUCCESS) {

            return -1;
        }
         /* Load server certs into ctx */
        if (wolfSSL_CTX_use_certificate_file(ctx_server, CERT_FILE, SSL_FILETYPE_PEM) != SSL_SUCCESS)
            slog(LOG_ERROR,"Error initSTLS loading %s\n",CERT_FILE);

        /* Load server key into ctx */
        if (wolfSSL_CTX_use_PrivateKey_file(ctx_server, KEY_FILE, SSL_FILETYPE_PEM) != SSL_SUCCESS)
            slog(LOG_ERROR,"Error initSTLS loading %s\n",KEY_FILE);


	slog(LOG_NORMAL,"Web server initSTLS done.\n");
	return 0;
}

WOLFSSL* initSTLSSocket(int socketSafed, char *SERVER) {
	slog(LOG_NORMAL,"Web server initSTLSSocket for %s (%s) starting.\n",SERVER, getNameFromIP(SERVER));
        /* Create wolfSSL object */
        WOLFSSL* ssl;
        if ( (ssl = wolfSSL_new(ctx_server)) == NULL)
            slog(LOG_ERROR,"Error initSTLSSocket wolfSSL_new error");

        wolfSSL_set_fd(ssl, socketSafed);

	slog(LOG_NORMAL,"Web server initTLSSocket for %s done.\n",SERVER);
	return ssl;
}

