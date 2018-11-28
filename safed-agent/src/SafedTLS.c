/* This example code is placed in the public domain. */
#ifdef HAVE_CONFIG_H

# include <config.h>
#endif


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <gnutls/abstract.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <errno.h>
#include <netdb.h>
#include "SafedTLS.h"
#include "Misc.h"


/* A TLS client that loads the certificate and key.
 */
#define CERT_FILE "/etc/safed/cert.pem"
#define KEY_FILE "/etc/safed/key.pem"
#define CAFILE "/etc/safed/ca.pem"
#define CRLFILE "/etc/safed/crl.pem"
#define DH_BITS 1024


gnutls_pcert_st crt;
gnutls_privkey_t key;
gnutls_certificate_credentials_t xcred;
gnutls_certificate_credentials_t x509_cred;
int TLSINIT = 0;


static void wrap_db_init (void);
static void wrap_db_deinit (void);
static int wrap_db_store (void *dbf, gnutls_datum_t key, gnutls_datum_t data);
static gnutls_datum_t wrap_db_fetch (void *dbf, gnutls_datum_t key);
static int wrap_db_delete (void *dbf, gnutls_datum_t key);
#define TLS_SESSION_CACHE 10
#define MAX_SESSION_ID_SIZE 32
#define MAX_SESSION_DATA_SIZE 512
typedef struct {
	char session_id[MAX_SESSION_ID_SIZE];
	size_t session_id_size;
	char session_data[MAX_SESSION_DATA_SIZE];
	size_t session_data_size;
} CACHE;
static CACHE *cache_db;
static int cache_db_ptr = 0;



char* getCAFILE(){
	return CAFILE;
}

char* getCERT_FILE(){
	return CERT_FILE;
}


char* getKEY_FILE(){
	return KEY_FILE;
}


/* This callback should be associated with a session by calling
 * gnutls_certificate_client_set_retrieve_function( session, cert_callback),
 * before a handshake.
 */
static int cert_callback(gnutls_session_t session,
		const gnutls_datum_t * req_ca_rdn, int nreqs,
		const gnutls_pk_algorithm_t * sign_algos, int sign_algos_length,
		gnutls_pcert_st ** pcert, unsigned int *pcert_length, gnutls_privkey_t * pkey) {
	char issuer_dn[256];
	int i, ret;
	size_t len;
	gnutls_certificate_type_t type;
	/* Print the server's trusted CAs
	 */
	if (nreqs > 0){
                slog(LOG_NORMAL, "- Server's trusted authorities:\n");

	}else{
		slog(LOG_NORMAL,"- Server did not send us any trusted authorities names.\n");
	}
	/* print the names (if any) */
	for (i = 0; i < nreqs; i++) {
		len = sizeof(issuer_dn);
		ret = gnutls_x509_rdn_get(&req_ca_rdn[i], issuer_dn, &len);
		if (ret >= 0) {
			slog(LOG_NORMAL,"%s\n", issuer_dn);
		}
	}

	/* Select a certificate and return it.
	 * The certificate must be of any of the "sign algorithms"
	 * supported by the server.
	 */
	type = gnutls_certificate_type_get(session);
	*pcert_length = 0;
	if (type == GNUTLS_CRT_X509) {
		*pcert_length = 1;
        *pcert = &crt;
        *pkey = key;
	} else {
		return -1;
	}
	return 0;
}


static int cert_verify_callback (gnutls_session_t session){
	int rc;
	unsigned int status;
	rc = gnutls_certificate_verify_peers2 (session, &status);
	if (rc != 0 || status != 0){
		slog(LOG_ERROR,"** Verifying server certificate failed...\n");
        return -1;
    }
  return 0;
}


/* Load the certificate and the private key.
 */
static int load_keys(void){
    int ret;
    gnutls_datum_t data;

    ret = gnutls_load_file(CERT_FILE, &data);
	if ( ret < 0) {
		slog(LOG_ERROR,"*** Error reading cert file.\n");
		return -1;
	}

    ret = gnutls_pcert_import_x509_raw(&crt, &data, GNUTLS_X509_FMT_PEM, 0);
	if ( ret < 0) {
		slog(LOG_ERROR,"*** Error loading cert file.\n");
		return -1;
	}
    gnutls_free(data.data);

    ret = gnutls_load_file(KEY_FILE, &data);
	if ( ret < 0) {
		slog(LOG_ERROR,"*** Error reading key file.\n");
		return -1;
	}
    ret = gnutls_privkey_init(&key);
	if ( ret < 0) {
		slog(LOG_ERROR,"*** Error initializing key file.\n");
		return -1;
	}

    ret = gnutls_privkey_import_x509_raw(key, &data, GNUTLS_X509_FMT_PEM, NULL, 0);
	if ( ret < 0) {
		slog(LOG_ERROR,"*** Error loading key file.\n");
		return -1;
	}
    gnutls_free(data.data);
	return 0;
}

int init_global(){
	int ret = 0;

	if(!TLSINIT){
		ret=gnutls_global_init();
		if(ret!=0) {
			slog(LOG_ERROR, "Error %s.\n", gnutls_strerror(ret));
			return -1;
		}

	}
	TLSINIT++;
	return 0;
}

const char* getTLSError(int ret){
	return gnutls_strerror(ret);
}


char* getNameFromIP(char* ip){
	struct hostent *he;
	struct in_addr addr;
	addr.s_addr = inet_addr(ip);
	he = gethostbyaddr((char *) &addr, 4, AF_INET);
	return he->h_name;
}


//TLS Client
int initTLS() {
	slog(LOG_NORMAL,"initTLS starting.\n");
	int ret;
	ret = init_global();
	if(ret){
		return -1;
	}
	//not supported with 2.12.1, ok with 2.12.23
	if(load_keys()) return -1;
	/* X509 stuff */
	ret=gnutls_certificate_allocate_credentials(&xcred);
	if(ret < 0){
		slog(LOG_ERROR,"Error %s.\n", gnutls_strerror(ret));
		return -1;
	}
	/* sets the trusted cas file
	 */
	ret=gnutls_certificate_set_x509_trust_file(xcred, CAFILE, GNUTLS_X509_FMT_PEM);
	if(ret < 0){
		slog(LOG_ERROR,"Error %s.\n", gnutls_strerror(ret));
		return -1;
	}

	/* If client holds a certificate it can be set using the following:
    */
	ret=gnutls_certificate_set_x509_key_file(xcred, CERT_FILE, KEY_FILE, GNUTLS_X509_FMT_PEM);
	if(ret < 0){
		slog(LOG_ERROR,"Error %s.\n", gnutls_strerror(ret));
		return -1;
	}

	slog(LOG_NORMAL,"initTLS done.\n");
	return 0;
}
//When rsyslog server is not available or missconfigured gnutls_handshake will hang up !!!
gnutls_session_t initTLSSocket(int socketSafed, char *SERVER) {
	slog(LOG_NORMAL,"initTLSSocket for %s (%s) starting.\n",SERVER, getNameFromIP(SERVER));
	int ret;
	const char *err;
	gnutls_session_t session;

	ret=gnutls_init(&session, GNUTLS_CLIENT);
	if(ret){
		slog(LOG_ERROR,"Error %s.\n", gnutls_strerror(ret));
		return NULL;
	}

	/* Use default priorities */
	//ret=gnutls_set_default_priority(session);
	ret=gnutls_priority_set_direct(session, "NORMAL:-VERS-TLS1.0:-VERS-TLS1.1", &err);
	if(ret < 0){
		//slog(LOG_ERROR,"Error %s.\n", gnutls_strerror(ret));
		slog(LOG_ERROR,"Error %s.\n", err);
		deinitTLSSocket(session,0);
		return NULL;
	}

	/* put the x509 credentials to the current session
	 */
	ret=gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, xcred);
	if(ret < 0){
		slog(LOG_ERROR,"Error %s.\n", gnutls_strerror(ret));
		deinitTLSSocket(session,0);
		return NULL;
	}

	gnutls_certificate_set_retrieve_function2(xcred, cert_callback);
	gnutls_certificate_set_verify_function (xcred, cert_verify_callback);
        gnutls_certificate_set_verify_flags (xcred, 0);

	/* connect to the peer
	 */
        gnutls_handshake_set_timeout(session, GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);
	gnutls_transport_set_int(session, socketSafed);
	/* Perform the TLS handshake
	 */

	do {
            ret = gnutls_handshake(session);
        }while (ret < 0 && gnutls_error_is_fatal(ret) == 0);
	
	//gnutls_handshake hangs up becausof rsyslog when the server is missconfigured
	if (ret < 0) {
		slog(LOG_ERROR,"*** Handshake failed %s\n",gnutls_strerror(ret));
		//gnutls_perror(ret);
		deinitTLSSocket(session,0);
		return NULL;
	} else {
		slog(LOG_ERROR,"- Handshake was completed\n");
	}

	slog(LOG_NORMAL,"initTLSSocket for %s done.\n",SERVER);
	return session;
}


long sendTLS(char* msg, gnutls_session_t session){
	return sendTLS2(msg, session,  0);
}
long sendTLS2(char* msg, gnutls_session_t session,  int size){
	if(!size)size = strlen(msg);
	return gnutls_record_send(session, msg, size);
}


long recvTLS(char* msg, int size, gnutls_session_t session){
	return gnutls_record_recv(session, msg, size);
}

int deinitTLS() {
	TLSINIT--;
	if(xcred)gnutls_certificate_free_credentials(xcred);
	gnutls_global_deinit();
	slog(LOG_NORMAL, "deinitTLS done.\n");
	return 0;
}

int deinitTLSSocket(gnutls_session_t session,int bye) {
	if(bye)gnutls_bye(session, GNUTLS_SHUT_RDWR);
	gnutls_deinit(session);
	slog(LOG_NORMAL, "deinitTLSSocket done.\n");
	return 0;
}

//TLS Server

int deinitSTLS() {
	TLSINIT--;
	if (TLS_SESSION_CACHE != 0){
		wrap_db_deinit ();
	}
	if(x509_cred)gnutls_certificate_free_credentials(x509_cred);
	if(!TLSINIT)gnutls_global_deinit();
	slog(LOG_NORMAL, "deinitTLS done.\n");
	return 0;
}


int initSTLS() {

	slog(LOG_NORMAL,"Web server initSTLS starting.\n");
	int ret;
	ret = init_global();
	if(ret){
		return -1;
	}

	/* X509 stuff */
	ret=gnutls_certificate_allocate_credentials(&x509_cred);
	if(ret < 0){
		slog(LOG_ERROR,"Error %s.\n", gnutls_strerror(ret));
		return -1;
	}
	/* sets the trusted cas file
	 */


	ret=gnutls_certificate_set_x509_trust_file(x509_cred, CAFILE, GNUTLS_X509_FMT_PEM);
	if(ret < 0){
		slog(LOG_ERROR,"Error %s.\n", gnutls_strerror(ret));
		return -1;
	}


	ret=gnutls_certificate_set_x509_crl_file(x509_cred, CRLFILE,GNUTLS_X509_FMT_PEM);
	/*if(ret < 0){//not mandatory
		slog(LOG_ERROR,"Error %s.\n", gnutls_strerror(ret));
		return -1;
	}*/

	ret=gnutls_certificate_set_x509_key_file(x509_cred, CERT_FILE, KEY_FILE,GNUTLS_X509_FMT_PEM);
	if(ret < 0){
		slog(LOG_ERROR,"Error %s.\n", gnutls_strerror(ret));
		return -1;
	}

    ret = gnutls_certificate_set_known_dh_params(x509_cred, GNUTLS_SEC_PARAM_MEDIUM);
    if(ret < 0){
		slog(LOG_ERROR,"Error %s.\n", gnutls_strerror(ret));
		return -1;
	}

	if (TLS_SESSION_CACHE != 0){
		wrap_db_init ();
	}

	slog(LOG_NORMAL,"Web server initSTLS done.\n");
	return 0;
}

gnutls_session_t initSTLSSocket(int socketSafed, char *SERVER) {
	slog(LOG_NORMAL,"Web server initSTLSSocket for %s (%s) starting.\n",SERVER, getNameFromIP(SERVER));
	int ret;
	const char *err;
	gnutls_session_t session;
	ret=gnutls_init(&session, GNUTLS_SERVER);

	if(ret){
		slog(LOG_ERROR,"Error %s.\n", gnutls_strerror(ret));
		return NULL;
	}

	/* Use default priorities */
	//ret=gnutls_set_default_priority(session);
	ret=gnutls_priority_set_direct(session, "NORMAL:-VERS-TLS1.0:-VERS-TLS1.1", &err);
	if(ret < 0){
		//slog(LOG_ERROR,"Error %s.\n", gnutls_strerror(ret));
		slog(LOG_ERROR,"Error %s.\n", err);
		deinitTLSSocket(session,0);
		return NULL;
	}



	/* put the x509 credentials to the current session
	 */
	ret=gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, x509_cred);
	if(ret < 0){
		slog(LOG_ERROR,"Error %s.\n", gnutls_strerror(ret));
		deinitTLSSocket(session,0);
		return NULL;
	}


	/* request client certificate if any.
	 */
	gnutls_certificate_server_set_request(session, GNUTLS_CERT_REQUEST);

	if (TLS_SESSION_CACHE != 0){
		gnutls_db_set_retrieve_function (session, wrap_db_fetch);
		gnutls_db_set_remove_function (session, wrap_db_delete);
		gnutls_db_set_store_function (session, wrap_db_store);
		gnutls_db_set_ptr (session, NULL);
	}

	gnutls_handshake_set_timeout(session, GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);
	gnutls_transport_set_int(session, socketSafed);
	/* Perform the TLS handshake
	 */


	ret = gnutls_handshake(session);

	//gnutls_handshake hangs up becausof rsyslog when the server is missconfigured
	if (ret < 0) {
		slog(LOG_ERROR,"*** Handshake failed %s\n",gnutls_strerror(ret));
		//gnutls_perror(ret);
		deinitTLSSocket(session,0);
		return NULL;
	} else {
		slog(LOG_ERROR,"- Handshake was completed\n");
	}


	slog(LOG_NORMAL,"Web server initTLSSocket for %s done.\n",SERVER);
	return session;
}


/* Functions and other stuff needed for session resuming.
* This is done using a very simple list which holds session ids
* and session data.
*/

static void wrap_db_init(void) {
	/* allocate cache_db */
	cache_db = (CACHE *)calloc(1, TLS_SESSION_CACHE * sizeof(CACHE));
}
static void wrap_db_deinit(void) {
	free(cache_db);
	cache_db = NULL;
	return;
}
static int wrap_db_store(void *dbf, gnutls_datum_t key, gnutls_datum_t data) {
	if (cache_db == NULL)
		return -1;
	if (key.size > MAX_SESSION_ID_SIZE)
		return -1;
	if (data.size > MAX_SESSION_DATA_SIZE)
		return -1;
	memcpy(cache_db[cache_db_ptr].session_id, key.data, key.size);
	cache_db[cache_db_ptr].session_id_size = key.size;
	memcpy(cache_db[cache_db_ptr].session_data, data.data, data.size);
	cache_db[cache_db_ptr].session_data_size = data.size;
	cache_db_ptr++;
	cache_db_ptr %= TLS_SESSION_CACHE;
	return 0;
}


static gnutls_datum_t wrap_db_fetch(void *dbf, gnutls_datum_t key) {


	gnutls_datum_t res = { NULL, 0 };
	int i;
	if (cache_db == NULL)
		return res;
	for (i = 0; i < TLS_SESSION_CACHE; i++) {

		if (key.size == cache_db[i].session_id_size && memcmp(key.data,
				cache_db[i].session_id, key.size) == 0) {
			res.size = cache_db[i].session_data_size;
			res.data = (unsigned char*)gnutls_malloc(res.size);
			if (res.data == NULL)
				return res;
			memcpy(res.data, cache_db[i].session_data, res.size);
			return res;
		}
	}
	return res;
}

static int wrap_db_delete(void *dbf, gnutls_datum_t key) {
	int i;
	if (cache_db == NULL)
		return -1;
	for (i = 0; i < TLS_SESSION_CACHE; i++) {
		if (key.size == cache_db[i].session_id_size && memcmp(key.data,
				cache_db[i].session_id, key.size) == 0) {
			cache_db[i].session_id_size = 0;
			cache_db[i].session_data_size = 0;
			return 0;
		}
	}
	return -1;
}
