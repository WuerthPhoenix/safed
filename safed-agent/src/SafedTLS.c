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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <gcrypt.h>
#include <pthread.h>
#include <errno.h>
#include <netdb.h>
#include "SafedTLS.h"
#include "Misc.h"

GCRY_THREAD_OPTION_PTHREAD_IMPL;



/* A TLS client that loads the certificate and key.
 */
#define CERT_FILE "/etc/safed/cert.pem"
#define KEY_FILE "/etc/safed/key.pem"
#define CAFILE "/etc/safed/ca.pem"
#define CRLFILE "/etc/safed/crl.pem"
#define DH_BITS 1024


gnutls_x509_crt crt;
gnutls_x509_privkey key;
gnutls_certificate_credentials xcred;
gnutls_certificate_credentials x509_cred;
gnutls_dh_params dh_params;
int TLSINIT = 0;


static void wrap_db_init (void);
static void wrap_db_deinit (void);
static int wrap_db_store (void *dbf, gnutls_datum key, gnutls_datum data);
static gnutls_datum wrap_db_fetch (void *dbf, gnutls_datum key);
static int wrap_db_delete (void *dbf, gnutls_datum key);
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
static int cert_callback(gnutls_session session,
		const gnutls_datum * req_ca_rdn, int nreqs,
		const gnutls_pk_algorithm * sign_algos, int sign_algos_length,
		gnutls_retr_st * st) {
	char issuer_dn[256];
	int i, ret;
	size_t len;
	gnutls_certificate_type type;
	/* Print the server's trusted CAs
	 */
	if (nreqs > 0)
		slog(LOG_NORMAL, "- Server's trusted authorities:\n");

	else
		slog(LOG_NORMAL, "- Server did not send us any trusted authorities names.\n");
	/* print the names (if any) */
	for (i = 0; i < nreqs; i++) {
		len = sizeof(issuer_dn);
		ret = gnutls_x509_rdn_get(&req_ca_rdn[i], issuer_dn, &len);
		if (ret >= 0) {
			slog(LOG_NORMAL, " [%d]: ", i);
			slog(LOG_NORMAL, "%s\n", issuer_dn);
		}
	}
	/* Select a certificate and return it.
	 * The certificate must be of any of the "sign algorithms"
	 * supported by the server.
	 */
	type = gnutls_certificate_type_get(session);
	if (type == GNUTLS_CRT_X509) {
		st->type = type;
		st->ncerts = 1;
		st->cert.x509 = &crt;
		st->key.x509 = key;
		st->deinit_all = 0;
	} else {
		return -1;
	}
	return 0;
}



/* This function will try to verify the peer's certificate, and
 * also check if the hostname matches and the activation, expiration dates..
 */
static int verify_certificate(gnutls_session session, const char *hostname) {
	unsigned int status;
	const gnutls_datum *cert_list;
	unsigned int cert_list_size;
	int ret;
	gnutls_x509_crt cert;
	/* This verification function uses the trusted CAs in the credentials
	 * structure. So you must have installed one or more CA certificates.
	 */
	ret = gnutls_certificate_verify_peers2(session, &status);
	if (ret < 0) {
		slog(LOG_NORMAL, "Error in gnutls_certificate_verify_peers2 \n");
		return -1;
	}
	if (status & GNUTLS_CERT_INVALID){
		slog(LOG_NORMAL, "The certificate is not trusted.\n");
		if (status & GNUTLS_CERT_SIGNER_NOT_FOUND)
			slog(LOG_NORMAL, "The certificate hasn't got a known issuer.\n");
		if (status & GNUTLS_CERT_REVOKED)
			slog(LOG_NORMAL, "The certificate has been revoked.\n");
		if (status & GNUTLS_CERT_SIGNER_NOT_CA)
			slog(LOG_NORMAL, "signer is not a CA\n");
		return -1;
	}

	slog(LOG_NORMAL, "The certificate is valid.\n");

	/* Up to here the process is the same for X.509 certificates and
	 * OpenPGP keys. From now on X.509 certificates are assumed. This can
	 * be easily extended to work with openpgp keys as well.
	 */
	if (gnutls_certificate_type_get(session) != GNUTLS_CRT_X509)
		return -1;

	cert_list = gnutls_certificate_get_peers(session, &cert_list_size);
	if (cert_list == NULL) {
		slog(LOG_NORMAL, "No certificate was found!\n");
		return -1;
	}
	ret = 0;
	slog(LOG_NORMAL, "Certificate was found!\n");
	time_t now;
	time(&now);
	time_t certtime;
	int i;
	for(i = 0 ; i < cert_list_size ; ++i) {
		if (gnutls_x509_crt_init(&cert) < 0) {
			slog(LOG_ERROR, "error in initialization\n");
			ret = -1;
			break;
		}
		/* This is not a real world example, since we only check the first
		 * certificate in the given chain.
		 */
		if (gnutls_x509_crt_import(cert, &cert_list[i], GNUTLS_X509_FMT_DER) < 0) {
			slog(LOG_ERROR, "error parsing certificate\n");
			ret = -1;
		}else{
			slog(LOG_NORMAL, "Certificate was parsed!\n");
			certtime = gnutls_x509_crt_get_activation_time(cert);
			if ((certtime != -1) && ((long)now > (long)certtime)){
				slog(LOG_NORMAL, "Certificate is active!\n");
				certtime = gnutls_x509_crt_get_expiration_time(cert);
				if ((certtime != -1) && ((long)now < (long)certtime)){
					slog(LOG_NORMAL, "Certificate is not expired!\n");
					if (i == 0){
							if(!gnutls_x509_crt_check_hostname(cert, hostname)) {
								slog (LOG_NORMAL, "The certificate's owner does not match hostname '%s'\n",
									hostname);
								ret = -1;
							}else {
								slog(LOG_NORMAL, "The certificate's owner matchs hostname '%s'\n", hostname);
								ret = 0;
							}
					}
				}else ret = -1;
			}else ret = -1;
		}

		gnutls_x509_crt_deinit (cert);
		if (ret == -1) break;
	}



	return ret;
}





/* Helper functions to load a certificate and key
 * files into memory.
 */
static gnutls_datum load_file(const char *file) {
	FILE *f;
	gnutls_datum loaded_file = { NULL, 0 };
	long filelen;
	void *ptr;

	if (!(f = fopen(file, "r")) || fseek(f, 0, SEEK_END) != 0 || (filelen
			= ftell(f)) < 0 || fseek(f, 0, SEEK_SET) != 0 || !(ptr = malloc(
			(size_t) filelen)) || fread(ptr, 1, (size_t) filelen, f)
			< (size_t) filelen) {
		return loaded_file;
	}
	loaded_file.data = (unsigned char *)ptr;
	loaded_file.size = (unsigned int) filelen;
	return loaded_file;
}
static void unload_file(gnutls_datum data) {
	free(data.data);
}
static int generate_dh_params(void) {
	/* Generate Diffie-Hellman parameters - for use with DHE
	 * kx algorithms. When short bit length is used, it might
	 * be wise to regenerate parameters.
	 *
	 * Check the ex-serv-export.c example for using static
	 * parameters.
	 */
	gnutls_dh_params_init(&dh_params);
	gnutls_dh_params_generate2(dh_params, DH_BITS);
	return 0;
}
/* Load the certificate and the private key.
 */
static int load_keys(void) {
	int ret;
	gnutls_datum data;
	data = load_file(CERT_FILE);
	if (data.data == NULL) {
		slog(LOG_ERROR, "*** Error loading cert file.\n");
		return -1;
	}
	gnutls_x509_crt_init(&crt);
	ret = gnutls_x509_crt_import(crt, &data, GNUTLS_X509_FMT_PEM);
	if (ret < 0) {
		slog(LOG_ERROR, "*** Error loading key file: %s\n",gnutls_strerror(ret));
		return -1;
	}
	unload_file(data);
	data = load_file (KEY_FILE);
	if (data.data == NULL) {
		slog(LOG_ERROR, "*** Error loading key file.\n");
		return -1;
	}
	gnutls_x509_privkey_init(&key);
	ret = gnutls_x509_privkey_import(key, &data, GNUTLS_X509_FMT_PEM);
	if (ret < 0) {
		slog(LOG_ERROR, "*** Error loading key file: %s\n", gnutls_strerror(ret));
		return -1;
	}
	unload_file(data);
	return 0;
}


int init_global(){
	int ret = 0;

	if(!TLSINIT){
		/* gcry_control must be called first, so that the thread system is correctly set up */
		gcry_control(GCRYCTL_SET_THREAD_CBS, &gcry_threads_pthread);

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

long sendTLS(char* msg, gnutls_session session){
	return sendTLS2(msg, session,  0);
}
long sendTLS2(char* msg, gnutls_session session,  int size){
	if(!size)size = strlen(msg);
	return gnutls_record_send(session, msg, size);
}


long recvTLS(char* msg, int size, gnutls_session session){
	return gnutls_record_recv(session, msg, size);
}

//TLS Client

int initTLS() {
	slog(LOG_DEBUG, "initTLS starting.\n");
	int ret;
	ret = init_global();
	if(ret){
		return -1;
	}


	if(load_keys()) return -1;
	/* X509 stuff */
	ret=gnutls_certificate_allocate_credentials(&xcred);
	if(ret){
		slog(LOG_ERROR, "Error %s.\n", gnutls_strerror(ret));
		return -1;
	}
	/* sets the trusted cas file
	 */
	ret=gnutls_certificate_set_x509_trust_file(xcred, CAFILE, GNUTLS_X509_FMT_PEM);
	if(ret < 0){
		slog(LOG_ERROR, "Error %s.\n", gnutls_strerror(ret));
		return -1;
	}

	gnutls_certificate_client_set_retrieve_function(xcred, cert_callback);
	/* Initialize TLS session
	 */
	slog(LOG_DEBUG, "initTLS done.\n");
	return 0;
}

//When rsyslog server is not available or missconfigured gnutls_handshake will hang up !!!
gnutls_session initTLSSocket(int socketSafed, const char *SERVER) {
	slog(LOG_DEBUG, "initTLSSocket for %s starting.\n",SERVER);
	int ret;
	static const int cert_type_priority[2] = { GNUTLS_CRT_X509, 0 };
	gnutls_session session;
	ret=gnutls_init(&session, GNUTLS_CLIENT);
	if(ret){
		slog(LOG_ERROR, "Error %s.\n", gnutls_strerror(ret));
		return NULL;
	}
	/* Use default priorities */
	ret=gnutls_set_default_priority(session);
	if(ret){
		slog(LOG_ERROR, "Error %s.\n", gnutls_strerror(ret));
		deinitTLSSocket(session,0);
		return NULL;
	}

	/* put the x509 certification priority to the current session
		 */
	ret=gnutls_certificate_type_set_priority(session, cert_type_priority);
	if(ret){
		slog(LOG_ERROR, "Error %s.\n", gnutls_strerror(ret));
		deinitTLSSocket(session,0);
		return NULL;
	}

	/* put the x509 credentials to the current session
	 */
	ret=gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, xcred);
	if(ret){
		slog(LOG_ERROR, "Error %s.\n", gnutls_strerror(ret));
		deinitTLSSocket(session,0);
		return NULL;
	}
	/* connect to the peer
	 */
	gnutls_transport_set_ptr(session, (gnutls_transport_ptr) socketSafed);
	/* Perform the TLS handshake
	 */
	ret = gnutls_handshake(session);
	//gnutls_handshake hangs up becausof rsyslog when the server is missconfigured
	if (ret < 0) {
		slog(LOG_NORMAL, "*** Handshake failed %s\n", gnutls_strerror(ret));
		//gnutls_perror(ret);
		deinitTLSSocket(session,0);
		return NULL;
	} else {
		slog(LOG_DEBUG, "- Handshake was completed\n");
	}

	if(verify_certificate(session, SERVER)){
		deinitTLSSocket(session,1);
		return NULL;
	}
	slog(LOG_DEBUG, "initTLSSocket for %s done.\n",SERVER);
	return session;
}

int deinitTLS() {
	TLSINIT--;
	if(xcred)gnutls_certificate_free_credentials(xcred);
	gnutls_global_deinit();
	slog(LOG_DEBUG, "deinitTLS done.\n");
	return 0;
}

int deinitTLSSocket(gnutls_session session,int bye) {
	if(bye)gnutls_bye(session, GNUTLS_SHUT_RDWR);
	gnutls_deinit(session);
	slog(LOG_DEBUG, "deinitTLSSocket done.\n");
	return 0;
}

//TLS Server

int deinitSTLS() {
	TLSINIT--;
	if (TLS_SESSION_CACHE != 0){
		wrap_db_deinit ();
	}
	if(x509_cred)gnutls_certificate_free_credentials(x509_cred);
	if(dh_params)gnutls_dh_params_deinit(dh_params);
	if(!TLSINIT)gnutls_global_deinit();
	slog(LOG_DEBUG, "deinitTLS done.\n");
	return 0;
}




int initSTLS() {

	slog(LOG_DEBUG, "initSTLS starting.\n");
	int ret;
	ret = init_global();
	if(ret){
		return -1;
	}

	//gnutls_global_set_log_function (tls_log_func);
	//gnutls_global_set_log_level (9);

	/* X509 stuff */
	ret=gnutls_certificate_allocate_credentials(&x509_cred);
	if(ret){
		slog(LOG_ERROR, "Error %s.\n", gnutls_strerror(ret));
		return -1;
	}
	/* sets the trusted cas file
	 */


	ret=gnutls_certificate_set_x509_trust_file(x509_cred, CAFILE, GNUTLS_X509_FMT_PEM);
	if(ret < 0){
		slog(LOG_ERROR, "Error %s.\n", gnutls_strerror(ret));
		return -1;
	}


	ret=gnutls_certificate_set_x509_crl_file(x509_cred, CRLFILE,GNUTLS_X509_FMT_PEM);
	/*if(ret < 0){//not mandatory
		verboseOutput("Error %s.\n", gnutls_strerror(ret));
		return -1;
	}*/

	ret=gnutls_certificate_set_x509_key_file(x509_cred, CERT_FILE, KEY_FILE,GNUTLS_X509_FMT_PEM);
	if(ret < 0){
		slog(LOG_ERROR, "Error %s.\n", gnutls_strerror(ret));
		return -1;
	}
	 /* Generate Diffie-Hellman parameters - for use with DHE
	   * kx algorithms. These should be discarded and regenerated
	   * once a week or once a month. Depends on the
	   * security requirements.
	   */

	ret=generate_dh_params();//generate them at any startup!!!
	if(ret < 0){
		slog(LOG_ERROR, "Error %s.\n", gnutls_strerror(ret));
		return -1;
	}

	if (TLS_SESSION_CACHE != 0){
		wrap_db_init ();
	}
	gnutls_certificate_set_dh_params(x509_cred, dh_params);

	slog(LOG_DEBUG, "initSTLS done.\n");
	return 0;
}

gnutls_session initSTLSSocket(int socketSafed, const char *SERVER) {
	slog(LOG_DEBUG, "initSTLSSocket for %s starting.\n",SERVER);
	int ret;
	gnutls_session session;
	ret=gnutls_init(&session, GNUTLS_SERVER);

	if(ret){
		slog(LOG_ERROR, "Error %s.\n", gnutls_strerror(ret));
		return NULL;
	}

	/* Use default priorities */
	ret=gnutls_set_default_priority(session);
	if(ret){
		slog(LOG_ERROR, "Error %s.\n", gnutls_strerror(ret));
		deinitTLSSocket(session,0);
		return NULL;
	}



	/* put the x509 credentials to the current session
	 */
	ret=gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, x509_cred);
	if(ret){
		slog(LOG_ERROR, "Error %s.\n", gnutls_strerror(ret));
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

	gnutls_transport_set_ptr(session, (gnutls_transport_ptr) socketSafed);
	/* Perform the TLS handshake
	 */


	ret = gnutls_handshake(session);

	//gnutls_handshake hangs up becausof rsyslog when the server is missconfigured
	if (ret < 0) {
		slog(LOG_ERROR, "*** Handshake failed %s\n",gnutls_strerror(ret));
		//gnutls_perror(ret);
		deinitTLSSocket(session,0);
		return NULL;
	} else {
		slog(LOG_DEBUG, "- Handshake was completed\n");
	}


	slog(LOG_DEBUG, "initTLSSocket for %s done.\n",SERVER);
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
static int wrap_db_store(void *dbf, gnutls_datum key, gnutls_datum data) {
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


static gnutls_datum wrap_db_fetch(void *dbf, gnutls_datum key) {


	gnutls_datum res = { NULL, 0 };
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

static int wrap_db_delete(void *dbf, gnutls_datum key) {
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
