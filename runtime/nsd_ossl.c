/* nsd_ossl.c
 *
 * An implementation of the nsd interface for OpenSSL.
 * 
 * Copyright (C) 2017 Adiscon GmbH.
 * Author: Pascal Withopf
 *
 * This file is part of the rsyslog runtime library.
 *
 * The rsyslog runtime library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * The rsyslog runtime library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with the rsyslog runtime library.  If not, see <http://www.gnu.org/licenses/>.
 *
 * A copy of the GPL can be found in the file "COPYING" in this distribution.
 * A copy of the LGPL can be found in the file "COPYING.LESSER" in this distribution.
 */
#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <openssl/engine.h>
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>

#include "rsyslog.h"
#include "syslogd-types.h"
#include "module-template.h"
#include "cfsysline.h"
#include "obj.h"
#include "stringbuf.h"
#include "errmsg.h"
#include "net.h"
#include "netstrms.h"
#include "netstrm.h"
#include "datetime.h"
#include "nsd_ptcp.h"
#include "prop.h"
#include "nsdsel_ossl.h"
#include "nsd_ossl.h"
#include "unicode-helper.h"




MODULE_TYPE_LIB
MODULE_TYPE_KEEP

/* static data */
DEFobjStaticHelpers
DEFobjCurrIf(errmsg)
DEFobjCurrIf(glbl)
DEFobjCurrIf(net)
DEFobjCurrIf(netstrms)
DEFobjCurrIf(netstrm)
DEFobjCurrIf(datetime)
DEFobjCurrIf(nsd_ptcp)
DEFobjCurrIf(prop)

static int bGlblSrvrInitDone = 0;	/**< 0 - server global init not yet done, 1 - already done */


/*--------------------------------------OpenSSL specifics------------------------------------------*/
static SSL_CTX *ctx;

int verify_callback(int status, X509_STORE_CTX *store)
{
	char data[256];

	if(!status) {
		X509 *cert = X509_STORE_CTX_get_current_cert(store);
		int depth = X509_STORE_CTX_get_error_depth(store);
		int err = X509_STORE_CTX_get_error(store);

		errmsg.LogError(0, RS_RET_NO_ERRCODE, "Certificate error at depth: %i", depth);
		X509_NAME_oneline(X509_get_issuer_name(cert), data, 256);
		errmsg.LogError(0, RS_RET_NO_ERRCODE, " issuer  = %s", data);
		X509_NAME_oneline(X509_get_subject_name(cert), data, 256);
		errmsg.LogError(0, RS_RET_NO_ERRCODE, " subject = %s", data);
		errmsg.LogError(0, RS_RET_NO_ERRCODE, " err %i:%s", err, X509_verify_cert_error_string(err));
	}

	return status;
}

long BIO_debug_callback(BIO *bio, int cmd, const char *argp,
                        int argi, long argl, long ret)
{
    long r = 1;

    if (BIO_CB_RETURN & cmd)
        r = ret;

    dbgprintf("openssl debug: BIO[%p]: ", (void *)bio);

    switch (cmd) {
    case BIO_CB_FREE:
        dbgprintf("openssl debug: Free - %s\n", bio->method->name);
        break;
    case BIO_CB_READ:
        if (bio->method->type & BIO_TYPE_DESCRIPTOR)
            dbgprintf("openssl debug: read(%d,%lu) - %s fd=%d\n",
                         bio->num, (unsigned long)argi,
                         bio->method->name, bio->num);
        else
            dbgprintf("openssl debug: read(%d,%lu) - %s\n",
                         bio->num, (unsigned long)argi, bio->method->name);
        break;
    case BIO_CB_WRITE:
        if (bio->method->type & BIO_TYPE_DESCRIPTOR)
            dbgprintf("openssl debug: write(%d,%lu) - %s fd=%d\n",
                         bio->num, (unsigned long)argi,
                         bio->method->name, bio->num);
        else
            dbgprintf("openssl debug: write(%d,%lu) - %s\n",
                         bio->num, (unsigned long)argi, bio->method->name);
        break;
    case BIO_CB_PUTS:
        dbgprintf("openssl debug: puts() - %s\n", bio->method->name);
        break;
    case BIO_CB_GETS:
        dbgprintf("openssl debug: gets(%lu) - %s\n", (unsigned long)argi,
                     bio->method->name);
        break;
    case BIO_CB_CTRL:
        dbgprintf("openssl debug: ctrl(%lu) - %s\n", (unsigned long)argi,
                     bio->method->name);
        break;
    case BIO_CB_RETURN | BIO_CB_READ:
        dbgprintf("openssl debug: read return %ld\n", ret);
        break;
    case BIO_CB_RETURN | BIO_CB_WRITE:
        dbgprintf("openssl debug: write return %ld\n", ret);
        break;
    case BIO_CB_RETURN | BIO_CB_GETS:
        dbgprintf("openssl debug: gets return %ld\n", ret);
        break;
    case BIO_CB_RETURN | BIO_CB_PUTS:
        dbgprintf("openssl debug: puts return %ld\n", ret);
        break;
    case BIO_CB_RETURN | BIO_CB_CTRL:
        dbgprintf("openssl debug: ctrl return %ld\n", ret);
        break;
    default:
        dbgprintf("openssl debug: bio callback - unknown type (%d)\n", cmd);
        break;
    }

    return (r);
}


/* globally initialize OpenSSL
 * 
 */
static rsRetVal
osslGlblInit(void)
{
	DEFiRet;
	DBGPRINTF("openssl: entering osslGlblInit\n");
	const char *caFile, *certFile, *keyFile;

	/*TODO: pascal: setup multithreading */
	if(!SSL_library_init()) {
		errmsg.LogError(0, RS_RET_NO_ERRCODE, "Error: OpenSSL initialization failed!");
	}
	SSL_load_error_strings();

	caFile = glbl.GetDfltNetstrmDrvrCAF();
	if(caFile == NULL) {
		errmsg.LogError(0, RS_RET_CA_CERT_MISSING, "Error: CA certificate is not set, cannot continue");
		ABORT_FINALIZE(RS_RET_CA_CERT_MISSING);
	}
	certFile = glbl.GetDfltNetstrmDrvrCertFile();
	if(certFile == NULL) {
		errmsg.LogError(0, RS_RET_CERT_MISSING, "Error: Certificate file is not set, cannot continue");
		ABORT_FINALIZE(RS_RET_CERT_MISSING);

	}
	keyFile = glbl.GetDfltNetstrmDrvrKeyFile();
	if(keyFile == NULL) {
		errmsg.LogError(0, RS_RET_CERTKEY_MISSING, "Error: Key file is not set, cannot continue");
		ABORT_FINALIZE(RS_RET_CERTKEY_MISSING);

	}
	ctx = SSL_CTX_new(SSLv23_method());
	if(SSL_CTX_load_verify_locations(ctx, caFile, NULL) != 1) {
		errmsg.LogError(0, RS_RET_NO_ERRCODE, "Error: CA certificate could not be accessed."
				" Is the file at the right path? And do we have the permissions?");
		ABORT_FINALIZE(RS_RET_NO_ERRCODE);
	}
	if(SSL_CTX_use_certificate_file(ctx, certFile, SSL_FILETYPE_PEM) != 1) {
		errmsg.LogError(0, RS_RET_NO_ERRCODE, "Error: Certificate file could not be "
				"accessed. Is the file at the right path? And do we have the "
				"permissions?");
		ABORT_FINALIZE(RS_RET_NO_ERRCODE);
	}
	if(SSL_CTX_use_PrivateKey_file(ctx, keyFile, SSL_FILETYPE_PEM) != 1) {
		errmsg.LogError(0, RS_RET_NO_ERRCODE, "Error: Key file could not be accessed. "
				"Is the file at the right path? And do we have the permissions?");
		ABORT_FINALIZE(RS_RET_NO_ERRCODE);
	}
	/* pascal: wird bei gnutls in methode gnutlsInitSession gemacht!!!*/
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT, verify_callback);
	/*TODO: pascal: Wie tief sollen Ketten geprüft werden? Zur Zeit 4 */
	SSL_CTX_set_verify_depth(ctx, 4);

	// TODO: Set timeout to a higher value
	SSL_CTX_set_timeout(ctx, 5);
	SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);

	bGlblSrvrInitDone = 1;


finalize_it:
	RETiRet;
}

static rsRetVal
osslInitSession(nsd_ossl_t *pThis)
{
	DEFiRet;
	DBGPRINTF("openssl: entering osslInitSession\n");
	BIO *client;

	if(!(pThis->ssl = SSL_new(ctx))) {
		errmsg.LogError(0, RS_RET_NO_ERRCODE, "Error creating SSL context");
	}
	client = BIO_pop(pThis->acc);
	
dbgprintf("osslInitSession: BIO[%p] \n", (void *)client);

	SSL_set_bio(pThis->ssl, client, client);
	pThis->bHaveSess = 1;

	RETiRet;
}

rsRetVal
osslRecordRecv(nsd_ossl_t *pThis)
{
	DEFiRet;
	DBGPRINTF("openssl: entering osslRecordRecv");
	ssize_t lenRcvd;
	int err;

	ISOBJ_TYPE_assert(pThis, nsd_ossl);
	lenRcvd =  SSL_read(pThis->ssl, pThis->pszRcvBuf, NSD_OSSL_MAX_RCVBUF);
	if(lenRcvd > 0) {
		pThis->lenRcvBuf = lenRcvd;
		pThis->ptrRcvBuf = 0;
	} else {
		err = SSL_get_error(pThis->ssl, lenRcvd);
		if(err != SSL_ERROR_ZERO_RETURN && err != SSL_ERROR_WANT_READ &&
			err != SSL_ERROR_WANT_WRITE) {
				errmsg.LogError(0, RS_RET_NO_ERRCODE, "Error while reading data: "
						"[%d] %s", err, ERR_error_string(err, NULL));
				errmsg.LogError(0, RS_RET_NO_ERRCODE, "Error is: %s",
						ERR_reason_error_string(err));
				ABORT_FINALIZE(RS_RET_NO_ERRCODE);
		} else {
			pThis->rtryCall =  osslRtry_recv;
			ABORT_FINALIZE(RS_RET_RETRY);
		}
	}

finalize_it:
	RETiRet;
}

/* globally de-initialize OpenSSL */
static rsRetVal
osslGlblExit(void)
{
	DEFiRet;
	DBGPRINTF("openssl: entering osslGlblExit\n");
	ENGINE_cleanup();
	ERR_free_strings();
	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();
	RETiRet;
}

/* end a OpenSSL session */
static rsRetVal
osslEndSess(nsd_ossl_t *pThis)
{
	DEFiRet;
	DBGPRINTF("openssl: entering osslEndSess\n");
	int ret;
	int err;

	if(pThis->bHaveSess) {
		ret = SSL_shutdown(pThis->ssl);
		while(ret == 0) {
			ret = SSL_shutdown(pThis->ssl);
		}
		if(ret < 0) {
			err = SSL_get_error(pThis->ssl, ret);
			if(err != SSL_ERROR_ZERO_RETURN && err != SSL_ERROR_WANT_READ &&
				err != SSL_ERROR_WANT_WRITE) {
				errmsg.LogError(0, RS_RET_NO_ERRCODE, "Error while closing "
						"session: [%d] %s", err,
						ERR_error_string(err, NULL));
				errmsg.LogError(0, RS_RET_NO_ERRCODE, "Error is: %s",
						ERR_reason_error_string(err));
			}
		}
		pThis->bHaveSess = 0;
	}

	RETiRet;
}

char *
getLastSSLErrorMsg(int ret, SSL *ssl, char* pszCallSource)
{
	unsigned long un_error = 0;
	char psz[256];
	int iMyRet = SSL_get_error(ssl, ret);

	/* Check which kind of error we have */
	DBGPRINTF("Error in Method: %s\n", pszCallSource);
	if(iMyRet == SSL_ERROR_SSL) {
		un_error = ERR_peek_last_error();
		ERR_error_string_n(un_error, psz, 256);
		errmsg.LogError(0, RS_RET_NO_ERRCODE, "%s", psz);
	} else if(iMyRet == SSL_ERROR_SYSCALL){
		iMyRet = ERR_get_error();
		if(ret == 0) {
			iMyRet = SSL_get_error(ssl, iMyRet);
			if(iMyRet = 0) {
				*psz = '\0';
			} else {
				ERR_error_string_n(iMyRet, psz, 256);
			}
		} else {
			un_error = ERR_peek_last_error();
			ERR_error_string_n(un_error, psz, 256);
		}
		errmsg.LogError(0, RS_RET_NO_ERRCODE, "%s", psz);
	} else {
		errmsg.LogError(0, RS_RET_NO_ERRCODE, "Unknown SSL Error, SSL_get_error: %d", iMyRet);
	}
}

/*--------------------------------End OpenSSL specifics----------------------------------------------*/

/* Standard-Constructor */
BEGINobjConstruct(nsd_ossl) /* be sure to specify the object type also in END macro! */
	pThis->acc = NULL;
ENDobjConstruct(nsd_ossl)

/* destructor for the nsd_ossl object */
PROTOTYPEobjDestruct(nsd_ossl);
BEGINobjDestruct(nsd_ossl) /* be sure to specify the object type also in END and CODESTART macros! */
CODESTARTobjDestruct(nsd_ossl)
	if(pThis->iMode == 1) {
		osslEndSess(pThis);
	}

	if(pThis->pRemHostName != NULL) {
		free(pThis->pRemHostName);
	}

	if(pThis->remoteIP != NULL) {
		prop.Destruct(&pThis->remoteIP);
	}

	if(pThis->acc != NULL) {
		BIO_free(pThis->acc);
	}

	if(pThis->pszRcvBuf == NULL) {
		free(pThis->pszRcvBuf);
	}

	if(pThis->bHaveSess) {
		SSL_shutdown(pThis->ssl);
	}
ENDobjDestruct(nsd_ossl)

/* Set the driver mode. For us, this has the following meaning:
 * 0 - work in plain tcp mode, without tls (e.g. before a STARTTLS)
 * 1 - work in TLS mode
 */
static rsRetVal
SetMode(nsd_t *pNsd, int mode)
{
	DEFiRet;
	nsd_ossl_t *pThis = (nsd_ossl_t*) pNsd;

	ISOBJ_TYPE_assert((pThis), nsd_ossl);
	if(mode != 0 && mode != 1) {
		errmsg.LogError(0, RS_RET_INVALID_DRVR_MODE, "error: driver mode %d not supported by"
				" ossl netstream driver", mode);
	}
	pThis->iMode = mode;

	RETiRet;
}

/* Set the authentication mode. For us, the following is supported:
 * anon - no certificate checks whatsoever (discouraged, but supported)
 * x509/certvalid - (just) check certificate validity
 * x509/fingerprint - certificate fingerprint
 * x509/name - cerfificate name check
 * mode == NULL is valid and defaults to x509/name
 */
static rsRetVal
SetAuthMode(nsd_t *pNsd, uchar *mode)
{
	DEFiRet;
	nsd_ossl_t *pThis = (nsd_ossl_t*) pNsd;

	ISOBJ_TYPE_assert((pThis), nsd_ossl);
	if(mode == NULL || !strcasecmp((char*)mode, "x509/name")) {
		pThis->authMode = OSSL_AUTH_CERTNAME;
	} else if(!strcasecmp((char*) mode, "x509/fingerprint")) {
		pThis->authMode = OSSL_AUTH_CERTFINGERPRINT;
	} else if(!strcasecmp((char*) mode, "x509/certvalid")) {
		pThis->authMode = OSSL_AUTH_CERTVALID;
	} else if(!strcasecmp((char*) mode, "anon")) {
		pThis->authMode = OSSL_AUTH_CERTANON;
	} else {
		errmsg.LogError(0, RS_RET_VALUE_NOT_SUPPORTED, "error: authentication mode '%s' not"
				" supported by ossl netstream driver", mode);
		ABORT_FINALIZE(RS_RET_VALUE_NOT_SUPPORTED);
	}

finalize_it:
	RETiRet;
}

/* Set permitted peers. It is depending on the auth mode if this are 
 * fingerprints or names. -- rgerhards, 2008-05-19
 */
static rsRetVal
SetPermPeers(nsd_t *pNsd, permittedPeers_t *pPermPeers)
{
	DEFiRet;
	nsd_ossl_t *pThis = (nsd_ossl_t*) pNsd;

	ISOBJ_TYPE_assert((pThis), nsd_ossl);
	if(pPermPeers == NULL)
		FINALIZE;

	if(pThis->authMode != OSSL_AUTH_CERTFINGERPRINT && pThis->authMode != OSSL_AUTH_CERTNAME) {
		errmsg.LogError(0, RS_RET_VALUE_NOT_IN_THIS_MODE, "authentication not supported by "
				"ossl netstream driver in the configured authentication mode - ignored");
		ABORT_FINALIZE(RS_RET_VALUE_NOT_IN_THIS_MODE);
	}
	pThis->pPermPeers = pPermPeers;

finalize_it:
	RETiRet;
}

/* Provide access to the underlying OS socket. This is primarily
 * useful for other drivers (like nsd_ossl) who utilize ourselfs
 * for some of their functionality.
 */
static rsRetVal
SetSock(nsd_t *pNsd, BIO *acc)
{
	DEFiRet;
	nsd_ossl_t *pThis = (nsd_ossl_t*) pNsd;

	ISOBJ_TYPE_assert((pThis), nsd_ossl);
	assert(acc != NULL);

	pThis->acc = acc;

	RETiRet;
}

/* Keep Alive Options
 */
static rsRetVal
SetKeepAliveIntvl(nsd_t *pNsd, int keepAliveIntvl)
{
	DEFiRet;
	RETiRet;
}


/* Keep Alive Options
 */
static rsRetVal
SetKeepAliveProbes(nsd_t *pNsd, int keepAliveProbes)
{
	DEFiRet;
	RETiRet;
}


/* Keep Alive Options
 */
static rsRetVal
SetKeepAliveTime(nsd_t *pNsd, int keepAliveTime)
{
	DEFiRet;
	RETiRet;
}

/* abort a connection. This is meant to be called immediately
 * before the Destruct call.
 */
static rsRetVal
Abort(nsd_t *pNsd)
{
	DEFiRet;
	RETiRet;
}

/* initialize the tcp socket for a listner
 * Here, we use the ptcp driver - because there is nothing special
 * at this point with OpenSSL. Things become special once we accept
 * a session, but not during listener setup.
 */
static rsRetVal
LstnInit(netstrms_t *pNS, void *pUsr, rsRetVal(*fAddLstn)(void*,netstrm_t*),
	 uchar *pLstnPort, uchar *pLstnIP, int iSessMax)
{
	DEFiRet;
	DBGPRINTF("openssl: entering LstnInit\n");
	nsd_t *pNewNsd = NULL;
	netstrm_t *pNewStrm = NULL;
	BIO *acc;

	acc = BIO_new_accept((const char*)pLstnPort);
	if(!acc) {
		errmsg.LogError(0, RS_RET_NO_ERRCODE, "Error creating server socket");
		ABORT_FINALIZE(RS_RET_NO_ERRCODE);
	}
	DBGPRINTF("openssl: Server socket created\n");
	if(BIO_do_accept(acc) <= 0) {
		errmsg.LogError(0, RS_RET_NO_ERRCODE, "Error binding server socket");
		ABORT_FINALIZE(RS_RET_NO_ERRCODE);
	}
	DBGPRINTF("openssl: Server socket bound\n");

	BIO_set_callback(acc, BIO_debug_callback);

	CHKiRet(nsd_osslConstruct(&pNewNsd));
dbgprintf("after construct");
	CHKiRet(SetSock(pNewNsd, acc));
	CHKiRet(SetMode(pNewNsd, netstrms.GetDrvrMode(pNS)));
	CHKiRet(SetAuthMode(pNewNsd, netstrms.GetDrvrAuthMode(pNS)));
	CHKiRet(SetPermPeers(pNewNsd, netstrms.GetDrvrPermPeers(pNS)));
	CHKiRet(netstrms.CreateStrm(pNS, &pNewStrm));
	pNewStrm->pDrvrData = (nsd_t*) pNewNsd;
	pNewNsd = NULL;
	CHKiRet(fAddLstn(pUsr, pNewStrm));
	pNewStrm = NULL;
	acc = NULL;

finalize_it:
	if(iRet != RS_RET_OK) {
		if(pNewStrm != NULL) {
			netstrm.Destruct(&pNewStrm);
		}
	}
	RETiRet;
}

/* This function checks if the connection is still alive - well, kind of...
 * This is a dummy here. For details, check function common in ptcp driver.
 */
static rsRetVal
CheckConnection(nsd_t __attribute__((unused)) *pNsd)
{

}

/* get the remote hostname. The returned hostname must be freed by the caller.
 */
static rsRetVal
GetRemoteHName(nsd_t *pNsd, uchar **ppszHName)
{
	DEFiRet;
	nsd_ossl_t *pThis = (nsd_ossl_t*) pNsd;
	ISOBJ_TYPE_assert(pThis, nsd_ossl);
	assert(ppszHName != NULL);
	//TODO: how can the RemHost be empty?

	CHKmalloc(*ppszHName = (uchar*)strdup(pThis->pRemHostName == NULL ? "" : (char*) pThis->pRemHostName));
finalize_it:
	RETiRet;
}


/* Provide access to the sockaddr_storage of the remote peer. This
 * is needed by the legacy ACL system.
 */
static rsRetVal
GetRemAddr(nsd_t *pNsd, struct sockaddr_storage **ppAddr)
{
	DEFiRet;
	RETiRet;
}

/* get the remote host's IP address. Caller must Destruct the object. */
static rsRetVal
GetRemoteIP(nsd_t *pNsd, prop_t **ip)
{
	DEFiRet;
	nsd_ossl_t *pThis = (nsd_ossl_t*) pNsd;
	ISOBJ_TYPE_assert(pThis, nsd_ossl);
	prop.AddRef(pThis->remoteIP);
	*ip = pThis->remoteIP;
	RETiRet;
}

/* Certificate of the peer is checked
 */
rsRetVal
post_connection_check(SSL *ssl)
{
	DEFiRet;
	/*TODO: pascal: check certificate from peer */
	RETiRet;
}

/* accept an incoming connection request - here, we do the usual accept
 * handling. TLS specific handling is done thereafter (and if we run in TLS
 * mode at this time).
 */
static rsRetVal
AcceptConnReq(nsd_t *pNsd, nsd_t **ppNew)
{
	DEFiRet;
	DBGPRINTF("openssl: entering AcceptConnReq\n");
	nsd_ossl_t *pNew = NULL;
	nsd_ossl_t *pThis = (nsd_ossl_t*) pNsd;
	BIO *client;
	long err;
	int ret;
	int iSocked;
	struct sockaddr_in addr;
	socklen_t addr_size;
	int res;
	char clientip[20];

	ISOBJ_TYPE_assert((pThis), nsd_ossl);
	CHKiRet(nsd_osslConstruct(&pNew));
	BIO_free(pNew->acc);
dbgprintf("AcceptConnReq: BIO[%p]\n", (void *)pThis->acc);	
	if(BIO_do_accept(pThis->acc) <= 0) {
		errmsg.LogError(0, RS_RET_NO_ERRCODE, "Error accepting connection");
		ABORT_FINALIZE(RS_RET_NO_ERRCODE);
	}
	
	if(pThis->iMode == 0) {
		/*we are in non-TLS mode, so we are done */
		DBGPRINTF("openssl: we are NOT in TLS mode\n");
		*ppNew = (nsd_t*) pNew;
		FINALIZE;
	}

	DBGPRINTF("openssl: we are in TLS mode\n");
	/*if we reach this point, we are in TLS mode */
	CHKiRet(osslInitSession(pThis)); // pNew));
	pNew->ssl = pThis->ssl;
	pNew->authMode = pThis->authMode;
	pNew->pPermPeers = pThis->pPermPeers;

	DBGPRINTF("openssl: starting handshake\n");
	/*we now do the handshake */
dbgprintf("SSL_accept: pNew->ssl[%p]\n", (void *)pNew->ssl);
	if((ret = SSL_accept(pNew->ssl)) <= 0) {
		errmsg.LogError(0, RS_RET_NO_ERRCODE, "Error accepting SSL connection");
		getLastSSLErrorMsg(ret, pNew->ssl, "AcceptConnReq");
	}
dbgprintf("SSL_accept: after function\n");

dbgprintf("openssl debug: socket client %p\n", SSL_get_fd(pNew->ssl));
	iSocked = SSL_get_fd(pNew->ssl);
	addr_size = sizeof(struct sockaddr_in); 
	res = getpeername(iSocked, (struct sockaddr *)&addr, &addr_size); 
	strcpy(clientip, inet_ntoa(addr.sin_addr));
dbgprintf("hostname: %s\n", clientip);
	/* zurzeitiger segfault because prop.CreateStringProp is a NULL Pointer */
	prop.CreateStringProp(&pNew->remoteIP, clientip, strlen(clientip));
dbgprintf("remoteIP: after create string prop: %p\n", pNew->remoteIP);

dbgprintf("openssl: reached post_connection_check()\n");
	if((err = post_connection_check(pNew->ssl)) != X509_V_OK) {
		errmsg.LogError(0, RS_RET_NO_ERRCODE, "Error checking SSL object after connection, peer"
				" certificate: %s", X509_verify_cert_error_string(err));
		ABORT_FINALIZE(RS_RET_NO_ERRCODE);
	}

	/*TODO: pascal: retry when handshake is not done emediatly because it is non-blocking */
	pNew->iMode = 1;

	*ppNew = (nsd_t*) pNew;

finalize_it:
	if(iRet != RS_RET_OK) {
		if(pNew != NULL) {
			nsd_osslDestruct(&pNew);
		}
	}
	RETiRet;
}

/* receive data from a tcp socket
 * The lenBuf parameter must contain the max buffer size on entry and contains
 * the number of octets read on exit. This function
 * never blocks, not even when called on a blocking socket. That is important
 * for client sockets, which are set to block during send, but should not
 * block when trying to read data.
 * The function now follows the usual iRet calling sequence.
 * With OpenSSL, we may need to restart a recv() system call. If so, we need
 * to supply the SAME buffer on the retry. We can not assure this, as the
 * caller is free to call us with any buffer location (and in current
 * implementation, it is on the stack and extremely likely to change). To
 * work-around this problem, we allocate a buffer ourselfs and always receive
 * into that buffer. We pass data on to the caller only after we have received it.
 * To save some space, we allocate that internal buffer only when it is actually 
 * needed, which means when we reach this function for the first time. To keep
 * the algorithm simple, we always supply data only from the internal buffer,
 * even if it is a single byte. As we have a stream, the caller must be prepared
 * to accept messages in any order, so we do not need to take care about this.
 * Please note that the logic also forces us to do some "faking" in select(), as
 * we must provide a fake "is ready for readign" status if we have data inside our
 * buffer.
 */
static rsRetVal
Rcv(nsd_t *pNsd, uchar *pBuf, ssize_t *pLenBuf, int *const oserr)
{
	DEFiRet;
	DBGPRINTF("openssl: entering Rcv\n");
	/*TODO: pascal: rcv data*/
	ssize_t iBytesCopy;
	nsd_ossl_t *pThis = (nsd_ossl_t*) pNsd;
	ISOBJ_TYPE_assert(pThis, nsd_ossl);

	if(pThis->iMode == 0) {
		/*TODO: pascal: rcv ohne ssl */
	}

	/* --- in TLS mode now --- */

	/* Buffer logic applies only if we are in TLS mode. Here we 
	 * assume that we will switch from plain to TLS, but never back. This
	 * assumption may be unsafe, but it is the model for the time being and I
	 * do not see any valid reason why we should switch back to plain TCP after
	 * we were in TLS mode. However, in that case we may lose something that
	 * is already in the receive buffer ... risk accepted.
	 */

	if(pThis->pszRcvBuf == NULL) {
		/* we have no buffer, so we need to malloc one */
		CHKmalloc(pThis->pszRcvBuf = MALLOC(NSD_OSSL_MAX_RCVBUF));
		pThis->lenRcvBuf = -1;
	}

	/* now check if we have something in our buffer. If so, we satisfy the request from buffer
	 * contents */
	if(pThis->lenRcvBuf == -1) { /* no data present, must read */
		CHKiRet(osslRecordRecv(pThis));
	}
	if(pThis->lenRcvBuf == 0) { /* EOS */
		*oserr = errno;
		ABORT_FINALIZE(RS_RET_CLOSED);
	}

	/* if we reach this point, data is present in the buffer and must be copied */
	iBytesCopy = pThis->lenRcvBuf - pThis->ptrRcvBuf;
	if(iBytesCopy > *pLenBuf) {
		iBytesCopy = *pLenBuf;
	} else {
		pThis->lenRcvBuf = -1; /* buffer will be emptied below */
	}

	memcpy(pBuf, pThis->pszRcvBuf + pThis->ptrRcvBuf, iBytesCopy);
	pThis->ptrRcvBuf += iBytesCopy;
	*pLenBuf = iBytesCopy;


finalize_it:
	if(iRet != RS_RET_OK && iRet != RS_RET_RETRY) {
		*pLenBuf = 0;
		free(pThis->pszRcvBuf);
		pThis->pszRcvBuf = NULL;
	}
	RETiRet;
}

/* send a buffer. On entry, pLenBuf contains the number of octets to
 * write. On exit, it contains the number of octets actually written.
 * If this number is lower than on entry, only a partial buffer has
 * been written.
 */
static rsRetVal
Send(nsd_t *pNsd, uchar *pBuf, ssize_t *pLenBuf)
{
	DEFiRet;
	DBGPRINTF("openssl: entering Send\n");
	int iSent;
	int err;
	nsd_ossl_t *pThis = (nsd_ossl_t*) pNsd;

	ISOBJ_TYPE_assert(pThis, nsd_ossl);

	if(pThis->iMode == 0) {
		/*TODO: pascal: send without ssl*/
	}

	while(1) {
		iSent = SSL_write(pThis->ssl, pBuf, *pLenBuf);
		if(iSent > 0) {
			*pLenBuf = iSent;
			break;
		} else {
			err = SSL_get_error(pThis->ssl, iSent);
			if(err != SSL_ERROR_ZERO_RETURN && err != SSL_ERROR_WANT_READ &&
				err != SSL_ERROR_WANT_WRITE) {
				/*SSL_ERROR_ZERO_RETURN: TLS connection has been closed. This
				 * result code is returned only if a closure alert has occurred
				 * in the protocol, i.e. if the connection has been closed cleanly.
				 *SSL_ERROR_WANT_READ/WRITE: The operation did not complete, try
				 * again later. */
				errmsg.LogError(0, RS_RET_NO_ERRCODE, "Error while sending data: "
						"[%d] %s", err, ERR_error_string(err, NULL));
				errmsg.LogError(0, RS_RET_NO_ERRCODE, "Error is: %s",
						ERR_reason_error_string(err));
				ABORT_FINALIZE(RS_RET_NO_ERRCODE);
			}
		}
	}
finalize_it:
	RETiRet;
}

/* Enable KEEPALIVE handling on the socket.
 */
static rsRetVal
EnableKeepAlive(nsd_t *pNsd)
{
	DEFiRet;
finalize_it:
	RETiRet;
}

/* open a connection to a remote host (server). With OpenSSL, we always
 * open a plain tcp socket and then, if in TLS mode, do a handshake on it.
 */
/*pascal*/
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations" /* TODO: FIX Warnings! */
static rsRetVal
Connect(nsd_t *pNsd, int family, uchar *port, uchar *host, char *device)
{
	DEFiRet;
	DBGPRINTF("openssl: entering Connect\n");
	nsd_ossl_t*pThis = (nsd_ossl_t*) pNsd;
	BIO *conn;
	SSL * ssl;
	long err;
	char *name;

	ISOBJ_TYPE_assert(pThis, nsd_ossl);
	assert(port != NULL);
	assert(host != NULL);

	if((name = malloc(strlen(host)+strlen(port)+2)) != NULL) {
		name[0] = '\0';
		strcat(name, host);
		strcat(name, ":");
		strcat(name, port);
	} else {
		errmsg.LogError(0, RS_RET_NO_ERRCODE, "Error: malloc failed");
	}

	conn = BIO_new_connect(name);
	if(!conn) {
		errmsg.LogError(0, RS_RET_NO_ERRCODE, "Error creating connection Bio");
		ABORT_FINALIZE(RS_RET_NO_ERRCODE);
	}
	if(BIO_do_connect(conn) <= 0) {
		errmsg.LogError(0, RS_RET_NO_ERRCODE, "Error connecting to remote machine");
		ABORT_FINALIZE(RS_RET_NO_ERRCODE);
	}

	if(pThis->iMode == 0) {
		FINALIZE;
	}

	DBGPRINTF("We are in tls mode\n");
	/*if we reach this point we are in tls mode */
	if(!(ssl = SSL_new(ctx))) {
		errmsg.LogError(0, RS_RET_NO_ERRCODE, "Error creating an SSL context");
		ABORT_FINALIZE(RS_RET_NO_ERRCODE);
	}
	SSL_set_bio(ssl, conn, conn);
	if(SSL_connect(ssl) <= 0) {
		errmsg.LogError(0, RS_RET_NO_ERRCODE, "Error connecting SSL object");
		ABORT_FINALIZE(RS_RET_NO_ERRCODE);
	}
	pThis->bHaveSess = 1;
	if((err = post_connection_check(ssl)) != X509_V_OK) {
		errmsg.LogError(0, RS_RET_NO_ERRCODE, "Error checking SSL object after connection, peer"
				" certificate: %s", X509_verify_cert_error_string(err));
		ABORT_FINALIZE(RS_RET_NO_ERRCODE);
	}

finalize_it:
	if(name != NULL) {
		free(name);
	}
	if(iRet != RS_RET_OK) {
		if(pThis->bHaveSess) {
			pThis->bHaveSess = 0;
			SSL_free(ssl);
		}
	}
	RETiRet;
}
#pragma GCC diagnostic pop

/* queryInterface function */
BEGINobjQueryInterface(nsd_ossl)
CODESTARTobjQueryInterface(nsd_ossl)
	if(pIf->ifVersion != nsdCURR_IF_VERSION) {/* check for current version, increment on each change */
		ABORT_FINALIZE(RS_RET_INTERFACE_NOT_SUPPORTED);
	}

	/* ok, we have the right interface, so let's fill it
	 * Please note that we may also do some backwards-compatibility
	 * work here (if we can support an older interface version - that,
	 * of course, also affects the "if" above).
	 */
	pIf->Construct = (rsRetVal(*)(nsd_t**)) nsd_osslConstruct;
	pIf->Destruct = (rsRetVal(*)(nsd_t**)) nsd_osslDestruct;
	pIf->Abort = Abort;
	pIf->LstnInit = LstnInit;
	pIf->AcceptConnReq = AcceptConnReq;
	pIf->Rcv = Rcv;
	pIf->Send = Send;
	pIf->Connect = Connect;
	pIf->SetSock = SetSock;
	pIf->SetMode = SetMode;
	pIf->SetAuthMode = SetAuthMode;
	pIf->SetPermPeers =SetPermPeers;
	pIf->CheckConnection = CheckConnection;
	pIf->GetRemoteHName = GetRemoteHName;
	pIf->GetRemoteIP = GetRemoteIP;
	pIf->GetRemAddr = GetRemAddr;
	pIf->EnableKeepAlive = EnableKeepAlive;
	pIf->SetKeepAliveIntvl = SetKeepAliveIntvl;
	pIf->SetKeepAliveProbes = SetKeepAliveProbes;
	pIf->SetKeepAliveTime = SetKeepAliveTime;
finalize_it:
ENDobjQueryInterface(nsd_ossl)

/* exit our class
 */
BEGINObjClassExit(nsd_ossl, OBJ_IS_LOADABLE_MODULE) /* CHANGE class also in END MACRO! */
CODESTARTObjClassExit(nsd_ossl)
	osslGlblExit();	/* shut down OpenSSL */

	/* release objects we no longer need */
	objRelease(nsd_ptcp, LM_NSD_PTCP_FILENAME);
	objRelease(net, LM_NET_FILENAME);
	objRelease(glbl, CORE_COMPONENT);
	objRelease(datetime, CORE_COMPONENT);
	objRelease(errmsg, CORE_COMPONENT);
	objRelease(netstrm, DONT_LOAD_LIB);
	objRelease(netstrms, LM_NETSTRMS_FILENAME);
	objRelease(prop, CORE_COMPONENT);
ENDObjClassExit(nsd_ossl)

/* Initialize the nsd_ossl class. Must be called as the very first method
 * before anything else is called inside this class.
 */
BEGINObjClassInit(nsd_ossl, 1, OBJ_IS_LOADABLE_MODULE) /* class, version */
	/* request objects we use */
	CHKiRet(objUse(errmsg, CORE_COMPONENT));
	CHKiRet(objUse(datetime, CORE_COMPONENT));
	CHKiRet(objUse(glbl, CORE_COMPONENT));
	CHKiRet(objUse(net, LM_NET_FILENAME));
	CHKiRet(objUse(netstrms, LM_NETSTRMS_FILENAME));
	CHKiRet(objUse(netstrm, DONT_LOAD_LIB));
	CHKiRet(objUse(prop, CORE_COMPONENT));

	/* now do global TLS init stuff */
	CHKiRet(osslGlblInit());
ENDObjClassInit(nsd_ossl)

/*---------------here now comes the plumbing that makes as a library module---------------*/

BEGINmodExit
CODESTARTmodExit
	nsdsel_osslClassExit();
	nsd_osslClassExit();
ENDmodExit

BEGINqueryEtryPt
CODESTARTqueryEtryPt
CODEqueryEtryPt_STD_LIB_QUERIES
ENDqueryEtryPt

BEGINmodInit()
CODESTARTmodInit
	*ipIFVersProvided = CURR_MOD_IF_VERSION; /* we only support the current interface specification */

	/* Initialize all classes that are in our module - this includes ourselfs */
	CHKiRet(nsd_osslClassInit(pModInfo)); /* must be done after tcps_sess, as we use it */
	CHKiRet(nsdsel_osslClassInit(pModInfo)); /* must be done after tcps_sess, as we use it */

ENDmodInit
/* vi:set ai:
 */
