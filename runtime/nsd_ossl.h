/* An implementation of the nsd interface for OpenSSL.
 *
 * Copyright 2018-2018 Adiscon GmbH.
 * Author: Andre Lorbach
 *
 * This file is part of the rsyslog runtime library.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *       -or-
 *       see COPYING.ASL20 in the source distribution
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef INCLUDED_NSD_OSSL_H
#define INCLUDED_NSD_OSSL_H

#include "nsd.h"

#define NSD_OSSL_MAX_RCVBUF 8 * 1024 /* max size of buffer for message reception */

typedef enum {
	osslRtry_None = 0,	/**< no call needs to be retried */
	osslRtry_handshake = 1,
	osslRtry_recv = 2
} osslRtryCall_t;		/**< IDs of calls that needs to be retried */

typedef enum {
	osslServer = 0,		/**< Server SSL Object */
	osslClient = 1		/**< Client SSL Object */
} osslSslState_t;


typedef nsd_if_t nsd_ossl_if_t; /* we just *implement* this interface */

/* the nsd_ossl object */
struct nsd_ossl_s {
	BEGINobjInstance;	/* Data to implement generic object - MUST be the first data element! */
	nsd_t *pTcp;		/**< our aggregated nsd_ptcp data */
	uchar *pszConnectHost;	/**< hostname used for connect - may be used to
					authenticate peer if no other name given */
	int iMode;		/* 0 - plain tcp, 1 - TLS */
	int bAbortConn;		/* if set, abort conncection (fatal error had happened) */
	enum {
		OSSL_AUTH_CERTNAME = 0,
		OSSL_AUTH_CERTFINGERPRINT = 1,
		OSSL_AUTH_CERTVALID = 2,
		OSSL_AUTH_CERTANON = 3
	} authMode;
	osslRtryCall_t rtryCall;/**< what must we retry? */
	int rtryOsslErr;	/**< store ssl error code into like SSL_ERROR_WANT_READ or SSL_ERROR_WANT_WRITE */
	int bIsInitiator;	/**< 0 if socket is the server end (listener), 1 if it is the initiator */
	int bHaveSess;		/* as we don't know exactly which gnutls_session values
					are invalid, we use this one to flag whether or
					not we are in a session (same as -1 for a socket
					meaning no sess) */
	int bReportAuthErr;	/* only the first auth error is to be reported, this var triggers it. Initially, it is
				 * set to 1 and changed to 0 after the first report. It is changed back to 1 after
				 * one successful authentication. */
	permittedPeers_t *pPermPeers; /* permitted peers */

//	uchar *gnutlsPriorityString;	/* gnutls priority string */
//	gnutls_x509_crt_t ourCert;	/**< our certificate, if in client mode (unused in server mode) */
//	gnutls_x509_privkey_t ourKey;	/**< our private key, if in client mode (unused in server mode) */

	short	bOurCertIsInit;	/**< 1 if our certificate is initialized and must be deinit on destruction */
	short	bOurKeyIsInit;	/**< 1 if our private key is initialized and must be deinit on destruction */
	char *pszRcvBuf;
	int lenRcvBuf;
	/**< -1: empty, 0: connection closed, 1..NSD_OSSL_MAX_RCVBUF-1: data of that size present */
	int ptrRcvBuf;		/**< offset for next recv operation if 0 < lenRcvBuf < NSD_OSSL_MAX_RCVBUF */

	/* Open SSL objects */
//	BIO *acc;		/* OpenSSL main BIO obj */
	SSL *ssl;		/* OpenSSL main SSL obj */
	osslSslState_t sslState;/**< what must we retry? */

};

/* interface is defined in nsd.h, we just implement it! */
#define nsd_osslCURR_IF_VERSION nsdCURR_IF_VERSION

/* prototypes */
PROTOTYPEObj(nsd_ossl);

/* some prototypes for things used by our nsdsel_ossl helper class */
uchar *osslStrerror(int error);
rsRetVal osslChkPeerAuth(nsd_ossl_t *pThis);
rsRetVal osslRecordRecv(nsd_ossl_t *pThis);
rsRetVal osslHandshakeCheck(nsd_ossl_t *pNsd);
void osslLastSSLErrorMsg(int ret, SSL *ssl, char* pszCallSource);


/* the name of our library binary */
#define LM_NSD_OSSL_FILENAME "lmnsd_ossl"

#endif /* #ifndef INCLUDED_NSD_OSSL_H */
