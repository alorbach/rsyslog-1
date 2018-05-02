/* An implementation of the nsd interface for OPENSSL.
 *
 * Copyright 2017 Adiscon GmbH.
 * Author: Pascal Withopf
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
} osslRtryCall_t;

typedef nsd_if_t nsd_ossl_if_t; /* we just *implement* this interface */

/* the nsd_gtls object */
struct nsd_ossl_s {
	BEGINobjInstance;	/* Data to implement generic object - MUST be the first data element! */
	uchar *pRemHostName;	/* host name of remote peer */
	prop_t *remoteIP;	/* IP address of remote peer */
	struct sockaddr_storage remAddr; /**< remote addr as sockaddr - used for legacy ACL code */
	int iMode;		/* 0 - plain tcp, 1 - TLS */
	enum {
		OSSL_AUTH_CERTNAME = 0,
		OSSL_AUTH_CERTFINGERPRINT = 1,
		OSSL_AUTH_CERTVALID = 2,
		OSSL_AUTH_CERTANON = 3
	} authMode;
	permittedPeers_t *pPermPeers;
	osslRtryCall_t rtryCall;
	BIO *acc;		/* Address is bound to Bio */
	int bioAccepted;	/* Helper to store if bio was accepted */
	SSL *ssl;		/* SSL connection */
	int sock;		/* Actual Socket handle! */
	int bHaveSess;
	char *pszRcvBuf;
	int lenRcvBuf;		/**< -1: empty, 0: connection closed, 1..NSD_GTLS_MAX_RCVBUF-1:
					data of that size present */
	int ptrRcvBuf;		/**< offset for next recv operation if 0 < lenRcvBuf < NSD_GTLS_MAX_RCVBUF */
};

/* interface is defined in nsd.h, we just implement it! */
#define nsd_osslCURR_IF_VERSION nsdCURR_IF_VERSION

/* prototypes */
PROTOTYPEObj(nsd_ossl);

#endif /* #ifndef INCLUDED_NSD_OSSL_H */
