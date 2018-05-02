/* nsdsel_ossl.c
 *
 * An implementation of the nsd select() interface for GnuTLS.
 *
 * Copyright (C) 2017 Adiscon GmbH.
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
#include "config.h"

#include <stdlib.h>
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <sys/select.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>

#include "rsyslog.h"
#include "module-template.h"
#include "obj.h"
#include "errmsg.h"
#include "nsd.h"
#include "nsd_ossl.h"
#include "nsdsel_ossl.h"
#include "unlimited_select.h"

/* static data */
DEFobjStaticHelpers
DEFobjCurrIf(errmsg)
DEFobjCurrIf(glbl)

static rsRetVal
osslHasRcvInBuffer(nsd_ossl_t *pThis)
{
	int ibuf;
	/* we have a valid receive buffer one such is allocated and
	 * NOT exhausted!
	 */
	DBGPRINTF("osslHasRcvInBuffer: NSD[%p], SSL[%p], BIO[%p]: pszRcvBuf %p, lenRcvBuf %d\n",
		pThis, pThis->ssl, (pThis->ssl != NULL ? SSL_get_rbio(pThis->ssl) : NULL),
		pThis->pszRcvBuf, pThis->lenRcvBuf);

	if (pThis->ssl != NULL) {
		dbgprintf("osslHasRcvInBuffer: ssl[%p] NOT NULL\n", pThis->ssl);
		if( (ibuf = SSL_pending(pThis->ssl)) > 0) {
			dbgprintf("osslHasRcvInBuffer: SSL[%p] should READ data %d bytes!\n", pThis->ssl, ibuf);
		}

		dbgprintf("osslHasRcvInBuffer: BIO[%p] NOT NULL\n", SSL_get_rbio(pThis->ssl));
		if( BIO_pending(SSL_get_rbio(pThis->ssl)) > 0 ) {
			dbgprintf("osslHasRcvInBuffer: BIO[%p] should READ data!\n", SSL_get_rbio(pThis->ssl));
		}

//*((char*)0)= 0;

	}

	return(pThis->pszRcvBuf != NULL && pThis->lenRcvBuf != -1);
}

/* Standard-Constructor
 */
BEGINobjConstruct(nsdsel_ossl) /* be sure to specify the object type also in END macro! */
ENDobjConstruct(nsdsel_ossl)

/* destructor for the nsdsel_ossl object */
BEGINobjDestruct(nsdsel_ossl) /* be sure to specify the object type also in END and CODESTART macros! */
CODESTARTobjDestruct(nsdsel_ossl)
ENDobjDestruct(nsdsel_ossl)

/* Add a socket to the select set */
static rsRetVal
Add(nsdsel_t *pNsdsel, nsd_t *pNsd, nsdsel_waitOp_t waitOp)
{
	DEFiRet;
	nsdsel_ossl_t *pThis = (nsdsel_ossl_t*) pNsdsel;
	nsd_ossl_t *pNsdOSSL = (nsd_ossl_t*) pNsd;

	ISOBJ_TYPE_assert(pThis, nsdsel_ossl);
	ISOBJ_TYPE_assert(pNsdOSSL, nsd_ossl);
	DBGPRINTF("nsdsel_ossl: Add for NSD[%p] \n", (void *)pNsdOSSL);

	if(pNsdOSSL->iMode == 1) {
		if(waitOp == NSDSEL_RD && osslHasRcvInBuffer(pNsdOSSL)) {
			++pThis->iBufferRcvReady;
			dbgprintf("Add: data already present in buffer, initiating "
				  "dummy select %p->iBufferRcvReady=%d\n",
				  pThis, pThis->iBufferRcvReady);
			FINALIZE;
		}
		if(pNsdOSSL->rtryCall != osslRtry_None) {
DBGPRINTF("Add: rtryCall != osslRtry_None\n");
/*			if(gnutls_record_get_direction(pNsdOSSL->sess) == 0) {
				CHKiRet(nsdsel_ptcp.Add(pThis->pTcp, pNsdOSSL->pTcp, NSDSEL_RD));
			} else {
				CHKiRet(nsdsel_ptcp.Add(pThis->pTcp, pNsdOSSL->pTcp, NSDSEL_WR));
			}
			FINALIZE; */
		}
	}
// *((char*)0)= 0;

	/* if we reach this point, we need no special handling */
	// WHAT TO DO INSTEAD ? CHKiRet(nsdsel_ptcp.Add(pThis->pTcp, pNsdOSSL->pTcp, waitOp)); */

finalize_it:
	RETiRet;
}


/* perform the select()  piNumReady returns how many descriptors are ready for IO
 * TODO: add timeout!
 */
static rsRetVal
Select(nsdsel_t *pNsdsel, int *piNumReady)
{
	DEFiRet;
	nsdsel_ossl_t *pThis = (nsdsel_ossl_t*) pNsdsel;
	ISOBJ_TYPE_assert(pThis, nsdsel_ossl);



	if(pThis->iBufferRcvReady > 0) {
		/* we still have data ready! */
		*piNumReady = pThis->iBufferRcvReady;
		dbgprintf("Select: doing dummy select, data present\n");
	} else {
dbgprintf("Select: RAW PTCP NOT IMPLEMENTED!\n");
		*piNumReady = 0;
//		iRet = nsdsel_ptcp.Select(pThis->pTcp, piNumReady);
	}

	RETiRet;
}

/* check if a socket is ready for IO */
static rsRetVal
IsReady(nsdsel_t *pNsdsel, nsd_t *pNsd, nsdsel_waitOp_t __attribute__((unused)) waitOp, int *pbIsReady)
{
	DEFiRet;
	nsdsel_ossl_t __attribute__((unused)) *pThis = (nsdsel_ossl_t*) pNsdsel;
	nsd_ossl_t *pNsdOSSL = (nsd_ossl_t*) pNsd;
int res;

	/* default rdy state */
	*pbIsReady = 0;

	DBGPRINTF("IsReady: NSD[%p], BIO[%p], SSL[%p] waitOp=%d, NSDSEL_RD=%d\n",
		(void *)pNsdOSSL, (void *)pNsdOSSL->acc, (void *)pNsdOSSL->ssl, waitOp, NSDSEL_RD);

	if(pNsdOSSL->iMode == 1) {
		if(waitOp == NSDSEL_RD && osslHasRcvInBuffer(pNsdOSSL)) {
			*pbIsReady = 1;
			--pThis->iBufferRcvReady; /* one "pseudo-read" less */
			dbgprintf("IsReady: dummy read, decermenting %p->iBufRcvReady, now %d\n",
				   pThis, pThis->iBufferRcvReady);
			FINALIZE;
		}

		if(pThis->iBufferRcvReady) {
			dbgprintf("IsReady: dummy read, buffer not available for this FD\n");
			*pbIsReady = 0;
			FINALIZE;
		}

		if (pNsdOSSL->ssl != NULL ){
			dbgprintf("IsReady: ssl[%p] NOT NULL\n", pNsdOSSL->ssl);
			if( (res = SSL_pending(pNsdOSSL->ssl)) >= 0) {
				dbgprintf("IsReady: SSL[%p] should READ %d bytes !\n", pNsdOSSL->ssl, res);
				*pbIsReady = 1;
				FINALIZE;
			}
		}
/* TODO THIS NEEDS TO BE DIFFERENT */
		if (pNsdOSSL->acc != NULL && waitOp == NSDSEL_RD){
			if( (res = BIO_pending(pNsdOSSL->acc)) > 0 ) {
				dbgprintf("IsReady: BIO[%p] should READ data!\n", pNsdOSSL->acc);
				*pbIsReady = 1;
				FINALIZE;
			} else {
				dbgprintf("IsReady: BIO[%p] should NOT READ %d bytes !\n", pNsdOSSL->acc, res);
				if (!pNsdOSSL->bioAccepted) {
					if( (res = BIO_do_accept(pNsdOSSL->acc)) <= 0) {
						errmsg.LogError(0, RS_RET_NO_ERRCODE, "Error accepting SSL connection, "
							"BIO_do_accept failed with return %d", res);
						ABORT_FINALIZE(RS_RET_NO_ERRCODE);
					} else {
						dbgprintf("IsReady: BIO[%p] accepted new SOCKET!\n", pNsdOSSL->acc);
						*pbIsReady = 1;
						pNsdOSSL->bioAccepted = TRUE;
						FINALIZE;
					}
				} else {
					dbgprintf("IsReady: BIO[%p] already accepted\n", pNsdOSSL->acc);
					*pbIsReady = 0;
					FINALIZE;
				}
			}
		}


	}

	if (*pbIsReady == 1) {
		dbgprintf("IsReady: SOCK[%d] has data!\n", pNsdOSSL->sock);
	}

/* Use PTCP default callback */
// TODO !
//	CHKiRet(nsdsel_ptcp.IsReady(pThis->pTcp, pNsdOSSL->pTcp, waitOp, pbIsReady));

finalize_it:
	RETiRet;
}

/* ------------------------------ end support for the select() interface ------------------------------ */

/* queryInterface function */
BEGINobjQueryInterface(nsdsel_ossl)
CODESTARTobjQueryInterface(nsdsel_ossl)
	if(pIf->ifVersion != nsdCURR_IF_VERSION) {/* check for current version, increment on each change */
		ABORT_FINALIZE(RS_RET_INTERFACE_NOT_SUPPORTED);
	}

	/* ok, we have the right interface, so let's fill it
	 * Please note that we may also do some backwards-compatibility
	 * work here (if we can support an older interface version - that,
	 * of course, also affects the "if" above).
	 */
	pIf->Construct = (rsRetVal(*)(nsdsel_t**)) nsdsel_osslConstruct;
	pIf->Destruct = (rsRetVal(*)(nsdsel_t**)) nsdsel_osslDestruct;
	pIf->Add = Add;
	pIf->Select = Select;
	pIf->IsReady = IsReady;
finalize_it:
ENDobjQueryInterface(nsdsel_ossl)

/* exit our class
 */
BEGINObjClassExit(nsdsel_ossl, OBJ_IS_CORE_MODULE) /* CHANGE class also in END MACRO! */
CODESTARTObjClassExit(nsdsel_ossl)
	/* release objects we no longer need */
	objRelease(glbl, CORE_COMPONENT);
	objRelease(errmsg, CORE_COMPONENT);
ENDObjClassExit(nsdsel_ossl)

/* Initialize the nsdsel_ossl class. Must be called as the very first method
 * before anything else is called inside this class.
 */
BEGINObjClassInit(nsdsel_ossl, 1, OBJ_IS_CORE_MODULE) /* class, version */
	/* request objects we use */
	CHKiRet(objUse(errmsg, CORE_COMPONENT));
	CHKiRet(objUse(glbl, CORE_COMPONENT));

	/* set our own handlers */
ENDObjClassInit(nsdsel_ossl)
/* vi:set ai:
 */
