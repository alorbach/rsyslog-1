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
	/* we have a valid receive buffer one such is allocated and 
	 * NOT exhausted!
	 */
	DBGPRINTF("hasRcvInBuffer on nsd %p: pszRcvBuf %p, lenRcvBuf %d\n", pThis,
		pThis->pszRcvBuf, pThis->lenRcvBuf);
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
	if(pNsdOSSL->iMode == 1) {
		if(waitOp == NSDSEL_RD && gtlsHasRcvInBuffer(pNsdOSSL)) {
			++pThis->iBufferRcvReady;
			dbgprintf("nsdsel_ossl: data already present in buffer, initiating "
				  "dummy select %p->iBufferRcvReady=%d\n",
				  pThis, pThis->iBufferRcvReady);
			FINALIZE;
		}
		if(pNsdOSSL->rtryCall != osslRtry_None) {
/*			if(gnutls_record_get_direction(pNsdGTLS->sess) == 0) {
				CHKiRet(nsdsel_ptcp.Add(pThis->pTcp, pNsdGTLS->pTcp, NSDSEL_RD));
			} else {
				CHKiRet(nsdsel_ptcp.Add(pThis->pTcp, pNsdGTLS->pTcp, NSDSEL_WR));
			}
			FINALIZE; */
		}
	}

	/* if we reach this point, we need no special handling */
/*	CHKiRet(nsdsel_ptcp.Add(pThis->pTcp, pNsdGTLS->pTcp, waitOp)); */

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
	RETiRet;
}

/* check if a socket is ready for IO */
static rsRetVal
IsReady(nsdsel_t *pNsdsel, nsd_t *pNsd, nsdsel_waitOp_t waitOp, int *pbIsReady)
{
	DEFiRet;
	
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
