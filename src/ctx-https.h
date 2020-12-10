/* ------------------------------------------- * 
 * ctx-https.h
 * ========
 * 
 * Summary 
 * -------
 * Header for HTTPS functions.
 *
 * Usage
 * -----
 * Soon to come...
 *
 * LICENSE
 * -------
 * Copyright 2020 Tubular Modular Inc. dba Collins Design
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy 
 * of this software and associated documentation files (the "Software"), to 
 * deal in the Software without restriction, including without limitation the 
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or 
 * sell copies of the Software, and to permit persons to whom the Software is 
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in 
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR 
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE 
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER 
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN 
 * THE SOFTWARE.
 *
 * CHANGELOG 
 * ---------
 * 
 * ------------------------------------------- */
#include "../vendor/zwalker.h"
#include "../vendor/zhasher.h"
#include <gnutls/gnutls.h>
#include <stddef.h>
#include "socket.h"
#include "server.h"
#include "util.h"
#include <assert.h>

#ifndef CTXHTTPS_H
#define CTXHTTPS_H

#if 0
#if 1
	//#define CAFILE   "/etc/ssl/certs/ca-certificates.crt"
	#define FPATH "tlshelp/"
	#define KEYFILE  FPATH "x509-server-key.pem"
	#define CERTFILE FPATH "x509-server.pem"
	#define CAFILE   FPATH "x509-ca.pem"
	#define CRLFILE  FPATH "crl.pem"
#else
	#define FPATH "tlshelp/collinshosting-final/"
	#define KEYFILE  FPATH "x509-collinshosting-key.pem"
	#define CERTFILE FPATH "x509-collinshosting-server.pem"
	#define CAFILE   FPATH "collinshosting_com.ca-bundle"
	#define CRLFILE  FPATH "crl.pem"
#endif
#endif

struct gnutls_abstr {
	gnutls_certificate_credentials_t x509_cred;
  gnutls_priority_t priority_cache;
	gnutls_session_t session;
#if 0
	const char *cafile;
	const char *crlfile; 
	const char *certfile;
	const char *keyfile;
#endif
};

const int pre_gnutls ( int, struct HTTPBody *, struct HTTPBody *, struct cdata *);

const int post_gnutls ( int, struct HTTPBody *, struct HTTPBody *, struct cdata *);

const int read_gnutls ( int, struct HTTPBody *, struct HTTPBody *, struct cdata *);

const int write_gnutls ( int, struct HTTPBody *, struct HTTPBody *, struct cdata *);

void create_gnutls( void ** );

void free_gnults( void **p );
#endif
