/* ------------------------------------------- * 
 * filter-redirect.h
 * =========
 * 
 * Summary 
 * -------
 * -
 *
 * LICENSE
 * -------
 * Copyright 2020-2021 Tubular Modular Inc. dba Collins Design
 *
 * See LICENSE in the top-level directory for more information.
 *
 * CHANGELOG 
 * ---------
 * -
 * ------------------------------------------- */
#include <zhttp.h>
#include "../server.h"
#include "../config.h"

const int 
filter_redirect ( int fd, zhttp_t *req, zhttp_t *res, struct cdata *conn );
