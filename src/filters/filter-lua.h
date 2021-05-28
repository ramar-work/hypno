/* ------------------------------------------- * 
 * filter-lua.h
 * ===========
 * 
 * Summary 
 * -------
 * Header file for functions comprising the dirent filter for interpreting 
 * HTTP messages.
 *
 * Usage
 * -----
 * filter-dirent.c allows hypno to act as a directory server, in which the
 * server simply presents the user with a list of files for view or download. 
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
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
#include <zhttp.h>
#include <ztable.h>
#include <zrender.h>
#include <zmime.h>
#include <errno.h>
#include <sys/stat.h>
#include <stdarg.h>
#include <router.h>
#include "../util.h"
#include "../server.h"
#include "../lua.h"
#include "../lua/lib.h"

#ifndef FILTER_LUA_H
#define FILTER_LUA_H

#define LD_LEN 128

#define LD_ERRBUF_LEN 1024

struct route_t { 
	int iroute_tlen;
	struct iroute_t { char *route; int index; } **iroute_tlist;
	zTable *src;
};


struct mvc_t {
	struct mvcmeta_t *mset;
	int flen, type; 
	int depth;   //track the depth, so you know when to stop iterating
	//int inherit; //a keyword

	int model;
	int view;
	int query;
	
	const char ctype[ 128 ];
	struct imvc_t {
		const char file[ 2048 ], base[ 128 ], ext[ 16 ];
		//leave some space here...
		//const char *dir;
	} **imvc_tlist;
};


struct luadata_t {
	struct HTTPBody *req, *res;
	lua_State *state;
#if 0
	const char *aroute;
	const char *rroute;
	const char *apath;
	const char *db;
	const char *fqdn;
	const char *root;
	const char *dctype;
#else
	const char aroute[ LD_LEN ];
	const char rroute[ LD_LEN ];
	const char apath[ LD_LEN ];
	const char db[ LD_LEN ];
	const char fqdn[ LD_LEN ];
	const char root[ LD_LEN ];
	const char dctype[ LD_LEN ];
#endif
#if 1
	int status; //can return a different status
	//other zTables could go here...
	zTable *zconfig;
	zTable *zroutes;
	zTable *zroute;
	zTable *zmodel;
	zTable *zhttp; //you might not need this anymore...
#endif
	struct mvc_t pp; 
	char err[ LD_ERRBUF_LEN ];
};

int http_error( struct HTTPBody *, int, char *, ... );

const int filter_lua( int , zhttp_t *, zhttp_t *, struct cdata * );
#endif
