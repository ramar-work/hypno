/* -------------------------------------------------------- *
 * server.c
 * ========
 * 
 * Summary 
 * -------
 * Server functions for Hypno's server
 * 
 * Usage
 * -----
 * These are the options:
 *   --start            Start new servers             
 *   --debug            Set debug rules               
 *   --kill             Test killing a server         
 *   --fork             Daemonize the server          
 *   --config <arg>     Use this file for configuration
 *   --port <arg>       Set a differnt port           
 *   --ssl              Use ssl or not..              
 *   --user <arg>       Choose a user to start as     
 * 
 * LICENSE
 * -------
 * Copyright 2020-2021 Tubular Modular Inc. dba Collins Design
 * 
 * See LICENSE in the top-level directory for more information.
 * 
 * Changelog 
 * ----------
 * - 
 * -------------------------------------------------------- */
#include "server.h"


// Check the validity of a filter
static filter_t * srv_check_filter ( const filter_t *filters, char *name ) {
	while ( filters && filters->name ) {
		filter_t *f = ( filter_t * )filters;
		if ( f->name && strcmp( f->name, name ) == 0 ) {
			return f;
		}
		filters++;
	}
	return NULL;
}



// Check that the website's chosen directory is accessible and it's log directory is writeable.
//static int srv_check_dir ( conn_t *conn, char *err, int errlen ) {
static int srv_check_dir ( conn_t *conn ) {
	//Check that log dir is accessible and writeable (or exists) - send 500 if not 
	struct stat sb;
	char *adir = NULL;
	char dir[ 2048 ] = { 0 };

	// Check that access directory exists 
	if ( !( adir = conn->hconfig->dir ) ) {
		snprintf( conn->err, conn->errlen, "Directory for host '%s' does not exist.", conn->hconfig->name );
		return 0;
	}

	// ...
	if ( stat( adir, &sb ) == -1 ) {
		//Try to build a full one
		snprintf( dir, sizeof(dir), "%s/%s", conn->config->wwwroot, conn->hconfig->dir );
		if ( stat( dir, &sb ) == -1 ) {
			const char *fmt = "Directory for host '%s' not accessible: %s.";
			snprintf( conn->err, conn->errlen, fmt, conn->hconfig->name, strerror(errno) );
			return 0;
		}

		//If we get this far, replace the original directory with this new one
		free( conn->hconfig->dir );
		conn->hconfig->dir = adir = strdup( dir );
	}

	if ( access( adir, W_OK ) == -1 ) {
		const char *fmt = "Directory for host '%s' not writeable: %s.";
		snprintf( conn->err, conn->errlen, fmt, conn->hconfig->name, strerror(errno) );
		return 0;
	}

	return 1;
}



//Build server configuration
static const int srv_start( const server_t *p, conn_t *c ) {
	FPRINTF( "Initial server allocation started...\n" );

	// Set reference to the server configuration	
	if ( !( c->config = p->config ) ) {
		c->count = -3;
		// This is a connection problem, but it just depends on what's wrong 
		// TODO: Tell me what file is causing this?
		snprintf( c->err, sizeof( c->err ), "Server configuration load error." );
		return 0;
	}

	c->stage = CONN_PRE;
	FPRINTF( "Initial server allocation complete.\n" );
	return 1;
}


//Find the chosen host and generate a response via one of the selected filters
//static const int srv_proc( int fd, zhttp_t *req, zhttp_t *res, struct cdata *conn) {
static const int srv_proc( const server_t *p, conn_t *conn ) { 
	//char err[2048] = {0};
	zTable *t = NULL;
	filter_t *filter = NULL;
	int count = conn->count;	

	// Make it ready for write
	conn->stage = CONN_WRITE;

	//With no default host, throw this 
	if ( !conn->req->host ) {
		snprintf( conn->err, conn->errlen, 
			"No host header specified." );
		return http_set_error( conn->res, 400, conn->err );
	}

	if ( !( conn->hconfig = find_host( conn->config->hosts, conn->req->host ) ) ) {
		snprintf( conn->err, conn->errlen, 
			"Could not find host '%s'.", conn->req->host );
		return http_set_error( conn->res, 404, conn->err ); 
	}

	// TODO: Move this to pre or even better yet to server checks
	if ( !conn->hconfig->filter ) {
		snprintf( conn->err, conn->errlen, 
			"No Filter specified for '%s'", conn->hconfig->name );
		return http_set_error( conn->res, 500, conn->err ); 
	}

	// TODO: Move this to pre or even better yet to server checks
	if ( !( filter = srv_check_filter( p->filters, conn->hconfig->filter ) ) ) {
		snprintf( conn->err, conn->errlen, 
			"Filter '%s' not supported", conn->hconfig->filter );
		return http_set_error( conn->res, 500, conn->err ); 
	}

	if ( conn->hconfig->dir && !srv_check_dir( conn ) ) {
		return http_set_error( conn->res, 500, conn->err ); 
	}
 
	//Finally, now we can evalute the filter and the route.
	if ( !filter->filter( p, conn ) ) {
		// What kinds of fatal errors could happen here?
		return 0;
	}

	//You can add a header to tell things to close
	conn->count = count;
	return 1;
}


//Generate a message in common log format: ip - - [date] "method path protocol" status clen
//static const int srv_log( int fd, zhttp_t *rq, zhttp_t *rs, struct cdata *conn) {
static const int srv_log( const server_t *p, conn_t *conn ) {
#if 0
	const char fmt[] = "%s %s %s [%s] \"%s %s %s\" %d %d";
	const char datefmt[] = "%d/%b/%Y:%H:%M:%S %z";
	char log[2048] = {0};
	char date[2048] = {0};

	//Generate the time	
	time_t t = time(NULL);
	struct tm *tmp = localtime(&t);
	strftime( date, sizeof(date), datefmt, tmp );

	//Bugs?
	char *prot = ( rq->protocol ) ? rq->protocol : "HTTP/1.1";	

	//Just print the log for now
	snprintf( log, sizeof(log), fmt, 
		conn->ipv4, "-", "-", date, rq->method, rq->path, prot, rs->status, rs->clen );
	FPRINTF( "%s\n", log );
#endif
	return 1;
}


// End the request by deallocating http bodies
static void srv_end( const server_t *p, conn_t *conn ) {
	http_free_body( conn->req ), http_free_body( conn->res );
	return;
}


//Generate a response
//int srv_response ( int fd, struct cdata *conn ) {
int srv_response ( server_t *p, conn_t *c ) {

	//Define
	zhttp_t rq = {0}, rs = {0};
	const protocol_t *sr = p->ctx;

	// All of these are connection failures
	FPRINTF( "Running srv_start\n" );
	if ( !srv_start( p, c ) ) {
		return 0;
	}

	// Set up the connection
	c->stage = CONN_INIT;

	// TODO: These need to be void pointers or some other kind of opaque
	c->req = &rq;
	c->res = &rs;
	c->req->type = ZHTTP_IS_CLIENT;
	c->res->type = ZHTTP_IS_SERVER;

	FPRINTF( "Setting any pre data for current protocol.\n" );
	if ( !sr->pre( p, c ) ) {
		FPRINTF( "(%s)->pre failure: %s\n", p->ctx->name, c->err );
		return 0;
	}

	FPRINTF( "Got pre data: %p...\n", p->data );
	FPRINTF( "Running c->ctx->read()\n" );
	if ( !sr->read( p, c ) ) {
		FPRINTF( "(%s)->read failure: %s\n", p->ctx->name, c->err );
		//Log what happened
		sr->post( p, c );	
		srv_end( p, c );
		return 0;
	}

	FPRINTF( "Running srv_proc()\n" );
	if ( c->stage == CONN_PROC && !srv_proc( p, c ) ) {
		FPRINTF( "(%s)->proc failure: %s\n", p->ctx->name, c->err );
		//Log what happened, but don't stop
	}

	FPRINTF( "Running c->ctx->write()\n" );
	if ( c->stage == CONN_WRITE && !sr->write( p, c ) ) {
		FPRINTF( "(%s)->write failure: %s\n", p->ctx->name, c->err );
		//Log what happened, but don't stop
	}

	FPRINTF( "Running c->ctx->post()\n" );
	if ( !sr->post( p, c ) ) {
		FPRINTF( "(%s)->post failure: %s\n", p->ctx->name, c->err );
		//Log what happened, but don't stop
	}

	FPRINTF( "Running srv_log\n" );
	if ( !srv_log( p, c ) ) {
		//Log what happened, but don't stop
		FPRINTF( "(%s)->log failure: %s\n", p->ctx->name, c->err );
	}

	FPRINTF( "Running srv_end\n" );
	srv_end( p, c ); 
	return 1;
}


