/* -------------------------------------------------------- *
 * main.c
 * ======
 * 
 * Summary 
 * -------
 * This is the basis of hypno's web server.
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
 * 
 * Building
 * --------
 * Lua is a necessity because of the configuration parsing. 
 * 
 * Running `make` is all we need for now on Linux and OSX.  
 * Windows will need some additional help and Cygwin as well.
 * 
 * -------------------------------------------------------- */
#include <zwalker.h>
#include <ztable.h>
#include <dlfcn.h>
#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>
#include <signal.h>
#include <sys/types.h>
#include <pwd.h>
#include "../socket.h"
#include "../server.h"
#include "../ctx/ctx-http.h"
#include "../ctx/ctx-https.h"
#include "../filters/filter-static.h"
#include "../filters/filter-echo.h"
#include "../filters/filter-dirent.h"
#include "../filters/filter-redirect.h"
#include "../filters/filter-lua.h"

#define eprintf(...) \
	fprintf( stderr, "%s: ", NAME "-server" ) && \
	fprintf( stderr, __VA_ARGS__ ) && \
	fprintf( stderr, "\n" )

#define NAME "hypno"

#define LIBDIR "/var/lib/hypno"

#define PIDFILE "/var/run/hypno.pid"

#if 0
#define PIDDIR "/var/run"
#else
#define PIDDIR "/tmp"
#endif

#define HELP \
	"-d, --dir <arg>          Define where to create a new application.\n"\
	"-n, --domain-name <arg>  Define a specific domain for the app.\n"\
	"    --title <arg>        Define a <title> for the app.\n"\
	"-s, --static <arg>       Define a static path. (Use multiple -s's to\n"\
	"                         specify multiple paths).\n"\
	"-b, --database <arg>     Define a specific database connection.\n"\
	"-x, --dump-args          Dump passed arguments.\n" \
	"-s, --start              Start the server\n" \
	"-c, --config <arg>       Use this Lua file for configuration\n" \
	"-p, --port <arg>         Start using a different port \n" \
	"-u, --user <arg>         Choose an alternate user to start as\n" \
	"-x, --dump               Dump configuration at startup\n" \
	"-k, --kill               Kill a running server\n" \
	"-l, --libs <arg>         Point to libraries at <arg>\n" \
	"    --no-fork            Do not fork\n" \
	"    --use-ssl            Use SSL\n" \
	"    --debug              set debug rules\n" \
	"-h, --help               Show the help menu.\n"

#ifdef LEAKTEST_H
 #define CONN_CONTINUE int i=0; i<1; i++
 #define CONN_CLOSE 1
#else
 #define CONN_CONTINUE ;;
 #define CONN_CLOSE 0 
#endif

const int defport = 2000;

const char libn[] = "libname";

const char appn[] = "filter";

char pidbuf[128] = {0};

struct values {
	int port;
	pid_t pid;
	int ssl;
	int start;
	int kill;
	int fork;
	int dump;
	int uid, gid;
	char *user;
	char *group;
	char *config;
	char *libdir;
	char *pidfile;
#ifdef DEBUG_H
	int pfork;
#endif
};


//Define a list of filters
struct filter filters[16] = { 
	{ "static", filter_static }
,	{ "echo", filter_echo }
,	{ "dirent", filter_dirent }
,	{ "redirect", filter_redirect }
,	{ "lua", filter_lua }
, { NULL }
, { NULL }
, { NULL }
, { NULL }
, { NULL }
, { NULL }
, { NULL }
, { NULL }
, { NULL }
, { NULL }
, { NULL }
};


int cmd_kill();

int procpid = 0;

//In lieu of an actual ctx object, we do this to mock pre & post which don't exist
const int fkctpre( int fd, zhttp_t *a, zhttp_t *b, struct cdata *c ) {
	return 1;
}

const int fkctpost( int fd, zhttp_t *a, zhttp_t *b, struct cdata *c) {
	return 1;
}

void sigkill( int signum ) {
	fprintf( stderr, "Killing the server..." );
	cmd_kill();
}


//Return fi
static int findex() {
	int fi = 0;
	for ( struct filter *f = filters; f->name; f++, fi++ ); 
	return fi;	
}



//Define a list of "context types"
struct senderrecvr sr[] = {
	{ read_notls, write_notls, create_notls, NULL, pre_notls, fkctpost  }
, { read_gnutls, write_gnutls, create_gnutls, NULL, pre_gnutls, post_gnutls }
,	{ NULL }
};


int cmd_kill ( ) {
	return 0;
}


//Loop should be extracted out
int cmd_server ( struct values *v, char *err, int errlen ) {
#if 1
	//Change root here?

	//Define
	struct sockAbstr su = {0};
	struct senderrecvr *ctx = NULL;

	//Initialize
	populate_tcp_socket( &su, &v->port );
	ctx = &sr[ v->ssl ];	
	ctx->init( &ctx->data );
	ctx->filters = filters;
	ctx->config = v->config;

	//Die if config is null or file not there 
	if ( !ctx->config ) {
		eprintf( "No config specified...\n" );
		return 0;
	}

	//Open a socket		
	if ( !open_listening_socket( &su, err, errlen ) ) {
		eprintf( "socket open error: %s", err );
		close_listening_socket( &su, err, sizeof(err) );
		return 0;
	}

#if 1
	struct passwd *p = getpwnam( v->user );
	int gid, uid;
	if ( !p ) {
		eprintf( "user %s not found.\n", v->user );
		return 0;
	}

#if 0
	fprintf( stderr, "username: %s\n", p->pw_name	 );
	fprintf( stderr, "user id: %d\n", p->pw_uid );
	fprintf( stderr, "group id: %d\n", p->pw_gid );
#endif

	if ( !( uid = p->pw_uid ) || !( gid = p->pw_gid ) ) {
		eprintf( "got incorrect uid / gid for user %s.\n", v->user );
		return 0;
	}
	
#if 1
	if ( !v->fork ) { 
		//Record the PID somewhere
		int len, fd = 0;
		char buf[64] = { 0 };

		//Would this ever return zero?
		v->pid = getpid();

		if ( ( fd = open( v->pidfile, O_CREAT | O_RDWR | O_TRUNC, S_IRUSR | S_IWUSR ) ) == -1 ) {
			eprintf( "Failed to access PID file: %s.", strerror(errno));
			return 0;
		}

		len = snprintf( buf, 63, "%d", v->pid );

		//Write the pid down
		if ( write( fd, buf, len ) == -1 ) {
			eprintf( "Failed to log PID: %s.", strerror(errno));
			return 0;
		}
	
		//The parent exited successfully.
		if ( close(fd) == -1 ) { 
			eprintf( "Could not close parent socket: %s", strerror(errno));
			return 0;
		}

		//Change proc info after we're done
		setuid( uid );
		setgid( gid );
	}
#endif
#else
	//Change process owner (may have to be done with either fork or something else)
	if ( values.fork ) {
		//Create another process with user and group 
		pid_t spid; 
		if ( ( spid = fork() ) == -1 ) {
			FPRINTF( "Failed to start new process for server: %s\n", strerror(errno) );
			return 0;
		}
		else if ( cpid == 0 ) {
			//Change the owner and group of the opened socket?
			return 0;
		}
		else {
			//Record the PID somewhere
			int len, fd = 0;
			char buf[64] = { 0 };
			//char pidfile[2048] = { 0 }; 
			char *pidfile = "/var/run/hypno.pid";

			if ( ( fd = open( pidfile, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR ) ) == -1 ) {
				eprintf( "Failed to access PID file: %s.", strerror(errno));
				return 0;
			}

			len = snprintf( buf, 63, "%d", spid );

			//Write the pid down
			if ( write( fd, buf, len ) == -1 ) {
				eprintf( "Failed to log PID: %s.", strerror(errno));
				return 0;
			}
		
			//The parent exited successfully.
			if ( close(fd) == -1 ) { 
				eprintf( "Could not close parent socket: %s", strerror(errno));
				return 0;
			}
		}
	}
#endif

	//This can have one global variable
	for ( CONN_CONTINUE ) {
		//Client address and length?
		int fd = 0, status;	
		pid_t cpid; 

		//Accept a connection.
		if ( !accept_listening_socket( &su, &fd, err, errlen ) ) {
			FPRINTF( "socket %d could not be marked as non-blocking\n", fd );
			continue;
		}

		//Fork and serve a request 
		//fork() should not be the only choice
		if ( ( cpid = fork() ) == -1 ) {
			//TODO: There is most likely a reason this didn't work.
			FPRINTF( "Failed to setup new child connection. %s\n", strerror(errno) );
			return 0;
		}
		else if ( cpid == 0 ) {
			//TODO: Additional logging ought to happen here.
			FPRINTF( "In parent...\n" );
			//Close the file descriptor here?
			if ( close( fd ) == -1 ) {
				FPRINTF( "Parent couldn't close socket.\n" );
			}
		}
		else if ( cpid ) {
			struct cdata connection = {0};	
			connection.flags = O_NONBLOCK;
			connection.ctx = ctx;
		
			//Get IP here and save it for logging purposes
			if ( !get_iip_of_socket( &su ) || !( connection.ipv4 = su.iip ) ) {
				FPRINTF( "Error in getting IP address of connecting client.\n" );
			}

			for ( ;; ) {
				//additionally, this one should block
				if ( !srv_response( fd, &connection ) ) {
					FPRINTF( "Error in TCP socket handling.\n" );
				}

				if ( CONN_CLOSE || connection.count < 0 || connection.count > 5 ) {
					FPRINTF( "Closing connection marked by descriptor %d to peer.\n", fd );
					if ( close( fd ) == -1 ) {
						FPRINTF( "Error when closing child socket.\n" );
					}
					FPRINTF( "Connection is done. count is %d\n", connection.count );
					break;
				}
			}
			break;
		}
	}

	//Close the socket
	if ( !close_listening_socket( &su, err, sizeof(err) ) ) {
		FPRINTF( "FAILURE\n" ); 
		eprintf( "Couldn't close parent socket. Error: %s", err );
		return 0;
	}
#endif	
	return 1;
}



int cmd_libs( struct values *v, char *err, int errlen ) {
	//Define
	DIR *dir;
	struct dirent *d;
	int findex = 0;

	//Find the last index
	for ( struct filter *f = filters; f->name; f++, findex++ );

	//Open directory
	if ( !( dir = opendir( v->libdir ) ) ) {
		snprintf( err, errlen, "lib fail: %s", strerror( errno ) );
		return 0;
	}

	//List whatever directory
	for ( ; ( d = readdir( dir ) );  ) { 
		void *lib = NULL;
		struct filter *f = &filters[ findex ];
		char fpath[2048] = {0};

		//Skip '.' & '..', and stop if you can't open it...
		if ( *d->d_name == '.' ) {
			continue;
		}

		//Try to open the library
		snprintf( fpath, sizeof( fpath ) - 1, "%s/%s", v->libdir, d->d_name );
		if ( ( lib = dlopen( fpath, RTLD_NOW ) ) == NULL ) { 
			fprintf( stderr, "dlopen error: %s\n", strerror( errno ) );
			continue; 
		}

		//Look for the symbol 'libname'
		if ( !( f->name = (const char *)dlsym( lib, libn ) ) ) {
			fprintf( stderr, "dlsym libname error: %s\n", dlerror() );
			//Don't open, don't load, and close what's there...
			dlclose( lib );
			continue;
		}

		//Look for the symbol 'app'
		if ( !( f->filter = dlsym( lib, appn ) ) ) {
			fprintf( stderr, "dlsym app error: %s\n", dlerror() );
			dlclose( lib );
			continue;
		}

		//Move to the next
		findex++;
	}

	return 1;
}



//dump
int cmd_dump( struct values *v, char *err, int errlen ) {
	fprintf( stderr, "Hypno is running with the following settings.\n" );
	fprintf( stderr, "===============\n" );
	fprintf( stderr, "Port:                %d\n", v->port );
	fprintf( stderr, "Using SSL?:          %s\n", v->ssl ? "T" : "F" );
	fprintf( stderr, "Daemonized:          %s\n", v->fork ? "T" : "F" );
	fprintf( stderr, "Request Model:       %s\n", "Fork" );
	fprintf( stderr, "User:                %s (%d)\n", v->user, v->uid );
	fprintf( stderr, "Group:               %s (%d)\n", v->group, v->gid );
	fprintf( stderr, "Config:              %s\n", v->config );
	fprintf( stderr, "PID file:            %s\n", v->pidfile );
	fprintf( stderr, "Library Directory:   %s\n", v->libdir );

	fprintf( stderr, "Filters enabled:\n" );
	for ( struct filter *f = filters; f->name; f++ ) {
		fprintf( stderr, "[ %-16s ] %p\n", f->name, f->filter ); 
	}
	return 1;
}


//...
void print_options ( struct values *v ) {
	const char *fmt = "%-10s: %s\n";
	fprintf( stderr, "%s invoked with options:\n", __FILE__ );
	fprintf( stderr, "%10s: %d\n", "start", v->start );	
	fprintf( stderr, "%10s: %d\n", "kill", v->kill );	
	fprintf( stderr, "%10s: %d\n", "port", v->port );	
	fprintf( stderr, "%10s: %d\n", "fork", v->fork );	
	fprintf( stderr, "%10s: %s\n", "config", v->config );	
	fprintf( stderr, "%10s: %s\n", "user", v->user );	
	fprintf( stderr, "%10s: %s\n", "ssl", v->ssl ? "true" : "false" );	
}


//We can also choose to daemonize the server or not.
//But is this too complicated?
#if 0
int daemonizer() {
	//If I could open a socket and listen successfully, then write the PID
	#if 0
	if ( values.fork ) {
		pid_t pid = fork();
		if ( pid == -1 ) {
			fprintf( stderr, "Failed to daemonize server process: %s", strerror(errno) );
			return 0;
		}
		else if ( !pid ) {
			//Close the parent?
			return 0;
		}
		else if ( pid ) {
			int len, fd = 0;
			char buf[64] = { 0 };

			if ( (fd = open( pidfile, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR )) == -1 )
				return ERRL( "Failed to access PID file: %s.", strerror(errno));

			len = snprintf( buf, 63, "%d", pid );

			//Write the pid down
			if (write( fd, buf, len ) == -1)
				return ERRL( "Failed to log PID: %s.", strerror(errno));
		
			//The parent exited successfully.
			if ( close(fd) == -1 )
				return ERRL( "Could not close parent socket: %s", strerror(errno));
			return SUC_PARENT;
		}
	}
	#endif
}
#endif


int main (int argc, char *argv[]) {
	struct values values = { 0 };
	char err[ 2048 ] = { 0 };
	int *port = NULL; 

	if ( argc < 2 ) {
		fprintf( stderr, HELP );
		return 1;	
	}
	
	while ( *argv ) {
		if ( !strcmp( *argv, "-s" ) || !strcmp( *argv, "--start" ) ) 
			values.start = 1;
		else if ( !strcmp( *argv, "-k" ) || !strcmp( *argv, "--kill" ) ) 
			values.kill = 1;
		else if ( !strcmp( *argv, "-x" ) || !strcmp( *argv, "--dump" ) ) 
			values.dump = 1;
	#if 0
		else if ( !strcmp( *argv, "-d" ) || !strcmp( *argv, "--daemonize" ) ) 
			values.fork = 1;
	#endif
		else if ( !strcmp( *argv, "--use-ssl" ) ) 
			values.ssl = 1;
		else if ( !strcmp( *argv, "-l" ) || !strcmp( *argv, "--libs" ) ) {
			argv++;
			if ( !*argv ) {
				eprintf( "Expected argument for --libs!" );
				return 0;
			}
			values.libdir = *argv;
		}
		else if ( !strcmp( *argv, "-c" ) || !strcmp( *argv, "--config" ) ) {
			argv++;
			if ( !*argv ) {
				eprintf( "Expected argument for --config!" );
				return 0;
			}
			values.config = *argv;
		}
		else if ( !strcmp( *argv, "--pidfile" ) ) {
			argv++;
			if ( !*argv ) {
				eprintf( "Expected argument for --port!" );
				return 0;
			}
			values.pidfile = *argv;
		}
		else if ( !strcmp( *argv, "-p" ) || !strcmp( *argv, "--port" ) ) {
			argv++;
			if ( !*argv ) {
				eprintf( "Expected argument for --port!" );
				return 0;
			}
			//TODO: This should be safeatoi 
			values.port = atoi( *argv );
		}
		else if ( !strcmp( *argv, "-g" ) || !strcmp( *argv, "--group" ) ) {
			argv++;
			if ( !*argv ) {
				eprintf( "Expected argument for --group!" );
				return 0;
			} 
			values.group = strdup( *argv );
		}
		else if ( !strcmp( *argv, "-u" ) || !strcmp( *argv, "--user" ) ) {
			argv++;
			if ( !*argv ) {
				eprintf( "Expected argument for --user!" );
				return 0;
			} 
			values.user = strdup( *argv );
		}
		argv++;
	}

	//Register SIGINT
	signal( SIGINT, sigkill );

	//Set all of the socket stuff
	if ( !values.port ) {
		values.port = defport;
	}

	//Set a default user and group
	if ( !values.user ) {
		values.user = getpwuid( getuid() )->pw_name;
		values.uid = getuid();
	}

	if ( !values.group ) {
		//values.group = getpwuid( getuid() )->pw_gid ;
		values.gid = getgid();
		values.group = getpwuid( values.gid )->pw_name ;
	}

	//Pull in a configuration
	if ( !values.config ) {
		eprintf( "No configuration specified." );
		return 1;
	}

	//Open the libraries (in addition to stuff)
	if ( !values.libdir ) {
		values.libdir = LIBDIR;
	}

	//Set pid file
	if ( !values.pidfile ) {
		struct timespec t;
		clock_gettime( CLOCK_REALTIME, &t );
		unsigned long time = t.tv_nsec % 3333;
		snprintf( pidbuf, sizeof( pidbuf ) - 1, "%s/%s-%ld", PIDDIR, NAME, time );
		values.pidfile = pidbuf;
	}

	//Load shared libraries
	if ( !cmd_libs( &values, err, sizeof( err ) ) ) {
		eprintf( "%s", err );
		return 1;
	}

	//Dump the configuration if necessary
	if ( values.dump ) {
		cmd_dump( &values, err, sizeof( err ) );		
	}

	//Start a server
	if ( values.start ) {
	#if 0
		if ( values.fork ) {
			//start a fork...
		}
	#endif
		if ( !cmd_server( &values, err, sizeof(err) ) ) {
			eprintf( "%s", err );
			return 1;
		}
	}

	if ( values.kill ) {
		eprintf ( "%s\n", "--kill not yet implemented." );
		return 1;
	}

	return 0;
}

