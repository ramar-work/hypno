/* ------------------------------------------- * 
 * zjson.c 
 * =======
 * 
 * Summary 
 * -------
 * JSON deserialization / serialization 
 *
 * LICENSE
 * -------
 * Copyright 2020 Tubular Modular Inc. dba Collins Design
 * 
 * See LICENSE in the top-level directory for more information.
 *
 * CHANGELOG 
 * ---------
 * No entries yet.
 *
 * TESTING
 * -------
 * TBD, but the tests will be shipping with
 * the code in the very near future.
 *
 * ------------------------------------------- */
#include "zjson.h"

#define ZJSON_MAX_KEY_LENGTH 256

#define ZJSON_MAX_VALUE_LENGTH 256

#ifndef DEBUG_H
 #define ZJSON_PRINTF(...)
#else
 #define ZJSON_PRINTF(...) \
		fprintf( stderr, "[%s:%d] ", __FILE__, __LINE__ ) && fprintf( stderr, __VA_ARGS__ )
#endif

struct zjd { int inText, isObject, isVal, index; }; 

//Trim any characters 
unsigned char *zjson_trim ( unsigned char *msg, char *trim, int msglen, int *nlen ) {
	//Define stuff
	unsigned char *m = msg, *u = &msg[ msglen ];
	int nl = msglen, sl = strlen( trim );

	//Adjust for end delimiter
	if ( *u == '\0' && !memchr( trim, '\0', sl ) ) {
		u--, nl--;
	}

	//Adjust for empty strings
	if ( !msg || msglen == 0 ) {
		*nlen = 0;
		return m;
	}

	//Adjust for small strings
	if ( msglen == 1 ) {
		*nlen = 1;
		return m;
	}

	//Move backwards
	for ( int s = 0, e = 0; !s || !e; ) {
//ZJSON_PRINTF( "%c -> %c\n", *m, *u );
		if ( !s ) {
			if ( !memchr( trim, *m, sl ) )
				s = 1;
			else {
				nl--, m++;
			}
		}

		if ( !e ) {
			if ( !memchr( trim, *u, sl ) )
				e = 1;
			else {
				nl--, u--;
			}
		}
	}

	*nlen = nl;
	return m;
}

#if 0
//Test for zjson_trim( ... )
int main (int argc, char *argv[]) {
const char *abcd[] = {
	"asfasdfasdfb ;;;",
	"   asfasdfasdfb ;;  >>",
	"asfasdfasdfb ;!;     \t",
	"bacon",
	"",
	NULL
};

for ( const char **a = abcd; *a; a++ ) {
	int l = 0;
	unsigned char * z = zjson_trim( (unsigned char *)*a, " >;\t", strlen( *a ), &l );
	write( 2, "'", 1 );
	write( 2, z, l );
	write( 2, "'", 1 );
	ZJSON_PRINTF( "%d\n", l );
}
return 0;
}
#endif



//Get an approximation of the number of keys needed
static int zjson_count ( unsigned char *src, int len ) {
	int sz = 0;

	//You can somewhat gauge the size needed by looking for all commas
	for ( int c = len; c; c-- ) {
		sz += ( memchr( "{[,]}", *src,  5 ) ) ? 1 : 0, src++;
	}
	return sz;
}


/**
 * int zjson_validate ( const char *str )a
 *
 * Simply check if a JSON string is a valid object.
 * (Notice, that we are handling this in a very
 * dogmatic way.  This library expects to deal with
 * JSON *objects* strictly.)
 *
 */
int zjson_validate ( const char *str ) {
	return ( *str == '{' || *str == '['	);
}

/**
 * int zjson_check ( const char *str )
 *
 * Check and make sure it's "balanced"
 *
 */
int zjson_check ( const char *str, int len, char *err, int errlen ) {
	int os=0, oe=0, as=0, ae=0;
	for ( int a=0; len; str++, len-- ) {
		//In a string
#if 1
		if ( *str == '"' ) {
			a = !a;
			continue;
		}

		if ( !a ) {
#else
		if ( *str != '"' && ( a = !a ) ) {
#endif
			if ( *str == '{' )
				os++;
			else if ( *str == '[' )
				as++;
			else if ( *str == '}' )
				oe++;
			else if ( *str == ']' ) {
				ae++;
			}
		}
	}

	return ( os == oe && as == ae );
}


#if 1
/**
 * zjson_decode( const char *str, int len, char *err, int errlen )
 *
 * Decodes JSON strings and turns them into a "table".
 *
 */
ztable_t * zjson_decode ( const char *str, int len, char *err, int errlen ) {
	const char tokens[] = "\"{[}]:,\\"; // this should catch the backslash
	unsigned char *b = NULL;
	zWalker w = {0};
	ztable_t *t = NULL;
	struct zjd zjdset[ ZJSON_MAX_DEPTH ], *d = zjdset;
	memset( zjdset, 0, ZJSON_MAX_DEPTH * sizeof( struct zjd ) );
	struct bot { char *key; unsigned char *val; int size; } bot;

	int size = zjson_count( (unsigned char *)str, len );
	if ( size < 1 ) {
		snprintf( err, errlen, "%s", "Got invalid JSON count." );
		return NULL;
	}

	ZJSON_PRINTF( "Got JSON block consisting of roughly %d values\n", size );

	//Return ztable_t
	if ( !( t = lt_make( size * 2 ) ) ) {
		snprintf( err, errlen, "%s", "Create table failed." );
		return NULL;
	}

	ZJSON_PRINTF( "Creating a table capable of holding %d values\n", size * 2 );

	//Walk through everything
	for ( int i = 0; memwalk( &w, (unsigned char *)str, (unsigned char *)tokens, len, strlen( tokens ) ); ) {
		char *srcbuf, *copybuf, statbuf[ ZJSON_MAX_STATIC_LENGTH ] = { 0 };
		int blen = 0;
#if 1
fprintf( stderr, "%c - %p - %d\n", w.chr, w.src, w.size );
//write( 2, w.src, w.size );write( 2, "\n", 1 );
getchar();
#endif

		if ( w.chr == '"' && !( d->inText = !d->inText ) ) { 
			//Rewind until we find the beginning '"'
			unsigned char *val = w.src;
			int size = w.size - 1, mallocd = 0;
			for ( ; *val != '"'; --val, ++size ) ;
			srcbuf = ( char * )zjson_trim( val, "\" \t\n\r", size, &blen );

			if ( ++blen < ZJSON_MAX_STATIC_LENGTH )
				memcpy( statbuf, srcbuf, blen ), copybuf = statbuf; 
			else {
			#if 0
				snprintf( err, errlen, "%s", "zjson max length is too large." );
				return NULL;
			#else
				if ( !( copybuf = malloc( blen + 1 ) ) ) {
					snprintf( err, errlen, "%s", "zjson out of memory." );
					return NULL;
				}
				memset( copybuf, 0, blen + 1 );
				memcpy( copybuf, srcbuf, blen );
				mallocd = 1;
			#endif
			}
	
			if ( !d->isObject ) {
				lt_addintkey( t, d->index ), lt_addtextvalue( t, copybuf ), lt_finalize( t );
				d->inText = 0, d->isVal = 0;
			}
			else {
				if ( !d->isVal ) {
					ZJSON_PRINTF( "Adding text key: %s\n", copybuf );
					lt_addtextkey( t, copybuf ), d->inText = 0; //, d->isVal = 1;
				}
				else {
					//ZJSON_PRINTF( "blen: %d\n", blen );
					//ZJSON_PRINTF( "ptr: %p\n", copybuf );
					//ZJSON_PRINTF( "Adding text value: %s\n", copybuf );
					ZJSON_PRINTF( "Adding text value: %s\n", copybuf );
					lt_addtextvalue( t, copybuf ), lt_finalize( t );
					ZJSON_PRINTF( "Finalizing.\n" );
					d->isVal = 0, d->inText = 0;
					( mallocd ) ? free( copybuf ) : 0;
				}		 
			}
			continue;
		}

		if ( !d->inText ) {
			if ( w.chr == '{' ) {
				//++i;
				if ( ++i > 1 ) {
					if ( !d->isObject ) {
						//ZJSON_PRINTF( "Adding int key: %d\n", d->index );
						lt_addintkey( t, d->index );
					}
					++d, d->isObject = 1, lt_descend( t );
				}
				else {
					d->isObject = 1;
				}
			}
			else if ( w.chr == '[' ) {
				if ( ++i > 1 ) {
					++d, d->isObject = 0, lt_descend( t );
				}
			}
			else if ( w.chr == '}' ) {
				if ( d->isVal ) {
					int mallocd = 0;
					//This should only run when values are null, t/f or numeric
					srcbuf = ( char * )zjson_trim( w.src, "\t\n\r ", w.size - 1, &blen );

					if ( blen < ZJSON_MAX_STATIC_LENGTH )
						memcpy( statbuf, srcbuf, blen ), copybuf = statbuf; 
					else {
					#if 0
						snprintf( err, errlen, "%s", "zjson max length is too large." );
						return NULL;
					#else
						if ( !( copybuf = malloc( blen + 1 ) ) ) {
							snprintf( err, errlen, "%s", "zjson out of memory." );
							return NULL;
						}
						memset( copybuf, 0, blen + 1 );
						memcpy( copybuf, srcbuf, blen );
						mallocd = 1;
					#endif
					}
					lt_addtextvalue( t, copybuf );
					lt_finalize( t );
					d->isVal = 0, d->inText = 0;
					if ( mallocd ) {
						free( copybuf );
					}
				}
				if ( --i > 0 ) {
					d->index = 0, d->inText = 0;
					--d, d->isVal = 0, lt_ascend( t );
				}
			}
			else if ( w.chr == ']' ) {
				if ( --i > 0 ) {
					d->index = 0, d->inText = 0;
					--d, d->isVal = 0, lt_ascend( t );
				}
			}
			else if ( w.chr == ',' || w.chr == ':' /*|| w.chr == '}'*/ ) {
				( w.chr == ',' && !d->isObject ) ? d->index++ : 0; 
				srcbuf = ( char * )zjson_trim( w.src, "\",: \t\n\r", w.size - 1, &blen );
				if ( blen >= ZJSON_MAX_STATIC_LENGTH ) {
					snprintf( err, errlen, "%s", "Key is too large." );
					//lt_free( t ), free( t );
					return NULL;
				}
				else if ( blen ) {
					memcpy( statbuf, srcbuf, blen + 1 );	
					if ( w.chr == ':' ) {
						ZJSON_PRINTF( "Adding text key: %s\n", statbuf );
						lt_addtextkey( t, statbuf );
					}
					else {
						ZJSON_PRINTF( "Adding text value: %s\n", statbuf );
						lt_addtextvalue( t, statbuf );
						lt_finalize( t );
					}
				}
				d->isVal = ( w.chr == ':' );
			}
		}
	}

	lt_lock( t );
	return t;
}
#endif


/**
 * zjson_check_syntax( const char *str, int len, int *newlen )
 *
 * Checks for syntax errors. 
 * 
 */
int zjson_check_syntax( const char *str, int len, char *err, int errlen ) { 
	//
	char tk, *start = NULL;
	int nlen = len, arr = 0, text = 0,  p = 0;

	//Die if the first non-whitespace character is not a valid JSON object token
	for ( char *s = (char *)str; nlen; s++, nlen-- ) {
		if ( memchr( " \r\t\n", *s, 4 ) ) {
			continue;
		}
	
		if ( ( tk = *s ) == '{' || tk == '[' ) {
			start = s;
			break;
		}
		else {	
			snprintf( err, errlen, "%s: %c\n", "Got invalid JSON object token at start", tk );
			return 0;	
		}
	}

	//We will also need to backtrack and make sure that we have properly closing pairs
	for ( char *s = (char *)&str[ len - 1 ]; ; s--, nlen-- ) {
		if ( memchr( " \r\t\n", *s, 4 ) ) {
			continue;
		}

		if ( ( tk == '{' && *s == '}' ) || ( tk == '[' && *s == ']' ) )
			break;
		else {	
			snprintf( err, errlen, "%s: %c\n", "Got invalid JSON object token at end", *s );
			return 0;	
		}
	}

	for ( char w = 0, *s = (char *)str; p < len; s++, p++ ) {
		if ( !text && memchr( "{}[]:", *s, 5 ) ) {
			//Check for invalid object or array closures
			//TODO: There MUST be a way to clean this up...
			if ( ( w == '{' && ( *s == ']' || *s == '[' ) ) ) {
				snprintf( err, errlen, "%s '%c' at position %d\n", "Got invalid JSON sequence", *s, p );
				return 0;	
			}

			if ( ( w == '[' && ( *s == '}' || *s == ':' ) ) ) {
				snprintf( err, errlen, "%s '%c' at position %d\n", "Got invalid JSON sequence", *s, p );
				return 0;	
			}

			//Do not increment if it's a ':'
			if ( ( w = *s ) != ':' ) {
				arr++;
			}
		}
		else if ( !text && *s == '\'' ) {
			snprintf( err, errlen, "%s '%c' at position %d\n", "JSON does not allow single quotes for strings", *s, p );
			return 0;	
		}
		else if ( !text && memchr( " \r\t\n", *s, 4 ) ) {
			continue;
		}
		else if ( *s == '"' && *( s - 1 ) != '\\' ) {
			arr++, text = !text;	
		}
	}

	//If it's divisible by 2, we're good... if not, we're not balanced
	if ( ( arr % 2 ) > 0 || text ) {
		snprintf( err, errlen, "%s\n", "Got unbalanced JSON object or unterminated string" );
		return 0;
	}
 
	return 1;	
}	


/**
 * zjson_compress( const char *str, int len, int *newlen )
 *
 * Creates a copy of JSON string with no spaces for easier 
 * parsing and less memory usage.  
 * 
 */
char * zjson_compress ( const char *str, int len, int *newlen ) {
	//Loop through the entire thing and "compress" it.
	char *cmp = NULL;
	int marked = 0;
	int cmplen = 0;

	//TODO: Replace with calloc() for brevity
	if ( !( cmp = malloc( len ) ) ) {
		return NULL;
	}

	memset( cmp, 0, len );

	//Move through, check for any other syntactical errors as well as removing whitespace
	for ( char *s = (char *)str, *x = cmp; *s && len; s++, len-- ) {
		//If there are any backslashes, we need to get the character immediately after
		if ( marked && ( *s == '\\' ) ) {
			fprintf( stderr, "Got a backslash\n" );
			//If the next character is any of these, copy it and move on
			if ( len > 1 ) {
				if ( memchr( "\"\\/bfnqt", *(s + 1), 8 ) ) {
					*x = *s, x++, cmplen++, s++;
					*x = *s, x++, cmplen++;
				}
			#if 0
				//TODO: Would really like Unicode point support, but it has to wait
				else if ( len > 4 && *(s + 1) == 'u' || *(s + 1) == 'U' ) {
					memcpy(  
					x += 5;
				} 
			#endif
			}
			//If there is a 3rd backslash with no character behind it, then just skip it.
			continue;
		}
		//If there is any text, mark it.
		else if ( *s == '"' ) { 
fprintf( stderr, "Got a quote\n" );
			marked = !marked;
		}
	#if 0
		//TODO: I want to reject single quotes
		else if ( *s == '\'' ) {
fprintf( stderr, "Got a quote\n" );
		}
	#endif
		//If the character is whitespace, skip it
		if ( !marked && memchr( " \r\t\n", *s, 4 ) ) {
			continue;
		}
		*x = *s, x++, cmplen++;
	}

	cmp = realloc( cmp, cmplen + 1 );
	*newlen = cmplen + 1;
	return cmp;
}


/**
 * void *mjson_add_item_to_list
 * 	( void ***list, void *element, int size, int * len )
 *
 * Adds a struct mjson to a dynamically sized list.
 * 
 */
void * mjson_add_item_to_list( void ***list, void *element, int size, int * len ) {
	//Reallocate
	if (( (*list) = realloc( (*list), size * ( (*len) + 2 ) )) == NULL ) {
		return NULL;
	}

	(*list)[ *len ] = element; 
	(*list)[ (*len) + 1 ] = NULL; 
	(*len) += 1; 
	return list;
}


/**
 * create_mjson ( const char *str, int len, char *err, int errlen )
 *
 * Creates and initializes a 'struct mjson'
 *
 * 
 */
#if 1
struct mjson * create_mjson () {
#else
struct mjson * create_mjson ( char type, unsigned char *val, int size ) {
	struct mjson *m = NULL; 

	if ( !( m = malloc( sizeof ( struct mjson ) ) ) ) {
		return NULL;
	}

	memset( m, 0, sizeof( struct mjson ) );
	m->type = type;
	m->value = val;
	m->size = size;
	m->index = 0;
#endif
	struct mjson *m = malloc( sizeof ( struct mjson ) );
	memset( m, 0, sizeof( struct mjson ) );
	return m;
}


/**
 * void zjson_dump_item ( struct mjson *mjson )
 *
 * Converts serialized JSON into a ztable_t
 * 
 */
void zjson_dump_item ( struct mjson *m ) {
	fprintf( stderr, "[ '%c', %d, ", m->type, m->index );
	if ( m->value && m->size ) {
		fprintf( stderr, "size: %d, ", m->size );
		write( 2, m->value, m->size );
	}
	write( 2, " ]\n", 3 );
}


/**
 * void zjson_dump( struct mjson ** )
 *
 * Dumps a list of 'struct mjson' structures
 *
 */
void zjson_dump ( struct mjson **mjson ) {
	//Dump out the list of what we found
	for ( struct mjson **v = mjson; v && *v; v++ ) {
	#if 1
		zjson_dump_item( *v );
	#else
		fprintf( stderr, "\n[ '%c', ", (*v)->type ); 
		if ( (*v)->value && (*v)->size ) {
			fprintf( stderr, "size: %d, ", (*v)->size );
			write( 2, (*v)->value, (*v)->size );
		}
		write( 2, " ]", 3 );
	#endif
	}
}

#if 0
/**
 * zjson_ptr_play( struct mjson **mjson )
 *
 * Demonstrates how to move pointers around, should I forget.
 *
 */
void zjson_ptr_play ( struct mjson **mjson ) {
	//Should you forget how to increment/decrement pointers...
	*p = mjson[ 0 ];
	fprintf( stderr, "%c %p\n", (*p)->type, (*p)->value );

	p++;
	*p = mjson[ 2 ];

	fprintf( stderr, "%c %p\n", (*p)->type, (*p)->value );
	p--;

	fprintf( stderr, "%c %p\n", (*p)->type, (*p)->value );
	return NULL;
}
#endif


/**
 * zjson_stringify( struct mjson **mjson, char *err, int errlen )
 *
 * Create a "compressed" JSON string out of a list of 'struct mjson'.
 *
 */
char * zjson_stringify( struct mjson **mjson, char *err, int errlen ) {
	return NULL;
}


/**
 * zjson_decode2( const char *str, int len, char *err, int errlen )
 *
 * Decodes JSON strings and turns them into something different.
 *
 */
struct mjson ** zjson_decode2 ( const char *str, int len, char *err, int errlen ) {
	const char tokens[] = "\"{[}]:,"; // this should catch the backslash
	struct mjson **mjson = NULL, *c = NULL, *d = NULL;
	int mjson_len = 0;
	zWalker w = {0};

	//Before we start, the parent must be set as the first item...
	struct mjson *m = create_mjson();
	m->type = *str;
	m->value = (unsigned char *)str;
	m->size = 0; // Carry the length of the string here...
	mjson_add_item( &mjson, m, struct mjson, &mjson_len );	
	str++;

	//Walk through it and deserialize
	for ( int text = 0, esc = 0, size = 0; strwalk( &w, str, tokens ); ) {
		//fprintf( stderr, "CHR: Got '%c' ", w.chr ); getchar();

		if ( text ) {
			if ( w.chr == '"' ) {
				//fprintf( stderr, "got end of text, finalizing\n" );
				//Check the preceding char, and see if it's a backslash.
				text = *( w.rptr - 1 ) == '\\';
#if 0
fprintf( stderr, "closing quote reached, got '%c', '%c', '%c' is escaped: %s\n", 
*( w.ptr ),
*( w.rptr - 1 ),
( w.chr ),
text ? "Y" : "N" );
#endif
				size += w.size;
				c->size = size; //Need to add the total size of whatever it may be.
				continue;
			}
			else {
				size += w.size;
				continue;
			}
		}

		if ( w.chr == '"' ) {
			text = 1;
			size = -1;
			//fprintf( stderr, "type: %c, tab: %d, size: %d\n", 'S', ind, size );
		#if 1
			struct mjson *m = create_mjson();
			m->type = 'S', m->value = w.ptr, m->size = 0;
		#else
			struct mjson *m = create_mjson( 'S', w.ptr, 0 );
		#endif
			c = m;
		}
		else if ( w.chr == '{' || w.chr == '[' ) {
			//fprintf( stderr, "type: %c, tab: %d\n", '{', ++ind );
		#if 1
			struct mjson *m = create_mjson();
			m->type = w.chr, m->value = NULL, m->size = 0;
		#else
			struct mjson *m = create_mjson( w.chr, NULL, 0 );
		#endif
			mjson_add_item( &mjson, m, struct mjson, &mjson_len );	
		}
		else {
			// }, ], :, ,
	#if 0
		fprintf( stderr, "CHR: Got '%c' ", w.chr );
		fprintf( stderr, "Sequence looks like: " );
		write( 2, "'", 1 ),	write( 2, w.ptr - 128, w.size + 128 ), write( 2, "'\n", 2 );
	#endif
			if ( c ) {
			#if 0
				fprintf( stderr, "Got saved word." );
				write( 2, "'", 1 ),	write( 2, c->value, c->size ), write( 2, "'\n", 2 );
			#endif
				mjson_add_item( &mjson, c, struct mjson, &mjson_len );	
				c = NULL;
			}

			//We may not need this after all	
		#if 1
			//Instead of readahead, read backward	& see if we find text
			int len = 0;
			unsigned char *p = w.ptr - 2;
			for ( ; ; p-- ) {
				if ( memchr( "{}[]:,'\"", *p, 8 ) ) {
					break;
				}
				else {
					len += 1;
				}
			}
		#endif

			if ( len ) {
			#if 0
				fprintf( stderr, "NUM: %d vs LEN: %d\n", numeric, len );
			#endif
			#if 0
				write( 2, "'", 1 ), write( 2, p + 1, len ), write( 2, "'", 1 );
				getchar();
			#endif
				//Make a new struct mjson and mark the pointer top
			#if 1
				struct mjson *m = create_mjson();
				m->value = p + 1, m->size = len, m->type = 'V';
			#else
				struct mjson *m = create_mjson( 'V', p + 1, len );
			#endif
				mjson_add_item( &mjson, m, struct mjson, &mjson_len );	
			}

			//Always save whatever character it might be
			if ( w.chr != ':' && w.chr != ',' ) {
			#if 1
				struct mjson *m = create_mjson();
				m->value = NULL, m->size = 0, m->type = w.chr; 
			#else
				struct mjson *m = create_mjson( w.chr, NULL, 0 );
			#endif
				mjson_add_item( &mjson, m, struct mjson, &mjson_len );	
			}
		}
	}

	//Terminate the last entry
	( mjson[ mjson_len - 1 ] )->index = -1;
	return mjson;
}


/**
 * zjson_free( struct mjson **mjson )
 *
 * Free a list of 'struct mjson'.
 * 
 */
void zjson_free ( struct mjson **mjson ) {
	free( (*mjson)->value );
	for ( struct mjson **v = mjson; v && *v; v++ ) {
		free( *v );
	}
	free( mjson );
}


/**
 * zjson_get_count( struct mjson **mjson )
 *
 * Get a count of entries in an 'struct mjson' list.
 * 
 */
static int zjson_get_count ( struct mjson **mjson ) {
	int count = 0;
	for ( struct mjson **v = mjson; v && *v; v++ ) {
		count++;
	}
	return count;
}


/**
 * zjson_to_ztable( struct mjson **mjson, void *null, char *err, int errlen )
 *
 * Converts serialized JSON into a ztable_t
 * 
 */
ztable_t * zjson_to_ztable ( struct mjson **mjson, void *null, char *err, int errlen ) {
	ztable_t *t = NULL;
	struct mjson *ptr[100] = { NULL }, **p = ptr;

	if ( !( t = lt_make( zjson_get_count( mjson ) * 2 ) ) ) {
		snprintf( err, errlen, "Failed to allocate space for ztable_t.\n" );
		return NULL;
	}

	//Use a static list of mjsons to keep track of which objects we're in
	*p = *mjson;

	for ( struct mjson **v = ++mjson; v && *v && ((*v)->index > -1 ); v++ ) {
		zjson_dump_item( *v );
		if ( (*v)->type == '{' || (*v)->type == '[' ) {
//fprintf( stderr, "%s - %c - ", "DESCENDING", (*v)->type == '{' ? 'A' : 'N' );
			//If the immediate member before is a [, then you need to add a key before descending
			if ( (*p)->type == '[' ) {
//fprintf( stderr, "Current (*p) is: %c - ", (*p)->type ), fprintf( stderr, "adding key (%d)\n", (*p)->index );
				lt_addintkey( t, (*p)->index );
				(*p)->index++;
			}
//fprintf( stderr, "\n" );
			lt_descend( t ), ++p, *p = *v;
		}
		else if ( (*v)->type == '}' || (*v)->type == ']' ) {
//fprintf( stderr, "%s - %c - ", "ASCENDING", (*v)->type == '{' ? 'A' : 'N' ), fprintf( stderr, "\n" );
			lt_ascend( t ), --p;
			//If the parent is 1, you need to reset it here, since this is most likely the value
			if ( ( (*p)->type == '{' ) && ( (*p)->index == 1 ) ) {
				(*p)->index = 0;
			}
		}
		else if ( (*v)->type == 'S' || (*v)->type == 'V' ) {
			// Put the value in a temporary buffer
			char *val = malloc( (*v)->size + 1 );
			memset( val, 0, (*v)->size + 1 );
		#if 0
			memcpy( val, (*v)->value, (*v)->size );
		#else	
			//Do not copy back slashes.
			if ( !memchr( (*v)->value, '\\', (*v)->size ) )
				memcpy( val, (*v)->value, (*v)->size );
			else {
				char *x = (char *)(*v)->value, *y = val;
				for ( int vsize = (*v)->size; vsize; vsize--, x++ ) {
					if ( *x == '\\' ) {
						continue;
					}
					*y = *x, y++;
				}
			}
		#endif

//fprintf( stderr, "Current (*p) is: %c - ", (*p)->type );
			if ( (*p)->type == '[' ) {
//fprintf( stderr, "adding key value pair (%d => '%s')\n", (*p)->index, val );
				lt_addintkey( t, (*p)->index );
				lt_addtextvalue( t, val );
				lt_finalize( t );
				(*p)->index++;
			}
			else if ( (*p)->type == '{' ) {
				if ( ( (*p)->index = !(*p)->index ) ) {
//fprintf( stderr, "adding key ('%s')\n", val );
					lt_addtextkey( t, val );
				}
				else {
//fprintf( stderr, "adding value ('%s') and finalizing\n", val );
					lt_addtextvalue( t, val );
					lt_finalize( t );
				}
			}
			free( val );
		}
	}
	return t;
}


/**
 * ztable_to_zjson ( ztable_t *t, char *err, int errlen )
 *
 * Converts from ztable_t to regular JSON structure.
 * 
 */
struct mjson ** ztable_to_zjson ( ztable_t *t, char *err, int errlen ) {
	//The first item in the table can be the source pointer.
	//It can work with both decoding and encoding if you are careful with where to
	//drop the reference.


#if 0
	//Define more
	struct ww {
		struct ww *ptr;
		int type, keysize, valsize;
		char *comma, *key, *val, vint[ 64 ];
	} **ptr, *ff, *rr, *br = NULL, *sr[ 1024 ] = { NULL };
	unsigned int tcount = 0, size = 0, jl = 0, jp = 0;
	char * json = NULL;
	const char emptystring[] = "''";

	if ( !t ) {
		snprintf( err, errlen, "Table for JSON conversion not initialized" );
		return NULL;
	}

	if ( !( tcount = lt_countall( t ) ) ) {
		snprintf( err, errlen, "Could not get table count" );
		return NULL;
	}

	//Always allocate tcount + 1, b/c we start processing ahead of time.
	if ( ( size = ( tcount + 1 ) * sizeof( struct ww ) ) < 0 ) {
		snprintf( err, errlen, "Could not allocate source JSON" );
		return NULL;
	}

	//?
	if ( !( br = malloc( size ) ) || !memset( br, 0, size ) ) { 
		snprintf( err, errlen, "Could not allocate source JSON" );
		return NULL;
	}

	//Initialize the first element
	br->type = ZTABLE_TBL, br->val = "{", br->valsize = 1, br->comma = " ";

	//Then initialize our other pointers
	ff = br + 1, rr = br, ptr = sr;

	//Initialize JSON string
	if ( !( json = malloc( 16 ) ) || !memset( json, 0, 16 ) ) {
		snprintf( err, errlen, "Could not allocate source JSON" );
		free( br );
		return NULL;
	}

	//Initialize things
	lt_reset( t );

	//Loop through all values and copy
	for ( zKeyval *kv ; ( kv = lt_next( t ) ); ) {
		zhValue k = kv->key, v = kv->value;
		char kbuf[ 256 ] = { 0 }, vbuf[ 2048 ] = { 0 }, *vv = NULL;
		int lk = 0, lv = 0;
		ff->comma = " ", ff->type = v.type;

		if ( k.type == ZTABLE_NON ) 
			ff->key = NULL, ff->keysize = 0;
		else if ( k.type == ZTABLE_TXT )
			ff->key = k.v.vchar, ff->keysize = strlen( k.v.vchar );
		else if ( k.type == ZTABLE_BLB )
			ff->key = (char *)k.v.vblob.blob, ff->keysize = k.v.vblob.size;
		else if ( k.type == ZTABLE_INT ) {
			ff->key = NULL, ff->keysize = 0;
			if ( rr->type == ZTABLE_TBL && *rr->val == '{' ) {
				rr->val = "[", rr->valsize = 1;
			}
		}
		else if ( k.type == ZTABLE_TRM ) {
			ff->key = NULL, ff->keysize = 0;
			ff->val = ( *(*ptr)->val == '{' ) ? "}" : "]", ff->valsize = 1;
			rr->comma = " ", ff->comma = ",", ff->type = ZTABLE_TRM; 
			ff++, rr++;
			ptr--;
			continue;	
		}
		else {
			snprintf( err, errlen, "Got invalid key type: %s", lt_typename( k.type ) );
			free( br ), free( json );
			return NULL;	
		}

		//TODO: Add rules to replace " in blobs and text
		if ( v.type == ZTABLE_NUL )
			0;
		else if ( v.type == ZTABLE_NON )
			break; 
		else if ( v.type == ZTABLE_INT )
			ff->valsize = snprintf( ff->vint, 64, "%d", v.v.vint ), ff->val = ff->vint, ff->comma = ",";
		else if ( v.type == ZTABLE_FLT )
			ff->valsize = snprintf( ff->vint, 64, "%f", v.v.vfloat ), ff->val = ff->vint, ff->comma = ",";
		else if ( v.type == ZTABLE_TXT ) {
			if ( v.v.vchar ) 	
				ff->val = v.v.vchar, ff->valsize = strlen( v.v.vchar );
			else {
				ff->val = (char *)emptystring; 
				ff->valsize = 2; 
			}
			ff->comma = ",";
		}
		else if ( v.type == ZTABLE_BLB )
			ff->val = (char *)v.v.vblob.blob, ff->valsize = v.v.vblob.size, ff->comma = ",";
		else if ( v.type == ZTABLE_TBL ) {
			ff->val = "{", ff->valsize = 1, ++ptr, *ptr = ff;	
		}
		else { /* ZTABLE_TRM || ZTABLE_NON || ZTABLE_USR */
			snprintf( err, errlen, "Got invalid value type: %s", lt_typename( v.type ) );
			free( br ), free( json );
			return NULL;
		}
		ff++, rr++;
	}

	//No longer null, b/c it exists...
	ff->keysize = -1;

	//TODO: There is a way to do this that DOES NOT need a second loop...
	for ( struct ww *yy = br; yy->keysize > -1; yy++ ) {
		char kbuf[ ZJSON_MAX_STATIC_LENGTH ] = {0}, vbuf[ 2048 ] = {0}, *v = vbuf, vmallocd = 0;
		int lk = 0, lv = 0;

		if ( yy->keysize ) {
			char *k = kbuf;
			// Stop on keys that are just too big...
			if ( yy->keysize >= ZJSON_MAX_STATIC_LENGTH ) {
				snprintf( err, errlen, "Key too large" );
				free( br ), free( json );
				return NULL;
			}

			if ( yy->type != ZTABLE_TRM ) {
				memcpy( k, "\"", 1 ), k++, lk++;
				memcpy( k, yy->key, yy->keysize ), k += yy->keysize, lk += yy->keysize;
				memcpy( k, "\": ", 3 ), k += 3, lk += 3;
			}
		}

		if ( yy->valsize ) {
			char *p = v; 

			// Values can be quite long when encoding
			if ( yy->valsize > ZJSON_MAX_STATIC_LENGTH ) {
				if ( !( p = v = malloc( yy->valsize + 3 ) ) ) {
					snprintf( err, errlen, "Could not claim memory for JSON value." );
					free( br ), free( json );
					return NULL;
				}
				vmallocd = 1;
			}

			memset( p, 0, yy->valsize );
			if ( yy->type == ZTABLE_TBL )
				memcpy( p, yy->val, yy->valsize ), p += yy->valsize, lv += yy->valsize;
			else if ( yy->type == ZTABLE_INT || yy->type == ZTABLE_FLT ) {
				memcpy( p, yy->vint, yy->valsize ), p += yy->valsize, lv += yy->valsize;
				memcpy( p, yy->comma, 1 ), p += 1, lv += 1;
			}
			else if ( yy->type == ZTABLE_TRM ) {
				memcpy( p, yy->val, yy->valsize ), p += yy->valsize, lv += yy->valsize;
				memcpy( p, yy->comma, 1 ), p += 1, lv += 1;
			}
			else {
				memcpy( p, "\"", 1 ), p++, lv++;
				memcpy( p, yy->val, yy->valsize ), p += yy->valsize, lv += yy->valsize;
				memcpy( p, "\"", 1 ), p += 1, lv += 1;
				memcpy( p, yy->comma, 1 ), p += 1, lv += 1;
			}
		}

		//Allocate and re-copy, starting with upping the total size
		jl += ( lk + lv );
		if ( !( json = realloc( json, jl ) ) ) {
			snprintf( err, errlen, "Could not re-allocate source JSON" );
			free( br ), free( json );
			return NULL;
		}

		//Copy stuff (don't try to initialize)
		memcpy( &json[ jp ], kbuf, lk ), jp += lk;
		memcpy( &json[ jp ], v, lv ), jp += lv;
		( vmallocd ) ? free( v ) : 0;
	}

	//This is kind of ugly
	if ( !( json = realloc ( json, jp + 3 ) ) ) {
		snprintf( err, errlen, "Could not re-allocate source JSON" );
		free( br ), free( json );
		return NULL;
	}

	json[ jp - 1 ] = ' '; 
	json[ jp     ] = ( *json == '[' ) ? ']' : '}'; 
	json[ jp + 1 ] = '\0';
	free( br );
	return json;
#endif
	return NULL;
}


/**
 * zjson_encode( ztable_t *t, char *err, int errlen )
 *
 * Converts from ztable_t to JSON string.
 * 
 */
char * zjson_encode ( ztable_t *t, char *err, int errlen ) {
	//Define more
	struct ww {
		struct ww *ptr;
		int type, keysize, valsize;
		char *comma, *key, *val, vint[ 64 ];
	} **ptr, *ff, *rr, *br = NULL, *sr[ 1024 ] = { NULL };
	unsigned int tcount = 0, size = 0, jl = 0, jp = 0;
	char * json = NULL;
	const char emptystring[] = "''";

	if ( !t ) {
		snprintf( err, errlen, "Table for JSON conversion not initialized" );
		return NULL;
	}

	if ( !( tcount = lt_countall( t ) ) ) {
		snprintf( err, errlen, "Could not get table count" );
		return NULL;
	}

	//Always allocate tcount + 1, b/c we start processing ahead of time.
	if ( ( size = ( tcount + 1 ) * sizeof( struct ww ) ) < 0 ) {
		snprintf( err, errlen, "Could not allocate source JSON" );
		return NULL;
	}

	//?
	if ( !( br = malloc( size ) ) || !memset( br, 0, size ) ) { 
		snprintf( err, errlen, "Could not allocate source JSON" );
		return NULL;
	}

	//Initialize the first element
	br->type = ZTABLE_TBL, br->val = "{", br->valsize = 1, br->comma = " ";

	//Then initialize our other pointers
	ff = br + 1, rr = br, ptr = sr;

	//Initialize JSON string
	if ( !( json = malloc( 16 ) ) || !memset( json, 0, 16 ) ) {
		snprintf( err, errlen, "Could not allocate source JSON" );
		free( br );
		return NULL;
	}

	//Initialize things
	lt_reset( t );

	//Loop through all values and copy
	for ( zKeyval *kv ; ( kv = lt_next( t ) ); ) {
		zhValue k = kv->key, v = kv->value;
		char kbuf[ 256 ] = { 0 }, vbuf[ 2048 ] = { 0 }, *vv = NULL;
		int lk = 0, lv = 0;
		ff->comma = " ", ff->type = v.type;

		if ( k.type == ZTABLE_NON ) 
			ff->key = NULL, ff->keysize = 0;
		else if ( k.type == ZTABLE_TXT )
			ff->key = k.v.vchar, ff->keysize = strlen( k.v.vchar );
		else if ( k.type == ZTABLE_BLB )
			ff->key = (char *)k.v.vblob.blob, ff->keysize = k.v.vblob.size;
		else if ( k.type == ZTABLE_INT ) {
			ff->key = NULL, ff->keysize = 0;
			if ( rr->type == ZTABLE_TBL && *rr->val == '{' ) {
				rr->val = "[", rr->valsize = 1;
			}
		}
		else if ( k.type == ZTABLE_TRM ) {
			ff->key = NULL, ff->keysize = 0;
			ff->val = ( *(*ptr)->val == '{' ) ? "}" : "]", ff->valsize = 1;
			rr->comma = " ", ff->comma = ",", ff->type = ZTABLE_TRM; 
			ff++, rr++;
			ptr--;
			continue;	
		}
		else {
			snprintf( err, errlen, "Got invalid key type: %s", lt_typename( k.type ) );
			free( br ), free( json );
			return NULL;	
		}

		//TODO: Add rules to replace " in blobs and text
		if ( v.type == ZTABLE_NUL )
			0;
		else if ( v.type == ZTABLE_NON )
			break; 
		else if ( v.type == ZTABLE_INT )
			ff->valsize = snprintf( ff->vint, 64, "%d", v.v.vint ), ff->val = ff->vint, ff->comma = ",";
		else if ( v.type == ZTABLE_FLT )
			ff->valsize = snprintf( ff->vint, 64, "%f", v.v.vfloat ), ff->val = ff->vint, ff->comma = ",";
		else if ( v.type == ZTABLE_TXT ) {
			if ( v.v.vchar ) 	
				ff->val = v.v.vchar, ff->valsize = strlen( v.v.vchar );
			else {
				ff->val = (char *)emptystring; 
				ff->valsize = 2; 
			}
			ff->comma = ",";
		}
		else if ( v.type == ZTABLE_BLB )
			ff->val = (char *)v.v.vblob.blob, ff->valsize = v.v.vblob.size, ff->comma = ",";
		else if ( v.type == ZTABLE_TBL ) {
			ff->val = "{", ff->valsize = 1, ++ptr, *ptr = ff;	
		}
		else { /* ZTABLE_TRM || ZTABLE_NON || ZTABLE_USR */
			snprintf( err, errlen, "Got invalid value type: %s", lt_typename( v.type ) );
			free( br ), free( json );
			return NULL;
		}
		ff++, rr++;
	}

	//No longer null, b/c it exists...
	ff->keysize = -1;

	//TODO: There is a way to do this that DOES NOT need a second loop...
	for ( struct ww *yy = br; yy->keysize > -1; yy++ ) {
		char kbuf[ ZJSON_MAX_STATIC_LENGTH ] = {0}, vbuf[ 2048 ] = {0}, *v = vbuf, vmallocd = 0;
		int lk = 0, lv = 0;

		if ( yy->keysize ) {
			char *k = kbuf;
			// Stop on keys that are just too big...
			if ( yy->keysize >= ZJSON_MAX_STATIC_LENGTH ) {
				snprintf( err, errlen, "Key too large" );
				free( br ), free( json );
				return NULL;
			}

			if ( yy->type != ZTABLE_TRM ) {
				memcpy( k, "\"", 1 ), k++, lk++;
				memcpy( k, yy->key, yy->keysize ), k += yy->keysize, lk += yy->keysize;
				memcpy( k, "\": ", 3 ), k += 3, lk += 3;
			}
		}

		if ( yy->valsize ) {
			char *p = v; 

			// Values can be quite long when encoding
			if ( yy->valsize > ZJSON_MAX_STATIC_LENGTH ) {
				if ( !( p = v = malloc( yy->valsize + 3 ) ) ) {
					snprintf( err, errlen, "Could not claim memory for JSON value." );
					free( br ), free( json );
					return NULL;
				}
				vmallocd = 1;
			}

			memset( p, 0, yy->valsize );
			if ( yy->type == ZTABLE_TBL )
				memcpy( p, yy->val, yy->valsize ), p += yy->valsize, lv += yy->valsize;
			else if ( yy->type == ZTABLE_INT || yy->type == ZTABLE_FLT ) {
				memcpy( p, yy->vint, yy->valsize ), p += yy->valsize, lv += yy->valsize;
				memcpy( p, yy->comma, 1 ), p += 1, lv += 1;
			}
			else if ( yy->type == ZTABLE_TRM ) {
				memcpy( p, yy->val, yy->valsize ), p += yy->valsize, lv += yy->valsize;
				memcpy( p, yy->comma, 1 ), p += 1, lv += 1;
			}
			else {
				memcpy( p, "\"", 1 ), p++, lv++;
				memcpy( p, yy->val, yy->valsize ), p += yy->valsize, lv += yy->valsize;
				memcpy( p, "\"", 1 ), p += 1, lv += 1;
				memcpy( p, yy->comma, 1 ), p += 1, lv += 1;
			}
		}

		//Allocate and re-copy, starting with upping the total size
		jl += ( lk + lv );
		if ( !( json = realloc( json, jl ) ) ) {
			snprintf( err, errlen, "Could not re-allocate source JSON" );
			free( br ), free( json );
			return NULL;
		}

		//Copy stuff (don't try to initialize)
		memcpy( &json[ jp ], kbuf, lk ), jp += lk;
		memcpy( &json[ jp ], v, lv ), jp += lv;
		( vmallocd ) ? free( v ) : 0;
	}

	//This is kind of ugly
	if ( !( json = realloc ( json, jp + 3 ) ) ) {
		snprintf( err, errlen, "Could not re-allocate source JSON" );
		free( br ), free( json );
		return NULL;
	}

	json[ jp - 1 ] = ' '; 
	json[ jp     ] = ( *json == '[' ) ? ']' : '}'; 
	json[ jp + 1 ] = '\0';
	free( br );
	return json;
}


#ifdef ZJSON_TEST

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <ztable.h>
#include <zwalker.h>

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
#include <math.h>

//TODO: Reject keys that aren't a certain type
void lua_dumpstack ( lua_State *L ) {
	const char spaces[] = /*"\t\t\t\t\t\t\t\t\t\t"*/"          ";
	const int top = lua_gettop( L );
	struct data { unsigned short count, index; } data[64], *dd = data;
	memset( data, 0, sizeof( data ) );
	dd->count = 1;

	//Return early if no values
	if ( ( dd->index = top ) == 0 ) {
		fprintf( stderr, "%s\n", "No values on stack." );
		return;
	}

	//Loop through all values on the stack
	for ( int it, depth=0, ix=0, index=top; index >= 1; ix++ ) {
		fprintf( stderr, "%s[%d:%d] ", &spaces[ 10 - depth ], index, ix );

		for ( int t = 0, count = dd->count; count > 0; count-- ) {
			if ( ( it = lua_type( L, index ) ) == LUA_TSTRING )
				fprintf( stderr, "(%s) %s", lua_typename( L, it ), lua_tostring( L, index ) );
			else if ( it == LUA_TFUNCTION )
				fprintf( stderr, "(%s) %d", lua_typename( L, it ), index );
			else if ( it == LUA_TNUMBER )
				fprintf( stderr, "(%s) %lld", lua_typename( L, it ), (long long)lua_tointeger( L, index ) );
			else if ( it == LUA_TBOOLEAN)
				fprintf( stderr, "(%s) %s", lua_typename( L, it ), lua_toboolean( L, index ) ? "T" : "F" );
			else if ( it == LUA_TTHREAD )
				fprintf( stderr, "(%s) %p", lua_typename( L, it ), lua_tothread( L, index ) );
			else if ( it == LUA_TLIGHTUSERDATA || it == LUA_TUSERDATA )
				fprintf( stderr, "(%s) %p", lua_typename( L, it ), lua_touserdata( L, index ) );
			else if ( it == LUA_TNIL || it == LUA_TNONE )
				fprintf( stderr, "(%s) %p", lua_typename( L, it ), lua_topointer( L, index ) );
			else if ( it == LUA_TTABLE ) {
				fprintf( stderr, "(%s) %p", lua_typename( L, it ), lua_topointer( L, index ) );
			}

			//Handle keys
			if ( count > 1 )
				index++, t = 1, dd->count -= 2, fprintf( stderr, " -> " );
			//Handle new tables
			else if ( it == LUA_TTABLE ) {
				lua_pushnil( L );
				if ( lua_next( L, index ) != 0 ) {
					++dd, ++depth; 
					dd->index = index, dd->count = 2, index = lua_gettop( L );
				}
			}
			//Handle situations in which a table is on the "other side"
			else if ( t ) {
				lua_pop( L, 1 );
				//TODO: This is quite gnarly... Maybe clarify a bit? 
				while ( depth && !lua_next( L, dd->index ) ) {
					( ( index = dd->index ) > top ) ? lua_pop( L, 1 ) : 0;
					--dd, --depth, fprintf( stderr, "\n%s}", &spaces[ 10 - depth ] );
				}
				( depth ) ? dd->count = 2, index = lua_gettop( L ) : 0;
			}
		}
		fprintf( stderr, "\n" );
		index--;
	}
}


/**
 * zjson_to_lua( struct mjson **mjson, void *null, char *err, int errlen )
 *
 * Converts serialized JSON into a ztable_t
 *
 * In any case, the first entry will ALWAYS be a table (or its not vaild JSON)
 * 
 */
int zjson_to_lua ( lua_State *L, struct mjson **mjson ) {
#if 0
	int count = 0;
	struct mjson *ptr[100] = { NULL };
	struct mjson **p = ptr;

	for ( struct mjson **v = mjson; v && *v; v++ ) {
		count++;
	}


	int i = 0, ecount = 0;
	for ( struct mjson **x = NULL, **v = mjson; v && *v; v++ ) {
		struct mjson *m = *v;
	#if 1
		fprintf( stderr, "\n[ '%c', ", (*v)->type );
		if ( (*v)->value && (*v)->size ) {
			fprintf( stderr, "size: %d, ", (*v)->size );
			write( 2, (*v)->value, (*v)->size );
		}
		write( 2, " ]", 3 );
	#endif
	#if 1
		// Make a new table
		if ( m->type == '{' || m->type == '[' ) {
			fprintf( stderr, "ptr = %p\n", p );
			// make an alpha table
			lua_newtable( L ), i++;
#if 1
			//fprintf( stderr, "\"parent\" element is: %c\n", (*( v - 1 ))->type );
			++p, *p = m;
			(*p)->ref = !ecount ? 0 : (*( v - 1 ))->type;
#endif
			//++p, *p = m;
		}

		// End a table
		else if ( m->type == ']' || m->type == '}' ) {
			fprintf( stderr, "ptr = %p\n", p );
			//fprintf( stderr, "wtf...%p, %p, '%c'\n", p, *p, (*p)->ref );
			if ( *p ) {
#if 1
				if ( (*p)->ref == 'S' || (*p)->ref == 'V' ) {
					i -= 2;
					lua_settable( L, i );
				}
#endif
			}
				--p;
		}

		// Add some kind of value
		else if ( m->type == 'S' || m->type == 'V' ) {

			// Put the value in a temporary buffer
			char *val = malloc( m->size + 1 );
			memset( val, 0, m->size + 1 );
			memcpy( val, m->value, m->size );
		
			// Check the value's type (is it a number, boolean, null or string)	
			#if 0
			#endif

		#if 1
			// Add values to a table.
			struct mjson *x = (*p);
			// For debugging
			fprintf( stderr, " - DEBUG (*p): %c %p\n", x->type, x->value );

			if ( x->type == '[' ) {
				//Add the number first, then add something else
				lua_pushnumber( L, ++x->index ), i++;
				lua_pushstring( L, val ), i++;
				i -= 2;
				lua_settable( L, i );
			}
			else if ( x->type == '{' ) {
				lua_pushstring( L, val ), i++;
				if ( ++x->index == 2 ) {
					i -= 2;
					lua_settable( L, i );
					x->index = 0;
				}
			}
		#endif
			// I think this is legal, b/c the library makes a copy
			free( val );
		}
		fprintf( stderr, "Current index is: %d, level index is: %d\n", i, (*p) ? (*p)->index : -1 );
		lua_dumpstack( L );
	#endif
	}
#endif
	return 0;
}

//Copy all records from a ztable_t to a Lua table at any point in the stack.
int ztable_to_lua ( lua_State *L, ztable_t *t ) {
	short ti[ 128 ] = { 0 }, *xi = ti; 

	//lt_kfdump( t, 1 );

	//Push a table and increase Lua's "save table" index
	lua_newtable( L );
	*ti = 1;

	//Reset table's index
	lt_reset( t );

	//Loop through all values and copy
	for ( zKeyval *kv ; ( kv = lt_next( t ) ); ) {
		zhValue k = kv->key, v = kv->value;
		if ( k.type == ZTABLE_NON )
			return 1;	
		//Arrays start at 1 in Lua, so increment by 1
		else if ( k.type == ZTABLE_INT ) {
			// FPRINTF( "Got integer key: %d - ", k.v.vint );
			lua_pushnumber( L, k.v.vint + 1 );				
		}
		else if ( k.type == ZTABLE_FLT ) {
			// FPRINTF( "Got double key: %f - ", k.v.vfloat );
			lua_pushnumber( L, k.v.vfloat );
		}				
		else if ( k.type == ZTABLE_TXT ) {
			// FPRINTF( "Got text key: %s - ", k.v.vchar );
			lua_pushstring( L, k.v.vchar );
		}
		else if ( k.type == ZTABLE_BLB) {
			// FPRINTF( "Got blob key: %d bytes long - ", k.v.vblob.size );
			lua_pushlstring( L, (char *)k.v.vblob.blob, k.v.vblob.size );
		}
		else if ( k.type == ZTABLE_TRM ) {
			lua_settable( L, *( --xi ) );
		}

		if ( v.type == ZTABLE_NUL )
			;
		else if ( v.type == ZTABLE_INT ) {
	//		FPRINTF( "Got integer value: %d\n", v.v.vint );
			lua_pushnumber( L, v.v.vint );	
		}			
		else if ( v.type == ZTABLE_FLT ) {
	//		FPRINTF( "Got double value: %f\n", v.v.vfloat );
			lua_pushnumber( L, v.v.vfloat );
		}				
		else if ( v.type == ZTABLE_TXT ) {
	//		FPRINTF( "Got text value: '%s'\n", v.v.vchar );
			lua_pushstring( L, v.v.vchar );
		}
		else if ( v.type == ZTABLE_BLB ) {
	//		FPRINTF( "Got blob value of size: %d\n", v.v.vblob.size );
			lua_pushlstring( L, (char *)v.v.vblob.blob, v.v.vblob.size );
		}
		else if ( v.type == ZTABLE_TBL ) {
			lua_newtable( L );
			*( ++xi ) = lua_gettop( L );
		}
		else /* ZTABLE_TRM || ZTABLE_NON || ZTABLE_USR */ {
		#if 1
			if ( v.type == ZTABLE_TRM )
				fprintf( stderr, "Got value of type: %s\n", "ZTABLE_TRM" );
			else if ( v.type == ZTABLE_NON )
				fprintf( stderr, "Got value of type: %s\n", "ZTABLE_NON" );
			else if ( v.type == ZTABLE_USR ) {
				fprintf( stderr, "Got value of type: %s\n", "ZTABLE_USR" );
			}
		#endif
			return 0;
		}

		if ( v.type != ZTABLE_NON && v.type != ZTABLE_TBL && v.type != ZTABLE_NUL ) {
		#if 0
			FPRINTF( "Setting table value to key => " );
			if ( k.type == ZTABLE_INT )
				FPRINTF( "%d\n", k.v.vint );
			else if ( k.type == ZTABLE_FLT )
				FPRINTF( "%f\n", k.v.vfloat );
			else if ( k.type == ZTABLE_TXT )
				FPRINTF( "'%s'\n", k.v.vchar );
			else if ( k.type == ZTABLE_BLB ) {
				FPRINTF( "(blob - %d bytes long)", k.v.vblob.size );
			}
		#endif
			lua_settable( L, *xi );
		}
	}
	return 1;
}


/**
 * int main(...)
 *
 * Simple command-line program using -decode and -encode flags to 
 * select a file and test decoding/encoding JSON.
 *
 */
int main (int argc, char *argv[]) {
	int encode = 0;
	int decode = 0;
	char *arg = NULL;

fprintf( stderr, "%ld\n", sizeof( struct mjson ) );
return 0;

	if ( argc < 2 ) {
		fprintf( stderr, "Not enough arguments..." );
		fprintf( stderr, "usage: ./zjson [ -decode, -encode ] <file>\n" );
		return 0;
	}

	argv++;
	for ( int ac = argc; *argv; argv++, argc-- ) {
		if ( strcmp( *argv, "-decode" ) == 0 ) {
			decode = 1;
			argv++;
			arg = *argv;
			break;
		}
		else if ( strcmp( *argv, "-encode" ) == 0 ) {
			encode = 1;
			argv++;
			arg = *argv;
			break;
		}
		else {
			fprintf( stderr, "Got invalid argument: %s\n", *argv );
			return 0;
		}
	}

	//Load the whole file if it's somewhat normally sized...
	struct stat sb = { 0 };
	if ( stat( arg, &sb ) == -1 ) {
		fprintf( stderr, "stat failed on: %s: %s\n", arg, strerror(errno) );
		return 0;
	}

	int fd = open( arg, O_RDONLY );
	if ( fd == -1 ) {
		fprintf( stderr, "open failed on: %s: %s\n", arg, strerror(errno) );
		return 0;
	}

	char *con = malloc( sb.st_size + 1 );
	memset( con, 0, sb.st_size + 1 );
	if ( read( fd, con, sb.st_size ) == -1 ) {
		fprintf( stderr, "read failed on: %s: %s\n", arg, strerror(errno) );
		return 0;
	}

	char err[ 1024 ] = {0};
	struct mjson **mjson = NULL; 

#if 0
	if ( !( mjson = zjson_decode_oneshot( con, sb.st_size, err, sizeof( err ) ) ) ) {
		fprintf( stderr, "Failed to decode JSON at zjson_decode_oneshot(): %s", err );
		return 0;
	}
#else
	// In lieu of a "oneshot" function, we'll need to define some more variables
	char *cmp = NULL;
	int cmplen = 0;

	// Dump the new string
	write( 2, "'", 1 ), write( 2, con, sb.st_size), write( 2, "'", 1 );

	// Check if the string is valid
	if ( !zjson_check_syntax( con, sb.st_size, err, sizeof( err ) ) ) {
		free( con );
		fprintf( stderr, "JSON string failed syntax check: %s\n", err );
		return 1;
	}

	// Compress the string first
	if ( !( cmp = zjson_compress( con, sb.st_size, &cmplen ) ) ) {
		free( con );
		fprintf( stderr, "Failed to compress JSON at zjson_compress(): %s", err );
		return 1;
	}

	// Dump the new string
	write( 2, "'", 1 ), write( 2, cmp, cmplen ), write( 2, "'", 1 );

	// Free the original string
	free( con );

	// Then decode the new string 
	if ( !( mjson = zjson_decode2( cmp, cmplen - 1, err, sizeof( err ) ) ) ) {
		fprintf( stderr, "Failed to deserialize JSON at json_decode(): %s", err );
		return 1;
	}
#endif

	// Dump the serialized JSON
	//zjson_dump( mjson );

#if 0
	// Trying using Lua directly to test...
	// Create an environment 
	lua_State *L = luaL_newstate();

	// Convert to a Lua table
	zjson_to_lua( L, mjson );

	// Use Lua dump stack to see what it looks like?
	lua_dumpstack( L );
#else
	// Make a ztable out of it
	ztable_t *t = zjson_to_ztable( mjson, NULL, err, sizeof( err ) ); 
	if ( !t ) {
		fprintf( stderr, "Failed to make table out of JSON at zjson_to_ztable(): %s", err );
		return 1;
	}

	// Dump the table (everything is duplicated)
	lt_kfdump( t, 2 );

	// And free it to reclaim resources
	lt_free( t ), free( t );
#endif

	// Free the JSON, then...
	zjson_free( mjson );

	// Free the source string
	// free( cmp );

	return 0;
}

#endif



