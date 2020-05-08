# This project...
NAME = hypno
OS = $(shell uname | sed 's/[_ ].*//')
LDFLAGS = -lgnutls -llua -ldl -lpthread
CLANGFLAGS = -g -O0 -Wall -Werror -std=c99 -Wno-unused -Wno-format-security -fsanitize=address -fsanitize-undefined-trap-on-error
GCCFLAGS = -g -Wall -Werror -Wno-unused -Wstrict-overflow -Wno-strict-aliasing -Wno-format-truncation -Wno-strict-overflow -std=c99 -Wno-deprecated-declarations -O2 #-DDEBUG_H
CFLAGS = $(CLANGFLAGS)
CFLAGS = $(GCCFLAGS)
CC = clang
CC = gcc
PREFIX = /usr/local
VERSION = 0.01
PORT = 2222
RANDOM_PORT = 1
PORT_FILE = /tmp/hypno.port
BROWSER = chromium
RECORDS = 3

# Some Linux systems need these, but pkg-config should handle it
#INCLUDE_DIR=-I/usr/include/lua5.3
#LD_DIRS=-L/usr/lib/x86_64-linux-gnu

# Not sure why these don't always work...
TESTS = config database http luabind render routes util server loader 
SRC = vendor/single.c vendor/sqlite3.c src/config.c src/hosts.c src/routes.c src/database.c src/http.c src/luabind.c src/mime.c src/render.c src/socket.c src/util.c src/luaext.c src/ctx-http.c src/ctx-https.c src/filter-static.c src/server.c src/loader.c #src/filter-echo.c src/filter-dirent.c src/filter-lua.c src/filter-c.c src/xml.c src/json.c src/dirent-filter.c
OBJ = ${SRC:.c=.o}

# main
main: $(OBJ)
	$(CC) $(LDFLAGS) $(CFLAGS) src/main.c -o $(NAME) $(OBJ) 
	$(CC) $(LDFLAGS) $(CFLAGS) src/cli.c -o hcli $(OBJ)

# Object
%.o: %.c 
ifeq ($(OS),CYGWIN)
	$(CC) -c -o $@ $< $(CFLAGS)
else
	$(CC) -c -o $@ $< $(CFLAGS)
endif

# A wildcard won't work, but an array might...
test: $(OBJ) 
test: CFLAGS+=-DTEST_H
test:
	-@test -d bin/ || mkdir bin/
	for t in $(TESTS); do $(CC) $(LDFLAGS) $(CFLAGS) -o bin/$$t src/$${t}-test.c $(OBJ); done

# Temporary target to kill runaway hypno sessions
kill:
	ps aux |grep hypno |awk '{print $$2}' | xargs kill -9

# Temporary target to start a server
#	valgrind --leak-check=full ./hypno --port $(PORT) --config ../hypno-www/config.lua --start
start:
	./hypno --port $(PORT) --config ../hypno-www/config.lua --start

# Generate some of the bigger vendor depedencies seperately
deps:
	$(CC) $(CFLAGS) -o vendor/single.o -c vendor/single.c 
	$(CC) $(CFLAGS) -o vendor/sqlite3.o -c vendor/sqlite3.c 

# Make an SSL Client
tlscli:
	$(CC) $(CFLAGS) -DSQROOGE_H -o cx vendor/single.c tlscli.c -lgnutls

# Make an SSL server that just runs forever... 
tlssvr:
	$(CC) $(CFLAGS) -DSQROOGE_H -o sx vendor/single.c tlssvr.c -lgnutls

# clean - Get rid of object files and tests 
clean:
	-@find src/ -maxdepth 1 -type f -name "*.o" | xargs rm
	-@find bin/ -maxdepth 1 -type f | xargs rm
	-@find -maxdepth 1 -type f -name "vgcore*" | xargs rm

# extra-clean - Get rid of yet more crap
extra-clean: clean
extra-clean:
	-@find . -type f -name "*.o" | xargs rm

# pkg - Make a package for distribution
pkg:
	git archive --format tar HEAD | gzip > $(NAME)-$(VERSION).tar.gz

# gitlog - Generate a full changelog from the commit history
gitlog:
	@printf "# CHANGELOG\n\n"
	@printf "## STATS\n\n"
	@printf -- "- Commit count: "
	@git log --full-history --oneline | wc -l
	@printf -- "- Project Inception "
	@git log --full-history | grep Date: | tail -n 1
	@printf -- "- Last Commit "
	@git log -n 1 | grep Date:
	@printf -- "- Authors:\n"
	@git log --full-history | grep Author: | sort | uniq | sed '{ s/Author: //; s/^/\t- /; }'
	@printf "\n"
	@printf "## HISTORY\n\n"
	@git log --full-history --author=Antonio | sed '{ s/^   /- /; }'
	@printf "\n<link rel=stylesheet href=changelog.css>\n"
