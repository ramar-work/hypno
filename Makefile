# This project...
NAME = hypno
OS = $(shell uname | sed 's/[_ ].*//')
LDFLAGS = -lgnutls -llua -ldl -lpthread -lsqlite3
CLANGFLAGS = -g -O0 -Wall -Werror -std=c99 -Wno-unused -Wno-format-security -fsanitize=address -fsanitize-undefined-trap-on-error
GCCFLAGS = -g -Wall -Werror -Wno-unused -Wstrict-overflow -Wno-strict-aliasing -Wno-format-truncation -Wno-strict-overflow -std=c99 -Wno-deprecated-declarations -Wno-return-local-addr -O2 -DSKIPMYSQL_H -DSKIPPGSQL_H #-DDEBUG_H
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
TESTS = config database filter http loader luabind render router server util
SRC = vendor/zrender.c vendor/zhasher.c vendor/zwalker.c src/config.c src/hosts.c src/db-sqlite.c src/http.c src/luabind.c src/mime.c src/socket.c src/util.c src/ctx-http.c src/ctx-https.c src/server.c src/loader.c src/mvc.c src/filter-static.c src/filter-lua.c src/router.c #src/filter-echo.c src/filter-dirent.c src/filter-c.c src/xml.c src/json.c src/dirent-filter.c
LIB = src/lua-db.c
OBJ = ${SRC:.c=.o}
LIBOBJ = ${LIB:.c=.o}

# main
main: $(OBJ)
	$(CC) $(LDFLAGS) $(CFLAGS) src/main.c -o $(NAME) $(OBJ) 
	$(CC) $(LDFLAGS) $(CFLAGS) src/cli.c -o hcli $(OBJ)

install:
	cp ./hypno ./hcli $(PREFIX)/bin/

# repl
#	test -f sqlite3.o || $(CC) $(CFLAGS) -fPIC -c vendor/sqlite3.c -o shared/sqlite3.o
repl:
	$(CC) $(CFLAGS) -fPIC -c src/database.c -o shared/database.o
	$(CC) $(CFLAGS) -fPIC -c vendor/zhasher.c -o shared/zhasher.o
	$(CC) $(CFLAGS) -fPIC -c src/luabind.c -o shared/luabind.o
	$(CC) $(CFLAGS) -fPIC -c src/lua-db.c -o shared/lua-db.o
	$(CC) -shared $(LDFLAGS) $(CFLAGS) -fPIC -o lib$(NAME).so shared/database.o shared/lua-db.o shared/zhasher.o shared/luabind.o
	lua -l libhypno - < tests/lua-db/dbtest.lua
 
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

# Test out hypno using embedded applications
test-www:
	./$(NAME) --port 2222 --config tests-www/config.lua --start

# Temporary target to kill runaway hypno sessions
kill:
	ps aux |grep hypno |awk '{print $$2}' | xargs kill -9

# Temporary target to start a server
start:
	./hypno --port $(PORT) --config ../hypno-www/config.lua --start

# Temporary target to start a server with Valgrind running
vstart:
	valgrind --leak-check=full ./hypno --port $(PORT) --config ../../site/hypno-www/config.lua --start

# Temporary target to start a server
tstart:
	./hypno --port $(PORT) --config ../../site/hypno-www/config.lua --start

# Generate some of the bigger vendor depedencies seperately
deps:
	$(CC) $(CFLAGS) -o vendor/single.o -c vendor/single.c 
	$(CC) $(CFLAGS) -o vendor/sqlite3.o -c vendor/sqlite3.c 

# clean - Get rid of object files and tests 
clean:
	-@find src/ -maxdepth 1 -type f -name "*.o" | xargs rm
	-@find bin/ -maxdepth 1 -type f | xargs rm
	-@rm hcli hypno
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
