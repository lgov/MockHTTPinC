# Makefile for MockHTTPinC

CC=clang
CFLAGS=-g -std=c99 -Wdeclaration-after-statement -Wall 

LIB_PATHS=-L/opt/local/lib -L/usr/local/lib
INC_PATHS=-I. -I/opt/local/include/apr-1 -I/opt/local/include

LIBS=-lapr-1 -laprutil-1 -lssl -lcrypto

SRCFILES=MockHTTP.c MockHTTP_server.c

OBJS=$(patsubst %.c,$(OBJDIR)/%.o, $(SRCFILES))
OBJDIR=build

$(OBJDIR)/%.o : %.c
		$(CC) $(CFLAGS) $(INC_PATHS) -o build/$*.o -c $<

# configstore.c : simplespdy.h

tests/CuTest/%.o : tests/CuTest/%.c
		$(CC) $(CFLAGS) $(INC_PATHS) -I.. -o tests/CuTest/$*.o -c $<
tests/%.o : tests/%.c
		$(CC) $(CFLAGS) $(INC_PATHS) -I.. -o tests/$*.o -c $<

test: $(OBJS) tests/expectations.o tests/httpClient.o tests/CuTest/CuTest.o
	$(CC) -o tests/mockhttp_tests $(LIB_PATHS) $(LIBS) $(OBJS)\
		tests/expectations.o tests/httpClient.o tests/CuTest/CuTest.o

clean:
	rm -f tests/mockhttp_tests build/*.o tests/*.o
