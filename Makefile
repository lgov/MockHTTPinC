# Makefile for MockHttpInC

CC=clang
CFLAGS=-g

LIB_PATHS=-L/opt/local/lib -L/usr/local/lib
INC_PATHS=-I.

LIBS=-lssl -lcrypto

SRCFILES=MockHttp.c

OBJS=$(patsubst %.c,$(OBJDIR)/%.o, $(SRCFILES))
OBJDIR=build

$(OBJDIR)/%.o : %.c
		$(CC) $(CFLAGS) $(INC_PATHS) -o build/$*.o -c $<

# configstore.c : simplespdy.h

tests/%.o : tests/%.c
		$(CC) $(CFLAGS) $(INC_PATHS) -I.. -o tests/$*.o -c $<

test: $(OBJS) tests/expectations.o
	$(CC) -o tests/mockhttp_tests $(LIB_PATHS) $(LIBS) $(OBJS)\
		tests/expectations.o

clean:
	rm -f tests/mockhttp_tests build/*.o tests/*.o
