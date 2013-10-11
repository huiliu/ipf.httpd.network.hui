
cc = gcc
opts = -O2 -Wall -levent -lmemcached

all: filter

filter: filter.c
	$(cc) $(opts) filter.c -o filter

clean:
	rm -rf filter
