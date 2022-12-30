build:
	gcc mybnc.c -g -ggdb -Wall -o mybnc -lcrypt
solaris:
	gcc mybnc.c -g -o mybnc -Wall -lsocket -lnsl
clean:
	test -f mybnc && rm mybnc
