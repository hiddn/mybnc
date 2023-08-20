build:
	gcc mybnc.c -g -ggdb -Wall -o mybnc -lcrypt
	gcc mkpasswd.c -g -ggdb -Wall -o mkpasswd -lcrypt
solaris:
	gcc mybnc.c -g -o mybnc -Wall -lsocket -lnsl
	gcc mkpasswd.c -g -ggdb -Wall -o mkpasswd -lcrypt
clean:
	test -f mybnc && rm mybnc
	test -f mkpasswd && rm mkpasswd
