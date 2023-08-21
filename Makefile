build:
	gcc mybnc.c -g -ggdb -Wall -o mybnc -lcrypt
	gcc mkpasswd.c -g -ggdb -Wall -o mkpasswd -lcrypt
	test -f mybnc.allow || cp mybnc.allow.default mybnc.allow
solaris:
	gcc mybnc.c -g -o mybnc -Wall -lsocket -lnsl
	gcc mkpasswd.c -g -ggdb -Wall -o mkpasswd -lcrypt
	test -f mybnc.allow || cp mybnc.allow.default mybnc.allow
clean:
	test -f mybnc && rm mybnc
	test -f mkpasswd && rm mkpasswd
