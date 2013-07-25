CFLAGS=-Wall -Wextra -pedantic -s -O2 -lnettle -lgpgme

salsamsg:
	cc ${CFLAGS} -o salsamsg salsamsg.c

clean:
	rm -f salsamsg
