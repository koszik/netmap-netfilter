all: ses

CFLAGS = -I /root/netmap/netmap/sys/ -ggdb -O3 -pg
netmap_io.o: netmap_io.c
	gcc -c netmap_io.c $(CFLAGS)

session.o: session.c
	gcc -c session.c $(CFLAGS)

dummy.o: dummy.c
	gcc -c dummy.c $(CFLAGS)

ses: session.o netmap_io.o dummy.o
	gcc -pg session.o dummy.o netmap_io.o -o ses -ggdb

clean:
	rm -f *.o ses
