all: preload.so

preload.so: preload.c
	gcc -Wall -fPIC -shared -o preload.so preload.c -ldl

clean:
	rm -f preload.so
