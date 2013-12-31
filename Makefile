all: keystretch phs_keystretch memorycpy

keystretch: keystretch_main.c keystretch.c sha256.c keystretch.h sha256.h
	gcc -Wall -m64 -O3 -pthread keystretch_main.c keystretch.c sha256.c -o keystretch

phs_keystretch: phs_main.c keystretch.c sha256.c keystretch.h sha256.h
	gcc -Wall -m64 -O3 -pthread phs_main.c keystretch.c sha256.c -o phs_keystretch

memorycpy: memorycpy.c
	gcc -Wall -m64 -O3 memorycpy.c -o memorycpy
