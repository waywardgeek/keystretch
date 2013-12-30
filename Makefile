all: keystretch phs_keystretch

keystretch: keystretch_main.c keystretch.c sha256.c keystretch.h sha256.h
	gcc -Wall -O2 -pthread keystretch_main.c keystretch.c sha256.c -o keystretch

phs_keystretch: phs_main.c keystretch.c sha256.c keystretch.h sha256.h
	gcc -Wall -O2 -pthread phs_main.c keystretch.c sha256.c -o phs_keystretch
