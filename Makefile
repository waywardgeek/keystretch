all: keystretch keystretch-ref phs_keystretch memorycpy noelkdf

keystretch: keystretch_main.c keystretch-nosse.c sha256.c keystretch.h sha256.h
	gcc -Wall -m64 -O3 -pthread keystretch_main.c keystretch-nosse.c sha256.c -o keystretch

keystretch-ref: keystretch_main.c keystretch-ref.c sha256.c keystretch.h sha256.h
	gcc -Wall -m64 -O3 -pthread keystretch_main.c keystretch-ref.c sha256.c -o keystretch-ref

phs_keystretch: phs_main.c keystretch-nosse.c sha256.c keystretch.h sha256.h
	gcc -Wall -m64 -O3 -pthread phs_main.c keystretch-nosse.c sha256.c -o phs_keystretch

memorycpy: memorycpy.c
	gcc -Wall -m64 -O3 -pthread memorycpy.c -o memorycpy

noelkdf: noelkdf.c
	gcc -Wall -m64 -O3 -pthread noelkdf.c sha256.c -o noelkdf
