keystretch: main.c keystretch.c sha256.c keystretch.h sha256.h
	#gcc -Wall -O2 -pthread main.c keystretch.c sha256.c -o keystretch
	gcc -Wall -m64 -O2 -pthread main.c keystretch.c sha256.c -o keystretch
	#gcc -Wall -m64 -g -pthread main.c keystretch.c sha256.c -o keystretch
