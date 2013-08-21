default: all

all: seccomp_launcher libseccomp_preload.so

clean:
	-rm seccomp_launcher
	-rm libseccomp_preload.so
	-rm malloc.o
	-rm seccomp_preload.o

seccomp_launcher: seccomp_launcher.c seccomp_launcher.h
	$(CC) -g -Wall seccomp_launcher.c -o seccomp_launcher

libseccomp_preload.so: malloc.o seccomp_preload.o
	$(CC) -g -Wall -fPIC seccomp_preload.o malloc.o -shared -o libseccomp_preload.so -ldl

malloc.o: malloc.c
	$(CC) -g -Wall -O2 -fPIC malloc.c -c -Dsbrk=my_sbrk -DUSE_DL_PREFIX -DMORECORE_CANNOT_TRIM -DUSE_LOCKS=0 -DHAVE_MMAP=0 -DHAVE_MREMAP=0

seccomp_preload.o: seccomp_preload.c seccomp_launcher.h
	$(CC) -g -Wall -fPIC seccomp_preload.c -c

test1: test1.c
	$(CC) test1.c -o test1

test2: test2.c
	$(CC) test2.c -o test2

test3: test3.c
	$(CC) test3.c -o test3

test4: test4.c
	$(CC) test4.c -o test4

check: all test1 test2 test3 test4 
	./run_tests.sh
