CC=i686-w64-mingw32-gcc
CC_64=x86_64-w64-mingw32-gcc

all: bin/loader.x64.o

bin:
	mkdir bin

#
# x64 targets
#
bin/loader.x64.o: bin
	$(CC_64) -DWIN_X64 -shared -Wall -Wno-pointer-arith -fno-ident -c src/loader.c -o bin/loader.x64.o

#
# Other targets
#
clean:
	rm -f bin/*
