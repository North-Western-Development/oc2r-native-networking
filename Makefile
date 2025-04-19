CFLAGS := -O2 -g -Wall -Wextra -pedantic

all: liboc2rnet-linux.so oc2rnet.dll

LINUXCC := gcc
WINCC := x86_64-w64-mingw32-gcc

liboc2rnet-linux.so: oc2rnet.c
	$(LINUXCC) $^ -shared -o $@ $(CFLAGS) -fPIC -Ijni-headers -Ijni-headers/linux

oc2rnet.dll: oc2rnet.c
	$(WINCC) $^ -shared -o $@ $(CFLAGS) -licmp -fPIC -Ijni-headers -Ijni-headers/win32

liboc2rnet.dylib: oc2rnet.c
	$(MACCC) $^ -shared -o $@ $(CFLAGS) -fPIC -Ijni-headers -Ijni-headers/mac

clean:
	rm -f liboc2rnet-linux.so oc2rnet.dll
