ifeq ($(shell arch), i686)
  TARGET=X86
  TARGET_CFLAGS=-D_FILE_OFFSET_BITS=64
endif
ifeq ($(shell arch), ppc64)
  TARGET=PPC64
  TARGET_CFLAGS=-m64
endif
ifeq ($(shell arch), ppc64le)
  TARGET=PPC64
  TARGET_CFLAGS=-m64
endif
ifeq ($(shell arch), ia64)
  TARGET=IA64
  TARGET_CFLAGS=
endif
ifeq ($(shell arch), x86_64)
  TARGET=X86_64
  TARGET_CFLAGS=
endif

ifeq ($(shell /bin/ls /usr/include/crash/defs.h 2>/dev/null), /usr/include/crash/defs.h)
  INCDIR=/usr/include/crash
endif
ifeq ($(shell /bin/ls ../defs.h 2> /dev/null), ../defs.h)
  INCDIR=..
endif
ifeq ($(shell /bin/ls ./defs.h 2> /dev/null), ./defs.h)
  INCDIR=.
endif

all: scsi.so

scsi.so: $(INCDIR)/defs.h scsi.c
	gcc -Wall -g -I$(INCDIR) -shared -rdynamic -o scsi.so scsi.c -fPIC -D$(TARGET) $(TARGET_CFLAGS) $(GDB_FLAGS)