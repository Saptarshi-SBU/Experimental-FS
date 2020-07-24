obj-m := luci.o
ccflags-y  = -DLUCIFS_DEBUG -DDEBUG_BLOCK -DLUCIFS_COMPRESSION -DDEBUG_COMPRESSION -DLUCIFS_CHECKSUM -O2
ccflags-y += -DTRACE_INCLUDE_PATH=$(PWD)
luci-y := super.o inode.o dir.o namei.o file.o ialloc.o page-io.o compress.o compress_heuristics.o zlib.o crc32.o utils.o

all:
	make -C /lib/modules/`uname -r`/build M=`pwd` modules
clean:
	make -C /lib/modules/`uname -r`/build M=`pwd` clean
