obj-m := luci.o
ccflags-y = -DLUCIFS_DEBUG -DLUCIFS_COMPRESSION -O2
luci-y := super.o inode.o dir.o file.o ialloc.o cluster.o compression.o zlib.o

all:
	make -C /lib/modules/`uname -r`/build M=`pwd` modules
clean:
	make -C /lib/modules/`uname -r`/build M=`pwd` clean
