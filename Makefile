obj-m := luci.o
luci-y := super.o inode.o dir.o file.o ialloc.o
all:
		make -C /lib/modules/`uname -r`/build M=`pwd` modules 
clean:
		make -C /lib/modules/`uname -r`/build M=`pwd` clean
