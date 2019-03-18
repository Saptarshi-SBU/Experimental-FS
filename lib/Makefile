obj-m := linux-btree.o
ccflags-y = -g
linux-btree-y := btree.o btree_proc.o page_io.o btree_ioctl.o

all:
	make -C /lib/modules/`uname -r`/build M=`pwd` modules
clean:
	make -C /lib/modules/`uname -r`/build M=`pwd` clean
