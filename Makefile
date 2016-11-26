obj-m := luci.o
luci-y := super.o 
all:
		make -C /lib/modules/`uname -r`/build M=`pwd` modules 
clean:
		make -C /lib/modules/`uname -r`/build M=`pwd` clean
