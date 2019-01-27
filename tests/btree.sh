#!/bin/bash

MOD=linux-btree.ko

rmmod $MOD
insmod lib/$MOD

#for i in {1..1048576};
for i in {0..8192};
        do 
                echo $i > /sys/kernel/debug/btree/dump;
                #echo "******BTREE LAYOUT********"
                #cat /sys/kernel/debug/btree/dump;
                #sleep 1;
        done
