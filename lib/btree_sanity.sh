#!/bin/bash

MOD=linux-btree.ko

rmmod $MOD
insmod lib/$MOD

#for i in {1..1048576};
for i in {0..64};
        do 
                key=$(($i * 2))
                echo $key
                echo $key > /sys/kernel/debug/btree/insert;
                echo "******BTREE LAYOUT********"
                cat /sys/kernel/debug/btree/insert;
                sleep 0.001;
        done

#for i in {64..0};
for i in {0..64};
        do 
                key=$(($i * 2))
                echo $key > /sys/kernel/debug/btree/delete;
                echo "******BTREE LAYOUT********"
                cat /sys/kernel/debug/btree/delete;
                sleep 0.001;
        done

#for i in {1..1048576};
for i in {0..64};
        do 
                key=$(($i * 2))
                echo $key
                echo $key > /sys/kernel/debug/btree/insert;
                echo "******BTREE LAYOUT********"
                cat /sys/kernel/debug/btree/insert;
                sleep 0.001;
        done

#for i in {64..0};
for i in {0..64};
        do 
                key=$(($i * 2))
                echo $key > /sys/kernel/debug/btree/delete;
                echo "******BTREE LAYOUT********"
                cat /sys/kernel/debug/btree/delete;
                sleep 0.001;
        done
