for i in {10,20,30,40,50,60,70,80,85,90,95};
	do
		rm -rf /mnt/fio
		mkdir -p /mnt/fio
		cmdoptions=" --directory=/mnt/fio --direct=0 --rw=write --refill_buffers
                --buffer_compress_percentage=$i --ioengine=libaio --bs=8k
                --iodepth=16 --numjobs=4 --size=512M --time_based --runtime=30
                --group_reporting --name=fs3 -o /tmp/log";
                echo $cmdoptions
                fio $cmdoptions
		python3 cest.py --file /mnt/fio/fs3.4.0
	done;
