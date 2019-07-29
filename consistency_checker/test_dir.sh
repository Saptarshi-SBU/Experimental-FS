mkdir -p /mnt/testdir
for i in {1..32}; do truncate -s 4K /mnt/testdir/$i; done
