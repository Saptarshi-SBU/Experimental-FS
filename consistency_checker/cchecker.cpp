#include <iostream>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <string>
#include <stdio.h>
#include <stdint.h>
#include <sys/stat.h>

#include "luci.h"

//#define TESTDEV "/dev/sdb1"
#define TESTDEV "/dev/loop0"

using namespace std;

int CCheckerLuciCheckBitMap(int fd, unsigned blocksize, unsigned blockno) {
        size_t i;
        int count = 0;
        unsigned long bitmap = 0UL;

        for (i = 0; i < blocksize; i+=sizeof(bitmap)) {
                off_t off = (blocksize * blockno);
                pread(fd, &bitmap, sizeof(bitmap), off + i);
                count += ((sizeof(bitmap) * 8) - __builtin_popcountl(bitmap));
                bitmap = 0UL;
        }
        return count;
}

void CCheckerLuciLoadInodeTable(int fd, unsigned blocksize, unsigned blockno) {
        size_t i;
        int count = 0;
        struct luci_inode inode;

        for (i = 0; i < blocksize; i+=sizeof(inode)) {
                off_t off = (blocksize * blockno);
                pread(fd, &inode, sizeof(inode), off + i);
                count++;
                printf ("Inode :%u regular :%d, blocks :%u\n", count, S_ISREG(inode.i_mode), inode.i_blocks);
        }
}

void CCheckerLuciLoadGroupDescriptor(int fd, struct luci_super_block *lsb) {
        int i = 0;
        struct luci_group_desc *gdesc;
        unsigned long nr_free_blocks = 0;
        unsigned long nr_free_blocks2 = 0;
        unsigned long nr_free_inodes = 0;
        unsigned block_size, nr_groups, nr_desc_per_block, nr_desc_blocks;

        block_size = (1024U << __le32_to_cpu(lsb->s_log_block_size));
        nr_desc_per_block = block_size/(sizeof(struct luci_group_desc));
        nr_groups = ((__le32_to_cpu(lsb->s_blocks_count) - __le32_to_cpu(lsb->s_first_data_block) - 1) /
                        __le32_to_cpu(lsb->s_blocks_per_group)) + 1;
        nr_desc_blocks = (nr_groups + nr_desc_per_block - 1)/nr_desc_per_block;
        gdesc = (struct luci_group_desc *) malloc(nr_desc_blocks * block_size);

        // 2nd block GDT entries
        pread(fd, gdesc, block_size, block_size);

        printf ("Nr Groups : %u\n", nr_groups);
        printf ("Nr Group descriptor blocks :%u\n", nr_desc_blocks); 
        for (i = 0; i < nr_groups; i++) {
                printf ("GD :%u\n", i);
                struct luci_group_desc *gd = (struct luci_group_desc *)((char *)gdesc + i * sizeof(struct luci_group_desc));
                printf ("Block Group BlockMap No[%u]   : 0x%x/crc=0x%x\n", i, gd->bg_block_bitmap, gd->bg_block_bitmap_checksum);
                printf ("Block Group Free Blocks[%u]   : %u/%u\n", i, gd->bg_free_blocks_count, CCheckerLuciCheckBitMap(fd, block_size, gd->bg_block_bitmap));
                printf ("Block Group InodeMap No[%u]   : 0x%x/crc=0x%x\n", i, gd->bg_inode_bitmap, gd->bg_inode_bitmap_checksum);
                printf ("Block Group Free Inodes[%u]   : %u/%u\n", i, gd->bg_free_inodes_count, CCheckerLuciCheckBitMap(fd, block_size, gd->bg_inode_bitmap));
                printf ("Block Group InodeTable No[%u] : 0x%x/crc=0x%x, 0x%x\n", i, gd->bg_inode_table, gd->bg_inode_table_checksum, gd->bg_checksum);
                nr_free_blocks += gd->bg_free_blocks_count;
                nr_free_inodes += gd->bg_free_inodes_count;
                CCheckerLuciLoadInodeTable(fd, block_size, gd->bg_inode_table);
        }
        printf("GDT Free Blocks :%u\n", nr_free_blocks);
        printf("GDT Free Inodes :%u\n", nr_free_inodes);
}

struct luci_super_block * CCheckerLuciLoadSuper(int fd) {
        struct luci_super_block *lsb = (struct luci_super_block *)malloc(1024);;
        pread(fd, lsb, 1024, 1024);
        printf ("SB Magic           :0x%x\n", lsb->s_magic);
        printf ("Nr Inodes          :%lu\n", lsb->s_inodes_count);
        printf ("Nr Blocks          :%lu\n", lsb->s_blocks_count);
        printf ("Nr Free Blocks     :%lu\n", lsb->s_free_blocks_count);
        printf ("Nr Free Inodes     :%lu\n", lsb->s_free_inodes_count);
        printf ("First DBlock       :%lu\n", lsb->s_first_data_block);
        printf ("Block Size         :%lu\n", (1024U << __le32_to_cpu(lsb->s_log_block_size)));
        printf ("Blocks Per Group   :%lu\n", lsb->s_blocks_per_group);
        printf ("Inodes Per Group   :%lu\n", lsb->s_inodes_per_group);
        printf ("Mount State        :%lu\n", lsb->s_state);
        return lsb;
}

int main(void) {
        struct luci_super_block *lsb;
        int fd = open(TESTDEV, O_RDONLY);
        if (fd < 0)
                std::cout << "failed to open device:" << strerror(errno) << std::endl;
        lsb = CCheckerLuciLoadSuper(fd);
        CCheckerLuciLoadGroupDescriptor(fd, lsb);
        free(lsb);
        return 0;
}

