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

#include <map>
#include <stdexcept>

#include "luci.h"

#define TESTDEV "/dev/sdb"
//#define TESTDEV "/dev/loop0"

using namespace std;

class Group {
        public:
        char *blockbitMap;
        char *inodebitMap;
        std::map<unsigned long, struct luci_inode> inodeMap;
};

size_t CCheckerCountBitMap(char *bitmap, size_t size) {
        size_t count = 0, wordsize = 4;
        for (size_t i = 0; i < size; i+=wordsize) {
                size_t val = *((unsigned *)(bitmap + i));
                count += ((sizeof(wordsize) * 8) - __builtin_popcount(val));
        }
        return count;
}

static char* CCheckerReadGroupInodeBitmap(struct luci_super_block *lsb, struct luci_group_desc *gd, int fd) {
        unsigned blocksize = (1024U << __le32_to_cpu(lsb->s_log_block_size));
        off_t off = __le32_to_cpu(gd->bg_inode_bitmap) * blocksize;
        char *bitmap = new char [blocksize];
        pread(fd, bitmap, blocksize, off);
        return bitmap;
}

static char* CCheckerReadGroupBlockBitmap(struct luci_super_block *lsb, struct luci_group_desc *gd, int fd) {
        unsigned blocksize = (1024U << __le32_to_cpu(lsb->s_log_block_size));
        off_t off = __le32_to_cpu(gd->bg_block_bitmap) * blocksize;
        char *bitmap = new char [blocksize];
        pread(fd, bitmap, blocksize, off);
        return bitmap;
}

void CCheckerReadGroupInodeTable(struct luci_super_block *lsb, struct luci_group_desc *gd, int group, int fd,
                std::map<unsigned long, struct luci_inode>& inodeMap) {
        size_t i, count;
        unsigned long ino = 0;
        struct luci_inode *inode;
        unsigned blockno = __le32_to_cpu(gd->bg_inode_table);
        unsigned blocksize = (1024U << __le32_to_cpu(lsb->s_log_block_size));
        unsigned inode_size = __le32_to_cpu(lsb->s_inode_size);
        off_t off = (blocksize * blockno);
        unsigned inodes_per_group = __le32_to_cpu(lsb->s_inodes_per_group);
        unsigned base_inode = group * inodes_per_group + 1;
        unsigned nr_blocks = (inodes_per_group * inode_size + blocksize - 1) / blocksize;
        char *buf = new char[inode_size];

        for (i = 0, count = 0; i < (nr_blocks * blocksize); i+=inode_size) {
                pread(fd, buf, inode_size, off + i);
                inode = (struct luci_inode *)buf;
                ino = base_inode + count;
                if (inode->i_mode) {
                        std::string type;
                        if (S_ISREG(inode->i_mode))
                                type.assign("regular");
                        else if (S_ISDIR(inode->i_mode))
                                type.assign("dir");
                        printf ("Inode :%u type :%s, blocks :%u\n", ino, type.c_str(), inode->i_blocks);
                        if (inodeMap.find(ino) != inodeMap.end())
                                throw std::runtime_error("inode already present");
                        inodeMap[ino] = *inode;
                }
                count++;
        }
        delete [] buf;
}

static int CCheckerLuciLoadGroupDescriptorSingle(struct luci_super_block *lsb, struct luci_group_desc *gd, int group, int fd) {
        Group *gp = new Group();
        gp->inodebitMap = CCheckerReadGroupInodeBitmap(lsb, gd, fd);
        gp->blockbitMap = CCheckerReadGroupBlockBitmap(lsb, gd, fd);
        printf ("Block Group BlockMap No[%u]   : 0x%x/crc=0x%x\n",
                        group, gd->bg_block_bitmap, gd->bg_block_bitmap_checksum);
        printf ("Block Group Free Blocks[%u]   : %u/%u\n",
                        group, gd->bg_free_blocks_count, CCheckerCountBitMap(gp->blockbitMap, 4096));
        printf ("Block Group InodeMap No[%u]   : 0x%x/crc=0x%x\n",
                        group, gd->bg_inode_bitmap, gd->bg_inode_bitmap_checksum);
        printf ("Block Group Free Inodes[%u]   : %u/%u\n",
                        group, gd->bg_free_inodes_count, CCheckerCountBitMap(gp->inodebitMap, 4096));
        printf ("Block Group InodeTable No[%u] : 0x%x/crc=0x%x, 0x%x\n",
                        group, gd->bg_inode_table, gd->bg_inode_table_checksum, gd->bg_checksum);

        CCheckerReadGroupInodeTable(lsb, gd, group, fd, gp->inodeMap);
        if (!gp->inodeMap.empty()) {
                std::cout << "group=" << group << ":" << "inode list:" << std::endl;
                for (auto &i : gp->inodeMap)
                        std::cout << i.first << " ";
                std::cout << std::endl;
        }
        delete gp;
}

void CCheckerLuciLoadGroupDescriptorAll(int fd, struct luci_super_block *lsb) {
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
                nr_free_blocks += gd->bg_free_blocks_count;
                nr_free_inodes += gd->bg_free_inodes_count;
                CCheckerLuciLoadGroupDescriptorSingle(lsb, gd, i, fd);
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
        printf ("InodeSize          :%lu\n", lsb->s_inode_size);
        printf ("Mount State        :%lu\n", lsb->s_state);
        return lsb;
}

int main(void) {
        struct luci_super_block *lsb;
        int fd = open(TESTDEV, O_RDONLY);
        if (fd < 0)
                std::cout << "failed to open device:" << strerror(errno) << std::endl;
        lsb = CCheckerLuciLoadSuper(fd);
        CCheckerLuciLoadGroupDescriptorAll(fd, lsb);
        free(lsb);
        close(fd);
        return 0;
}

