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
#include <list>
#include <set>
#include <vector>
#include <cassert>
#include <stdexcept>

#include "luci.h"

using namespace std;

class Group {
        public:
        char *blockbitMap;
        char *inodebitMap;
        struct luci_group_desc *gd;
        std::map<unsigned long, struct luci_inode> inodeMap;

        Group() {}

        ~Group() {
                if (blockbitMap)
                        delete blockbitMap;
                if (inodebitMap)
                        delete inodebitMap;
                inodeMap.clear();
        }
};

std::map<unsigned long, Group *> groupList;

char *globalBlockBitMap;

std::set<unsigned long> duplicateblocksInodeList;

std::set<unsigned long> missingblocksInodeList;

static int nr_pass;

static inline size_t sectors_count(struct luci_super_block *lsb, unsigned nr_blocks) {
        unsigned blocksize = (1024U << __le32_to_cpu(lsb->s_log_block_size));
        size_t size = nr_blocks * blocksize;
        return size >> 9;
}

static inline bool bpOk(blkptr *bp) {
        return !((!bp->blockno) || (bp->blockno == UINT32_MAX));
}

static void CleanupGroupList(std::map<unsigned long, Group*> groupList) {
        groupList.clear();
}

static size_t CCheckerCountBitMap(char *bitmap, size_t size) {
        size_t count = 0;
        for (size_t i = 0; i < size; i+=4) {
                unsigned val = *((unsigned *)(bitmap + i));
                count += ((sizeof(unsigned) * 8) - __builtin_popcount(val));
        }
        return count;
}

static int __CCheckerCheckBitMap(char *bitmap, unsigned long blockno) {
        unsigned block = blockno / 8;
        unsigned offset = blockno & 7;

        char *val = bitmap + block; 
        if (offset) {
                if ((*val &= (1 << (offset - 1))) == 0)
                        return -ENOENT;
        } else {
                if ((*val &= (1 << 7)) == 0)
                        return -ENOENT;
        }
        return 0;
}

static void CCheckerCheckBitMap(struct luci_super_block *lsb, unsigned long ino, blkptr bp) {
        Group *gp;
        unsigned long blockno = bp.blockno;
        unsigned long blocks_per_group = __le32_to_cpu(lsb->s_blocks_per_group);
        unsigned group = blockno / blocks_per_group;
        gp = (groupList.find(group))->second;

        if (nr_pass == 1)
                return;

        if ((blockno >= lsb->s_blocks_count) ||
                ((__CCheckerCheckBitMap(gp->blockbitMap, blockno) < 0)  && !bp.length)) {
                if (missingblocksInodeList.find(ino) == missingblocksInodeList.end())
                        duplicateblocksInodeList.insert(ino);
        }
}

static int __CCheckerAddBitMap(char *bitmap, unsigned long blockno) {
        unsigned block = blockno / 8;
        unsigned offset = blockno & 7;

        char *val = bitmap + block; 
        if (offset) {
                if ((*val &= (1 << (offset - 1))) != 0)
                        return -EEXIST;
                *val |= (1 << (offset - 1));
        } else {
                if ((*val &= (1 << 7)) != 0)
                        return -EEXIST;
                *val |= (1 << 7);
        }
        return 0;
}

static int CCheckerAddBitMap(struct luci_super_block *lsb, unsigned long ino, char *bitmap, blkptr bp) {
        unsigned long blockno = bp.blockno;

        if (nr_pass != 1)
                return 0;

        if ((blockno >= lsb->s_blocks_count) ||
                ((__CCheckerAddBitMap(bitmap, blockno) < 0)  && !bp.length)) {
                if (duplicateblocksInodeList.find(ino) == duplicateblocksInodeList.end())
                        duplicateblocksInodeList.insert(ino);
        }
        return 0;
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

static size_t CCheckerScanInodeIndirectBlocks(struct luci_super_block *lsb, unsigned long ino, unsigned long blockno, int level, int fd) {
        int i;
        char *buf;
        size_t nr_blocks = 0;
        unsigned blocksize = (1024U << __le32_to_cpu(lsb->s_log_block_size));
        int nr_blkptr = blocksize / LUCI_BLKPTR_SIZE;
        off_t off = (blocksize * blockno);

        if (level == 0)
                return nr_blocks;

        buf = new char[LUCI_BLKPTR_SIZE];
        for (i = 0; i < nr_blkptr; i++) {
                blkptr *bp;
                pread(fd, buf, LUCI_BLKPTR_SIZE, off + i * LUCI_BLKPTR_SIZE);
                bp = (blkptr *)buf;
                if (!bpOk(bp))
                        continue;
                CCheckerAddBitMap(lsb, ino, globalBlockBitMap, *bp);
                CCheckerCheckBitMap(lsb, ino, *bp);
                nr_blocks += CCheckerScanInodeIndirectBlocks(lsb, ino, bp->blockno, level - 1, fd);
                nr_blocks++;
        }
        delete buf;
        return nr_blocks;
}

void CCheckerScanInodeBlockTree(struct luci_super_block *lsb, struct luci_inode *inode, unsigned long ino, int fd) {
        blkptr bp;
        size_t nr_blocks = 0;

        bp = inode->i_block[0];
        std::cout << "L0 Block :" << bp.blockno << std::endl;
        if (bpOk(&bp)) {
                CCheckerAddBitMap(lsb, ino, globalBlockBitMap, bp);
                CCheckerCheckBitMap(lsb, ino, bp);
                nr_blocks++;
        }

        bp = inode->i_block[1];
        std::cout << "L0 Block :" << bp.blockno << std::endl;
        if (bpOk(&bp)) {
                CCheckerAddBitMap(lsb, ino, globalBlockBitMap, bp);
                CCheckerCheckBitMap(lsb, ino, bp);
                nr_blocks++;
        }

        bp = inode->i_block[2];
        std::cout << "L1 Block :" << bp.blockno << std::endl;
        if (bpOk(&bp)) {
                CCheckerAddBitMap(lsb, ino, globalBlockBitMap, bp);
                CCheckerCheckBitMap(lsb, ino, bp);
                nr_blocks += CCheckerScanInodeIndirectBlocks(lsb, ino, bp.blockno, 1, fd);
                nr_blocks++;
        }

        bp = inode->i_block[3];
        std::cout << "L2 Block :" << bp.blockno << std::endl;
        if (bpOk(&bp)) {
                CCheckerAddBitMap(lsb, ino, globalBlockBitMap, bp);
                CCheckerCheckBitMap(lsb, ino, bp);
                nr_blocks += CCheckerScanInodeIndirectBlocks(lsb, ino, bp.blockno, 2, fd);
                nr_blocks++;
        }

        bp = inode->i_block[4];
        std::cout << "L3 Block :" << bp.blockno << std::endl;
        if (bpOk(&bp)) {
                CCheckerAddBitMap(lsb, ino, globalBlockBitMap, bp);
                CCheckerCheckBitMap(lsb, ino, bp);
                nr_blocks += CCheckerScanInodeIndirectBlocks(lsb, ino, bp.blockno, 3, fd);
                nr_blocks++;
        }
        std::cout << "NR Blocks: " << sectors_count(lsb, nr_blocks)
                  << " isize:" << (inode->i_size >> 9) << std::endl;
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
                        if (nr_pass == 1) {
                                if (inodeMap.find(ino) != inodeMap.end())
                                        throw std::runtime_error("inode already present");
                                inodeMap[ino] = *inode;
                        }
                        printf ("Inode :%u type :%s, blocks :%u links_count :%u\n", ino, type.c_str(), inode->i_blocks, inode->i_links_count);
                        CCheckerScanInodeBlockTree(lsb, inode, ino, fd);
                }
                count++;
        }
        delete [] buf;
}

static Group *CCheckerLuciLoadGroupDescriptorSingle(struct luci_super_block *lsb, struct luci_group_desc *gd, int group, int fd) {
        Group *gp = new Group();
        gp->gd = gd;
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
        return gp;
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
                Group *gp;
                printf ("GD :%u\n", i);
                struct luci_group_desc *gd = (struct luci_group_desc *)((char *)gdesc + i * sizeof(struct luci_group_desc));
                nr_free_blocks += gd->bg_free_blocks_count;
                nr_free_inodes += gd->bg_free_inodes_count;
                gp = CCheckerLuciLoadGroupDescriptorSingle(lsb, gd, i, fd);
                groupList[i] = gp;
        }
        printf("GDT Free Blocks :%u\n", nr_free_blocks);
        printf("GDT Free Inodes :%u\n", nr_free_inodes);
}

static void CCheckerLuciMissingBlocks(struct luci_super_block *lsb, int fd) {
        for (auto &i : groupList)
                CCheckerReadGroupInodeTable(lsb, i.second->gd, i.first, fd, i.second->inodeMap);
}

struct luci_super_block *CCheckerLuciLoadSuper(int fd) {
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

static void TestFreeBlocksCount(struct luci_super_block *lsb, std::map<unsigned long, Group*> &groupList) {
        size_t sum_blocks = 0;
        for (auto &i : groupList)
                sum_blocks += i.second->gd->bg_free_blocks_count;
        assert(lsb->s_free_blocks_count == sum_blocks);
        std::cout << "CChecker:TestFreeBlocksCount pass" << std::endl;
}

static void TestFreeInodesCount(struct luci_super_block *lsb, std::map<unsigned long, Group*> &groupList) {
        size_t sum_inodes = 0;
        for (auto &i : groupList)
                sum_inodes += i.second->gd->bg_free_inodes_count;
        assert(lsb->s_free_inodes_count == sum_inodes);
        std::cout << "CChecker:TestFreeInodesCount pass" << std::endl;
}

static void TestDuplicateBlocks(std::set<unsigned long> &duplicateblocksInodeList) {
        assert(duplicateblocksInodeList.empty());
        std::cout << "CChecker:TestDuplicateBlocks pass" << std::endl;
}

static void TestMissingBlocks(std::set<unsigned long> &missingblocksInodeList) {
        assert(missingblocksInodeList.empty());
        std::cout << "CChecker:TestMissingBlocks pass" << std::endl;
}

int main(int argc, char *argv[]) {
        int fd;
        char *testdev;
        struct luci_super_block *lsb;

        if (argc < 2) {
                std::cerr << "need device path" << std::endl;
                return -1;
        }

        testdev = argv[1];
        fd = open(testdev, O_RDONLY);
        if (fd < 0) {
                std::cout << "failed to open device:" << strerror(errno) << std::endl;
                return -1;
        }

        nr_pass = 1;
        lsb = CCheckerLuciLoadSuper(fd);
        globalBlockBitMap = new char[lsb->s_blocks_count/8];
        CCheckerLuciLoadGroupDescriptorAll(fd, lsb);
        TestFreeBlocksCount(lsb, groupList);
        TestFreeInodesCount(lsb, groupList);
        TestDuplicateBlocks(duplicateblocksInodeList);

        nr_pass = 2;
        CCheckerLuciMissingBlocks(lsb, fd);
        TestMissingBlocks(missingblocksInodeList);

        CleanupGroupList(groupList);
        delete [] globalBlockBitMap;
        free(lsb);
        close(fd);
        return 0;
}
