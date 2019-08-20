/*
 * luci file system consistency checker
 *
 */
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include <map>
#include <set>
#include <list>
#include <string>
#include <cassert>
#include <stdexcept>

#include "luci.h"
#include "graph.h"

using namespace std;

//#define dbg_printf printf
#define dbg_printf

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

// bitMap for duplicate blocks
char *checkdupBlockBitMap;

// stores block group info
std::map<unsigned long, Group *> blockgroupMap;

// stores inodes in fs
std::map<unsigned long, struct luci_inode> globalInodeMap;

// stores directory link count
std::map<unsigned long, unsigned> globalDirMap;

// inconsistent inodes list
std::set<unsigned long> InodeWithDuplicateBlocks;

std::set<unsigned long> InodeBlocksNotMarkedInBitMap;

std::list<unsigned long> orphanInodeList;

std::set<unsigned long>  InodeNotMarkedInBitMap;

// DAG for detecting directory cycles
cchecker_graph::Graph<long> dirGraph;

static int nr_pass;

static inline size_t sectors_count(struct luci_super_block *lsb, unsigned nr_blocks) {
        unsigned blocksize = (1024U << __le32_to_cpu(lsb->s_log_block_size));
        size_t size = nr_blocks * blocksize;
        return size >> 9;
}

static inline bool bpOk(blkptr *bp) {
        return !((!bp->blockno) || (bp->blockno == UINT32_MAX));
}

static void CleanupGroupList(std::map<unsigned long, Group*> blockgroupMap) {
        blockgroupMap.clear();
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
        gp = (blockgroupMap.find(group))->second;

        if (nr_pass == 1)
                return;

        if ((blockno >= lsb->s_blocks_count) ||
                ((__CCheckerCheckBitMap(gp->blockbitMap, blockno) < 0)  && !bp.length)) {
                if (InodeBlocksNotMarkedInBitMap.find(ino) ==
                                InodeBlocksNotMarkedInBitMap.end())
                        InodeWithDuplicateBlocks.insert(ino);
        }
}

static void CCheckerCheckInodeBitMap(struct luci_super_block *lsb, unsigned long ino) {
        unsigned long inodes_per_group = __le32_to_cpu(lsb->s_inodes_per_group);
        unsigned group = ino / inodes_per_group;
        Group *gp = (blockgroupMap.find(group))->second;

        if (nr_pass == 1)
                return;

        if (__CCheckerCheckBitMap(gp->inodebitMap, ino) < 0) {
                if (InodeNotMarkedInBitMap.find(ino) == InodeNotMarkedInBitMap.end())
                        InodeNotMarkedInBitMap.insert(ino);
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

static int CCheckerAddBitMap(struct luci_super_block *lsb, unsigned long ino,
                char *bitmap, blkptr bp) {
        unsigned long blockno = bp.blockno;

        if (nr_pass != 1)
                return 0;

        if ((blockno >= lsb->s_blocks_count) ||
                ((__CCheckerAddBitMap(bitmap, blockno) < 0)  && !bp.length)) {
                if (InodeWithDuplicateBlocks.find(ino) == InodeWithDuplicateBlocks.end())
                        InodeWithDuplicateBlocks.insert(ino);
        }
        return 0;
}

static char* CCheckerReadGroupInodeBitmap(struct luci_super_block *lsb,
                struct luci_group_desc *gd, int fd) {
        unsigned long blocksize = (1024UL << __le32_to_cpu(lsb->s_log_block_size));
        //loff_t off = __le32_to_cpu(gd->bg_inode_bitmap) * blocksize;
        loff_t off = gd->bg_inode_bitmap * blocksize;
        char *bitmap = new char [blocksize];
        pread(fd, bitmap, blocksize, off);
        printf("inodebitMap :%lx/%lx\n", off, off/blocksize);
        //for (int i = 0; i < blocksize; i++)
        //        printf("[%d] 0x%x ", i, *(bitmap + i));
        //printf("\n");
        return bitmap;
}

static char* CCheckerReadGroupBlockBitmap(struct luci_super_block *lsb,
                struct luci_group_desc *gd, int fd) {
        unsigned blocksize = (1024U << __le32_to_cpu(lsb->s_log_block_size));
        off_t off = __le32_to_cpu(gd->bg_block_bitmap) * blocksize;
        char *bitmap = new char [blocksize];
        pread(fd, bitmap, blocksize, off);
        return bitmap;
}

static size_t CCheckerScanInodeIndirectBlocks(struct luci_super_block *lsb, unsigned long ino,
                unsigned long blockno, int level, int fd) {
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
                CCheckerAddBitMap(lsb, ino, checkdupBlockBitMap, *bp);
                CCheckerCheckBitMap(lsb, ino, *bp);
                nr_blocks += CCheckerScanInodeIndirectBlocks(lsb, ino, bp->blockno, level - 1, fd);
                nr_blocks++;
        }
        delete buf;
        return nr_blocks;
}

static void CCheckerScanInodeBlockTree(struct luci_super_block *lsb, struct luci_inode *inode,
                unsigned long ino, int fd) {
        blkptr bp;
        size_t nr_blocks = 0;

        bp = inode->i_block[0];
        dbg_printf("L0 Block :%u\n", bp.blockno);
        if (bpOk(&bp)) {
                CCheckerAddBitMap(lsb, ino, checkdupBlockBitMap, bp);
                CCheckerCheckBitMap(lsb, ino, bp);
                nr_blocks++;
        }

        bp = inode->i_block[1];
        dbg_printf("L0 Block :%u\n", bp.blockno);
        if (bpOk(&bp)) {
                CCheckerAddBitMap(lsb, ino, checkdupBlockBitMap, bp);
                CCheckerCheckBitMap(lsb, ino, bp);
                nr_blocks++;
        }

        bp = inode->i_block[2];
        dbg_printf("L1 Block :%u\n", bp.blockno);
        if (bpOk(&bp)) {
                CCheckerAddBitMap(lsb, ino, checkdupBlockBitMap, bp);
                CCheckerCheckBitMap(lsb, ino, bp);
                nr_blocks += CCheckerScanInodeIndirectBlocks(lsb, ino, bp.blockno, 1, fd);
                nr_blocks++;
        }

        bp = inode->i_block[3];
        dbg_printf("L2 Block :%u\n", bp.blockno);
        if (bpOk(&bp)) {
                CCheckerAddBitMap(lsb, ino, checkdupBlockBitMap, bp);
                CCheckerCheckBitMap(lsb, ino, bp);
                nr_blocks += CCheckerScanInodeIndirectBlocks(lsb, ino, bp.blockno, 2, fd);
                nr_blocks++;
        }

        bp = inode->i_block[4];
        dbg_printf("L3 Block :%u\n", bp.blockno);
        if (bpOk(&bp)) {
                CCheckerAddBitMap(lsb, ino, checkdupBlockBitMap, bp);
                CCheckerCheckBitMap(lsb, ino, bp);
                nr_blocks += CCheckerScanInodeIndirectBlocks(lsb, ino, bp.blockno, 3, fd);
                nr_blocks++;
        }
        dbg_printf("NR Blocks: %u isize: %u\n",
                sectors_count(lsb, nr_blocks), (inode->i_size >> 9));
}

static int CCheckerCalculateBlockTreeIndexes(struct luci_super_block *lsb, unsigned long i_block,
                long path[LUCI_MAX_DEPTH])
{
        int n = 0;
        const long file_block = i_block;
        const long nr_direct = LUCI_NDIR_BLOCKS;
        const long nr_indirect = LUCI_ADDR_PER_BLOCK(lsb);
        const long nr_dindirect = (1 << (LUCI_ADDR_PER_BLOCK_BITS(lsb) * 2));
        const long nr_addr_per_block_bits = LUCI_ADDR_PER_BLOCK_BITS(lsb);

        if (i_block < nr_direct) {
                path[n++] = i_block;
                goto done;
        }

        i_block -= nr_direct;
        if (i_block < nr_indirect) {
                path[n++] = LUCI_IND_BLOCK;
                path[n++] = i_block;
                goto done;
        }

        i_block -= nr_indirect;
        if (i_block < nr_dindirect) {
                path[n++] = LUCI_DIND_BLOCK;
                path[n++] = i_block >> nr_addr_per_block_bits;
                path[n++] = i_block & (LUCI_ADDR_PER_BLOCK(lsb) - 1);
                goto done;
        }

        i_block -= nr_dindirect;
        if ((i_block >> (LUCI_ADDR_PER_BLOCK_BITS(lsb) * 2)) <
            LUCI_ADDR_PER_BLOCK(lsb)) {
                path[n++] = LUCI_TIND_BLOCK;
                path[n++] = i_block >> (LUCI_ADDR_PER_BLOCK_BITS(lsb) * 2);
                path[n++] = (i_block >> LUCI_ADDR_PER_BLOCK_BITS(lsb)) &
                    (LUCI_ADDR_PER_BLOCK(lsb) - 1);
                path[n++] = i_block & (LUCI_ADDR_PER_BLOCK(lsb) - 1);
                goto done;
        }

        return -E2BIG;

        done:

        dbg_printf("i_block :%lu n:%d bmap indices :%ld :%ld :%ld :%ld\n",
                file_block, n, path[0], path[1], path[2], path[3]);
        return n;
}

static int CCheckerWalkBlockTree(struct luci_super_block *lsb, struct luci_inode *inode,
                unsigned long ino, char *buffer, long path[LUCI_MAX_DEPTH], int depth, int fd) {
        blkptr bp;
        off_t off;
        unsigned blocksize = (1024U << __le32_to_cpu(lsb->s_log_block_size));

        for (int d = 1; d <= depth; d++) {
                int index = path[d - 1];
                if (d == 1)
                        bp = inode->i_block[index];
                else {
                        off = bp.blockno * blocksize;
                        pread(fd, &bp, sizeof(blkptr), off + index);
                }
                dbg_printf("%s:inode=%u depth=%u index=%u blockno=%u\n", __func__,
                        ino, d, index, bp.blockno);
        }
        pread(fd, buffer, blocksize, bp.blockno*blocksize);
}

static inline struct
luci_dir_entry_2 *luci_next_entry(struct luci_dir_entry_2 *p)
{
    return (struct luci_dir_entry_2 *)((char *)p +
        __le32_to_cpu(p->rec_len));
}

static int CCheckerReadDirBlock(struct luci_super_block *lsb, struct luci_inode *dir,
                unsigned long ino, char *buf, size_t readsize) {
        int links_count = 0;
        struct luci_dir_entry_2 *de, *limit;

        de = (struct luci_dir_entry_2*)buf;
        limit = (struct luci_dir_entry_2*)
                ((char*)buf + readsize - LUCI_DIR_REC_LEN(1));

        // lookup dentries in the page
        for (; de <= limit; de = luci_next_entry(de)) {
                if (!de->rec_len)
                        break;
                if (de->rec_len && de->inode) {
                        struct luci_inode inode;
                        dbg_printf("DIR: inode :%u dentry name :%s, inode :%u/%llu, namelen :%u "
                                "reclen :%u\n",
                                ino, de->name, de->inode, dir->i_size,
                                de->name_len, de->rec_len);
                        if (globalInodeMap.find(de->inode) == globalInodeMap.end()) {
                                dbg_printf("inode in directory has no entry in inode tables\n");
                                orphanInodeList.push_back(de->inode);
                        }
                        inode = globalInodeMap[de->inode];
                        if (S_ISDIR(inode.i_mode)) {
                                links_count++;
                                dirGraph.add_vertex(de->inode);
                                dirGraph.add_edge(ino, de->inode);
                        }
                }
        }
        return links_count;
}

static int CCheckerReadDirInode(struct luci_super_block *lsb, struct luci_inode *inode,
                unsigned long ino, int fd) {
        int depth;
        int links_count = 0;
        long path[LUCI_MAX_DEPTH];
        size_t size = inode->i_size;
        size_t blocksize = (1024U << __le32_to_cpu(lsb->s_log_block_size));
        unsigned int nr_blocks = (size + blocksize - 1)/blocksize;
        char *buf = new char[blocksize];

        dirGraph.add_vertex(ino);

        for (size_t fblock = 0; fblock < nr_blocks; fblock++) {
                size_t readbytes = std::min(size, blocksize);
                memset(path, 0, sizeof(long) * LUCI_MAX_DEPTH);
                memset(buf, 0, blocksize);
                depth = CCheckerCalculateBlockTreeIndexes(lsb, fblock, path);
                if (depth < 0)
                        break;
                CCheckerWalkBlockTree(lsb, inode, ino, buf, path, depth, fd);
                links_count += CCheckerReadDirBlock(lsb, inode, ino, buf, readbytes);
                size -= readbytes;
                assert(size >= 0);
        }
        delete [] buf;
        return links_count;
}

static std::string CCheckerGetFileType(int mode) {
        std::string type;
        if (S_ISREG(mode))
                type.assign("regular");
        if (S_ISDIR(mode))
                type.assign("dir");
        return type;
}

static void CCheckerReadGroupInodeTable(struct luci_super_block *lsb, struct luci_group_desc *gd,
                int group, int fd, std::map<unsigned long, struct luci_inode>& inodeMap, char *inodebitMap) {
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

        for (i = 0, count = 0; i < (nr_blocks * blocksize); i+=inode_size, count++) {
                // Lookup inodes only marked in bitmap
                // For certain groups, inode table entries may not be
                // initialized if unmarked in inode bitmap
                if (__CCheckerCheckBitMap(inodebitMap, count) != 0)
                        continue;
                printf("count :%lu\n", count);
                pread(fd, buf, inode_size, off + i);
                inode = (struct luci_inode *)buf;
                ino = base_inode + count;
                if (inode->i_mode) {
                        if (nr_pass == 1) {
                                assert(inodeMap.find(ino) == inodeMap.end());
                                inodeMap[ino] = *inode;
                                assert(globalInodeMap.find(ino) == globalInodeMap.end());
                                globalInodeMap[ino] = *inode;
                                CCheckerCheckInodeBitMap(lsb, ino);
                        }

                        if ((nr_pass == 2) && S_ISDIR(inode->i_mode)) {
                                int links;
                                links = CCheckerReadDirInode(lsb, inode, ino, fd);
                                assert(globalDirMap.find(ino) == globalDirMap.end());
                                globalDirMap[ino] = links;
                        }

                        dbg_printf ("Inode :%u type :%s, blocks :%u links_count :%u\n", ino,
                                CCheckerGetFileType(inode->i_mode).c_str(), inode->i_blocks,
                                inode->i_links_count);

                        CCheckerScanInodeBlockTree(lsb, inode, ino, fd);
                }
                //count++;
        }
        delete [] buf;
}

static Group *CCheckerLuciLoadGroupDescriptorSingle(struct luci_super_block *lsb,
                struct luci_group_desc *gd, int group, int fd) {
        Group *gp = new Group();
        gp->gd = gd;
        gp->inodebitMap = CCheckerReadGroupInodeBitmap(lsb, gd, fd);
        gp->blockbitMap = CCheckerReadGroupBlockBitmap(lsb, gd, fd);
        dbg_printf ("Block Group BlockMap No[%u]   : 0x%x/crc=0x%x\n",
                        group, gd->bg_block_bitmap, gd->bg_block_bitmap_checksum);
        dbg_printf ("Block Group Free Blocks[%u]   : %u/%u\n",
                        group, gd->bg_free_blocks_count, CCheckerCountBitMap(gp->blockbitMap, 4096));
        dbg_printf ("Block Group InodeMap No[%u]   : 0x%x/crc=0x%x\n",
                        group, gd->bg_inode_bitmap, gd->bg_inode_bitmap_checksum);
        dbg_printf ("Block Group Free Inodes[%u]   : %u/%u\n",
                        group, gd->bg_free_inodes_count, CCheckerCountBitMap(gp->inodebitMap, 4096));
        dbg_printf ("Block Group InodeTable No[%u] : 0x%x/crc=0x%x, 0x%x\n",
                        group, gd->bg_inode_table, gd->bg_inode_table_checksum, gd->bg_checksum);

        CCheckerReadGroupInodeTable(lsb, gd, group, fd, gp->inodeMap, gp->inodebitMap);
        if (!gp->inodeMap.empty()) {
                dbg_printf("group=%u inode list:\n", group);
                for (auto &i : gp->inodeMap) {
                        dbg_printf("%u ", i.first);
                }
                dbg_printf("\n");
        }
        return gp;
}

static void CCheckerLuciLoadGroupDescriptorAll(int fd, struct luci_super_block *lsb) {
        int i = 0;
        struct luci_group_desc *gdesc;
        unsigned long nr_free_blocks = 0;
        unsigned long nr_free_blocks2 = 0;
        unsigned long nr_free_inodes = 0;
        unsigned block_size, nr_groups, nr_desc_per_block, nr_desc_blocks;

        block_size = (1024U << __le32_to_cpu(lsb->s_log_block_size));
        nr_desc_per_block = block_size/(sizeof(struct luci_group_desc));
        nr_groups = ((__le32_to_cpu(lsb->s_blocks_count) -
                        __le32_to_cpu(lsb->s_first_data_block) - 1) /
                        __le32_to_cpu(lsb->s_blocks_per_group)) + 1;
        nr_desc_blocks = (nr_groups + nr_desc_per_block - 1)/nr_desc_per_block;
        gdesc = (struct luci_group_desc *) malloc(nr_desc_blocks * block_size);

        // 2nd block GDT entries
        pread(fd, gdesc, block_size * nr_desc_blocks, block_size);

        dbg_printf ("Nr Groups : %u\n", nr_groups);
        dbg_printf ("Nr Group descriptor blocks :%u\n", nr_desc_blocks); 
        for (i = 0; i < nr_groups; i++) {
                Group *gp;
                dbg_printf ("GD :%u\n", i);
                struct luci_group_desc *gd = (struct luci_group_desc *)
                        ((char *)gdesc + i * sizeof(struct luci_group_desc));
                nr_free_blocks += gd->bg_free_blocks_count;
                nr_free_inodes += gd->bg_free_inodes_count;
                gp = CCheckerLuciLoadGroupDescriptorSingle(lsb, gd, i, fd);
                blockgroupMap[i] = gp;
        }
        dbg_printf("GDT Free Blocks :%u\n", nr_free_blocks);
        dbg_printf("GDT Free Inodes :%u\n", nr_free_inodes);
}

static void CCheckerLuciMissingBlocks(struct luci_super_block *lsb, int fd) {
        for (auto &i : blockgroupMap)
                CCheckerReadGroupInodeTable(lsb, i.second->gd, i.first, fd,
                        i.second->inodeMap, i.second->inodebitMap);
}

struct luci_super_block *CCheckerLuciLoadSuper(int fd) {
        struct luci_super_block *lsb = (struct luci_super_block *)malloc(1024);;
        pread(fd, lsb, 1024, 1024);
        dbg_printf ("SB Magic           :0x%x\n", lsb->s_magic);
        dbg_printf ("Nr Inodes          :%lu\n", lsb->s_inodes_count);
        dbg_printf ("Nr Blocks          :%lu\n", lsb->s_blocks_count);
        dbg_printf ("Nr Free Blocks     :%lu\n", lsb->s_free_blocks_count);
        dbg_printf ("Nr Free Inodes     :%lu\n", lsb->s_free_inodes_count);
        dbg_printf ("First DBlock       :%lu\n", lsb->s_first_data_block);
        dbg_printf ("Block Size         :%lu\n", (1024U << __le32_to_cpu(lsb->s_log_block_size)));
        dbg_printf ("Blocks Per Group   :%lu\n", lsb->s_blocks_per_group);
        dbg_printf ("Inodes Per Group   :%lu\n", lsb->s_inodes_per_group);
        dbg_printf ("InodeSize          :%lu\n", lsb->s_inode_size);
        dbg_printf ("Mount State        :%lu\n", lsb->s_state);
        return lsb;
}

static void TestFreeBlocksCount(struct luci_super_block *lsb,
                std::map<unsigned long, Group*> &blockgroupMap) {
        size_t sum_blocks = 0;
        for (auto &i : blockgroupMap)
                sum_blocks += i.second->gd->bg_free_blocks_count;
        assert(lsb->s_free_blocks_count == sum_blocks);
        printf ("CChecker:TestFreeBlocksCount pass\n");
}

static void TestFreeInodesCount(struct luci_super_block *lsb,
                std::map<unsigned long, Group*> &blockgroupMap) {
        size_t sum_inodes = 0;
        for (auto &i : blockgroupMap)
                sum_inodes += i.second->gd->bg_free_inodes_count;
        assert(lsb->s_free_inodes_count == sum_inodes);
        printf ("CChecker:TestFreeInodesCount pass\n");
}

static void TestMissingInodes(std::set<unsigned long>& InodeNotMarkedInBitMap) {
        assert(InodeNotMarkedInBitMap.empty());
        printf ("CChecker:TestMissingInodes pass\n");
}

static void TestDuplicateBlocks(std::set<unsigned long> &InodeWithDuplicateBlocks) {
        assert(InodeWithDuplicateBlocks.empty());
        printf ("CChecker:TestDuplicateBlocks pass\n");
}

static void TestMissingBlocks(std::set<unsigned long> &InodeBlocksNotMarkedInBitMap) {
        assert(InodeBlocksNotMarkedInBitMap.empty());
        printf ("CChecker:TestMissingBlocks pass\n");
}

static void TestDirLinks(std::map<unsigned long, unsigned>& globalDirMap) {
        struct luci_inode inode;
        for (auto &i : globalDirMap) {
                assert(globalInodeMap.find(i.first) != globalInodeMap.end());
                inode = globalInodeMap[i.first];
                assert(S_ISDIR(inode.i_mode));
                if (i.first == LUCI_ROOT_INO)
                        assert((i.second + 1) == inode.i_links_count);
                else
                        assert(i.second == inode.i_links_count);
                dbg_printf("links : inode :%u %u/%u\n", i.first, i.second,
                                inode.i_links_count);
        }
        printf ("CChecker:TestDirLinks pass\n");
}

static void TestOrphanInodes(std::list<unsigned long>& orphanInodeList) {
        assert(orphanInodeList.empty());
        printf ("CChecker:TestOrphanInodes pass\n");
}

static void TestDirCycle(cchecker_graph::Graph<long>& dirGraph) {
        assert(!cchecker_graph::DetectCycle<long>(dirGraph));
        printf ("CChecker:TestDirCycle pass\n");
}

int main(int argc, char *argv[]) {
        int fd;
        char *testdev;
        struct luci_super_block *lsb;

        if (argc < 2) {
                printf("need device path\n");
                return -1;
        }

        testdev = argv[1];
        fd = open(testdev, O_RDONLY);
        if (fd < 0) {
                printf("failed to open device:%s\n", strerror(errno));
                return -1;
        }

        lsb = CCheckerLuciLoadSuper(fd);
        checkdupBlockBitMap = new char[lsb->s_blocks_count/8];

        nr_pass = 1;
        CCheckerLuciLoadGroupDescriptorAll(fd, lsb);
        TestFreeBlocksCount(lsb, blockgroupMap);
        TestFreeInodesCount(lsb, blockgroupMap);
        TestMissingInodes(InodeNotMarkedInBitMap);
        TestDuplicateBlocks(InodeWithDuplicateBlocks);

        nr_pass = 2;
        CCheckerLuciMissingBlocks(lsb, fd);
        TestMissingBlocks(InodeBlocksNotMarkedInBitMap);
        TestDirLinks(globalDirMap);
        TestDirCycle(dirGraph);
        TestOrphanInodes(orphanInodeList);

        CleanupGroupList(blockgroupMap);
        delete [] checkdupBlockBitMap;
        blockgroupMap.clear();
        InodeWithDuplicateBlocks.clear();
        InodeBlocksNotMarkedInBitMap.clear();
        globalInodeMap.clear();
        globalDirMap.clear();

        free(lsb);
        close(fd);
        return 0;
}
