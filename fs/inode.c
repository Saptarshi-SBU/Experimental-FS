/*--------------------------------------------------------------------
 * Copyright(C) 2016, Saptarshi Sen
 *
 * LUCI inode operaitons
 *
 * ------------------------------------------------------------------*/
#include <linux/fs.h>
#include <linux/ktime.h>
#include <linux/mpage.h>
#include <linux/kernel.h>
#include <linux/blkdev.h>
#include <linux/dcache.h>
#include <linux/version.h>
#include <linux/writeback.h>
#include <linux/buffer_head.h>

#include "kern_feature.h"
#include "luci.h"

#define CREATE_TRACE_POINTS
#include "trace.h"

EXPORT_TRACEPOINT_SYMBOL_GPL(luci_get_block);
EXPORT_TRACEPOINT_SYMBOL_GPL(luci_write_inode_raw);

static atomic64_t readfile_in;
static atomic64_t readfile_out;

static atomic64_t writefile_in;
static atomic64_t writefile_out;

static atomic64_t writeback_in;
static atomic64_t writeback_out;

static atomic64_t setattr_in;
static atomic64_t setattr_out;

static atomic64_t getattr_in;
static atomic64_t getattr_out;

extern debugfs_t dbgfsparam;

static int
__luci_setsize(struct inode *inode, loff_t newsize)
{
    int err = 0;

    if (S_ISREG(inode->i_mode)) {
        luci_dbg_inode(inode, "oldsize %llu newsize %llu\n",
            inode->i_size, newsize);
        luci_truncate(inode, newsize); // update bmap

        truncate_setsize(inode, newsize);
        inode->i_mtime = inode->i_ctime = LUCI_CURR_TIME;
        if (inode_needs_sync(inode)) {
            sync_mapping_buffers(inode->i_mapping);
            sync_inode_metadata(inode, 1);
        } else
            mark_inode_dirty(inode);
    } else {
        err = -EINVAL;
        luci_err_inode(inode, "luci :cannot modify size of directory\n");
    }

    return err;
}

static int
luci_setattr(struct dentry *dentry, struct iattr *attr)
{
    int err = 0;
    struct inode *inode = DENTRY_INODE(dentry);

    atomic64_inc(&setattr_in);
    // check we have permissions to change attributes
#ifdef HAVE_CHECKINODEPERM
    err = inode_change_ok(inode, attr);
#else
    err = setattr_prepare(dentry, attr);
#endif
    if (err) {
        luci_err_inode(inode, "setattr failed :%d", err);
        return err ? err : -EPERM;
    }

    if (attr->ia_size != inode->i_size) {
        // We do not support DIO
        // Wait for all pending direct I/O requests prior doing a truncate
        // inode_dio_wait(inode);
        err = __luci_setsize(inode, attr->ia_size);
        if (err)
                goto exit;
    }

    setattr_copy(inode, attr);
    mark_inode_dirty(inode);

exit:
    atomic64_inc(&setattr_out);
    return err;
}

static int
__luci_getattr_private(const struct dentry *dentry, struct kstat *stat)
{
    struct inode *inode = DENTRY_INODE(dentry);

    generic_fillattr(inode, stat);
    stat->blksize = inode->i_sb->s_blocksize;
    return 0;
}

#ifdef HAVE_NEW_GETATTR
int
luci_getattr(const struct path *path,
             struct kstat *stat,
             u32 request_mask,
             unsigned int query_flags)
{
    int ret;

    atomic64_inc(&getattr_in);
    ret = __luci_getattr_private(path->dentry, stat);
    atomic64_inc(&getattr_out);
    return ret;
}
#else
int
luci_getattr(struct vfsmount *mnt,
             struct dentry *dentry,
             struct kstat *stat)
{
    int ret;
    atomic64_inc(&getattr_in);
    ret = __luci_getattr_private(dentry, stat);
    atomic64_inc(&getattr_out);
    return ret;
}
#endif

const struct inode_operations luci_file_inode_operations =
{
    .setattr = luci_setattr,
    .getattr = luci_getattr,
};

/* bmap functions */

/*
 * Use this function for updating metadata block checksum
 * All access to metadata blocks are protected by inode truncate mutex
 */
static int
luci_update_blkptr_chain_csum(struct inode *inode,
                              Indirect ichain[],
                              int depth,
                              unsigned long i_block)
{
    u32 crc32;
    Indirect *p;
    struct buffer_head *currbh;

    depth -= 1; // ignore leaf block/extent, already csummed

    while (depth-- > 0) {
        p = &ichain[depth];
        currbh = p->bh;
        BUG_ON(currbh == NULL || currbh->b_page == NULL);
        lock_buffer(currbh);
        crc32 = luci_compute_page_cksum(currbh->b_page, 0, PAGE_SIZE, ~0U);
        p->key.checksum = crc32;
        memcpy((char*)p->p, (char*)&p->key, sizeof(blkptr));
        mark_buffer_dirty(currbh);
        unlock_buffer(currbh);
        luci_info("%s meta cksum, inode :%lu i_block :%lu depth :%u bp {%u/0x%x}",
                  "updated",
                  inode->i_ino,
                  i_block,
                  depth,
                  p->key.blockno,
                  p->key.checksum);
    }

    // This is needed, since modifications propagate till root indices which
    // are part of inode.
    mark_inode_dirty(inode);
    return 0;
}

/*
 * Use this function for only metadata block verification
 * All access to metadata blocks are protected by mutex
 */
static int
luci_validate_bmap_blkptr_csum(struct inode *inode,
                               int curr_level,
                               int max_depth,
                               struct buffer_head *bh,
                               struct blkptr *bp)
{
    u32 crc32;
    int err = 0;

    BUG_ON(bh == NULL || bh->b_page == NULL || bh->b_page->mapping == NULL);

    lock_buffer(bh);

    if (buffer_dirty(bh) || !bp->checksum) {
        luci_info("bh is dirty or has zero csum, cannot verify csum");
        goto exit;
    }

    if (bp->flags) {
        luci_err_inode(inode, "unexpected flag detected in bmap blockptr ipath[%d/%d] %u-0x%x-0x%u[0x%x]",
                            curr_level,
                            max_depth,
                            bp->blockno,
                            bp->flags,
                            bp->length,
                            bp->checksum);
        return -EIO;
        BUG_ON(bp->flags);
    }

    crc32 = luci_compute_page_cksum(bh->b_page, 0, PAGE_SIZE, ~0U);
    if (bp->checksum != crc32) {
        err = -EBADE;
        luci_err("meta csum ERROR, inode :%lu depth :%u/%u "
                 "bp {%u/ EXP :0x%x GOT :0x%x}",
                 inode->i_ino,
                 curr_level,
                 max_depth,
                 bp->blockno,
                 bp->checksum,
                 crc32);
    } else
        luci_info("meta csum OK, inode :%lu depth :%u/%u bp {%u/0x%x}",
                 inode->i_ino,
                 curr_level,
                 max_depth,
                 bp->blockno,
                 bp->checksum);

exit:
    unlock_buffer(bh);
    return err;
}

static inline void
luci_bmap_add_chain(Indirect *p, struct buffer_head *bh, blkptr *v)
{
    p->p = v;
    p->bh = bh;
    memcpy((char*)&p->key, (char*)v, sizeof(blkptr));
}

/* bmap search */
static int
luci_bmap_get_indices(struct inode *inode,
                   long i_block,
                   long path[LUCI_MAX_DEPTH],
                   int *blocks_to_boundary)
{
    int n = 0;
    int final = 0;
    const long file_block = i_block;
    const long nr_direct = LUCI_NDIR_BLOCKS;
    const long nr_indirect = LUCI_ADDR_PER_BLOCK(inode->i_sb);
    const long nr_dindirect = (1 << (LUCI_ADDR_PER_BLOCK_BITS(inode->i_sb) * 2));

    BUG_ON(i_block < 0);

    if (i_block < nr_direct) {
        path[n++] = i_block;
        final = nr_direct;
        luci_dbg("block %ld maps to a direct block", file_block);
        goto done;
    }

    i_block -= nr_direct;
    if (i_block < nr_indirect) {
        path[n++] = LUCI_IND_BLOCK;
        path[n++] = i_block;
        final = nr_indirect;
        luci_dbg("block %ld maps to an indirect block", file_block);
        goto done;
    }

    i_block -= nr_indirect;
    if (i_block < nr_dindirect) {
        path[n++] = LUCI_DIND_BLOCK;
        path[n++] = i_block >> LUCI_ADDR_PER_BLOCK_BITS(inode->i_sb);
        path[n++] = i_block & (LUCI_ADDR_PER_BLOCK(inode->i_sb) - 1);
        final = nr_indirect;
        luci_dbg("block %ld maps to a double indirect block", file_block);
        goto done;
    }

    i_block -= nr_dindirect;
    if ((i_block >> (LUCI_ADDR_PER_BLOCK_BITS(inode->i_sb) * 2)) <
            LUCI_ADDR_PER_BLOCK(inode->i_sb)) {
        path[n++] = LUCI_TIND_BLOCK;
        path[n++] = i_block >> (LUCI_ADDR_PER_BLOCK_BITS(inode->i_sb) * 2);
        path[n++] = (i_block >> LUCI_ADDR_PER_BLOCK_BITS(inode->i_sb)) &
            (LUCI_ADDR_PER_BLOCK(inode->i_sb) - 1);
        path[n++] = i_block & (LUCI_ADDR_PER_BLOCK(inode->i_sb) - 1);
        final = nr_indirect;
        luci_dbg("block %ld maps to a triple indirect block", file_block);
        goto done;
    }

    luci_err_inode(inode, "file block :%lu exceeds bmap limits", file_block);
    return -E2BIG;

done:
    if (blocks_to_boundary)
        *blocks_to_boundary = final - path[n - 1];

    luci_info_inode(inode,"i_block :%lu n:%d bmap indices :%ld :%ld :%ld :%ld",
       file_block, n, path[0], path[1], path[2], path[3]);
    return n;
}

/* In case of error lets continue scanning the entire path */
static Indirect *
luci_bmap_get_path(struct inode *inode,
                   int depth,
                   long ipaths[LUCI_MAX_DEPTH],
                   Indirect ichain[LUCI_MAX_DEPTH],
                   int *err,
                   int flags)
{
    int i = 0, ret = 0;
    Indirect *p = ichain;
    struct buffer_head *bh = NULL;
    struct super_block *sb = inode->i_sb;
    unsigned long parent_block = 0; // only for debug
    bool skip_leaf = (S_ISREG(inode->i_mode) &&
                     ((flags & COMPR_BLK_INSERT) || (flags & COMPR_BLK_UPDATE) || (flags & COMPR_BLK_INFO)));

    BUG_ON(!depth);

    *err = 0;

    if (depth == 1)
        luci_bmap_add_chain (p, NULL, LUCI_I(inode)->i_data + *ipaths);
    else {
        luci_bmap_add_chain (p, NULL, LUCI_I(inode)->i_data + *ipaths);
        if ((bh = sb_bread(sb, p->key.blockno)) == NULL)
            panic("metadata read error inode :%lu ipath[%d]%u",
                inode->i_ino, depth, p->key.blockno);
        p->bh = bh;
    }

    if (!p->key.blockno) {
        luci_dbg_inode(inode, "root chain :ipath :%ld :%p", *ipaths, p->p);
        goto no_block;
    }

    if (depth > 1)
        *err = luci_validate_bmap_blkptr_csum(inode, i, depth, p->bh, &p->key);

    luci_info_inode(inode, "bmap get path, ipath[%d] %d-%u-%u-0x%x[%ld]",
                            i,
                            p->key.blockno,
                            p->key.flags,
                            p->key.length,
                            p->key.checksum,
                            *ipaths);

    while (++i < depth) {
        parent_block = p->key.blockno;

        luci_bmap_add_chain(++p, NULL, (blkptr*)bh->b_data + *++ipaths);
        if (!p->key.blockno)
            goto no_block;

        if ((i + 1 == depth) && skip_leaf)
                break;

        if ((bh = sb_bread(sb, p->key.blockno)) == NULL)
            panic("metadata read error inode :%lu ipath[%d]%u",
                inode->i_ino, depth, p->key.blockno);
        else
            p->bh = bh;

        luci_info_inode(inode, "bmap get path, ipath[%d] %d-%u-%u-0x%x[%ld][%lu]",
                                i,
                                p->key.blockno,
                                p->key.flags,
                                p->key.length,
                                p->key.checksum,
                                *ipaths,
                                parent_block);
        if (i + 1 < depth)
            ret = luci_validate_bmap_blkptr_csum(inode, i, depth, p->bh, &p->key);

        if (!*err)
               *err = ret;
    }

    return NULL;

no_block:
    luci_info("found no key in block path walk at level %d for inode :%lu "
       "ipaths :%ld", i, inode->i_ino, *ipaths);
    return p;
}

/*
 * traverses bmap based on indices from getpath and populates block entries.
 *
 * Notes:
 *      meta data buffers are not part of inode's address space. They
 *      do not lie in radix tree pages for the inode. They are part of
 *      bdev's address space. Here we, add buffers to inode's address
 *      space private list as part of associated mapping. (note we use
 *      sb_bread/sb_getblk for creating pages for meta data, wherein we
 *      pass super block and not the inode itself)
 */
static int
luci_bmap_allocate_entry(struct inode *inode,
                         Indirect ichain[],
                         long index[],
                         int curr_level,
                         int depth,
                         unsigned long i_block)
{
    int bmap_index;
    unsigned long curr_block;
    struct buffer_head *parent_bh, *currbh;

    BUG_ON (curr_level > LUCI_MAX_DEPTH);

    if (curr_level >= depth) // base case
        return 0;

    if (luci_new_block(inode, 1, &curr_block) < 0)
        panic("block allocation failed\n");

    if ((currbh = sb_getblk(inode->i_sb, curr_block)) == NULL)
        panic("block read failed for %lu/%lu\n", curr_block, i_block);

    lock_buffer(currbh);

    // b_data comes mapped
    memset(currbh->b_data, 0, currbh->b_size);
    set_buffer_uptodate(currbh);

    ichain[curr_level].key.blockno = curr_block;
    ichain[curr_level].key.checksum =
            luci_compute_page_cksum(currbh->b_page, 0, PAGE_SIZE, ~0U);
    ichain[curr_level].bh = currbh;

    unlock_buffer(currbh);

    mark_buffer_dirty(currbh);

    // lookup bmap memory index to update block entry
    bmap_index = index[curr_level];
    if (IS_INLINE(curr_level)) {
        parent_bh = NULL;
        ichain[curr_level].p = (blkptr*) LUCI_I(inode)->i_data + bmap_index;
    } else {
        parent_bh = ichain[curr_level - 1].bh;
        if (!parent_bh)
            panic("parent bh null %lu (%d-%d-%lu)\n", inode->i_ino,
                curr_level, depth, i_block);
        ichain[curr_level].p = (blkptr*) parent_bh->b_data + bmap_index;
        lock_buffer(parent_bh);
    }

    // imp : update memory index (i_data array)
    memcpy((char*)ichain[curr_level].p,
           (char*)&ichain[curr_level].key,
           sizeof(blkptr));

    if (parent_bh != NULL) {
        // scan and dump all entries in an indirect block
        #ifdef DEBUG_BLOCK_PARANOIA
        int i;
        for (i = 0; i <= bmap_index; i++) {
            blkptr *bp = (blkptr*) parent_bh->b_data + i;
            luci_info_inode(inode, "bmap entry [%d] level [%d] for iblock %lu "
                "block[%u-%lu-%u-%u-0x%x]", i, curr_level, i_block,
                parent_bh->b_blocknr, ichain[curr_level - 1].key.blockno,
                bp->blockno, bp->checksum);
        }
        #endif
        unlock_buffer(parent_bh);
        mark_buffer_dirty(parent_bh);
    } else
        mark_inode_dirty(inode);

    luci_info_inode(inode, "created bmap entry, iblock %lu level %d-%u(%d) "
        "block %u index %u\n", i_block, curr_level, bmap_index, depth,
        ichain[curr_level].key.blockno, bmap_index);

    return luci_bmap_allocate_entry(inode,
                                    ichain,
                                    index,
                                    ++curr_level,
                                    depth,
                                    i_block);
}

static int
luci_bmap_insert_entry(struct inode *inode,
                       Indirect ichain[],
                       long index[],
                       int curr_level,
                       int depth,
                       unsigned long i_block,
                       struct buffer_head *bh)
{
    int bmap_index;
    unsigned long curr_block;
    struct buffer_head *parent_bh, *currbh;

    BUG_ON (curr_level > LUCI_MAX_DEPTH);

    if (curr_level >= depth) // base case
        return 0;

    // only allocate till L1 block
    if (curr_level + 1 < depth) {

        if (luci_new_block(inode, 1, &curr_block) < 0)
            panic("block allocation failed\n");

        if ((currbh = sb_getblk(inode->i_sb, curr_block)) == NULL)
            panic("block read failed for %lu/%lu", curr_block, i_block);

        ichain[curr_level].key.blockno = curr_block;
        ichain[curr_level].bh = currbh;

        lock_buffer(currbh);

        memset(currbh->b_data, 0, currbh->b_size);
        set_buffer_uptodate(currbh);

        unlock_buffer(currbh);

        mark_buffer_dirty(currbh);

    } else {
        // update L1 block with L0 block ptr
        ichain[curr_level].bh = NULL;
        ichain[curr_level].key.blockno = bh->b_blocknr;
        ichain[curr_level].key.checksum = *(u32*)(bh->b_data);

        if ((bh->b_state & BH_PrivateStart)) {
            ichain[curr_level].key.flags |= LUCI_COMPR_FLAG;
            ichain[curr_level].key.length = (unsigned int) bh->b_size;
        }
    }

    bmap_index = index[curr_level];
    if (curr_level == 0) {
        parent_bh = NULL;
        ichain[curr_level].p = (blkptr*) LUCI_I(inode)->i_data + bmap_index;
    } else {
        parent_bh = ichain[curr_level - 1].bh;
        if (!parent_bh)
            panic("parent bh null %lu (%d-%d-%lu)",
                inode->i_ino, curr_level, depth, i_block);

        ichain[curr_level].p = (blkptr*) parent_bh->b_data + bmap_index;
        lock_buffer(parent_bh);
    }

    // imp : update memory index (i_data array)
    memcpy((char*)ichain[curr_level].p,
           (char*)&ichain[curr_level].key,
           sizeof(blkptr));

    if (parent_bh != NULL) {
        #ifdef DEBUG_BLOCK_PARANOIA
        int i;
        for (i = bmap_index; i <= bmap_index; i++) {
            blkptr *bp = (blkptr*) parent_bh->b_data + i;
            luci_info_inode(inode, "bmap entry [%d] level [%d] for iblock %lu "
                "block[%u-%lu-%u-%u-0x%x]",
                 i,
                 curr_level,
                 i_block,
                 parent_bh->b_blocknr,
                 ichain[curr_level - 1].key.blockno,
                 bp->blockno,
                 bp->checksum);
        }
        #endif
        unlock_buffer(parent_bh);
        //mark_buffer_dirty_inode(parent_bh, inode);
        mark_buffer_dirty(parent_bh);
    } else
        mark_inode_dirty(inode);

    luci_info_inode(inode, "inserted bmap entry, iblock %lu level :%d(%d) "
        "block %u(%x-%u-0x%x) index %u",
        i_block,
        curr_level,
        depth,
        ichain[curr_level].key.blockno,
        ichain[curr_level].key.flags,
        ichain[curr_level].key.length,
        ichain[curr_level].key.checksum,
        bmap_index);

    return luci_bmap_insert_entry(inode,
                                  ichain,
                                  index,
                                  ++curr_level,
                                  depth,
                                  i_block,
                                  bh);
}

// We are abusing luci_get_block for updating block pointer
// since it has common code for walking indirect block map.
int
luci_get_block(struct inode *inode,
               sector_t iblock,
               struct buffer_head *bh_result,
               int flags)
{
    int err = 0;
    int depth = 0;
    u32 block_no = 0;
    int nr_blocks = 0;
    int blocks_to_boundary = 0;
    Indirect *partial;
    long ipaths[LUCI_MAX_DEPTH];
    Indirect ichain[LUCI_MAX_DEPTH];

    BUG_ON(bh_result == NULL);

    memset((char*)ipaths, 0, sizeof(long)*LUCI_MAX_DEPTH);
    memset((char*)ichain, 0, sizeof(Indirect)*LUCI_MAX_DEPTH);

    depth = luci_bmap_get_indices(inode,
                                  iblock,
                                  ipaths,
                                  &blocks_to_boundary);
    if (depth < 0)
        return -EIO;

    //buffer forms boundary of contig blocks, (BH_Boundary)
    if (!blocks_to_boundary)
        set_buffer_boundary(bh_result);

    luci_dbg_inode(inode, "mapping block, i_block %lu, depth %d op :%s",
                          iblock,
                          depth,
                          flags ? "create" : "lookup");

    mutex_lock(&(LUCI_I(inode)->truncate_mutex));

    partial = luci_bmap_get_path(inode, depth, ipaths, ichain, &err, flags);
    if (err < 0) {
        luci_err_inode(inode, "bmap path error %d", err);
        goto exit;
    }

    if (flags & COMPR_BLK_INFO)
            flags = 0;

    // L0 block exists
    if (!partial) {

        // update L0 block entry on COW
        if (S_ISREG(inode->i_mode) &&
           ((flags & COMPR_BLK_INSERT) || (flags & COMPR_BLK_UPDATE))) {

            // update L0 block ptr at L1
            BUG_ON(ichain[depth - 1].p == NULL);
            ichain[depth - 1].p->blockno = bh_result->b_blocknr;
            ichain[depth - 1].p->checksum = *(u32*)bh_result->b_data;
            if (bh_result->b_state & BH_PrivateStart) {
                ichain[depth - 1].p->flags |= LUCI_COMPR_FLAG;
                ichain[depth - 1].p->length = (unsigned short) bh_result->b_size;
            }

            luci_info_inode(inode, "COW L0 block iblock :%lu, %u(%x-%u-0x%x) "
                "depth :%d",
                iblock,
                ichain[depth - 1].p->blockno,
                ichain[depth - 1].p->flags,
                ichain[depth - 1].p->length,
                ichain[depth - 1].p->checksum,
                depth);

            // FIXED: on exit free buffer-heads allocated during block lookup
            goto done;
        }

gotit:
        block_no = ichain[depth - 1].key.blockno;

        // BH_Mapped, bh blockno, length
        map_bh(bh_result, inode->i_sb, block_no);

        // hack to fetch bp checksum from bmap lookup
        if (bh_result->b_state & BH_PrivateStart)
            *(u32*) bh_result->b_data = ichain[depth - 1].key.checksum;

        // update bp size with compressed length
        if (ichain[depth - 1].key.flags & LUCI_COMPR_FLAG)
            bh_result->b_size = (size_t) ichain[depth - 1].key.length;
        else
            bh_result->b_state &= ~BH_PrivateStart;

        luci_dump_blkptr(inode, iblock, &ichain[depth - 1].key);

        luci_info_inode(inode, "i_block :%lu paths :%d :%d :%d :%d",
                        iblock,
                        ichain[0].key.blockno,
                        ichain[1].key.blockno,
                        ichain[2].key.blockno,
                        ichain[3].key.blockno);

    } else {
    // L0 block does not exist

        if (flags) {
            nr_blocks = (ichain + depth) - partial;
            BUG_ON(nr_blocks == 0);
            if (S_ISREG(inode->i_mode) && (flags & COMPR_BLK_INSERT)) {
                err = luci_bmap_insert_entry(inode,
                                             ichain,
                                             ipaths,
                                             partial - ichain,
                                             depth,
                                             iblock,
                                             bh_result);
                BUG_ON(err);
                goto done;
            } else {
                err = luci_bmap_allocate_entry(inode,
                                               ichain,
                                               ipaths,
                                               partial - ichain,
                                               depth,
                                               iblock);
                BUG_ON(err);
                goto gotit;
           }
        } else
            // We have a hole. mpage API identifies a hole if bh is not mapped.
            // So we are fine even if we do not have an block created for a hole.
            luci_info_inode(inode, "found hole at i_block :%lu", iblock);
    }

done:

    if (flags)
        err = luci_update_blkptr_chain_csum(inode, ichain, depth, iblock);

    // FIXED : free bhs associated with lookup, meta pages are already in memory
    partial = ichain + depth - 1;
    while (partial >= ichain) {
        if (partial->bh != NULL)
            brelse(partial->bh);
        partial--;
    }

exit:

    if (!dbgfsparam.inode_inspect || (dbgfsparam.inode_inspect == inode->i_ino)) {
        #ifdef HAVE_TRACEPOINT_ENABLED
        if (trace_luci_get_block_enabled())
        #endif
                trace_luci_get_block(inode, iblock, ichain, flags);
    }

    mutex_unlock(&(LUCI_I(inode)->truncate_mutex));
    return err;
}
EXPORT_SYMBOL_GPL(luci_get_block);

/*
 * Scan inode bmap meta data. We scan till max depth for cases where file
 * is sparse.
 */
static int
luci_bmap_scan_metacsum(struct inode  *inode)
{
    int i = 0, err = 0;
    long nr_direct = LUCI_NDIR_BLOCKS;
    long nr_indirect = LUCI_ADDR_PER_BLOCK(inode->i_sb);
    long nr_dindirect = (1 << (LUCI_ADDR_PER_BLOCK_BITS(inode->i_sb) * 2));
    long i_blocks[] = {
            0,
            nr_direct,
            nr_direct + nr_indirect,
            nr_direct + nr_indirect + nr_dindirect
    };
    struct buffer_head bh;

    luci_info_inode(inode, "scanning inode metadata");
    do {
        memset((char*)&bh, 0, sizeof(bh));
        err = luci_get_block(inode, i_blocks[i++], &bh, 0);
    } while (!err && i < LUCI_MAX_DEPTH);

    return err;
}

// get bp info from bmap via bh entry
blkptr
luci_bmap_fetch_L0bp(struct inode *inode,
                     unsigned long i_block)
{
    blkptr bp;
    struct buffer_head bh;

    memset((char*)&bp, 0, sizeof(blkptr));
    memset((char*)&bh, 0, sizeof(struct buffer_head));

    bh.b_state = BH_PrivateStart;
    bh.b_data = (void *)&bp.checksum;
    if (luci_get_block(inode, i_block, &bh, COMPR_BLK_INFO) < 0)
        panic("error L0 bp, inode :%lu i_block: %lu", inode->i_ino, i_block);

    // BH_Mapped
    if (buffer_mapped(&bh)) {
        bp.blockno = bh.b_blocknr;
        bp.checksum = *(u32*)bh.b_data;
        bp.length = (unsigned int)bh.b_size;
        if (bh.b_state & BH_PrivateStart)
            bp.flags = LUCI_COMPR_FLAG;
        luci_dump_blkptr(inode, i_block, &bp);
    }
    return bp;
}

// passthrough bp info to bmap via bh entry
int
luci_bmap_insert_L0bp(struct inode *inode,
                      unsigned long i_block,
                      blkptr *bp)
{
    int ret;
    struct buffer_head bh;
    struct super_block *sb = inode->i_sb;

    // sanity
    BUG_ON(bp->blockno > blkdev_max_block(sb->s_bdev));

    memset((char*)&bh, 0, sizeof(struct buffer_head));
    bh.b_blocknr = bp->blockno;
    bh.b_data = (void *)&bp->checksum;

    if (bp->flags == LUCI_COMPR_FLAG) {
        bh.b_size = (size_t) bp->length;
        bh.b_state = BH_PrivateStart; // flag for compressed block
    }

    ret = luci_get_block(inode,
                         i_block,
                         &bh,
                         COMPR_BLK_UPDATE | COMPR_BLK_INSERT);
    if (ret < 0)
        luci_err_inode(inode, "error inserting leaf i_block :%lu", i_block);

    return ret;
}

static int
luci_account_delta(blkptr bp_old [],
                   blkptr bp_new [],
                   unsigned nr_blocks)
{
    blkptr old, new;
    int i, delta = 0, bytes_uncomp = 0;
    bool new_extent = true, prv_extent = true;

    BUG_ON(nr_blocks == 0);
    for (i = 0; i < nr_blocks; i++) {
        old = bp_old[i];
        new = bp_new[i];

        if ((old.flags & LUCI_COMPR_FLAG) && (new.flags & LUCI_COMPR_FLAG)) {
            delta += (sector_align(new.length) - sector_align(old.length));
            break;
        } else if (new.flags & LUCI_COMPR_FLAG) {
            bytes_uncomp += sector_align(old.length);
            prv_extent = false;
        } else if (old.flags & LUCI_COMPR_FLAG) {
            bytes_uncomp += sector_align(new.length);
            new_extent = false;
        } else
            delta += (sector_align(new.length) - sector_align(old.length));
    }

    if (!new_extent)
        delta += (bytes_uncomp - old.length);
    else if (!prv_extent)
        delta += (new.length - bytes_uncomp);
    return delta;
}

static void
luci_extent_range(struct page *page,
                  unsigned long *begin,
                  unsigned long *end)
{
    unsigned nr_blocks;
    struct inode *inode;

    BUG_ON(page->mapping == NULL);

    inode = page->mapping->host;
    nr_blocks = EXTENT_NRBLOCKS(inode->i_sb);
    *begin = luci_extent_no(page->index) * nr_blocks;
    *end = *begin + nr_blocks - 1;
}

static void
luci_bmap_lookup_extent_bp(struct page *page,
                           struct inode *inode,
                           blkptr bp_array [])
{
    blkptr bp;
    unsigned long i, b_i, b_start, b_end;

    luci_extent_range(page, &b_start, &b_end);

    for (b_i = b_start, i = 0; b_i <= b_end; b_i++, i++) {
        BUG_ON(i >= EXTENT_NRBLOCKS_MAX);
        bp = luci_bmap_fetch_L0bp(inode, b_i);
        bp_array[i] = bp;
    }
}

int
luci_bmap_update_extent_bp(struct page *page,
                           struct inode *inode,
                           blkptr bp_new [])
{
    int delta;
    unsigned long extent;
    unsigned long i, b_i, b_start, b_end, blockno = 0;
    blkptr bp_old[EXTENT_NRBLOCKS_MAX];

    extent = luci_extent_no(page_index(page));
    luci_dbg_inode(inode, "lookup bp for extent %lu(%lu)", extent,
        page_index(page));

    // save the old bp
    luci_bmap_lookup_extent_bp(page, inode, bp_old);

    luci_extent_range(page, &b_start, &b_end);

    // update block pointer
    for (i = 0, b_i = b_start; b_i <= b_end; b_i++, i++) {
        if (luci_bmap_insert_L0bp(inode, b_i, &bp_new[i]) < 0)
            BUG();

        luci_info_inode(inode, "updated bp %u-%x-%u(%u)-0x%x for file block %lu"
                               " extent %lu",
                                bp_new[i].blockno,
                                bp_new[i].flags,
                                bp_new[i].length,
                                bp_old[i].blockno,
                                bp_new[i].checksum,
                                b_i,
                                extent);

        // for compressed extent, start blkptr spans across file offsets entries
        if (blockno && blockno == bp_old[i].blockno)
                continue;
        // TBD : add comment why block entry can be zero
        blockno = bp_old[i].blockno;
        if (blockno)
                luci_free_block(inode, blockno);
    }

    delta = luci_account_delta(bp_old, bp_new, i);
    luci_dbg_inode(inode, "delta bytes :%d", delta);
    return delta;
}

static int
luci_bmap_delete_compressed_bp(struct inode *inode, struct blkptr *bp)
{
        int ret = 0;
        unsigned long block;
        unsigned blksize = LUCI_BLOCK_SIZE(inode->i_sb);
        unsigned nblocks = (bp->length + blksize - 1) / blksize;

        for (block = bp->blockno; block <= nblocks; block++) {
                if ((ret = luci_free_block(inode, block)) < 0)
                        break;
        }
        return ret;
}

int
luci_bmap_free_extents(struct inode *inode,
                       blkptr extents_array[],
                       int n_extents)
{
        blkptr bp;
        int i, err = 0;
        for (i = 0; i < n_extents; i++) {
                if (i && bp.blockno == extents_array[i].blockno)
                        continue;
                bp = extents_array[i];
                err = luci_bmap_delete_compressed_bp(inode, &bp);
                break;
        }
        return err;
}

#ifdef DEBUG_BLOCK2
static void
luci_check_bp(struct inode *inode, unsigned long file_block)
{
    blkptr bp = luci_bmap_fetch_L0bp(inode, file_block);
    luci_dump_blkptr(inode, file_block, &bp);
}
#endif

static struct luci_inode*
luci_get_inode(struct super_block *sb,
               ino_t ino,
               struct buffer_head **p)
{
    struct buffer_head * bh;
    unsigned long block_group;
    unsigned long block;
    unsigned long offset;
    struct luci_group_desc * gdp;

    *p = NULL;
    if ((ino != LUCI_ROOT_INO && ino < LUCI_FIRST_INO(sb)) ||
         ino > le32_to_cpu(LUCI_SB(sb)->s_lsb->s_inodes_count))
        goto Einval;

    block_group = (ino - 1) / LUCI_INODES_PER_GROUP(sb);
    gdp = luci_get_group_desc(sb, block_group, NULL);
    if (!gdp)
        goto Egdp;

    // calc offset within the block group inode table
    offset = ((ino - 1) % LUCI_INODES_PER_GROUP(sb)) * LUCI_INODE_SIZE(sb);
    block = le32_to_cpu(gdp->bg_inode_table) +
                       (offset >> LUCI_BLOCK_SIZE_BITS(sb));
    if (!(bh = sb_bread(sb, block)))
        goto Eio;

    *p = bh;
    offset &= (LUCI_BLOCK_SIZE(sb) - 1);
    return (struct luci_inode *) (bh->b_data + offset);

Einval:
    luci_err("bad inode number: %lu", (unsigned long) ino);
    return ERR_PTR(-EINVAL);
Eio:
    luci_err("unable to read inode block - inode=%lu, block=%lu",
       (unsigned long) ino, block);
Egdp:
    return ERR_PTR(-EIO);
}

/*
 * This code path gets trigerred when the inode has already been created
 * on disk and we are fetching inode. inode is loaded with raw inode
 * details from disk.
 */
struct inode *
luci_iget(struct super_block *sb, unsigned long ino) {
    int n, err = 0;
    struct inode *inode;
    struct luci_inode_info *li;
    struct luci_inode *raw_inode;
    unsigned long block_group;
    unsigned long block_no;
    struct buffer_head *bh;
    struct luci_group_desc *gdesc;
    uint32_t offset;

    inode = iget_locked(sb, ino);

    if (!inode)
        return ERR_PTR(-ENOMEM);

    if (!(inode->i_state & I_NEW))
        return inode;

    if ((ino != LUCI_ROOT_INO && ino < LUCI_FIRST_INO(sb)) ||
            (ino > le32_to_cpu(LUCI_SB(sb)->s_lsb->s_inodes_count))) {
        return ERR_PTR(-EINVAL);
    }

    block_group = (ino - 1)/LUCI_SB(sb)->s_inodes_per_group;
    block_no = block_group/LUCI_SB(sb)->s_desc_per_block;
    offset = block_group & (LUCI_SB(sb)->s_desc_per_block - 1);
    gdesc = (struct luci_group_desc *)
        LUCI_SB(sb)->s_group_desc[block_no]->b_data + offset;
    if (!gdesc) {
        return ERR_PTR(-EIO);
    }

    offset = ((ino - 1) % (LUCI_SB(sb)->s_inodes_per_group)) *
        (LUCI_SB(sb)->s_inode_size);
    block_no = gdesc->bg_inode_table +
        (offset >> sb->s_blocksize_bits);
    if (!(bh = sb_bread(sb, block_no))) {
        return (ERR_PTR(-EIO));
    }

    offset &= (sb->s_blocksize - 1);
    raw_inode = (struct luci_inode*)(bh->b_data + offset);
    inode->i_mode = le16_to_cpu(raw_inode->i_mode);
    set_nlink(inode, le16_to_cpu(raw_inode->i_links_count));
    inode->i_size = le32_to_cpu(raw_inode->i_size);
    if (S_ISREG(inode->i_mode)) {
        inode->i_size |= (((uint64_t)(le32_to_cpu(raw_inode->i_dir_acl))) << 32);
    }

    //luci_info_inode(inode, "inode size low :%u high :%u",
    //   raw_inode->i_size, raw_inode->i_dir_acl);
    if (i_size_read(inode) < 0)
        return ERR_PTR(-EFSCORRUPTED);

    inode->i_atime.tv_sec = (signed)le32_to_cpu(raw_inode->i_atime);
    inode->i_ctime.tv_sec = (signed)le32_to_cpu(raw_inode->i_ctime);
    inode->i_mtime.tv_sec = (signed)le32_to_cpu(raw_inode->i_mtime);
    inode->i_atime.tv_nsec = inode->i_mtime.tv_nsec = inode->i_ctime.tv_nsec = 0;
    inode->i_blocks = le32_to_cpu(raw_inode->i_blocks);
    inode->i_generation = le32_to_cpu(raw_inode->i_generation);

    li = LUCI_I(inode);
    li->i_block_alloc_info = NULL;
    li->i_flags = le32_to_cpu(raw_inode->i_flags);
    li->i_dtime = 0;
    li->i_state = 0;
    li->i_block_group = (ino - 1)/LUCI_SB(sb)->s_inodes_per_group;
    li->i_active_block_group = li->i_block_group;
    li->i_dir_start_lookup = 0;
    li->i_dtime = le32_to_cpu(raw_inode->i_dtime);
#ifdef LUCIFS_COMPRESSION
    li->i_size_comp = raw_inode->osd1.linux1.l_i_reserved1;
#endif

    if (inode->i_nlink == 0 && (inode->i_mode == 0 || li->i_dtime)) {
        /* this inode is deleted */
        brelse (bh);
        iget_failed(inode);
        return ERR_PTR(-ESTALE);
    }

    luci_dbg_inode(inode, "nr_blocks :%lu",
       (inode->i_blocks*512)/sb->s_blocksize);
    for (n = 0; n < LUCI_N_BLOCKS; n++) {
        li->i_data[n] = raw_inode->i_block[n];
        luci_dbg_inode(inode, "i_data[%d]:%u", n, li->i_data[n].blockno);
    }

    err = luci_bmap_scan_metacsum(inode);
    if(err < 0)
        return ERR_PTR(err);

    if (S_ISREG(inode->i_mode)) {
        inode->i_op = &luci_file_inode_operations;
        inode->i_mapping->a_ops = &luci_aops;
        inode->i_fop = &luci_file_operations;
    } else if (S_ISDIR(inode->i_mode)) {
        inode->i_op = &luci_dir_inode_operations;
        inode->i_mapping->a_ops = &luci_aops;
        inode->i_fop = &luci_dir_operations;
    } else {
        luci_err("Inode mode not supported");
    }

    brelse(bh);

    // clears the new state
    unlock_new_inode(inode);
    return inode;
}

int
luci_write_inode_raw(struct inode *inode, int do_sync)
{
    int n, err = 0;
    struct super_block *sb = inode->i_sb;
    struct buffer_head *bh;
    struct luci_inode *raw_inode;
    struct luci_inode_info *ei = LUCI_I(inode);

    raw_inode = luci_get_inode(sb, inode->i_ino, &bh);
    if (IS_ERR(raw_inode))
        return -EIO;

    /* For fields not not tracking in the in-memory inode,
     * initialise them to zero for new inodes. */
    if (ei->i_state & LUCI_STATE_NEW)
        memset(raw_inode, 0, LUCI_SB(sb)->s_inode_size);

    raw_inode->i_mode = cpu_to_le16(inode->i_mode);

    raw_inode->i_links_count = cpu_to_le16(inode->i_nlink);
    raw_inode->i_size = cpu_to_le32(inode->i_size);
    // Use dir_acl for storing high bits for files > 4GB
    // Note inode->i_size is lofft , but luci inode i_size is 32bits
    raw_inode->i_dir_acl = cpu_to_le32(inode->i_size >> 32);
    raw_inode->i_atime = cpu_to_le32(inode->i_atime.tv_sec);
    raw_inode->i_ctime = cpu_to_le32(inode->i_ctime.tv_sec);
    raw_inode->i_mtime = cpu_to_le32(inode->i_mtime.tv_sec);

    // i_blocks count is sector based (512 bytes)
    raw_inode->i_blocks = cpu_to_le32(inode->i_blocks);
    raw_inode->i_dtime = cpu_to_le32(ei->i_dtime);
    raw_inode->i_flags = cpu_to_le32(ei->i_flags);
    raw_inode->i_faddr = cpu_to_le32(ei->i_faddr);
    raw_inode->i_file_acl = cpu_to_le32(ei->i_file_acl);

#ifdef LUCIFS_COMPRESSION
    raw_inode->osd1.linux1.l_i_reserved1 = cpu_to_le32(ei->i_size_comp);
#endif
    raw_inode->i_generation = cpu_to_le32(inode->i_generation);

    for (n = 0; n < LUCI_N_BLOCKS; n++)
        raw_inode->i_block[n] = ei->i_data[n];

    mark_buffer_dirty(bh);
    if (do_sync) {
        sync_dirty_buffer(bh);
        if (buffer_req(bh) && !buffer_uptodate(bh)) {
            luci_err("IO error syncing luci inode [%s:%08lx]\n", sb->s_id,
               (unsigned long) inode->i_ino);
            err = -EIO;
        }
    }

    ei->i_state &= ~LUCI_STATE_NEW;

#ifdef HAVE_TRACEPOINT_ENABLED
    if (trace_luci_write_inode_raw_enabled())
#endif
           trace_luci_write_inode_raw(raw_inode, inode->i_ino, do_sync);

    brelse (bh);
    return err;
}
EXPORT_SYMBOL_GPL(luci_write_inode_raw);

int
luci_write_inode(struct inode *inode, struct writeback_control *wbc)
{
   return luci_write_inode_raw(inode, wbc->sync_mode == WB_SYNC_ALL);
}

static int
luci_writepage(struct page *page, struct writeback_control *wbc)
{
    int ret;
#ifdef LUCIFS_COMPRESSION
    struct inode * inode = page->mapping->host;

    atomic64_inc(&writeback_in);
    if (S_ISREG(inode->i_mode)) {
        ret = luci_write_extent(page, wbc);
        goto done;
    }
#endif
    ret = block_write_full_page(page, luci_get_block, wbc);
done:
    atomic64_inc(&writeback_out);
    return ret;
}

static int
luci_writepages(struct address_space *mapping, struct writeback_control *wbc)
{
    int ret;
#ifdef LUCIFS_COMPRESSION
    struct inode * inode = mapping->host;
    atomic64_inc(&writeback_in);
    if (S_ISREG(inode->i_mode)) {
        struct blk_plug plug;

        blk_start_plug(&plug);
        ret = luci_write_extents(mapping, wbc);
        blk_finish_plug(&plug);
        goto done;
    }
#endif
    ret = mpage_writepages(mapping, wbc, luci_get_block);
done:
    atomic64_inc(&writeback_out);
    return ret;
}

static int
luci_write_begin(struct file *file,
                 struct address_space *mapping,
                 loff_t pos,
                 unsigned len,
                 unsigned flags,
                 struct page **pagep,
                 void **fsdata)
{
    int ret;
    struct inode *inode = file_inode(file);

    atomic64_add(len >> PAGE_CACHE_SHIFT, &writefile_in);

#ifdef LUCIFS_COMPRESSION
    if (S_ISREG(inode->i_mode)) {
        ret = luci_write_extent_begin(mapping,
                                      pos,
                                      len,
                                      flags,
                                      pagep);
        goto done;
    }
#endif
    ret = block_write_begin(mapping,
                            pos,
                            len,
                            flags,
                            pagep,
                            luci_get_block);
done:
    if (ret < 0)
        luci_err_inode(inode, "write_begin failed with %d", ret);

    return ret;
}

static int
luci_write_end(struct file *file,
               struct address_space *mapping,
               loff_t pos,
               unsigned len,
               unsigned copied,
               struct page *page,
               void *fsdata)
{
    int ret;
    struct inode *inode = file_inode(file);

#ifdef LUCIFS_COMPRESSION
    if (S_ISREG(inode->i_mode)) {
        ret = luci_write_extent_end(mapping,
                                    pos,
                                    len,
                                    0,
                                    page);
        goto done;
    }
#endif
    ret = generic_write_end(file,
                            mapping,
                            pos,
                            len,
                            copied,
                            page,
                            fsdata);
done:
    if (ret < 0)
        luci_err_inode(inode, "write_end failed with %d", ret);

    atomic64_add(len >> PAGE_CACHE_SHIFT, &writefile_out);
    return ret;
}

/*
 * Note : file can be null in cases, when the API is in internally
 * invoked via luci_get_page(do_read_cache_page->filler)
 */
static int
luci_readpage(struct file *file, struct page *page)
{
    int ret = 0;
#ifdef LUCIFS_COMPRESSION
    blkptr bp;
    struct page *cachep;
    bool do_verify = false;
    unsigned long file_block;
    struct inode *inode = page->mapping->host;

    atomic64_inc(&readfile_in);

    if (S_ISREG(inode->i_mode)) {

        if (page_offset(page) > inode->i_size) {
            zero_user(page, 0, PAGE_SIZE);

            SetPageUptodate(page);
            if (PageLocked(page))
                unlock_page(page);

            luci_info_inode(inode, "offset exceed inode size, offset (%llu) > "
                "file size (%llu)", page_offset(page), i_size_read(inode));
            goto done;
        }

        // We can safely assume page is present in cache, due to page readahead
        // and locked. Fixed : we need to pass page index
        cachep = find_get_page(inode->i_mapping, page_index(page));
        if (!cachep) {
            luci_info("page (%lu) not found in cache, allocating",
                page_index(page));
            cachep = find_or_create_page(page->mapping,
                                         page_index(page),
                                         GFP_KERNEL);
        }

        BUG_ON(!cachep);

        if (!PageUptodate(cachep)) {
            #ifdef LUCIFS_CHECKSUM
            do_verify = true;
            #endif
            file_block = page_offset(page)/luci_chunk_size(inode);

            bp = luci_bmap_fetch_L0bp(inode, file_block);
            if (bp.flags & LUCI_COMPR_FLAG) {
                luci_info_inode(inode, "reading compressed page :%lu",
                    page_index(page));
                ret = luci_read_extent(page, &bp);
                if (ret)
                    panic("read failed :%d", ret);
            } else {
                put_page(cachep);
                luci_info_inode(inode, "reading uncompressed page :%lu",
                    page_index(page));
                goto uncompressed_read;
            }
            luci_dump_blkptr(inode, file_block, &bp);
        }

        copy_pages(page, cachep, 0, 0, PAGE_SIZE);
        if (PageLocked(cachep))
            unlock_page(cachep);

        put_page(cachep);

        // Needed otherwise will result in an EIO
        SetPageUptodate(page);
        BUG_ON(page_has_buffers(page));

        // Ideally page should be locked, but seen cases where page not locked
        if (PageLocked(page))
            unlock_page(page);

        luci_info_inode(inode, "compressed read completed for pg index :%lu "
            "status :%d\n", page_index(page), ret);
        goto done;
    }
#endif
uncompressed_read:
    // trace mpage_readpage with unlock issue
    ret = mpage_readpage(page, luci_get_block);

    if (!ret && bp.length && do_verify) {
        wait_on_page_locked(page);
        BUG_ON(!PageUptodate(page));
        ret = luci_validate_data_page_cksum(page, &bp);
        if (ret < 0)
            luci_err_inode(inode,
                "L0 blkptr checksum mismatch on read page, block=%u-%u",
                bp.blockno, bp.length);
    }

done:
    atomic64_inc(&readfile_out);
    return ret;
}

static int
luci_readpages(struct file *file, struct address_space *mapping,
    struct list_head *pages, unsigned nr_pages)
{
    int ret;

    atomic64_add(nr_pages, &readfile_in);
    ret = mpage_readpages(mapping, pages, nr_pages, luci_get_block);
    atomic64_add(nr_pages, &readfile_out);
    return ret;
}

static int luci_releasepage(struct page *page, gfp_t wait)
{
    int rlse = try_to_free_buffers(page);
    if (!rlse)
        dbgfsparam.rlsebsy++;
    return rlse;
}

static int luci_debugfs_show_stats(struct seq_file *m, void *data)
{
        seq_printf(m, "readfile  in   :%ld\n"
                      "readfile  done :%ld\n"
                      "writefile in   :%ld\n"
                      "writefile done :%ld\n"
                      "writeback in   :%ld\n"
                      "writeback done :%ld\n"
                      "setattr   in   :%ld\n"
                      "setattr   done :%ld\n"
                      "getattr   in   :%ld\n"
                      "getattr   done :%ld\n",
                      atomic64_read(&readfile_in),
                      atomic64_read(&readfile_out),
                      atomic64_read(&writefile_in),
                      atomic64_read(&writefile_out),
                      atomic64_read(&writeback_in),
                      atomic64_read(&writeback_out),
                      atomic64_read(&setattr_in),
                      atomic64_read(&setattr_out),
                      atomic64_read(&getattr_in),
                      atomic64_read(&getattr_out));
        return 0;
}

static int luci_debugfs_open(struct inode *inode, struct file *file)
{
        return single_open(file, luci_debugfs_show_stats, inode->i_private);
}

const struct file_operations luci_iostat_ops = {
        .open		= luci_debugfs_open,
        .read		= seq_read,
        .llseek		= no_llseek,
        .release	= single_release,
};

const struct address_space_operations luci_aops = {
    .readpage       = luci_readpage,
    //.readpages      = luci_readpages, // FIXME :readahead causes deadlock
    .writepage      = luci_writepage,
    .writepages     = luci_writepages,
    .write_begin    = luci_write_begin,
    .write_end      = luci_write_end,
    .releasepage    = luci_releasepage,
};
