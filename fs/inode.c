/*--------------------------------------------------------------------
 * Copyright(C) 2016, Saptarshi Sen
 *
 * LUCI inode operaitons
 *
 * ------------------------------------------------------------------*/
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/buffer_head.h>
#include <linux/version.h>
#include <linux/writeback.h>
#include <linux/blkdev.h>
#include <linux/dcache.h>
#include <linux/path.h>
#include <linux/mpage.h>
#include <linux/delay.h>
#include <linux/ktime.h>
#include "kern_feature.h"
#include "luci.h"
#include "compression.h"

static int
luci_setsize(struct inode *inode, loff_t newsize)
{
    // Cannot modify size of directory
    if (!S_ISREG(inode->i_mode)) {
       luci_err_inode(inode, "luci :setsize not valid for inode");
       return -EINVAL;
    }
    luci_truncate(inode, newsize);
    truncate_setsize(inode, newsize);
    inode->i_mtime = inode->i_ctime = LUCI_CURR_TIME;
    // sync
    if (inode_needs_sync(inode)) {
       sync_mapping_buffers(inode->i_mapping);
       sync_inode_metadata(inode, 1);
    // async
    } else {
       mark_inode_dirty(inode);
    }
    return 0;
}

static int
luci_setattr(struct dentry *dentry, struct iattr *attr)
{
    int err;
    struct inode *inode = DENTRY_INODE(dentry);
    // check we have permissions to change attributes
#ifdef HAVE_CHECKINODEPERM
    err = inode_change_ok(inode, attr);
#else
    err = setattr_prepare(dentry, attr);
#endif
    if (err) {
        return err;
    }

    luci_dbg_inode(inode, "setattr");
    // Wait for all pending direct I/O requests so that
    // we can proceed with a truncate
    inode_dio_wait(inode);

    // check modify size
    if (attr->ia_valid & ATTR_SIZE && attr->ia_size != inode->i_size) {
       luci_dbg_inode(inode, "oldsize %llu newsize %llu", inode->i_size,
          attr->ia_size);
       err = luci_setsize(inode, attr->ia_size);
       if (err) {
           return err;
       }
    }
    // does not mark inode dirty so explicitly marked dirty
    setattr_copy(inode, attr);
    mark_inode_dirty(inode);
    //luci_dump_layout(inode);
    return 0;
}

static int
luci_getattr_private(const struct dentry *dentry, struct kstat *stat)
{
    struct super_block *sb = dentry->d_sb;
    struct inode *inode = DENTRY_INODE(dentry);
    generic_fillattr(inode, stat);
    stat->blksize = sb->s_blocksize;
    luci_dbg_inode(inode, "get attributes");
    return 0;
}

#ifdef HAVE_NEW_GETATTR
static int
luci_getattr(const struct path *path, struct kstat *stat,
        u32 request_mask, unsigned int query_flags)
{
    return luci_getattr_private(path->dentry, stat);
}
#else
static int
luci_getattr(struct vfsmount *mnt, struct dentry *dentry,
        struct kstat *stat)
{
    return luci_getattr_private(dentry, stat);
}
#endif

inline unsigned
luci_chunk_size(struct inode *inode)
{
    return inode->i_sb->s_blocksize;
}

inline unsigned
luci_sectors_per_block(struct inode *inode)
{
    return luci_chunk_size(inode)/512;
}

static inline void
luci_set_de_type(struct luci_dir_entry_2 *de, struct inode *inode)
{
    // TBD
    de->file_type  = 0;
}

int
luci_prepare_chunk(struct page *page, loff_t pos, unsigned len)
{
    int ret = 0;
    struct address_space *mapping = page->mapping;
    struct inode *dir = mapping->host;
    luci_dbg_inode(dir, "pos :%llu len :%u", pos, len);
    ret =  __block_write_begin(page, pos, len, luci_get_block);
    return ret;
}

// is this specific to directory usage ?
int
luci_commit_chunk(struct page *page, loff_t pos, unsigned len)
{
    int err = 0;
    struct address_space *mapping = page->mapping;
    struct inode *dir = mapping->host;

    dir->i_version++;
    block_write_end(NULL, mapping, pos, len, len, page, NULL);
    // note directory inode size is updated here
    if (pos + len > dir->i_size) {
        i_size_write(dir, pos + len);
        mark_inode_dirty(dir);
        luci_dbg_inode(dir, "updating inode new size %llu", dir->i_size);
    }
    if (IS_DIRSYNC(dir)) {
        err = write_one_page(page, 1);
        if (!err) {
            err = sync_inode_metadata(dir, 1);
        }
    } else {
        unlock_page(page);
    }
    luci_dbg_inode(dir,"pos :%llu len :%u err :%d", pos, len, err);
    return err;
}

static inline void
add_chain(Indirect *p, struct buffer_head *bh, blkptr *v)
{
    p->p = v;
    memcpy((char*)&p->key, (char*)p->p, sizeof(blkptr));
    p->bh = bh;
}

// Update path based on block number, offsets into indices
static int
luci_block_to_path(struct inode *inode,
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

    if (i_block < 0) {
        luci_err_inode(inode, "warning invalid i_block :%ld", file_block);
        return -EINVAL;
    }

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
        luci_dbg("block %ld maps to an indirect block\n", file_block);
        goto done;
    }

    i_block -= nr_indirect;
    // Imagery :
    // 1st-Level : each row corresponds to n addr-bits blocks
    // 2nd-Level : each row corresponds to index to the addr per block
    if (i_block < nr_dindirect) {
        path[n++] = LUCI_DIND_BLOCK;
        path[n++] = i_block >> LUCI_ADDR_PER_BLOCK_BITS(inode->i_sb);
        path[n++] = i_block & (LUCI_ADDR_PER_BLOCK(inode->i_sb) - 1);
        final = nr_indirect;
        luci_dbg("block %ld maps to a double indirect block\n", file_block);
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
        luci_dbg("block %ld maps to a triple indirect block\n", file_block);
        goto done;
    }

    luci_err_inode(inode, "warning block is too big");
done:
    if (blocks_to_boundary) {
        *blocks_to_boundary = final - path[n - 1];
    }
    luci_dbg_inode(inode,"i_block :%lu n:%d indexes :%ld :%ld :%ld :%ld",
       file_block, n, path[0], path[1], path[2], path[3]);
    return n;
}

static int
alloc_branch(struct inode *inode,
             unsigned long i_block,
             int nr,
             long int *offsets,
             Indirect *branch,
             struct buffer_head *bh)
{
    int ret, i = 0;
    unsigned long curr_block;
    struct buffer_head *prevbh = NULL, *currbh = NULL;
    bool leafblock = false;

    if (nr == 0) {
        luci_dbg_inode(inode, "deferring leaf block allocation %lu", i_block);
        return 0;
    }
    BUG_ON(branch[0].key.blockno);

    luci_dbg_inode(inode, "allocating nr blocks :%d", nr);
    // Walk block table for allocating indirect block entries
    for (i = 0; i < nr; i++) {
        if ((i == nr - 1) && (bh != NULL)) {
            curr_block = bh->b_blocknr;
            leafblock = true;
        } else {
            ret = luci_new_block(inode, 1, &curr_block);
            if (ret < 0) {
                luci_err_inode(inode, "block allocation failed iblock %lu",
                        i_block);
                goto fail;
            }
        }

        if (i > 0) {
            BUG_ON(currbh == NULL);
            prevbh = currbh;
            currbh = NULL;
        }

        if (prevbh) {
            lock_buffer(prevbh);
            branch[i].key.blockno = curr_block;
            // compressed blocks are taken care of here
            if (leafblock && (bh->b_state & BH_PrivateStart)) {
                branch[i].key.flags |= LUCI_COMPR_FLAG;
                branch[i].key.length = (unsigned int) bh->b_size;
            }
            // offset to indirect block table to store block address entry
            branch[i].p = (blkptr*) prevbh->b_data + offsets[i];
            // imp : i_data array updated here
            memcpy((char*)branch[i].p, (char*)&branch[i].key, sizeof(blkptr));
            // note this is buffer head of previous block
            branch[i].bh = prevbh;
            unlock_buffer(prevbh);
            mark_buffer_dirty_inode(prevbh, inode);
            luci_dbg_inode(inode, "iblock %lu block %u(%x) offset %lu", i_block,
                branch[i].key.blockno, branch[i].key.flags, offsets[i]);
        } else {
            // root node already has slot for holding block ptr in i_data
            branch[0].key.blockno = curr_block;
            if (leafblock && (bh->b_state & BH_PrivateStart)) {
                branch[0].key.flags |= LUCI_COMPR_FLAG;
                branch[0].key.length = (unsigned int) bh->b_size;
            }
            memcpy((char*)branch[i].p, (char*)&branch[i].key, sizeof(blkptr));
            luci_dbg_inode(inode, "iblock %lu root block %u(%x) offset %lu",
                i_block, branch[i].key.blockno, branch[i].key.flags, offsets[i]);
        }
#ifdef LUCIFS_COMPRESSION
        // Fix:We need not allocate buffer head for l0 block. Since we do not
        // issue do buffer-head based read/writes in compression path.
        // allocating and not submitting bh was causing slab objects to swell
        // and system would be really low on memory on a few large copies
        if (leafblock) {
            break;
        }
#endif
        if ((currbh = sb_getblk(inode->i_sb, curr_block)) == NULL) {
            ret = -EIO;
            luci_err_inode(inode, "block read fail %lu iblock %lu",
                    curr_block, i_block);
            goto fail;
        }
        //clear the newly allocated block
        lock_buffer(currbh);
        memset(currbh->b_data, 0, currbh->b_size);
        set_buffer_uptodate(currbh);
        unlock_buffer(currbh);
        //mark_buffer_dirty_inode(currbh, inode);
    }

#ifdef LUCIFS_COMPRESSION
    //Fix: We leaked the last bh for the l0 block.
    //Since the leaf bh is not contained in the chain.
    if (currbh != NULL) {
        brelse(currbh);
    }
#endif
    return 0;
fail:
    luci_err_inode(inode, "failed alloc path branch iblock %lu(%d)", i_block, i);
    return ret;
}

static inline Indirect *
luci_get_branch(struct inode *inode,
        int depth,
        long ipaths[LUCI_MAX_DEPTH],
        Indirect ichain[LUCI_MAX_DEPTH],
        int *err)
{
    struct super_block *sb = inode->i_sb;
    struct buffer_head *bh;
    Indirect *p = ichain;
    int i = 0;
    *err = 0;

    add_chain (p, NULL, LUCI_I(inode)->i_data + *ipaths);
    if (!p->key.blockno) {
        luci_dbg_inode(inode, "root chain :ipath :%ld :%p", *ipaths, p->p);
        goto no_block;
    }
    luci_dbg_inode(inode, "block walk path ipath[%d] %d", i, p->key.blockno);
    i++;
    while (i < depth) {
        if ((bh = sb_bread(sb, p->key.blockno)) == NULL)  {
            luci_err_inode(inode, "metadata read error ipath[%d]%d", i,
                    p->key.blockno);
            goto failure;
        }
        add_chain(++p, bh, (blkptr*)bh->b_data + *++ipaths);
        if (!p->key.blockno) {
            goto no_block;
        }
        luci_dbg_inode(inode, "block walk path ipath[%d] %d", i, p->key.blockno);
        i++;
    }
    return NULL;

failure:
    for (i = 0; i < LUCI_MAX_DEPTH; i++) {
        if (!ichain[i].key.blockno) {
            break;
        }
        brelse(ichain[i].bh);
    }
    *err = -EIO;
no_block:
    luci_dbg("found no key in block path walk at level %d for inode :%lu "
       "ipaths :%ld", i, inode->i_ino, *ipaths);
    return p;
}

int
luci_get_block(struct inode *inode, sector_t iblock,
        struct buffer_head *bh_result, int create)
{
    int err = 0;
    int depth = 0;
    u32 block_no = 0;
    int nr_blocks = 0;
    int blocks_to_boundary = 0;
    Indirect *partial;
    long ipaths[LUCI_MAX_DEPTH];
    Indirect ichain[LUCI_MAX_DEPTH];

    luci_dbg("getting block for inode :%lu, i_block :%lu "
      "create :%s", inode->i_ino, iblock, create ? "alloc" : "noalloc");
    // Standard usage of get_block passes a valid bh_result. This is
    // done to check if the buffer has an on-disk associated block.
    BUG_ON(bh_result == NULL);
    memset((char*)ipaths, 0, sizeof(long)*LUCI_MAX_DEPTH);
    memset((char*)ichain, 0, sizeof(Indirect)*LUCI_MAX_DEPTH);

    depth = luci_block_to_path(inode, iblock, ipaths, &blocks_to_boundary);
    if (!depth) {
        luci_err_inode(inode, "get_block, invalid block depth!");
        return -EIO;
    }

    luci_dbg_inode(inode, "get_block, block depth %d", depth);

    //Buffer forms the boundary of contiguous blocks the next block is
    //discontinuous (BH_Boundary). We need a new meta data block for fetching
    //the next leaf block.
    if (!blocks_to_boundary) {
        set_buffer_boundary(bh_result);
    }

    partial = luci_get_branch(inode, depth, ipaths, ichain, &err);
    if (err < 0) {
        luci_err_inode(inode, "error reading block to path :%u", err);
        return err;
    }

    if (!partial) {
        // We are abusing luci_get_block for updating block pointer
        // since it has common code for walking indirect block map.
        if (S_ISREG(inode->i_mode) &&
           ((create & COMPR_BLK_INSERT) || (create & COMPR_BLK_UPDATE))) {
            BUG_ON(ichain[depth - 1].p == NULL);
            // update L0 block ptr at L1
            ichain[depth - 1].p->blockno = bh_result->b_blocknr;
            ichain[depth - 1].p->length = (unsigned short) bh_result->b_size;
            if (bh_result->b_state & BH_PrivateStart) {
                ichain[depth - 1].p->flags |= LUCI_COMPR_FLAG;
            }
            luci_dbg_inode(inode, "iblock :%lu data block :%u(%x) depth :%d",
                iblock, ichain[depth - 1].p->blockno, ichain[depth - 1].p->flags,
                depth);
            // Fix: on exit free buffer-heads allocated during block lookup
            goto done;
        }
gotit:
        block_no = ichain[depth - 1].key.blockno;
        if (bh_result) {
           map_bh(bh_result, inode->i_sb, block_no);
           // indicates block was compressed
           if (ichain[depth - 1].key.flags & LUCI_COMPR_FLAG) {
               bh_result->b_state |= BH_PrivateStart;
               bh_result->b_size = (size_t) ichain[depth - 1].key.length;
           }
        }
        luci_dbg_inode(inode, "i_block :%lu paths :%d :%d :%d :%d", iblock,
           ichain[0].key.blockno, ichain[1].key.blockno, ichain[2].key.blockno,
           ichain[3].key.blockno);
        err = 0;
    } else {
        if (create) {
            bool need_leaf = true;
            nr_blocks = (ichain + depth) - partial;
            BUG_ON(nr_blocks == 0);
            luci_dbg_inode(inode, "get block allocating i_block :%lu, "
               "nr_blocks :%u", iblock, nr_blocks);
#ifdef LUCIFS_COMPRESSION
            if (S_ISREG(inode->i_mode) && (create & COMPR_BLK_INSERT)) {
                need_leaf = false;
            }
#endif
            if (need_leaf) {
                err = alloc_branch(inode, iblock, nr_blocks,
                    ipaths + (partial - ichain), partial, NULL);
                BUG_ON(err);
                goto gotit;
            } else {
                err = alloc_branch(inode, iblock, nr_blocks,
                    ipaths + (partial - ichain), partial, bh_result);
                BUG_ON(err);
            }
        } else {
            // We have a hole. mpage API identifies a hole if bh is not mapped.
            // So we are fine even if we do not have an block created for a hole.
            luci_dbg_inode(inode, "found hole at block no :%u", block_no);
        }
    }
done:
    // Fix : free buffer-heads associated with the lookup
    // The metadata pages are already in memory
    partial = ichain + depth - 1;
    while (partial > ichain) {
        brelse(partial->bh);
        partial--;
    }
    return err;
}

blkptr
luci_find_leaf_block(struct inode * inode, unsigned long i_block)
{
    int ret;
    blkptr blkptr;
    struct buffer_head bh;

    memset((char*)&bh, 0, sizeof(struct buffer_head));
    memset((char*)&blkptr, 0, sizeof(blkptr));
    ret = luci_get_block(inode, i_block, &bh, 0);
    if (ret < 0) {
        luci_err_inode(inode, "error get leaf block : %lu", i_block);
        BUG();
    }
    if (buffer_mapped(&bh)) {
        blkptr.blockno = bh.b_blocknr;
        // For now this indicates this block was compressed
        if (bh.b_state & BH_PrivateStart) {
            blkptr.flags = LUCI_COMPR_FLAG;
        }
    }
    return blkptr;
}

int
luci_insert_block(struct inode * inode, unsigned long i_block, blkptr *bp)
{
    int ret;
    struct buffer_head bh;

    memset((char*)&bh, 0, sizeof(struct buffer_head));
    bh.b_blocknr = bp->blockno;
    if (bp->flags == LUCI_COMPR_FLAG) {
        bh.b_size = (size_t) bp->length;
        bh.b_state = BH_PrivateStart; // flag for compressed block
    }
    ret = luci_get_block(inode, i_block, &bh, COMPR_BLK_UPDATE |
        COMPR_BLK_INSERT);
    if (ret < 0) {
        luci_err_inode(inode, "error inserting leaf i_block : %lu", i_block);
        return ret;
    }
    return 0;
}

// This code path gets trigerred when the inode has already been created on disk
// and we are fetching inode. inode is loaded with raw inode details from disk
struct inode *
luci_iget(struct super_block *sb, unsigned long ino) {
    int n;
    struct inode *inode;
    struct luci_inode_info *li;
    struct luci_inode *raw_inode;
    unsigned long block_group;
    unsigned long block_no;
    struct buffer_head *bh;
    struct luci_group_desc *gdesc;
    uint32_t offset;

    inode = iget_locked(sb, ino);

    if (!inode) {
        return ERR_PTR(-ENOMEM);
    }

    if (!(inode->i_state & I_NEW)) {
        return inode;
    }

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
    luci_info_inode(inode, "inode size low :%u high :%u",
        raw_inode->i_size, raw_inode->i_dir_acl);
    if (i_size_read(inode) < 0) {
        return ERR_PTR(-EFSCORRUPTED);
    }
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

static struct luci_inode*
luci_get_inode(struct super_block *sb, ino_t ino,
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
    /*
     * Figure out the offset within the block group inode table
     */
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

static int
luci_add_link(struct dentry *dentry, struct inode *inode) {
    int err;
    loff_t pos;  // offset in page with empty dentry
    int new_dentry_len;  // name length of the new entry
    int rec_len  = 0;
    struct page *page = NULL;
    unsigned long n, npages;
    struct luci_dir_entry_2 *de = NULL;  //dentry iterator
    struct inode *dir;  // directory inode storing dentries
    unsigned chunk_size = luci_chunk_size(inode);

    // sanity check for new inode
    BUG_ON(inode->i_ino == 0);
    dir = DENTRY_INODE(dentry->d_parent);
    // Note block size may not be the same as page size
    npages = dir_pages(dir);
    new_dentry_len = LUCI_DIR_REC_LEN(dentry->d_name.len);
    luci_dbg("dir npages :%lu add dentry :%s len :%d", npages,
       dentry->d_name.name, new_dentry_len);
    for (n = 0; n < npages; n++) {
        char *kaddr, *page_boundary;
        page = luci_get_page(dir, n);
        if (IS_ERR(page)) {
            err = PTR_ERR(page);
            luci_err_inode(inode, "error getting page %lu :%d", n, err);
            return err;
        }
        lock_page(page);
        kaddr = page_address(page);
        // We do not want dentry to be across page boundary
        page_boundary = kaddr + PAGE_SIZE - new_dentry_len;
        luci_dbg("dentries lookup in dir inode:%lu", dir->i_ino);
        de = (struct luci_dir_entry_2*)((char*)kaddr);
	// Note : multiple dentry blocks can reside in a page
        while ((char*)de <= page_boundary) {
	    // dentry rolls over to next block
            // terminal dentry in this block
            if (de->rec_len == 0) {
                de->inode = 0;
                de->rec_len = luci_rec_len_to_disk(chunk_size);
                goto gotit;
            }
            // entry already exists
            if (luci_match(dentry->d_name.len, dentry->d_name.name, de)) {
                err = -EEXIST;
                luci_err("failed to add link, file exists %s",
		   dentry->d_name.name);
                goto outunlock;
            }
            // offset to next valid dentry from current de
            rec_len = luci_rec_len_from_disk(de->rec_len);
            luci_dbg("dname :%s inode :%u next_len :%u", de->name, de->inode,
               rec_len);
	    // if new dentry record can be acommodated in this block
            if (!de->inode && rec_len >= new_dentry_len) {
               goto gotit;
            }
            if (rec_len >= (LUCI_DIR_REC_LEN(de->name_len) +
               LUCI_DIR_REC_LEN(dentry->d_name.len))) {
               goto gotit;
            }
            de = (struct luci_dir_entry_2*)((char*)de + rec_len);
        }
        unlock_page(page);
        luci_put_page(page);
        luci_dbg("dentry page %ld nr_pages :%ld ", n, npages);
    }

    // extend the directory to accomodate new dentry
    page = luci_get_page(dir, n);
    if (IS_ERR(page)) {
       err = -ENOSPC;
       luci_err_inode(inode, "error getting page %lu :%ld", n, PTR_ERR(page));
       luci_err("failed to adding new link entry, no space");
       return err;
    }

    lock_page(page);
    de = (struct luci_dir_entry_2*) page_address(page);
    de->inode = 0;
    de->rec_len = luci_rec_len_to_disk(chunk_size);
    goto gotit;

outunlock:
    BUG_ON(page == NULL);
    unlock_page(page);
    luci_put_page(page);
    return err;

gotit:
    luci_dbg("luci: empty dentry found, adding new link entry");
    // Previous entry have to be modified
    if (de->inode) {
        struct luci_dir_entry_2 * de_new = (struct luci_dir_entry_2*)
	   ((char*) de + LUCI_DIR_REC_LEN(de->name_len));
	de_new->inode = inode->i_ino;
        de->rec_len = luci_rec_len_to_disk(LUCI_DIR_REC_LEN(de->name_len));
        de_new->rec_len = luci_rec_len_to_disk(rec_len - de->rec_len);
        de = de_new;
    }

    pos = page_offset(page) +
        (char*)de - (char*)page_address(page);
    err = luci_prepare_chunk(page, pos, new_dentry_len);
    if (err) {
        luci_err("error to prepare chunk during dentry insert");
        goto outunlock;
    }
    de->name_len = dentry->d_name.len;
    memcpy(de->name, dentry->d_name.name, de->name_len);
    de->inode = cpu_to_le32(inode->i_ino);
    luci_set_de_type(de, inode);
    err = luci_commit_chunk(page, pos, new_dentry_len);
    if (err) {
        luci_err("error to commit chunk during dentry insert");
    }
    dir->i_mtime = dir->i_ctime = LUCI_CURR_TIME;
    mark_inode_dirty(dir);
    luci_put_page(page);
    luci_dbg_inode(inode, "sucessfully inserted dentry %s record_len :%d "
       "next_record :%d", dentry->d_name.name, LUCI_DIR_REC_LEN(de->name_len),
       de->rec_len);
    return err;
}

static int
__luci_write_inode(struct inode *inode, int do_sync)
{
    struct luci_inode_info *ei = LUCI_I(inode);
    struct super_block *sb = inode->i_sb;
    ino_t ino = inode->i_ino;
    struct buffer_head * bh;
    struct luci_inode * raw_inode = luci_get_inode(sb, ino, &bh);
    int n;
    int err = 0;

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

    raw_inode->i_generation = cpu_to_le32(inode->i_generation);
    for (n = 0; n < LUCI_N_BLOCKS; n++)
        raw_inode->i_block[n] = ei->i_data[n];
    mark_buffer_dirty(bh);
    if (do_sync) {
        sync_dirty_buffer(bh);
        if (buffer_req(bh) && !buffer_uptodate(bh)) {
            luci_err("IO error syncing luci inode [%s:%08lx]\n", sb->s_id,
               (unsigned long) ino);
            err = -EIO;
        }
    }
    ei->i_state &= ~LUCI_STATE_NEW;
    brelse (bh);
    return err;
}

int
luci_write_inode(struct inode *inode, struct writeback_control *wbc)
{
   return __luci_write_inode(inode, wbc->sync_mode == WB_SYNC_ALL);
}

const struct inode_operations luci_file_inode_operations =
{
    .setattr = luci_setattr,
    .getattr = luci_getattr,
};

static struct dentry *
luci_lookup(struct inode * dir, struct dentry *dentry,
        unsigned int flags) {
    ino_t ino;
    struct inode * inode;
    luci_dbg_inode(dir, "dir lookup");
    if (dentry->d_name.len > LUCI_NAME_LEN) {
        return ERR_PTR(-ENAMETOOLONG);
    }
    ino = luci_inode_by_name(dir, &dentry->d_name);
    inode = NULL;
    if (ino) {
        inode = luci_iget(dir->i_sb,  ino);
        if (inode == ERR_PTR(-ESTALE)) {
            luci_err("deleted inode referenced %lu", (unsigned long) ino);
            return ERR_PTR(-EIO);
        }
    } else {
        luci_err("inode lookup failed for %s", dentry->d_name.name);
    }
    //splice a disconnected dentry into the tree if one exists
    return d_splice_alias(inode, dentry);
}

static int
luci_mknod(struct inode * dir, struct dentry *dentry, umode_t mode, dev_t rdev)
{
    luci_dbg("inode :%lu", dir->i_ino);
    return 0;
}

static int
luci_tmpfile(struct inode *dir, struct dentry *dentry, umode_t mode)
{
    luci_dbg("inode :%lu", dir->i_ino);
    return 0;
}

static void
luci_track_size(struct inode * inode) {
   loff_t size = inode->i_blocks * 512;
   luci_dbg_inode(inode, "size :%llu phy size :%llu blocks :%lu",
      inode->i_size, size, inode->i_blocks);
   // TBD : Check cases when this becomes true
   BUG_ON(size < inode->i_size);
}

static int
luci_create(struct inode *dir, struct dentry *dentry, umode_t mode,
        bool excl)
{
    int err;
    struct inode * inode;
    // create inode
    inode = luci_new_inode(dir, mode, &dentry->d_name);
    if (IS_ERR(inode)) {
        luci_err("Failed to create new inode");
        return PTR_ERR(inode);
    }
    luci_dbg_inode(inode, "Created new inode name :%s", dentry->d_name.name);
    inode->i_op = &luci_file_inode_operations;
    inode->i_fop = &luci_file_operations;
    inode->i_mapping ->a_ops = &luci_aops;
    mark_inode_dirty(inode);
    luci_track_size(dir);
    err = luci_add_link(dentry, inode);
    if (err) {
       inode_dec_link_count(inode);
       unlock_new_inode(inode);
       iput(inode);
       luci_err("inode add link failed, err :%d", err);
       return err;
    }
    unlock_new_inode(inode);
    d_instantiate(dentry, inode);
    return 0;
}

static int
luci_symlink(struct inode * dir, struct dentry *dentry,
        const char * symname)
{
    luci_dbg("inode :%lu", dir->i_ino);
    return 0;
}

static int
luci_link(struct dentry * old_dentry, struct inode * dir,
        struct dentry *dentry)
{
    luci_dbg("inode :%lu", dir->i_ino);
    return 0;
}

int
luci_make_empty(struct inode *inode, struct inode *parent) {
    struct page * page = grab_cache_page(inode->i_mapping, 0);
    unsigned chunk_size = luci_chunk_size(inode);
    struct luci_dir_entry_2* de;
    int err;
    void *kaddr;

    if (!page) {
        return -ENOMEM;
    }

    err = luci_prepare_chunk(page, 0, chunk_size);
    if (err) {
        luci_err("failed to pepare chunk");
        unlock_page(page);
        goto fail;
    }
    kaddr = kmap_atomic(page);
    memset(kaddr, 0, chunk_size);
    de = (struct luci_dir_entry_2*)kaddr;
    de->name_len = 1;
    de->rec_len = luci_rec_len_to_disk(LUCI_DIR_REC_LEN(1));
    memcpy(de->name, ".\0\0", 4);
    de->inode = cpu_to_le32(inode->i_ino);
    luci_set_de_type(de, inode);

    de = (struct luci_dir_entry_2*)(kaddr + LUCI_DIR_REC_LEN(1));
    de->name_len = 2;
    de->rec_len = luci_rec_len_to_disk(chunk_size - LUCI_DIR_REC_LEN(1));
    memcpy(de->name, "..\0", 4);
    de->inode = cpu_to_le32(parent->i_ino);
    luci_set_de_type(de, inode);
    // Bug Fix : do atomic, otherwize segfault in user land
    kunmap_atomic(kaddr);
    err = luci_commit_chunk(page, 0, chunk_size);
fail:
    put_page(page);
    return err;
}

static int
luci_mkdir(struct inode * dir, struct dentry *dentry, umode_t mode)
{
    int err = 0;
    struct inode *inode;

    luci_dbg_inode(dir,"mkdir");

    inode_inc_link_count(dir);
    inode = luci_new_inode(dir, S_IFDIR | mode, &dentry->d_name);
    if (IS_ERR(inode)) {
        luci_err("failed to create new inode");
        goto fail_dir;
    }
    inode->i_op = &luci_dir_inode_operations;
    inode->i_fop = &luci_dir_operations;
    inode->i_mapping->a_ops = &luci_aops;
    inode_inc_link_count(inode);
    err = luci_make_empty(inode, dir);
    if (err) {
        luci_err("failed to make empty directory");
        goto out_fail;
    }
    err = luci_add_link(dentry, inode);
    if (err) {
        luci_err("failed to add dentry in parent directory");
        goto out_fail;
    }

    unlock_new_inode(inode);
    d_instantiate(dentry, inode);
    return err;

out_fail:
    inode_dec_link_count(inode);
    inode_dec_link_count(inode);
    unlock_new_inode(inode);
    iput(inode);
    inode_dec_link_count(dir);
    return err;

fail_dir:
    inode_dec_link_count(dir);
    return PTR_ERR(inode);
}

static int
luci_unlink(struct inode * dir, struct dentry *dentry)
{
    struct inode * inode = DENTRY_INODE(dentry);
    struct luci_dir_entry_2 * de;
    struct page * page;
    int err;

    luci_dbg("name :%s", dentry->d_name.name);

    de = luci_find_entry(dir, &dentry->d_name, &page);
    if (!de) {
       err = -ENOENT;
       luci_err("name :%s not found", dentry->d_name.name);
       goto out;
    }

    err = luci_truncate(inode, 0);
    if (err) {
       err = -EIO;
       luci_err("name :%s failed to free blocks", dentry->d_name.name);
       goto out;
    }

    err = luci_delete_entry(de, page);
    if (err) {
       err = -EIO;
       luci_err("name :%s failed to delete", dentry->d_name.name);
       goto out;
    }

    inode->i_ctime = dir->i_ctime;
    inode_dec_link_count(inode);
out:
    return err;
}

static int
luci_rmdir(struct inode * dir, struct dentry *dentry)
{
    int err = -ENOTEMPTY;
    struct inode * inode = DENTRY_INODE(dentry);

    luci_dbg_inode(inode, "rmdir on inode");
    if (luci_empty_dir(inode) == 0) {
        err = luci_unlink(dir, dentry);
	if (err) {
            luci_err("rmdir failed for inode %lu", inode->i_ino);
	    return err;
	}
        inode_dec_link_count(inode);
        inode_dec_link_count(dir);
	return 0;
    }
    return err;
}

#ifdef HAVE_NEW_RENAME
static int
luci_rename(struct inode * old_dir, struct dentry *old_dentry,
        struct inode * new_dir, struct dentry *new_dentry, unsigned int flags)
{
    luci_dbg_inode(old_dir, "renaming");
    return 0;
}
#else
static int
luci_rename(struct inode * old_dir, struct dentry *old_dentry,
    struct inode * new_dir, struct dentry *new_dentry)
{
    luci_dbg_inode(old_dir, "renaming");
    return 0;
}
#endif

static inline bool
areas_overlap(unsigned long src, unsigned long dst, unsigned long len)
{
    unsigned long distance = (src > dst) ? src - dst : dst - src;
    return distance < len;
}

static void
copy_pages(struct page *dst_page, struct page *src_page,
    unsigned long dst_off, unsigned long src_off, unsigned long len)
{
    char *dst_kaddr = page_address(dst_page);
    char *src_kaddr;
    int must_memmove = 0;

    if (dst_page != src_page) {
        src_kaddr = page_address(src_page);
    } else {
        src_kaddr = dst_kaddr;
        if (areas_overlap(src_off, dst_off, len)) {
            must_memmove = 1;
        }
    }

    if (must_memmove) {
        memmove(dst_kaddr + dst_off, src_kaddr + src_off, len);
    } else {
        memcpy(dst_kaddr + dst_off, src_kaddr + src_off, len);
    }
}

static int
luci_writepage(struct page *page, struct writeback_control *wbc)
{
    int ret;
#ifdef LUCIFS_COMPRESSION
    struct inode * inode = page->mapping->host;
    if (S_ISREG(inode->i_mode)) {
        ret = luci_writepage_compressed(page, wbc);
        goto done;
    }
#endif
    ret = block_write_full_page(page, luci_get_block, wbc);
done:
    return ret;
}

static int
luci_writepages(struct address_space *mapping, struct writeback_control *wbc)
{
    int ret;
#ifdef LUCIFS_COMPRESSION
    struct inode * inode = mapping->host;
    if (S_ISREG(inode->i_mode)) {
        struct blk_plug plug;

        blk_start_plug(&plug);
        ret = luci_writepages_compressed(mapping, wbc);
        blk_finish_plug(&plug);
        goto done;
    }
#endif
    ret = mpage_writepages(mapping, wbc, luci_get_block);
done:
    return ret;
}

static int
luci_write_begin(struct file *file, struct address_space *mapping,
    loff_t pos, unsigned len, unsigned flags,
    struct page **pagep, void **fsdata)
{
    int ret;
    struct inode *inode = file->f_inode;
#ifdef LUCIFS_COMPRESSION
    if (S_ISREG(inode->i_mode)) {
        ret = luci_write_compressed_begin(mapping, pos, len, flags, pagep);
        goto done;
    }
#endif
    ret = block_write_begin(mapping, pos, len, flags, pagep, luci_get_block);
done:
    if (ret < 0) {
        luci_err_inode(inode, "failed with %d", ret);
    }
    return ret;
}

static int
luci_write_end(struct file *file, struct address_space *mapping,
    loff_t pos, unsigned len, unsigned copied,
    struct page *page, void *fsdata)
{
    int ret;
    struct inode *inode = file->f_inode;
#ifdef LUCIFS_COMPRESSION
    if (S_ISREG(inode->i_mode)) {
        ret = luci_write_compressed_end(mapping, pos, len, 0, page);
        goto done;
    }
#endif
    ret = generic_write_end(file, mapping, pos, len, copied, page, fsdata);
done:
    if (ret < 0) {
        luci_err_inode(inode, "failed with %d", ret);
    }
    return ret;
}

static int
luci_readpage(struct file *file, struct page *page)
{
    int ret = 0;
#ifdef LUCIFS_COMPRESSION
    struct page *cachep;
    // file can be null in cases, when the API is in internally
    // invoked via luci_get_page(do_read_cache_page->filler)
    struct inode *inode = page->mapping->host;
    BUG_ON(page == NULL);
    if (S_ISREG(inode->i_mode)) {
        // file limits are already checked by vfs
        BUG_ON(page_offset(page) > inode->i_size);
        // We can safely assume page is present in cache, due to page readahead
        // and locked
        cachep = find_get_page(inode->i_mapping, page_offset(page));
        BUG_ON(!cachep);
        BUG_ON(!PageLocked(page));
        if (!PageUptodate(cachep)) {
            blkptr bp = luci_find_leaf_block(inode, page_offset(page));
            if (bp.flags & LUCI_COMPR_FLAG) {
                ret = luci_read_compressed(page, &bp);
                if (ret != 0) {
                    panic("read failed :%d", ret);
                }    
            } else {
                goto uncompressed_read;
            }    
        }
        copy_pages(page, cachep, 0, 0, PAGE_SIZE);
        unlock_page(cachep);
        // Needed otherwise will result in an EIO
        SetPageUptodate(page);
        luci_dbg_inode(inode, "compressed read completed for pg index :%lu",
            page_index(page));
        goto done;
    }
#endif
uncompressed_read:    
    ret = mpage_readpage(page, luci_get_block);
done:
    return ret;
}

static int
luci_readpages(struct file *file, struct address_space *mapping,
    struct list_head *pages, unsigned nr_pages)
{
    return mpage_readpages(mapping, pages, nr_pages, luci_get_block);
}

// Depth first traversal of blocks
// assumes file is not truncated during this operation
int
luci_dump_layout(struct inode * inode) {
    int err, depth;
    unsigned long i, nr_blocks, nr_holes;
    long ipaths[LUCI_MAX_DEPTH];
    Indirect ichain[LUCI_MAX_DEPTH];

    nr_blocks = inode->i_size/luci_chunk_size(inode);

    for (i = 0, nr_holes = 0; i < nr_blocks; i++) {
       memset((char*)ipaths, 0, sizeof(long) * LUCI_MAX_DEPTH);

       depth = luci_block_to_path(inode, i, ipaths, NULL);
       if (!depth) {
          luci_err_inode(inode, "invalid block depth, iblock %ld", i);
          return -EIO;
       }

       // walk blocks in the path and store in ichain
       memset((char*)ichain, 0, sizeof(Indirect) * LUCI_MAX_DEPTH);

       if (luci_get_branch(inode, depth, ipaths, ichain, &err) != NULL) {
          luci_dbg_inode(inode, "detected hole at iblock %ld", i);
          nr_holes++;
       }

       if (err < 0) {
          luci_err_inode(inode, "error reading path iblock : %ld", i);
          return err;
       }

       luci_dbg_inode(inode, "block_path iblock %lu path %u %u %u %u", i,
          ichain[0].key.blockno, ichain[1].key.blockno, ichain[2].key.blockno,
          ichain[3].key.blockno);
    }

    luci_info_inode(inode, "total blocks :%lu holes :%lu", nr_blocks, nr_holes);
    return 0;
}

const struct inode_operations luci_dir_inode_operations = {
    .create         = luci_create,
    .lookup         = luci_lookup,
    .link           = luci_link,
    .unlink         = luci_unlink,
    .symlink        = luci_symlink,
    .mkdir          = luci_mkdir,
    .rmdir          = luci_rmdir,
    .mknod          = luci_mknod,
    .rename         = luci_rename,
    .getattr        = luci_getattr,
    .tmpfile        = luci_tmpfile,
};

const struct address_space_operations luci_aops = {
    .readpage       = luci_readpage,
    //.readpages      = luci_readpages,
    .writepage      = luci_writepage,
    .writepages     = luci_writepages,
    .write_begin    = luci_write_begin,
    .write_end      = luci_write_end,
};
