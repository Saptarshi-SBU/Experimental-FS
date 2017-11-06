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
#include <linux/dcache.h>
#include <linux/path.h>
#include <linux/mpage.h>
#include "luci.h"

static int
luci_setsize(struct inode *inode, loff_t newsize)
{
    // Cannot modify size of directory
    if (!S_ISREG(inode->i_mode)) {
       printk (KERN_ERR "luci :setsize not valid for inode :%lu", inode->i_ino);
       return -EINVAL;
    }
    luci_truncate(inode, newsize);
    truncate_setsize(inode, newsize);
    inode->i_mtime = inode->i_ctime = current_time(inode);
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
    struct inode *inode = d_inode(dentry);
    printk(KERN_INFO "luci : %s", __func__);

    // check we have permissions to change attributes
    err = setattr_prepare(dentry, attr);
    if (err) {
       return err;
    }

    // Wait for all pending direct I/O requests so that
    // we can proceed with a truncate
    inode_dio_wait(inode);

    // check modify size
    if (attr->ia_valid & ATTR_SIZE && attr->ia_size != inode->i_size) {
       printk(KERN_INFO "luci : setattr inode :%lu oldsize :%llu newsize :%llu",
          inode->i_ino, inode->i_size, attr->ia_size);
       err = luci_setsize(inode, attr->ia_size);
       if (err) {
           return err;
       }
    }

    luci_dump_layout(inode);

    // TBD : change mode
    return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,8)
static int
luci_getattr(const struct path *path, struct kstat *stat,
        u32 request_mask, unsigned int query_flags) {
    struct super_block *sb = path->dentry->d_sb;
    struct inode *inode = d_inode(path->dentry);
    generic_fillattr(inode, stat);
    stat->blksize = sb->s_blocksize;
    printk(KERN_INFO "Luci:%s", __func__);
    return 0;
}
#else
static int
luci_getattr(struct vfsmount *mnt, struct dentry *dentry,
        struct kstat *stat)
{
    struct super_block *sb = dentry->d_sb;
    generic_fillattr(dentry->d_inode, stat);
    stat->blksize = sb->s_blocksize;
    printk(KERN_INFO "Luci:%s", __func__);
    return 0;
}
#endif

inline unsigned
luci_chunk_size(struct inode *inode)
{
    return inode->i_sb->s_blocksize;
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
    ret =  __block_write_begin(page, pos, len, luci_get_block);
    printk(KERN_INFO "luci : block write begin, pos :%llu len :%u ret :%d",
       pos, len, ret);
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
        printk(KERN_INFO "luci : updating dir inode %lu new size :%llu",
	    dir->i_ino, dir->i_size);
    }
    if (IS_DIRSYNC(dir)) {
        err = write_one_page(page, 1);
        if (!err) {
            err = sync_inode_metadata(dir, 1);
        }
    } else {
        unlock_page(page);
    }
    printk(KERN_INFO "luci : block write end, inode :%lu, pos :%llu len :%u "
       "err :%d", dir->i_ino, pos, len, err);
    return err;
}

static inline void
add_chain(Indirect *p, struct buffer_head *bh, __le32 *v)
{
    p->key = *(p->p = v);
    p->bh = bh;
}

// Update path based on block number, offsets into indices
static int
luci_block_to_path(struct inode *inode,
        long i_block,
        long path[LUCI_MAX_DEPTH])
{
    int n = 0;
    const long nr_direct = LUCI_NDIR_BLOCKS;
    const long nr_indirect = LUCI_ADDR_PER_BLOCK(inode->i_sb);
    const long nr_dindirect = (1 << (LUCI_ADDR_PER_BLOCK_BITS(inode->i_sb) * 2));

    if (i_block < 0) {
        printk(KERN_ERR "warning: %s: block < 0", __func__);
        return -EINVAL;
    }

    if (i_block < nr_direct) {
        path[n++] = i_block;
        printk(KERN_INFO " luci : block %ld maps to a direct block", i_block);
        goto done;
    }

    i_block -= nr_direct;
    if (i_block < nr_indirect) {
        path[n++] = LUCI_IND_BLOCK;
        path[n++] = i_block;
        printk(KERN_INFO " luci : block %ld maps to an indirect block", i_block);
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
        printk(KERN_INFO " luci : block %ld maps to a double indirect block",
	   i_block);
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
        printk(KERN_INFO " luci : block %ld maps to a triple indirect block",
	   i_block);
        goto done;
    }

    printk(KERN_ERR "warning: %s: block is too big", __func__);
done:
    printk(KERN_INFO "%s, n:%d", __func__, n);
    return n;
}

static int
alloc_branch(struct inode *inode,
             int num,
             long int *offsets,
             Indirect *branch)
{
    int n = 0;
    int ret;
    int curr_block, parent_block;
    struct buffer_head *bh; // storing parent block buffer head

    ret = luci_new_block(inode);
    if (ret < 0) {
       goto fail;
    }
    branch[0].key = curr_block = ret;
   *branch[0].p = branch[0].key;
    //printk(KERN_INFO "luci: alloc branch for inode :%lu, block :%u : %p",
    //   inode->i_ino, branch[0].key, branch[0].p);

    // Walk block table for allocating indirect block entries
    for (n = 1; n < num; n++) {
        ret = luci_new_block(inode);
        if (ret < 0) {
           goto fail;
        }
        parent_block = curr_block;
        curr_block = ret;
	// will locate and if necessary create buffer head
        bh = sb_getblk(inode->i_sb, parent_block);
        if (bh == NULL) {
	   printk(KERN_ERR "luci : failed to read parent block :%d for inode "
	      "%lu", parent_block, inode->i_ino);
           ret = -EIO;
           goto fail;
        }
        lock_buffer(bh);
	// clear the newly allocated parent block
	memset(bh->b_data, 0, bh->b_size);
	printk(KERN_INFO "luci : zeroing newly allocated parent block :%d for "
           " inode :%lu", parent_block, inode->i_ino);
        branch[n].key = curr_block;
        // offset to indirect block table to store block address entry
        branch[n].p = (__le32*) bh->b_data + offsets[n];
	// imp : i_data array updated here
       *branch[n].p = branch[n].key;
        // note this is buffer head of previous block
        branch[n].bh = bh;
        set_buffer_uptodate(bh);
        unlock_buffer(bh);
        mark_buffer_dirty_inode(bh, inode);
        //printk(KERN_INFO "luci: alloc branch for inode :%lu, block :%u",
        //   inode->i_ino, branch[n].key);
	//brelse(bh);
    }

    printk(KERN_INFO "luci: allocated blocks for inode :%lu, depth : %d "
       "leaf block :%d", inode->i_ino, num, curr_block);
    return 0;
fail:
    printk(KERN_ERR "luci: failed to alloc full path for branch, "
       "inode :%lu path length :%d", inode->i_ino, n);
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
    if (!p->key) {
        //printk(KERN_INFO "luci: root chain for inode :%lu : ipath :%ld : %p",
        //inode->i_ino, *ipaths, p->p);
        goto no_block;
    }
    i++;
    while (i < depth) {
        if ((bh = sb_bread(sb, p->key)) == NULL)  {
            printk(KERN_ERR "Luci: failed block walk path for inode %lu, "
	       "ipath[%d] %d read failed", inode->i_ino, i, p->key);
            goto failure;
        }
        add_chain(++p, bh, (__le32 *)bh->b_data + *++ipaths);
        if (!p->key) {
            goto no_block;
        }
        i++;
        printk(KERN_INFO "luci : block walk path : inode :%lu ipath[%d] %d",
	   inode->i_ino, i, p->key);
    }
    return NULL;

failure:
    for (i = 0; i < LUCI_MAX_DEPTH; i++) {
        if (!ichain[i].key) {
            break;
        }
        brelse(ichain[i].bh);
    }
    *err = -EIO;
no_block:
    printk(KERN_INFO "luci : found no key in block path walk at level %d"
        " for inode :%lu ipaths :%ld", i, inode->i_ino, *ipaths);
    return p;
}

int
luci_get_block(struct inode *inode, sector_t iblock,
        struct buffer_head *bh_result, int create)
{
    int err = 0;
    int depth = 0;
    u32 block_no = -1;
    int nr_blocks = 0;
    Indirect *partial;
    long ipaths[LUCI_MAX_DEPTH];
    Indirect ichain[LUCI_MAX_DEPTH];

    printk(KERN_INFO "luci : Fetch block for inode :%lu, i_block :%lu "
      "create :%s", inode->i_ino, iblock, create ? "alloc" : "noalloc");

    depth = luci_block_to_path(inode, iblock, ipaths);
    if (!depth) {
        printk(KERN_ERR "Luci:get_block, invalid block depth!");
        return -EIO;
    }

    partial = luci_get_branch(inode, depth, ipaths, ichain, &err);
    if (err < 0) {
        printk(KERN_ERR "Luci:error reading block to path :%u", err);
        return err;
    }

    if (!partial) {
gotit:
        block_no = ichain[depth - 1].key;
        printk(KERN_ERR "luci : get block ino %lu found block: %lu for "
	   "i_block :%u", inode->i_ino, iblock, block_no);
        if (bh_result) {
           map_bh(bh_result, inode->i_sb, block_no);
        }
        return 0;
    } else {
        if (create) {
            printk(KERN_INFO "luci : get block allocating block for inode %lu",
	       inode->i_ino);
            nr_blocks = (ichain + depth) - partial;
            err = alloc_branch(inode, nr_blocks, ipaths + (partial - ichain), partial);
            if (!err) {
                // note inode is still not updated
                goto gotit;
            }
            printk(KERN_ERR "Luci:block allocation failed, err :%d", err);
            return err;
        }
    }
    return -EINVAL;
}

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
    li->i_dir_start_lookup = 0;
    li->i_dtime = le32_to_cpu(raw_inode->i_dtime);

    if (inode->i_nlink == 0 && (inode->i_mode == 0 || li->i_dtime)) {
        /* this inode is deleted */
        brelse (bh);
        iget_failed(inode);
        return ERR_PTR(-ESTALE);
    }

    printk(KERN_INFO "ino :%lu nr_blocks:%lu", ino,
       (inode->i_blocks*512)/sb->s_blocksize);
    for (n = 0; n < LUCI_N_BLOCKS; n++) {
        li->i_data[n] = raw_inode->i_block[n];
        printk(KERN_INFO "ino :%lu i_data[%d]:%u", ino, n, li->i_data[n]);
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
        printk(KERN_ERR "Inode mode not supported");
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
    printk(KERN_ERR "luci_get_inode bad inode number: %lu",
       (unsigned long) ino);
    return ERR_PTR(-EINVAL);
Eio:
    printk(KERN_ERR "luci_get_inode"
            "unable to read inode block - inode=%lu, block=%lu",
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

    dir = d_inode(dentry->d_parent);

    // Note block size may not be the same as page size
    npages = dir_pages(dir);

    new_dentry_len = LUCI_DIR_REC_LEN(dentry->d_name.len);

    printk(KERN_INFO "Luci :%s dir npages :%lu add dentry :%s len :%d",
       __func__, npages, dentry->d_name.name, new_dentry_len);

    for (n = 0; n < npages; n++) {
        char *kaddr, *page_boundary;
        page = luci_get_page(dir, n);
        if (IS_ERR(page)) {
            err = PTR_ERR(page);
            printk(KERN_ERR "Luci: Error getting page %lu :%d", n, err);
            return err;
        }
        lock_page(page);
        kaddr = page_address(page);
        // We do not want dentry to be across page boundary
        page_boundary = kaddr + PAGE_SIZE - new_dentry_len;
        printk(KERN_INFO "luci : dentries lookup in dir inode:%lu", dir->i_ino);
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
                printk(KERN_ERR "luci : failed to add link, file exists %s",
		    dentry->d_name.name);
                goto outunlock;
            }
            // offset to next valid dentry from current de
            rec_len = luci_rec_len_from_disk(de->rec_len);
            //printk(KERN_INFO "luci : dname :%s inode :%u next_len :%u",
	    //   de->name, de->inode, rec_len);
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
        printk(KERN_INFO "luci : dentry page %ld nr_pages :%ld ", n, npages);
    }

    // extend the directory to accomodate new dentry
    page = luci_get_page(dir, n);
    if (IS_ERR(page)) {
       err = -ENOSPC;
       printk(KERN_ERR "Luci: Error getting page %lu :%ld", n, PTR_ERR(page));
       printk(KERN_ERR "luci: failed to adding new link entry, no space");
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
    printk(KERN_INFO "luci: empty dentry found, adding new link entry");
    // Previous entry have to be modified
    if (de->inode) {
        struct luci_dir_entry_2 * de_new = (struct luci_dir_entry_2*)
	   ((char*) de + LUCI_DIR_REC_LEN(de->name_len));
	de_new->inode = inode->i_ino;
        de_new->rec_len = luci_rec_len_to_disk(rec_len - new_dentry_len);
        de->rec_len = luci_rec_len_to_disk(LUCI_DIR_REC_LEN(de->name_len));
        de = de_new;
    }

    pos = page_offset(page) +
        (char*)de - (char*)page_address(page);
    err = luci_prepare_chunk(page, pos, new_dentry_len);
    if (err) {
        printk(KERN_ERR "luci : error to prepare chunk during dentry insert");
        goto outunlock;
    }
    de->name_len = dentry->d_name.len;
    memcpy(de->name, dentry->d_name.name, de->name_len);
    de->inode = cpu_to_le32(inode->i_ino);
    luci_set_de_type(de, inode);
    err = luci_commit_chunk(page, pos, new_dentry_len);
    if (err) {
        printk(KERN_ERR "luci : error to commit chunk during dentry insert");
    }
    dir->i_mtime = dir->i_ctime = current_time(dir);
    mark_inode_dirty(dir);
    luci_put_page(page);
    printk(KERN_INFO "luci : sucessfully inserted dentry %s for inode :%lu"
	" record_len :%d next_record :%d", dentry->d_name.name, inode->i_ino,
	LUCI_DIR_REC_LEN(de->name_len), de->rec_len);
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
            printk ("IO error syncing luci inode [%s:%08lx]\n",
                    sb->s_id, (unsigned long) ino);
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
    struct inode * inode = NULL;

    printk(KERN_INFO "%s", __func__);

    if (dentry->d_name.len > LUCI_NAME_LEN) {
        return ERR_PTR(-ENAMETOOLONG);
    }

    ino = luci_inode_by_name(dir, &dentry->d_name);
    if (ino) {
        inode = luci_iget(dir->i_sb,  ino);
        if (inode == ERR_PTR(-ESTALE)) {
            printk(KERN_ERR "delete inode referenced: %lu",
                    (unsigned long) ino);
            return ERR_PTR(-EIO);
        }
    }
    //splice a disconnected dentry into the tree if one exists
    return d_splice_alias(inode, dentry);
}

static int
luci_mknod(struct inode * dir, struct dentry *dentry, umode_t mode, dev_t rdev)
{
    printk(KERN_INFO "%s",__func__);
    return 0;
}

static int
luci_tmpfile(struct inode *dir, struct dentry *dentry, umode_t mode)
{
    printk(KERN_INFO "%s",__func__);
    return 0;
}

static void
luci_track_size(struct inode * inode) {
   loff_t size = inode->i_blocks * 512;
   printk(KERN_INFO "luci: %s inode: %lu size :%llu phy size :%llu blocks :%lu",
      __func__, inode->i_ino, inode->i_size, size, inode->i_blocks);
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
        printk(KERN_ERR "Failed to create new inode");
        return PTR_ERR(inode);
    }
    printk(KERN_INFO "luci : Created new inode, inode :%lu, name :%s",
       inode->i_ino, dentry->d_name.name);
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
       printk(KERN_ERR "Luci :%s Inode add link failed, err :%d", __func__, err);
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
    printk(KERN_INFO "%s", __func__);
    return 0;
}

static int
luci_link(struct dentry * old_dentry, struct inode * dir,
        struct dentry *dentry)
{
    printk(KERN_INFO "%s", __func__);
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
        printk(KERN_ERR "Luci:%s failed to pepare chunk", __func__);
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

    printk(KERN_INFO "%s", __func__);

    inode_inc_link_count(dir);
    inode = luci_new_inode(dir, S_IFDIR | mode, &dentry->d_name);
    if (IS_ERR(inode)) {
        printk(KERN_ERR "Luci:failed to create new inode");
        goto fail_dir;
    }
    inode->i_op = &luci_dir_inode_operations;
    inode->i_fop = &luci_dir_operations;
    inode->i_mapping->a_ops = &luci_aops;
    inode_inc_link_count(inode);
    err = luci_make_empty(inode, dir);
    if (err) {
        printk(KERN_ERR "Luci:failed to make empty directory");
        goto out_fail;
    }
    err = luci_add_link(dentry, inode);
    if (err) {
        printk(KERN_ERR "luci:failed to add dentry in parent directory");
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
    struct inode * inode = d_inode(dentry);
    struct luci_dir_entry_2 * de;
    struct page * page;
    int err;

    printk(KERN_INFO "Luci : %s name :%s", __func__, dentry->d_name.name);

    de = luci_find_entry(dir, &dentry->d_name, &page);
    if (!de) {
       err = -ENOENT;
       printk(KERN_ERR "Luci : %s name :%s not found",
           __func__, dentry->d_name.name);
       goto out;
    }

    err = luci_delete_entry(de, page);
    if (err) {
       err = -EIO;
       printk(KERN_ERR "Luci : %s name :%s failed to delete",
           __func__, dentry->d_name.name);
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
    printk(KERN_INFO "%s", __func__);
    return 0;
}

static int
luci_rename(struct inode * old_dir, struct dentry *old_dentry,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,8)
        struct inode * new_dir, struct dentry *new_dentry, unsigned int flags)
#else
    struct inode * new_dir, struct dentry *new_dentry)
#endif
{
    printk(KERN_INFO "%s", __func__);
    return 0;
}

static int
luci_writepage(struct page *page, struct writeback_control *wbc)
{
    return block_write_full_page(page, luci_get_block, wbc);
}

static int
luci_write_begin(struct file *file, struct address_space *mapping,
    loff_t pos, unsigned len, unsigned flags,
    struct page **pagep, void **fsdata)
{
    int ret;
    ret = block_write_begin(mapping, pos, len, flags, pagep,
       luci_get_block);
    if (ret < 0) {
       printk(KERN_ERR "Luci:%s failed with %d", __func__, ret);
    }
    return ret;
}

static int
luci_write_end(struct file *file, struct address_space *mapping,
    loff_t pos, unsigned len, unsigned copied,
    struct page *page, void *fsdata)
{
    int ret;
    ret = generic_write_end(file, mapping, pos, len, copied, page, fsdata);
    if (ret < 0) {
       printk(KERN_ERR "Luci:%s failed with %d", __func__, ret);
    }
    return ret;
}

static int
luci_readpage(struct file *file, struct page *page)
{
    printk(KERN_INFO "luci : %s", __func__);
    return mpage_readpage(page, luci_get_block);
}

// Depth first traversal of blocks
// assumes file is not truncated during this operation
int
luci_dump_layout(struct inode * inode) {
    ino_t ino;
    int err, depth;
    unsigned long i, nr_blocks;
    long ipaths[LUCI_MAX_DEPTH];
    Indirect ichain[LUCI_MAX_DEPTH];

    ino = inode->i_ino;
    nr_blocks = inode->i_size/luci_chunk_size(inode);
    printk(KERN_INFO "luci : inode layout %lu nr_blocks :%lu", ino, nr_blocks);

    for (i = 0; i < nr_blocks; i++) {
       memset((char*)ipaths, 0, sizeof(long) * LUCI_MAX_DEPTH);
       // depth for i_block
       depth = luci_block_to_path(inode, i, ipaths);
       if (!depth) {
          printk(KERN_ERR "luci : invalid block depth %ld inode :%lu", i, ino);
          return -EIO;
       }
       //  walk blocks in the path and store in ichain
       memset((char*)ichain, 0, sizeof(Indirect) * LUCI_MAX_DEPTH);
       if (luci_get_branch(inode, depth, ipaths, ichain, &err) != NULL) {
          // all blocks must be allocated in the path
          BUG();
       }
       if (err < 0) {
          printk(KERN_ERR "luci : error reading path %ld inode :%lu", i, ino);
          return err;
       }
       // dump path
       printk(KERN_INFO "Luci : block_path, inode %lu i_block :%lu path "
          "%u %u %u %u", inode->i_ino, i, ichain[0].key, ichain[1].key,
	  ichain[2].key, ichain[3].key);
    }
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
    .writepage      = luci_writepage,
    .write_begin    = luci_write_begin,
    .write_end      = luci_write_end,
};
