/*--------------------------------------------------------------------
 * Copyright(C) 2016, Saptarshi Sen
 *
 * LUCI inode operaitons
 *
 * ------------------------------------------------------------------*/
#include <linux/fs.h>
#include <linux/buffer_head.h>
#include <linux/version.h>
#include <linux/dcache.h>
#include <linux/path.h>
#include <linux/mpage.h>
#include "luci.h"

//extern struct inode *luci_iget(struct super_block *sb, unsigned long ino);

static int
luci_setattr(struct dentry *dentry, struct iattr *attr)
{
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
    printk(KERN_INFO "%s", __func__);
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
    printk(KERN_INFO "%s", __func__);
    return 0;
}
#endif

static inline void
add_chain(Indirect *p, struct buffer_head *bh, __le32 *v)
{
    p->key = *(p->p = v);
    p->bh = bh;
}

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
        path[n++] = i_block >> LUCI_ADDR_PER_BLOCK_BITS(inode->i_sb);
        path[n++] = i_block & (LUCI_ADDR_PER_BLOCK(inode->i_sb) - 1);
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
        goto done;
    }

    printk(KERN_ERR "warning: %s: block is too big", __func__);
done:
    return n;
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
        goto no_block;
    }

    while (--depth) {
        if ((bh = sb_bread(sb, p->key)) == NULL)  {
            goto failure;
        }
        add_chain(++p, bh, (__le32 *)bh->b_data + *++ipaths);
        if (!p->key) {
            goto no_block;
        }
        i++;
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
    return p;
}

int
luci_get_block(struct inode *inode, sector_t iblock,
        struct buffer_head *bh_result, int create)
{
    int ret = 0;
    Indirect *partial;
    long ipaths[LUCI_MAX_DEPTH];
    Indirect ichain[LUCI_MAX_DEPTH];

    int depth = luci_block_to_path(inode, iblock, ipaths);
    if (!depth) {
        printk(KERN_ERR "%s invalid block depth!", __func__);  
        return -EIO;
    }

    partial = luci_get_branch(inode, depth, ipaths, ichain, &ret);
    if (ret < 0) {
        printk(KERN_ERR "Error reading block to path :%u", ret);
        return ret;
    }

    if (!partial) {
        unsigned long block_no = ichain[depth - 1].key;
        map_bh(bh_result, inode->i_sb, block_no);
        return 0;
    }

    if (create) {
        printk(KERN_ERR "%s:Block allocation not supported!", __func__);
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

    for (n = 0; n < LUCI_N_BLOCKS; n++) {
        li->i_data[n] = raw_inode->i_block[n];
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

const struct inode_operations luci_file_inode_operations = {
    .setattr = luci_setattr,
    .getattr = luci_getattr,
};

static struct dentry *
luci_lookup(struct inode * dir, struct dentry *dentry,
        unsigned int flags) {
    ino_t ino;
    struct inode * inode = NULL;

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

static int
luci_create(struct inode *dir, struct dentry *dentry, umode_t mode,
        bool excl)
{
    printk(KERN_INFO "%s",__func__);
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

static int
luci_mkdir(struct inode * dir, struct dentry *dentry, umode_t mode)
{
    printk(KERN_INFO "%s", __func__);
    return 0;
}

static int
luci_unlink(struct inode * dir, struct dentry *dentry)
{
    printk(KERN_INFO "%s", __func__);
    return 0;
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
luci_readpage(struct file *file, struct page *page)
{
    return mpage_readpage(page, luci_get_block);
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
};
