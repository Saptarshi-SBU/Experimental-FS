/*-----------------------------------------------------------
 * Copyright(C) 2016, Saptarshi Sen
 *
 * Playground for Luci Super block and namespace operations
 *
 * ----------------------------------------------------------*/

#include <linux/module.h>
#include <linux/blkdev.h>
#include <linux/init.h>
#include <linux/vfs.h>
#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/backing-dev.h>
#include <linux/buffer_head.h>
#include <linux/log2.h>
#include "luci.h"
#include "kern_feature.h"

MODULE_AUTHOR("Saptarshi.S");
MODULE_ALIAS_FS("luci");
MODULE_DESCRIPTION("COW File System for Linux");
MODULE_LICENSE("GPL");

extern const struct inode_operations luci_dir_inode_operations;

extern const struct file_operations luci_dir_operations;

extern const struct address_space_operations luci_aops;

static struct kmem_cache* luci_inode_cachep;

static struct inode *luci_alloc_inode(struct super_block *sb)
{
    struct luci_inode_info *ei;
    ei = (struct luci_inode_info *)kmem_cache_alloc(luci_inode_cachep, GFP_KERNEL);
    if (!ei)
        return NULL;
    return &ei->vfs_inode;
}

static void luci_i_callback(struct rcu_head *head)
{
    struct inode *inode = container_of(head, struct inode, i_rcu);
    kmem_cache_free(luci_inode_cachep, luci_i(inode));
}

static void luci_destroy_inode(struct inode *inode)
{
    call_rcu(&inode->i_rcu, luci_i_callback);
}

static void luci_put_super(struct super_block *sb) {
    int i;
    struct luci_sb_info *sbi = sb->s_fs_info;
    for (i = 0; i < sbi->s_gdb_count; i++) {
       brelse(sbi->s_group_desc[i]);
    }
    kfree(sbi->s_group_desc);
    brelse(sbi->s_sbh);
    sb->s_fs_info = NULL;
    kfree(sbi);
}

static void init_once(void *foo)
{
    struct luci_inode_info *ei = (struct luci_inode_info *) foo;
    inode_init_once(&ei->vfs_inode);
}

static int init_inodecache(void)
{
    luci_inode_cachep = kmem_cache_create("luci_inode_cache",
                        sizeof(struct luci_inode_info),
                        0,
                        (SLAB_RECLAIM_ACCOUNT|SLAB_MEM_SPREAD),
                        init_once);

    if (luci_inode_cachep == NULL)
        return -ENOMEM;
    return 0;
}

static void destroy_inodecache(void)
{
    rcu_barrier();
    kmem_cache_destroy(luci_inode_cachep);
}

static const struct super_operations luci_sops = {
    .alloc_inode    = luci_alloc_inode,
    .destroy_inode  = luci_destroy_inode,
    .put_super = luci_put_super,
};

static int luci_read_inode(struct inode* inode, unsigned int mode) {
/* TBD : Read from device. But currently faking */
    inode->i_mode = mode;
    inode->i_blocks = 1;
    inode->i_size = 4096;
    inode->i_mtime = inode->i_atime = inode->i_ctime = current_time(inode);
    return 0;
}

struct inode *luci_iget(struct super_block *sb, unsigned long ino) {
    int err = 0;
    struct inode *inode;

    // TBD : iget* initializes i_mode
    inode = iget_locked(sb, ino);
    if (!inode)
        return ERR_PTR(-ENOMEM);
    if (!(inode->i_state & I_NEW))
        return inode;

    // First inode for the root directory
    err = luci_read_inode(inode, S_IFDIR);
    if (err)
        return ERR_PTR(err);
    // clears the new state
    unlock_new_inode(inode);
    return inode;
}

// TBD
static size_t
luci_file_maxsize(int bits) {

   return 0;
}

static int
luci_read_superblock(struct super_block *sb) {
   int ret = 0;
   unsigned long i;
   unsigned long block_no;
   unsigned long block_of;
   unsigned long block_size;
   struct buffer_head *bh;
   struct luci_super_block *lsb;
   struct luci_sb_info *sbi;

   sbi = kzalloc(sizeof(struct luci_sb_info), GFP_KERNEL);
   if (!sbi) {
      return -ENOMEM;
   }

   // Note : This block number assumes BLOCK_SIZE
   block_no = 1;

   // internally sets sb block_size based on min
   (void) sb_min_blocksize(sb, BLOCK_SIZE);

restart:

   if (sb->s_blocksize != BLOCK_SIZE) {
      block_of = (block_no*BLOCK_SIZE)%sb->s_blocksize;
      block_no = (block_no*BLOCK_SIZE)/sb->s_blocksize;
   } else {
      block_of = 0;
   }

   if (!(bh = sb_bread(sb, block_no))) {
     printk(KERN_ERR "LUCI: error reading super block");
     ret = -EIO;
     goto failed_sbi;
   }

   if (sb->s_blocksize != bh->b_size) {
      printk(KERN_ERR "LUCI: invalid block-size in buffer-head");
      brelse(bh);
      ret = -EIO;
      goto failed_sbi;
   }

   // luci on-disk super-block format
   lsb = (struct luci_super_block*)((char*) bh->b_data + block_of);
   sbi->s_lsb = lsb;

   sb->s_magic = le16_to_cpu(lsb->s_magic);
   if (sb->s_magic != LUCI_SUPER_MAGIC) {
      printk(KERN_ERR "LUCI: invalid magic number on super-block");
      ret = -EINVAL;
      goto failed_mount;
   }

   // get the on-disk block size
   block_size = BLOCK_SIZE << le32_to_cpu(lsb->s_log_block_size);
   if (sb->s_blocksize != block_size) {
     brelse(bh);
     if (!sb_set_blocksize(sb, block_size)) {
        ret = -EPERM;
        goto failed_mount;
     }
     printk(KERN_INFO "LUCI: default block size mismatch! re-reading...");
     goto restart;
   }

   sbi->s_sbh = bh;
   sb->s_maxbytes = luci_file_maxsize(sb->s_blocksize_bits);
   sb->s_max_links = LUCI_LINK_MAX;

   // inode size
   sbi->s_inode_size = le16_to_cpu(lsb->s_inode_size);
   if ((sbi->s_inode_size < LUCI_GOOD_OLD_INODE_SIZE) ||
       (sbi->s_inode_size > sb->s_blocksize) ||
       (!is_power_of_2(sbi->s_inode_size))) {
      printk(KERN_ERR "LUCI: invalid inode size in super block :%d",
         sbi->s_inode_size);
      ret = -EINVAL;
      goto failed_mount;
   }

   sbi->s_inodes_per_block = sb->s_blocksize/sbi->s_inode_size;
   if (sbi->s_inodes_per_block == 0) {
      printk(KERN_ERR "LUCI: invalid inodes per block");
      ret = -EINVAL;
      goto failed_mount;
   }

   // fragment size
   sbi->s_frag_size = LUCI_MIN_FRAG_SIZE << le32_to_cpu(lsb->s_log_frag_size);
   if (sbi->s_frag_size == 0) {
      printk(KERN_ERR "LUCI: fragment size invalid");
      ret = -EINVAL;
      goto failed_mount;
   }
   sbi->s_frags_per_block = sb->s_blocksize/sbi->s_frag_size;

   sbi->s_first_ino = le32_to_cpu(lsb->s_first_ino);

   // block group
   sbi->s_frags_per_group = le32_to_cpu(lsb->s_frags_per_group);
   // check based on bits per block
   if ((sbi->s_frags_per_group == 0) ||
       (sbi->s_frags_per_group > sb->s_blocksize * 8)) {
      printk(KERN_ERR "LUCI: invalid frags per group");
      ret = -EINVAL;
      goto failed_mount;
   }

   sbi->s_blocks_per_group = le32_to_cpu(lsb->s_blocks_per_group);
   // check based on bits per block
   if ((sbi->s_blocks_per_group == 0) ||
       (sbi->s_blocks_per_group > sb->s_blocksize * 8)) {
      printk(KERN_ERR "LUCI: invalid blocks per group");
      ret = -EINVAL;
      goto failed_mount;
   }
   sbi->s_inodes_per_group = le32_to_cpu(lsb->s_inodes_per_group);
   if ((sbi->s_inodes_per_group == 0) ||
       (sbi->s_inodes_per_group > sb->s_blocksize * 8)) {
      printk(KERN_ERR "LUCI: invalid inodes per group");
      ret = -EINVAL;
      goto failed_mount;
   }

   // blocks to store inode table
   sbi->s_itb_per_group = sbi->s_inodes_per_group/sbi->s_inodes_per_block;
   // group desc per block
   sbi->s_desc_per_block = sb->s_blocksize/sizeof(struct luci_group_desc);

   sbi->s_mount_state = le16_to_cpu(lsb->s_state);

   sbi->s_addr_per_block_bits = ilog2 (LUCI_ADDR_PER_BLOCK(sb));
   sbi->s_desc_per_block_bits = ilog2 (sbi->s_desc_per_block);

   // nr_groups
   sbi->s_groups_count =
     (le32_to_cpu(lsb->s_blocks_count) - le32_to_cpu(lsb->s_first_data_block))/
     sbi->s_blocks_per_group;
   sbi->s_gdb_count = sbi->s_groups_count/sbi->s_desc_per_block;
   // bh array
   sbi->s_group_desc = (struct buffer_head **) kmalloc
      (sbi->s_gdb_count * sizeof(struct buffer_head *), GFP_KERNEL);
   if (sbi->s_group_desc == NULL) {
      ret = -ENOMEM;
      printk(KERN_ERR "LUCI: cannot allocate memory for group descriptors");
      goto failed_mount;
   }

   for (i = 0; i < sbi->s_gdb_count; i++) {
      // Meta-bg not supported
      sbi->s_group_desc[i] = sb_bread(sb, block_no + i + 1);
      if (sbi->s_group_desc[i] == NULL) {
         printk(KERN_ERR "LUCI: failed to read group descriptors");
	 ret = -EIO;
         goto failed_gdb;
      }
   }

   sb->s_fs_info = sbi;

   // ready the super-block for any operations
   sb->s_op = &luci_sops;

   // increase mount count
   le16_add_cpu(&lsb->s_mnt_count, 1);

   lsb->s_wtime = cpu_to_le32(get_seconds());
   mark_buffer_dirty(sbi->s_sbh);
   sync_dirty_buffer(sbi->s_sbh);

   printk(KERN_INFO "LUCI: super_block read successfull");
   return 0;

failed_gdb:
   while (i >= 0) {
     brelse(sbi->s_group_desc[i]);
     i--;
   };
   kfree(sbi->s_group_desc);
failed_mount:
   sbi->s_sbh = NULL;
   brelse(bh);
failed_sbi:
   kfree(sbi);
   printk(KERN_ERR "LUCI: luci super block read error");
   return ret;
}

static struct dentry*
luci_read_rootinode(struct super_block *sb) {
    struct dentry *dentry;
    struct inode *root_inode;

    root_inode = luci_iget(sb, LUCI_ROOT_INO);
    if (IS_ERR(root_inode)) {
        printk(KERN_ERR "LUCI: failed to read root dir inode\n");
        return ERR_PTR(-EIO);
    }

    if (!S_ISDIR(root_inode->i_mode) || !root_inode->i_blocks ||
        !root_inode->i_size) {
        printk(KERN_ERR "LUCI: corrupt root dir inode.\n");
	iput(root_inode);
        return ERR_PTR(-EINVAL);
    }

    root_inode->i_fop = &luci_dir_operations;
    root_inode->i_op = &luci_dir_inode_operations;
    root_inode->i_mapping->a_ops = &luci_aops;

#if HAVE_D_OBTAIN_ROOT
    dentry = d_obtain_root(root_inode);
#else
    dentry = d_make_root(root_inode);
#endif

    if (IS_ERR(dentry)) {
       printk(KERN_ERR "LUCI: root dir inode dentry error.");
    }

    return dentry;
}

static int
luci_fill_super(struct super_block *sb, void *data, int silent)
{
    int ret = 0;
    struct dentry* dentry;

    ret = luci_read_superblock(sb);
    if (ret != 0) {
       return ret;
    }

    dentry = luci_read_rootinode(sb);
    if (IS_ERR(dentry)) {
       return PTR_ERR(dentry);
    }

    sb->s_root = dentry;
    printk(KERN_INFO "LUCI: luci super block read sucess");
    return 0;
}

static struct dentry *
luci_mount(struct file_system_type *fs_type, int flags,
         const char *dev_name, void *data)
{
    return mount_bdev(fs_type, flags, dev_name, data, luci_fill_super);
}

struct file_system_type luci_fs = {
    .owner    = THIS_MODULE,
    .name     = "luci",
    .mount    = luci_mount,
    .kill_sb  = kill_block_super,
    .fs_flags = FS_REQUIRES_DEV,
};

static int __init init_luci_fs(void)
{
    int err;

    err = init_inodecache();
    if (err)
        return err;

    err = register_filesystem(&luci_fs);
    if (err)
        goto failed;

    printk(KERN_INFO "LUCI FS loaded\n");
    return 0;

failed:
    destroy_inodecache();
    return err;
}

static void __exit exit_luci_fs(void)
{
    unregister_filesystem(&luci_fs);
    destroy_inodecache();
}

module_init(init_luci_fs)
module_exit(exit_luci_fs)
