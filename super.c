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
#include "luci.h"

#define KERNV_311 0
#define KERNV_317 1

MODULE_AUTHOR("Saptarshi.S");
MODULE_ALIAS_FS("LUCI");
MODULE_DESCRIPTION("COW File System for Linux");
MODULE_LICENSE("GPL");

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
};


static int luci_read_inode(struct inode* inode, int mode) {

/* TBD : Read from device. But currently faking */
    inode->i_mode |= mode;
    inode->i_blocks = 1;
    inode->i_size = 4096;
    inode->i_mtime = inode->i_atime = inode->i_ctime = CURRENT_TIME;
    return 0;
}

struct inode *luci_iget(struct super_block *sb, unsigned long ino)
{
    int err = 0;
    struct inode *inode;

    inode = iget_locked(sb, ino);
    if (!inode)
        return ERR_PTR(-ENOMEM);
    if (!(inode->i_state & I_NEW))
        return inode;

    err = luci_read_inode(inode, S_IFDIR);
    if (err)
        return ERR_PTR(err);
    return inode;
}

static int
luci_fill_super(struct super_block *sb, void *data, int silent)
{
    struct dentry* dentry;
    struct inode* root_inode;
    int ret = 0;

    root_inode = luci_iget(sb, LUCI_ROOT_INODE);
    if (IS_ERR(root_inode)) {
        printk(KERN_ERR "LUCI: get root inode failed\n");
        ret = PTR_ERR(root_inode);
        goto out;
    }

    if (!S_ISDIR(root_inode->i_mode) || !root_inode->i_blocks || !root_inode->i_size) {
        iput(root_inode);
        printk(KERN_ERR "LUCI: corrupt root inode.\n");
        ret = -EINVAL;
        goto out;
    }

#if KERNV_317
    dentry = d_obtain_root(root_inode);
#elif KERNV_311
    dentry = d_make_root(root_inode);
#endif
    if (IS_ERR(dentry)) {
        ret = PTR_ERR(dentry);
        goto failed_dentry;
    }

    sb->s_root = dentry;
    sb->s_bdi = &bdev_get_queue(sb->s_bdev)->backing_dev_info;
    sb->s_op = &luci_sops;

out:
    return ret;

failed_dentry:
    iput(root_inode);
    return ret;
}

static int luci_set_bdev_super(struct super_block *s, void *data)
{
    s->s_bdev = data;
    s->s_dev = s->s_bdev->bd_dev;
    return 0;
}

static int luci_test_bdev_super(struct super_block *s, void *data)
{
    return (void *)s->s_bdev == data;
}

static struct dentry *
luci_mount(struct file_system_type *fs_type, int flags,
         const char *dev_name, void *data)
{
    struct super_block *s;
    struct block_device *bdev;
    struct dentry *root_dentry;
    fmode_t mode = FMODE_READ | FMODE_EXCL;
    int err, s_new = false;

    bdev = blkdev_get_by_path(dev_name, mode, fs_type);
    if (IS_ERR(bdev)) {
        printk(KERN_ERR "block device not found!");
        return ERR_CAST(bdev);
    }

    s = sget(fs_type, luci_test_bdev_super, luci_set_bdev_super, flags, bdev);
    if (IS_ERR(s)) {
        printk(KERN_ERR "super block error!");
        err = PTR_ERR(s);
        goto failed;
    }

    if (!s->s_root) {
        char b[BDEVNAME_SIZE];
        s_new = true;
        s->s_mode = mode;
        strlcpy(s->s_id, bdevname(bdev, b), sizeof(s->s_id));
        sb_set_blocksize(s, block_size(bdev));
        err = luci_fill_super(s, data, flags & MS_SILENT ? 1 : 0);
        if (err)
            goto failed_super;
        s->s_flags |= MS_ACTIVE;
        printk(KERN_INFO "super block instance created");
    }

    root_dentry = dget(s->s_root);
    BUG_ON(!root_dentry);
    return root_dentry;

 failed_super:
    deactivate_locked_super(s);

 failed:
    if (!s_new)
        blkdev_put(bdev, mode);
    return ERR_PTR(err);
}

struct file_system_type luci_fs = {
    .owner    = THIS_MODULE,
    .name     = "LUCI",
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
