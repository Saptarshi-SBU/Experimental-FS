/*--------------------------------------------------------------------
 * Copyright(C) 2016, Saptarshi Sen
 *
 * LUCI inode operaitons
 *
 * ------------------------------------------------------------------*/
#include <linux/fs.h>
#include <linux/version.h>
#include "luci.h"

static int luci_setattr(struct dentry *dentry, struct iattr *attr)
{
    return 0;
}


#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,8)
static int luci_getattr(const struct path *path, struct kstat *stat,
   u32 request_mask, unsigned int query_flags)
#else
static int luci_getattr(struct vfsmount *mnt, struct dentry *dentry,
   struct kstat *stat)
#endif
{
    return 0;
}

const struct inode_operations luci_file_inode_operations = {
    .setattr = luci_setattr,
    .getattr = luci_getattr,
};

static struct dentry *luci_lookup(struct inode * dir, struct dentry *dentry, unsigned int flags)
{
    printk(KERN_INFO "%s", __func__);
    return NULL;
}

static int luci_mknod(struct inode * dir, struct dentry *dentry, umode_t mode, dev_t rdev)
{
    printk(KERN_INFO "%s",__func__);
    return 0;
}

static int luci_tmpfile(struct inode *dir, struct dentry *dentry, umode_t mode)
{
    printk(KERN_INFO "%s",__func__);
    return 0;
}

static int luci_create(struct inode *dir, struct dentry *dentry, umode_t mode,
                bool excl)
{
    printk(KERN_INFO "%s",__func__);
    return 0;
}

static int luci_symlink(struct inode * dir, struct dentry *dentry,
          const char * symname)
{
    printk(KERN_INFO "%s", __func__);
    return 0;
}

static int luci_link(struct dentry * old_dentry, struct inode * dir,
        struct dentry *dentry)
{
    printk(KERN_INFO "%s", __func__);
    return 0;
}

static int luci_mkdir(struct inode * dir, struct dentry *dentry, umode_t mode)
{
    printk(KERN_INFO "%s", __func__);
    return 0;
}

static int luci_unlink(struct inode * dir, struct dentry *dentry)
{
    printk(KERN_INFO "%s", __func__);
    return 0;
}

static int luci_rmdir(struct inode * dir, struct dentry *dentry)
{
    printk(KERN_INFO "%s", __func__);
    return 0;
}
static int luci_rename(struct inode * old_dir, struct dentry *old_dentry,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,8)
   struct inode * new_dir, struct dentry *new_dentry, unsigned int flags)
#else
   struct inode * new_dir, struct dentry *new_dentry)
#endif
{
    printk(KERN_INFO "%s", __func__);
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
