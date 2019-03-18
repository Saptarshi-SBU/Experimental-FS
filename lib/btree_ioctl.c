#include <linux/fs.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/ioctl.h>
#include <linux/miscdevice.h>
#include <asm/uaccess.h>

#include "btree.h"
#include "btree_ioctl.h"
#include "page_io.h"

#define BTREE_MISC 254

struct list_head btree_ver_list;

static long btreedev_create_extent_tree(int version, int fanout)
{
        struct btree_root_node *root, *iter;

        list_for_each_entry(iter, &btree_ver_list, list) {
                if (iter->version == version) {
                        pr_err("version already exists! :%d\n", version);
                        return -EEXIST;
                }
        }

        root = extent_tree_init(version, fanout);
        if (root)
                list_add(&root->list, &btree_ver_list);
        else {
                pr_err("extent tree create failed\n");
                return -EIO;
        }

        pr_info("extent tree created with version :%d\n", version);
        return root->version;
}

static long btreedev_destroy_extent_tree(int version)
{
        long retl = -ENOENT;
        struct btree_root_node *iter, *tmp;

        list_for_each_entry_safe(iter, tmp, &btree_ver_list, list) {
                if (iter->version != version)
                        continue;
                list_del(&iter->list);
                extent_tree_destroy(iter);
                retl = 0;
        }

        if (!retl)
                pr_info("extent tree destroyed with version :%d\n", version);
        return retl;
}

static long btreedev_insert_extent(int version, loff_t off, void __user *data, size_t datalen)
{
        unsigned long block;
        struct buffer_head *bh;
        struct btree_root_node *root = NULL, *iter = NULL;

        if (datalen > PAGE_SIZE) {
                pr_err("%s, invalid datalen\n", __func__);
                return -EINVAL;
        }

        list_for_each_entry(iter, &btree_ver_list, list) {
                if (iter->version != version)
                        continue;
                root = iter;
                break;
        }

        if (!root) {
                pr_err("%s failed, root node not found!", __func__);
                return -EINVAL;
        }

        block = bump_alloc_data_block();

        bh = bump_get_buffer_head(block);
        if (!bh) {
                pr_err("%s failed, buffer head!", __func__);
                return -EIO;
        }

        if (copy_from_user((void *)bh->b_data, data, datalen)) {
                brelse(bh);
                return -EFAULT;
        }

        bump_put_buffer_head(bh);

        pr_debug("inserting off=%llu, block=%lu\n", off, block);
        return extent_tree_insert_item(root, off, block, datalen);
}

static long btreedev_lookup_extent(int version, loff_t off, void __user *data, size_t datalen)
{
        unsigned long retl, block;
        struct buffer_head *bh;
        struct btree_root_node *root = NULL, *iter = NULL;

        if (datalen > PAGE_SIZE) {
                pr_err("%s, invalid datalen\n", __func__);
                return -EINVAL;
        }

        list_for_each_entry(iter, &btree_ver_list, list) {
                if (iter->version != version)
                        continue;
                root = iter;
                break;
        }

        if (!root) {
                pr_err("%s failed, root node not found!", __func__);
                return -EINVAL;
        }

        block = extent_tree_lookup_item(root, off, datalen);
        if (block < 0) {
                pr_err("%s failed, cannot find key :%llu\n", __func__, off);
                return -ENOENT;
        }

        bh = bump_get_buffer_head(block);
        if (!bh) {
                pr_err("%s failed, buffer head!", __func__);
                return -EIO;
        }

        if (copy_to_user(data, (void*) bh->b_data, PAGE_SIZE)) {
                retl = -ENOENT;
        } else
                retl = datalen;

        bump_put_buffer_head(bh);

        return retl;
}

static long btreedev_range_query_extents(int version, loff_t off, size_t range, int level)
{
        unsigned long count = 0;
#if 0
        struct list_head range_list;
        struct btree_root_node *root = NULL, *iter = NULL;

        INIT_LIST_HEAD(&range_list);

        list_for_each_entry(iter, &btree_ver_list, list) {
                if (iter->version != version)
                        continue;
                root = iter;
                break;
        }

        if (!root) {
                pr_err("%s failed, root node not found!", __func__);
                return -EINVAL;
        }
        
        extent_tree_range_query(root, off, range, &range_list, level);

        list_for_each_entry(iter_key, &range_list, list)
                count++;
#endif
        return count;
}

static long btreedev_fetch_extent_delta(int fd, int snapfd, loff_t off, size_t datalen)
{
        return -ENOTSUPP;
}

long btreedev_ioctl(struct file *file, unsigned cmd, unsigned long arg)
{
        struct btree_ioctl_arg *argp = (struct btree_ioctl_arg *) (void __user *) arg;

        switch (cmd) {

        case BTREE_IOCTL_CREATE:
                return btreedev_create_extent_tree(argp->version, argp->fanout);

        case BTREE_IOCTL_DESTROY:
                return btreedev_destroy_extent_tree(argp->version);

        case BTREE_IOCTL_READ:
                return btreedev_lookup_extent(argp->version, argp->offset, argp->data, argp->datalen);

        case BTREE_IOCTL_WRITE:
                return btreedev_insert_extent(argp->version, argp->offset, argp->data, argp->datalen);

        case BTREE_IOCTL_RQUERY:
                return btreedev_range_query_extents(argp->version, argp->offset, argp->datalen, 0);

        case BTREE_IOCTL_DELTA:
                return btreedev_fetch_extent_delta(argp->version, argp->snapid, argp->offset, argp->datalen);

        case BTREE_IOCTL_SNAP:
                break;
        }

        return -ENOTTY;
}

static struct file_operations btreedev_misc_fops = {
        //.owner          = THIS_MODULE,
        .unlocked_ioctl = btreedev_ioctl,
        .llseek         = noop_llseek,
};

struct miscdevice btreedev_misc = {
        .minor = BTREE_MISC,
        .name  = "btree-store",
        .fops  = &btreedev_misc_fops,
};

int __init btreedev_init(void)
{
        INIT_LIST_HEAD(&btree_ver_list);
        return misc_register(&btreedev_misc);
}

void __exit btreedev_exit(void)
{
        struct btree_root_node *iter, *tmp;

        list_for_each_entry_safe(iter, tmp, &btree_ver_list, list) {
                pr_info("releasing btree version :%d\n", iter->version);
                extent_tree_destroy(iter);
                list_del(&iter->list);
        }

        if (misc_deregister(&btreedev_misc) < 0)
                pr_err("failed to de-register device\n");
        return;
}
