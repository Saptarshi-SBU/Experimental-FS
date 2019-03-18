#include <linux/fs.h>
#include <linux/debugfs.h>
#include <linux/seq_file.h>

#include "btree.h"

int bt_version;

extern struct list_head btree_ver_list;

static int btree_debugfs_show(struct seq_file *m, void *data)
{
        unsigned long nr_keys;
        struct btree_root_node *root_node;

        root_node = (struct btree_root_node *)m->private;
        if (root_node) {
                nr_keys = extent_tree_dump(m,
                                           root_node->node,
                                           atomic_read(&root_node->bh->b_count),
                                           0);
                seq_printf(m, "Total Keys Stored :%lu\n", nr_keys);
        }
        return 0;
}

static int btree_debugfs_show_version(struct seq_file *m, void *data)
{
        int vers;
        unsigned long nr_keys;
        struct btree_root_node *root_node;

        vers = *(int *)m->private;

        list_for_each_entry(root_node, &btree_ver_list, list) {
                if (root_node->version != vers)
                        continue;
                nr_keys = extent_tree_dump(m,
                                           root_node->node,
                                           atomic_read(&root_node->bh->b_count),
                                           0);
                seq_printf(m, "Total Keys Stored :%lu\n", nr_keys);
                break;
        }
        return 0;
}

static ssize_t btree_debugfs_insert(struct file *file,
                                   const char __user *ubuf,
                                   size_t count,
                                   loff_t *off)
{
        int rc;
        unsigned long value;
        struct btree_root_node *root_node;

        rc = kstrtoul_from_user(ubuf, count, 10, &value);
        if (rc)
                return rc;

        root_node = (struct btree_root_node *) (file_inode(file)->i_private);
        if (extent_tree_insert_item(root_node, value, 0, PAGE_SIZE) < 0)
                return -EIO;
        return count;
}

static ssize_t btree_debugfs_delete(struct file *file,
                                   const char __user *ubuf,
                                   size_t count,
                                   loff_t *off)
{
        int rc;
        unsigned long value;
        struct btree_root_node *root_node;

        rc = kstrtoul_from_user(ubuf, count, 10, &value);
        if (rc)
                return rc;

        root_node = (struct btree_root_node *) (file_inode(file)->i_private);
        if (extent_tree_delete_item(root_node, value) < 0)
                return -EIO;
        return count;
}

static ssize_t btree_debugfs_update_version(struct file *file,
                                            const char __user *ubuf,
                                            size_t count,
                                            loff_t *off)
{
        int rc;
        long vers;

        rc = kstrtol_from_user(ubuf, count, 10, &vers);
        if (rc)
                return rc;
        bt_version = vers;
        return count;
}

static int btree_debugfs_open(struct inode *inode, struct file *file)
{
        return single_open(file, btree_debugfs_show, inode->i_private);
}

static int btree_debugfs_open_version(struct inode *inode, struct file *file)
{
        return single_open(file, btree_debugfs_show_version, inode->i_private);
}

static const struct file_operations btree_insops = {
        .open		= btree_debugfs_open,
        .read		= seq_read,
        .write		= btree_debugfs_insert,
        .llseek		= no_llseek,
        .release	= single_release,
};

static const struct file_operations btree_delops = {
        .open		= btree_debugfs_open,
        .read 		= seq_read,
        .write 		= btree_debugfs_delete,
        .llseek 	= no_llseek,
        .release 	= single_release,
};

static const struct file_operations btree_ioctlops = {
        .open		= btree_debugfs_open_version,
        .read 		= seq_read,
        .write 		= btree_debugfs_update_version,
        .llseek 	= no_llseek,
        .release 	= single_release,
};

struct dentry *btree_debugfs_init(struct btree_root_node *btree_root)
{
        struct dentry *dir;
        struct dentry *insert, *delete, *ioctl;

        dir = debugfs_create_dir("btree", NULL);
        if (!dir)
                goto free_out;
                
        insert = debugfs_create_file("insert",
                                     0644,
                                     dir,
                                     (void *) btree_root,
                                     &btree_insops);
        if (!insert)
                goto free_out;

        delete = debugfs_create_file("delete",
                                     0644,
                                     dir,
                                     (void *) btree_root,
                                     &btree_delops);
        if (!insert)
                goto free_out;

        ioctl = debugfs_create_file("version",
                                     0644,
                                     dir,
                                     (void *) &bt_version,
                                     &btree_ioctlops);
        if (!ioctl)
                goto free_out;

        return dir;

free_out:
        pr_err("failed to create debugfs dir\n");
        debugfs_remove_recursive(dir);
        return NULL;
}

int btree_debugfs_destroy(struct dentry *root_dentry)
{
        debugfs_remove_recursive(root_dentry);
        return 0;
}
