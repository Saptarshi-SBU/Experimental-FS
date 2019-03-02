#include <linux/fs.h>
#include <linux/debugfs.h>
#include <linux/seq_file.h>

#include "btree.h"

static int btree_debugfs_show(struct seq_file *m, void *data)
{
        struct btree_root_node *root_node = (struct btree_root_node *)m->private;
        if (root_node)
                extent_tree_dump(m, root_node->node, 0);
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
        if (extent_tree_insert_item(NULL, root_node, value, PAGE_SIZE) < 0)
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
        if (extent_tree_delete_item(NULL, root_node, value) < 0)
                return -EIO;
        return count;
}

static int btree_debugfs_open(struct inode *inode, struct file *file)
{
        return single_open(file, btree_debugfs_show, inode->i_private);
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

struct dentry *btree_debugfs_init(struct btree_root_node *btree_root)
{
        struct dentry *dir;
        struct dentry *insert, *delete;

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
