#include <linux/fs.h>
#include <linux/debugfs.h>
#include <linux/seq_file.h>

#include "btree.h"

#define BTREE_DEBUGFS_TREE "tree_dump"

static int btree_debugfs_show(struct seq_file *m, void *data)
{
        struct btree_root_node *root_node = (struct btree_root_node *)m->private;
        if (root_node)
                extent_tree_dump(m, root_node->node, 0);
        return 0;
}

static ssize_t btree_debugfs_write(struct file *file,
                                   const char __user *ubuf,
                                   size_t count,
                                   loff_t *off)
{
        int rc;
        unsigned long block;
        struct btree_root_node *root_node;

        rc = kstrtoul_from_user(ubuf, count, 10, &block);
        if (rc)
                return rc;

        root_node = (struct btree_root_node *) (file_inode(file)->i_private);
        if (extent_tree_insert_item(NULL, root_node, block, PAGE_SIZE) < 0)
                return -EIO;
        return count;
}

static int btree_debugfs_open(struct inode *inode, struct file *file)
{
        return single_open(file, btree_debugfs_show, inode->i_private);
}

static const struct file_operations btree_dbgfops = {
        .open = btree_debugfs_open,
        .read = seq_read,
        .write = btree_debugfs_write,
        .llseek = no_llseek,
        .release = single_release,
};

struct dentry *btree_debugfs_init(struct btree_root_node *btree_root)
{
        struct dentry *dir;
        struct dentry *dump;

        dir = debugfs_create_dir("btree", NULL);
        if (!dir)
                goto free_out;
                
        dump = debugfs_create_file("dump",
                                   0644,
                                   dir,
                                   (void *) btree_root,
                                   &btree_dbgfops);
        if (!dump)
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
