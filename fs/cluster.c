#include "luci.h"
#include "cluster.h"

#include <linux/mm.h>
#include <linux/kernel.h>

static void
luci_cluster_block_range(struct page *page, unsigned long *begin,
    unsigned long *end)
{
    struct inode *inode = page->mapping->host;
    struct super_block *sb = inode->i_sb;
    *begin = luci_cluster_no(page->index) * CLUSTER_NRBLOCKS(sb);
    *end = *begin + CLUSTER_NRBLOCKS(sb) - 1;
}

static void
luci_cluster_block_lookup(struct page *page, struct inode *inode,
    unsigned long blkptr_array [])
{
    unsigned long i = 0, cur_block, begin_block, end_block;
    luci_cluster_block_range(page, &begin_block, &end_block);
    cur_block = begin_block;
    while (cur_block <= end_block) {
        BUG_ON(i >= CLUSTER_NRBLOCKS_MAX);
        blkptr_array[i++] = luci_find_leaf_block(inode, cur_block++);
    }    
}

static void
luci_cluster_block_free(struct page *page, struct inode *inode,
    unsigned long blkptr_array [])
{
    unsigned blkptr;
    unsigned long i = 0, cur_block, begin_block, end_block;
    luci_cluster_block_range(page, &begin_block, &end_block);
    cur_block = begin_block;
    while (cur_block <= end_block) {
        BUG_ON(i >= CLUSTER_NRBLOCKS_MAX);
        blkptr = blkptr_array[i++];
        // This may not be a bug, since we may free the bimtap while freeing
        // other leaf entries that belong to the same cluster
        if (blkptr) {
            luci_free_block(inode, blkptr);
        }    
        cur_block++;
    }
}

int
luci_cluster_block_update(struct page *page, struct inode *inode,
    unsigned long start_block)
{
    int ret;
    unsigned long cluster;
    unsigned long i, begin_block, end_block;
    unsigned long blkptr_array[CLUSTER_NRBLOCKS_MAX];

    cluster = luci_cluster_no(page_index(page));
    // Look for common existing start compressed block for the cluster
    luci_cluster_block_lookup(page, inode, blkptr_array);
    // Update block map
    luci_cluster_block_range(page, &begin_block, &end_block);
    for (i = begin_block; i <= end_block; i++) {
        ret = luci_insert_leaf_block(inode, i, start_block);
        BUG_ON(ret < 0);
    }
    // Free old blocks since we allocated a new one
    luci_cluster_block_free(page, inode, blkptr_array);
    luci_info_inode(inode, "new block ptr %lu for cluster %lu",
        start_block, cluster);
    return 0;
}
