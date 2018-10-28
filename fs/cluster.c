#include "luci.h"
#include "cluster.h"
#include "compression.h"

#include <linux/mm.h>
#include <linux/kernel.h>

static void
luci_cluster_file_range(struct page *page, unsigned long *begin,
    unsigned long *end)
{
    struct inode *inode = page->mapping->host;
    struct super_block *sb = inode->i_sb;
    *begin = luci_cluster_no(page->index) * CLUSTER_NRBLOCKS(sb);
    *end = *begin + CLUSTER_NRBLOCKS(sb) - 1;
}

static void
luci_cluster_lookup_bp(struct page *page, struct inode *inode,
    blkptr bp_array [])
{
    unsigned long i = 0, cur_block, begin_block, end_block;
    luci_cluster_file_range(page, &begin_block, &end_block);
    cur_block = begin_block;
    while (cur_block <= end_block) {
        blkptr bp;
        BUG_ON(i >= CLUSTER_NRBLOCKS_MAX);
        bp = luci_find_leaf_block(inode, cur_block++);
        bp_array[i++] = bp;
    }
}

static int
luci_account_delta(blkptr bp_old [], blkptr bp_new [], unsigned nr_blocks)
{
    blkptr old, new;
    int i, delta = 0, bytes_uncomp = 0;
    bool new_compressed = true, old_compressed = true;

    BUG_ON(nr_blocks == 0);
    for (i = 0; i < nr_blocks; i++) {
        old = bp_old[i];
        new = bp_new[i];

        if ((old.flags & LUCI_COMPR_FLAG) && (new.flags & LUCI_COMPR_FLAG)) {
            delta += (sector_align(new.length) - sector_align(old.length));
            break;
        } else if (new.flags & LUCI_COMPR_FLAG) {
            bytes_uncomp += sector_align(old.length);
            old_compressed = false;
        } else if (old.flags & LUCI_COMPR_FLAG) {
            bytes_uncomp += sector_align(new.length);
            new_compressed = false;
        } else {
            delta += (sector_align(new.length) - sector_align(old.length));
        }
    }

    if (!new_compressed) {
        delta += (bytes_uncomp - old.length);
    } else if (!old_compressed) {
        delta += (new.length - bytes_uncomp);
    }
    return delta;
}

int
luci_cluster_update_bp(struct page *page, struct inode *inode, blkptr bp_new [])
{
    int ret, delta;
    unsigned long cluster;
    unsigned long i = 0, curr_block, begin_block, end_block;
    blkptr bp_old[CLUSTER_NRBLOCKS_MAX];

    cluster = luci_cluster_no(page_index(page));
    luci_dbg_inode(inode, "lookup bp for cluster %lu(%lu)", cluster,
        page_index(page));
    luci_cluster_lookup_bp(page, inode, bp_old);
    // update block pointer
    luci_cluster_file_range(page, &begin_block, &end_block);
    for (i = 0, curr_block = begin_block; curr_block <= end_block; curr_block++) {
        luci_info_inode(inode, "updating bp %u-%x-%u(%u) for file block %lu "
            " cluster %lu", bp_new[i].blockno, bp_new[i].flags,
            bp_new[i].length, bp_old[i].blockno, curr_block, cluster);
        ret = luci_insert_block(inode, curr_block, &bp_new[i++]);
        BUG_ON(ret < 0);
    }
    // free old block pointers
    i = 0;
    curr_block = begin_block;
    while (curr_block <= end_block) {
        unsigned blockno;
        blockno = bp_old[i++].blockno;
        // This may not be a bug, since we may free the bimtap while freeing
        // other leaf entries that belong to the same cluster
        if (blockno) {
            luci_free_block(inode, blockno);
        }
        curr_block++;
    }
    delta = luci_account_delta(bp_old, bp_new, i);
    luci_dbg_inode(inode, "delta bytes :%d", delta);
    pr_info("delta bytes :%d", delta);
    return delta;
}
