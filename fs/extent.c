#include "luci.h"
#include "extent.h"

void inline
luci_get_extent_range(unsigned long i_block, unsigned long *begin,
    unsigned long *end)
{
    *begin = luci_extent_no(i_block) * EXTENT_NRBLOCKS;
    *end = *begin + EXTENT_NRBLOCKS - 1;
    //luci_dbg("%lu : %lu", *begin, *end);
}

void
luci_extent_offset(struct inode * inode, unsigned long i_block,
     loff_t *start_offset, unsigned long * total_in)
{
    unsigned long begin_block, end_block;
    luci_get_extent_range(i_block, &begin_block, &end_block);
    *start_offset = begin_block * LUCI_BLOCK_SIZE(inode->i_sb);
    *total_in = EXTENT_SIZE(inode->i_sb);
}

unsigned long
luci_lookup_extent(struct inode *inode, unsigned long i_block)
{
    bool found = false;
    unsigned long i, begin_block, end_block, blkptr;

    luci_get_extent_range(i_block, &begin_block, &end_block);
    i = begin_block;
    do {
        blkptr = luci_find_leaf_block(inode, i);
        if (blkptr) {
            found = true;
        }
        i++;
    } while (!found && i <= end_block);
    return blkptr;
}

int
luci_update_extent(struct inode *inode, unsigned long i_block,
    unsigned long start_block)
{
    int ret;
    unsigned long i, begin_block, end_block, old_blkptr;

    // Look for common existing start compressed block for the extent
    old_blkptr = luci_lookup_extent(inode, i_block);

    luci_get_extent_range(i_block, &begin_block, &end_block);
    for (i = begin_block; i <= end_block; i++) {
        ret = luci_insert_leaf_block(inode, i, start_block);
        if (ret < 0) {
            BUG();
        }
    }
    // Free old start block since we allocated a new one
    if (old_blkptr) {
        if (luci_free_block(inode, old_blkptr) < 0) {
            // This may not be a bug, since we may free the bimtap while freeing
            // other leaf entries that belong to the same extent
            luci_dbg_inode(inode, "can't find blk, oldblkptr %lu newblkptr %lu",
                old_blkptr, start_block);
        }
    }
    return 0;
}
