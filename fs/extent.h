#ifndef __EXTENT_H_
#define __EXTENT_H_

#include "luci.h"

/* Extent Unit */

#define EXTENT_NRBLOCKS 4

#define EXTENT_SIZE(s) (LUCI_BLOCK_SIZE(s) * EXTENT_NRBLOCKS)

#define EXTENT_NRPAGES(s) ((EXTENT_SIZE(s)) >> PAGE_SHIFT)

static inline unsigned long
luci_extent_no(unsigned long i_block)
{
    return i_block/EXTENT_NRBLOCKS;
}

void
luci_extent_range(unsigned long i_block, unsigned long *begin,
                  unsigned long *end);

void
luci_extent_offset(struct inode * inode, unsigned long i_block,
                   loff_t *start_offset, unsigned long * total_in);

unsigned long
luci_lookup_extent(struct inode *inode, unsigned long i_block);

int
luci_update_extent(struct inode *inode, unsigned long i_block,
                   unsigned long start_compr_block);

#endif


