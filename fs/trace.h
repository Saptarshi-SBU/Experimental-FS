#undef TRACE_SYSTEM
#define TRACE_SYSTEM luci

#if !defined(_TRACE_LUCI_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_LUCI_H

#include <linux/tracepoint.h>
#include <linux/trace_seq.h>

#include "luci.h"

TRACE_EVENT(luci_get_block,
            TP_PROTO(struct inode *inode, sector_t iblock, Indirect ichain[], int flags),
            TP_ARGS(inode, iblock, ichain, flags),
            TP_STRUCT__entry(
                __field(int, inum)
                __field(int, iblock)
                __field(int, bptr_0)
                __field(int, bptr_0_flags)
                __field(int, bptr_0_checksum)
                __field(int, bptr_1)
                __field(int, bptr_1_flags)
                __field(int, bptr_1_checksum)
                __field(int, bptr_2)
                __field(int, bptr_2_flags)
                __field(int, bptr_2_checksum)
                __field(int, flags)
            ),
            TP_fast_assign(
                __entry->inum = inode->i_ino;
                __entry->iblock = iblock;
                __entry->bptr_0 = ichain[0].p ? ichain[0].p->blockno  : 0;
                __entry->bptr_0_flags = ichain[0].p ? ichain[0].p->flags : 0;
                __entry->bptr_0_checksum = ichain[0].p ? ichain[0].p->checksum : 0;
                __entry->bptr_1 = ichain[1].p ? ichain[1].p->blockno  : 0;
                __entry->bptr_1_flags = ichain[1].p ? ichain[1].p->flags : 0;
                __entry->bptr_1_checksum = ichain[1].p ? ichain[1].p->checksum : 0;
                __entry->bptr_2 = ichain[2].p ? ichain[2].p->blockno  : 0;
                __entry->bptr_2_flags = ichain[2].p ? ichain[2].p->flags : 0;
                __entry->bptr_2_checksum = ichain[2].p ? ichain[2].p->checksum : 0;
                __entry->flags = flags;
            ),
            TP_printk("inum=%u off=%u, 0-lba=%u-%u-0x%x, 1-lba=%u-%u-0x%x 2-lba=%u-%u-0x%x flags=0x%x",
                      __entry->inum, __entry->iblock,
                      __entry->bptr_0, __entry->bptr_0_flags, __entry->bptr_0_checksum,
                      __entry->bptr_1, __entry->bptr_1_flags, __entry->bptr_1_checksum,
                      __entry->bptr_2, __entry->bptr_2_flags, __entry->bptr_2_checksum,
                      __entry->flags)
);

TRACE_EVENT(luci_write_inode_raw,
            TP_PROTO(struct luci_inode *raw_inode, int inum, bool sync),
            TP_ARGS(raw_inode, inum, sync),
            TP_STRUCT__entry(
                __field(int, inum)
                __field(bool, sync)
                __field(int, bptr_0)
                __field(int, bptr_0_flags)
                __field(int, bptr_0_checksum)
                __field(int, bptr_1)
                __field(int, bptr_1_flags)
                __field(int, bptr_1_checksum)
                __field(int, bptr_2)
                __field(int, bptr_2_flags)
                __field(int, bptr_2_checksum)
                __field(int, bptr_3)
                __field(int, bptr_3_flags)
                __field(int, bptr_3_checksum)
                __field(int, bptr_4)
                __field(int, bptr_4_flags)
                __field(int, bptr_4_checksum)
            ),
            TP_fast_assign(
                __entry->inum = inum;
                __entry->sync = sync;
                __entry->bptr_0 = raw_inode->i_block[0].blockno;
                __entry->bptr_0_flags = raw_inode->i_block[0].flags;
                __entry->bptr_0_checksum = raw_inode->i_block[0].checksum;
                __entry->bptr_1 = raw_inode->i_block[1].blockno;
                __entry->bptr_1_flags = raw_inode->i_block[1].flags;
                __entry->bptr_1_checksum = raw_inode->i_block[1].checksum;
                __entry->bptr_2 = raw_inode->i_block[2].blockno;
                __entry->bptr_2_flags = raw_inode->i_block[2].flags;
                __entry->bptr_2_checksum = raw_inode->i_block[2].checksum;
                __entry->bptr_3 = raw_inode->i_block[3].blockno;
                __entry->bptr_3_flags = raw_inode->i_block[3].flags;
                __entry->bptr_3_checksum = raw_inode->i_block[3].checksum;
                __entry->bptr_4 = raw_inode->i_block[4].blockno;
                __entry->bptr_4_flags = raw_inode->i_block[4].flags;
                __entry->bptr_4_checksum = raw_inode->i_block[4].checksum;
            ),
            TP_printk("inum=%u sync=%u 0-lba=%u-%u-0x%x, 1-lba=%u-%u-0x%x 2-lba=%u-%u-0x%x 3-lba=%u-%u-0x%x 4-lba=%u-%u-0x%x",
                      __entry->inum,
                      __entry->sync,
                      __entry->bptr_0, __entry->bptr_0_flags, __entry->bptr_0_checksum,
                      __entry->bptr_1, __entry->bptr_1_flags, __entry->bptr_1_checksum,
                      __entry->bptr_2, __entry->bptr_2_flags, __entry->bptr_2_checksum,
                      __entry->bptr_3, __entry->bptr_3_flags, __entry->bptr_3_checksum,
                      __entry->bptr_4, __entry->bptr_4_flags, __entry->bptr_4_checksum)
);

TRACE_EVENT(luci_scan_pgtree_dirty_pages,
            TP_PROTO(struct inode *inode, pgoff_t next_index, struct page *page),
            TP_ARGS(inode, next_index, page),
            TP_STRUCT__entry(
                __field(int, inum)
                __field(unsigned long, next_index)
                __field(unsigned long, offset)
                __field(unsigned long, index)
            ),
            TP_fast_assign(
                __entry->inum = inode->i_ino;
                __entry->next_index = next_index;
                __entry->offset = page_offset(page);
                __entry->index = page_index(page);
            ),
            TP_printk("inum=%u next_index=%lu page_off=%lu page_index=%lu",
                __entry->inum,
                __entry->next_index,
                __entry->offset,
                __entry->index)
);

#endif /* _TRACE_LUCI_H */

// updated as config in Makefile
//#undef TRACE_INCLUDE_PATH
//#define TRACE_INCLUDE_PATH .

#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE trace

/* This part must be outside protection */
#include <trace/define_trace.h>
