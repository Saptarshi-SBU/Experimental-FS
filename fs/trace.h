#undef TRACE_SYSTEM
#define TRACE_SYSTEM luci

#if !defined(_TRACE_LUCI_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_LUCI_H

#include <linux/dcache.h>
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
                __field(int, bptr_0_length)
                __field(int, bptr_0_flags)
                __field(int, bptr_0_checksum)
                __field(int, bptr_1)
                __field(int, bptr_1_length)
                __field(int, bptr_1_flags)
                __field(int, bptr_1_checksum)
                __field(int, bptr_2)
                __field(int, bptr_2_length)
                __field(int, bptr_2_flags)
                __field(int, bptr_2_checksum)
                __field(int, bptr_3)
                __field(int, bptr_3_length)
                __field(int, bptr_3_flags)
                __field(int, bptr_3_checksum)
                __field(int, flags)
            ),
            TP_fast_assign(
                __entry->inum = inode->i_ino;
                __entry->iblock = iblock;
                __entry->bptr_0 = ichain[0].p ? ichain[0].p->blockno  : 0;
                __entry->bptr_0_length = ichain[0].p ? ichain[0].p->length  : 0;
                __entry->bptr_0_flags = ichain[0].p ? ichain[0].p->flags : 0;
                __entry->bptr_0_checksum = ichain[0].p ? ichain[0].p->checksum : 0;
                __entry->bptr_1 = ichain[1].p ? ichain[1].p->blockno  : 0;
                __entry->bptr_1_length = ichain[1].p ? ichain[1].p->length  : 0;
                __entry->bptr_1_flags = ichain[1].p ? ichain[1].p->flags : 0;
                __entry->bptr_1_checksum = ichain[1].p ? ichain[1].p->checksum : 0;
                __entry->bptr_2 = ichain[2].p ? ichain[2].p->blockno  : 0;
                __entry->bptr_2_length = ichain[2].p ? ichain[2].p->length  : 0;
                __entry->bptr_2_flags = ichain[2].p ? ichain[2].p->flags : 0;
                __entry->bptr_2_checksum = ichain[2].p ? ichain[2].p->checksum : 0;
                __entry->bptr_3 = ichain[3].p ? ichain[3].p->blockno  : 0;
                __entry->bptr_3_length = ichain[3].p ? ichain[3].p->length  : 0;
                __entry->bptr_3_flags = ichain[3].p ? ichain[3].p->flags : 0;
                __entry->bptr_3_checksum = ichain[3].p ? ichain[3].p->checksum : 0;
                __entry->flags = flags;
            ),
            TP_printk("inum=%u off=%u, 0-lba=%u-%u-%u-0x%x, 1-lba=%u-%u-%u-0x%x 2-lba=%u-%u-%u-0x%x 3-lba=%u-%u-%u-0x%x flags=0x%x",
                      __entry->inum, __entry->iblock,
                      __entry->bptr_0, __entry->bptr_0_length,__entry->bptr_0_flags, __entry->bptr_0_checksum,
                      __entry->bptr_1, __entry->bptr_1_length,__entry->bptr_1_flags, __entry->bptr_1_checksum,
                      __entry->bptr_2, __entry->bptr_2_length,__entry->bptr_2_flags, __entry->bptr_2_checksum,
                      __entry->bptr_3, __entry->bptr_3_length,__entry->bptr_3_flags, __entry->bptr_3_checksum,
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

TRACE_EVENT(luci_write_extents,
	     TP_PROTO(struct inode *inode, size_t dirty_counter_enter, size_t dirty_counter_exit),
	     TP_ARGS(inode, dirty_counter_enter, dirty_counter_exit),
	     TP_STRUCT__entry(
                __field(int, inum);
                __field(unsigned long, dirty_counter_enter);
                __field(unsigned long, dirty_counter_exit);
            ),
            TP_fast_assign(
                __entry->inum = inode->i_ino;
                __entry->dirty_counter_enter = dirty_counter_enter;
                __entry->dirty_counter_exit  = dirty_counter_exit;
            ),
            TP_printk("inum=%u dirty_counter_enter=%lu dirty_counter_exit=%lu",
                __entry->inum,
                __entry->dirty_counter_enter,
                __entry->dirty_counter_exit)
);

TRACE_EVENT(luci_free_block,
	     TP_PROTO(struct inode *inode, unsigned long block, unsigned long blockgroup, unsigned bitpos),
	     TP_ARGS(inode, block, blockgroup, bitpos),
	     TP_STRUCT__entry(
                __field(int, inum);
                __field(unsigned long, block);
                __field(unsigned long, blockgroup);
                __field(unsigned int,  bitpos);
            ),
            TP_fast_assign(
                __entry->inum = inode->i_ino;
                __entry->block = block;
                __entry->blockgroup = blockgroup;
                __entry->bitpos = bitpos;
            ),
            TP_printk("inum=%u block=%lu blockgroup=%lu bitpos=%u",
                __entry->inum,
                __entry->block,
                __entry->blockgroup,
                __entry->bitpos)
);

TRACE_EVENT(luci_new_inode,
	     TP_PROTO(struct inode *inode, unsigned long blockgroup, unsigned bitpos),
	     TP_ARGS(inode, blockgroup, bitpos),
	     TP_STRUCT__entry(
                __field(int, inum);
                __field(unsigned long, blockgroup);
                __field(unsigned int,  bitpos);
            ),
            TP_fast_assign(
                __entry->inum = inode->i_ino;
                __entry->blockgroup = blockgroup;
                __entry->bitpos = bitpos;
            ),
            TP_printk("inum=%u blockgroup=%lu bitpos=%u",
                __entry->inum,
                __entry->blockgroup,
                __entry->bitpos)
);

TRACE_EVENT(luci_free_inode,
	     TP_PROTO(struct inode *inode, unsigned long blockgroup, unsigned bitpos),
	     TP_ARGS(inode, blockgroup, bitpos),
	     TP_STRUCT__entry(
                __field(int, inum);
                __field(unsigned long, blockgroup);
                __field(unsigned int,  bitpos);
            ),
            TP_fast_assign(
                __entry->inum = inode->i_ino;
                __entry->blockgroup = blockgroup;
                __entry->bitpos = bitpos;
            ),
            TP_printk("inum=%u blockgroup=%lu bitpos=%u",
                __entry->inum,
                __entry->blockgroup,
                __entry->bitpos)
);

TRACE_EVENT(luci_bio_complete,
        TP_PROTO(struct bio *bio, int error, u32 crc),
        TP_ARGS(bio, error, crc),
        TP_STRUCT__entry(
                __field( dev_t,         dev             )
                __field( unsigned,      blockno         )
                __field( unsigned,      length          )
                __field( int,           error           )
                __field( unsigned,      crc             )
        ),
        TP_fast_assign(
                __entry->dev            = bio->bi_bdev->bd_dev;
#ifdef HAVE_BIO_ITER
                __entry->blockno        = bio->bi_iter.bi_sector >> 3;
#else
                __entry->blockno        = bio->bi_sector >> 3;
#endif
                __entry->length         = bio_sectors(bio) << 9;
                __entry->error          = error;
                __entry->crc            = crc;
        ),
        TP_printk("device :%d,%d blockno :%llu length :%u error :%d crc :0x%x",
                  MAJOR(__entry->dev), MINOR(__entry->dev),
                  (unsigned long long)__entry->blockno,
                  __entry->length, __entry->error, __entry->crc)
);

/* directory operation traces */

TRACE_EVENT(luci_add_link,
        TP_PROTO(struct dentry *dentry, struct inode *inode),
        TP_ARGS(dentry, inode),
        TP_STRUCT__entry(
                __field( const char *,  name           )
                __field( unsigned,      inum           )
                __field( unsigned,      dir_inum       )
        ),
        TP_fast_assign(
                __entry->name           = dentry->d_name.name;
                __entry->inum           = inode->i_ino;
                __entry->dir_inum       = DENTRY_INODE(dentry->d_parent)->i_ino;
        ),
        TP_printk("name :%s, inode :%u, dir_inode :%u",
                __entry->name, __entry->inum, __entry->dir_inum)
);

TRACE_EVENT(luci_unlink,
        TP_PROTO(struct inode *dir, struct dentry *dentry),
        TP_ARGS(dir, dentry),
        TP_STRUCT__entry(
                __field( const char *,  name           )
                __field( unsigned,      inum           )
                __field( unsigned,      dir_inum       )
        ),
        TP_fast_assign(
                __entry->name           = dentry->d_name.name;
                __entry->inum           = DENTRY_INODE(dentry)->i_ino;
                __entry->dir_inum       = dir->i_ino;
        ),
        TP_printk("name :%s, inode :%u, dir_inode :%u",
                __entry->name, __entry->inum, __entry->dir_inum)
);

TRACE_EVENT(luci_make_empty,
        TP_PROTO(struct inode *inode, struct inode *parent),
        TP_ARGS(inode, parent),
        TP_STRUCT__entry(
                __field( unsigned,      inum           )
                __field( unsigned,      dir_inum       )
        ),
        TP_fast_assign(
                __entry->inum           = inode->i_ino;
                __entry->dir_inum       = parent->i_ino;
        ),
        TP_printk("inode :%u, dir_inode :%u",
                __entry->inum, __entry->dir_inum)
);

TRACE_EVENT(luci_delete_entry,
        TP_PROTO(struct luci_dir_entry_2* de),
        TP_ARGS(de),
        TP_STRUCT__entry(
                __field( const char *,  name           )
                __field( unsigned,      inum           )
        ),
        TP_fast_assign(
                __entry->name           = de->name;
                __entry->inum           = de->inode;
        ),
        TP_printk("name :%s, inode :%u", __entry->name, __entry->inum)
);

TRACE_EVENT(luci_mkdir,
        TP_PROTO(struct inode *dir, struct dentry *dentry),
        TP_ARGS(dir, dentry),
        TP_STRUCT__entry(
                __field( const char *,  name           )
                __field( unsigned,      inum           )
                __field( unsigned,      dir_inum       )
        ),
        TP_fast_assign(
                __entry->name           = dentry->d_name.name;
                __entry->inum           = DENTRY_INODE(dentry)->i_ino;
                __entry->dir_inum       = dir->i_ino;
        ),
        TP_printk("name :%s, inode :%u, dir_inode :%u",
                __entry->name, __entry->inum, __entry->dir_inum)
);

TRACE_EVENT(luci_rmdir,
        TP_PROTO(struct inode *dir, struct dentry *dentry),
        TP_ARGS(dir, dentry),
        TP_STRUCT__entry(
                __field( const char *,  name           )
                __field( unsigned,      inum           )
                __field( unsigned,      dir_inum       )
        ),
        TP_fast_assign(
                __entry->name           = dentry->d_name.name;
                __entry->inum           = DENTRY_INODE(dentry)->i_ino;
                __entry->dir_inum       = dir->i_ino;
        ),
        TP_printk("name :%s, inode :%u, dir_inode :%u",
                __entry->name, __entry->inum, __entry->dir_inum)
);

TRACE_EVENT(luci_symlink,
        TP_PROTO(struct inode *dir, struct dentry *dentry, const char *symlink),
        TP_ARGS(dir, dentry, symlink),
        TP_STRUCT__entry(
                __field( const char *,  name           )
                __field( unsigned,      inum           )
                __field( unsigned,      dir_inum       )
                __field( const char *,  symlink        )
        ),
        TP_fast_assign(
                __entry->name           = dentry->d_name.name;
                __entry->inum           = DENTRY_INODE(dentry)->i_ino;
                __entry->dir_inum       = dir->i_ino;
                __entry->symlink        = symlink;
        ),
        TP_printk("name :%s, inode :%u, dir_inode :%u, symlink :%s",
                __entry->name, __entry->inum, __entry->dir_inum, __entry->symlink)
);

TRACE_EVENT(luci_rename,
        TP_PROTO(struct inode *src_dir, struct dentry* src_dentry,
                struct inode *dst_dir, struct dentry* dst_dentry),
        TP_ARGS(src_dir, src_dentry, dst_dir, dst_dentry),
        TP_STRUCT__entry(
                __field( const char *,  src_name       )
                __field( unsigned,      src_inum       )
                __field( const char *,  dst_name       )
                __field( unsigned,      dst_inum       )
        ),
        TP_fast_assign(
                __entry->src_name       = src_dentry->d_name.name;
                __entry->src_inum       = src_dir->i_ino;
                __entry->dst_name       = dst_dentry->d_name.name;
                __entry->dst_inum       = dst_dir->i_ino;
        ),
        TP_printk("src_name :%s, src_inode :%u dst_name :%s dst_inode :%u",
                __entry->src_name, __entry->src_inum,
                __entry->dst_name, __entry->dst_inum)
);

#endif /* _TRACE_LUCI_H */

// updated as config in Makefile
//#undef TRACE_INCLUDE_PATH
//#define TRACE_INCLUDE_PATH .

#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE trace

/* This part must be outside protection */
#include <trace/define_trace.h>
