/*
 * Copyright (C) 2018 Saptarshi Sen
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License v2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 021110-1307, USA.
 */

#include <linux/kernel.h>
#include <linux/bio.h>
#include <linux/buffer_head.h>
#include <linux/fs.h>
#include <linux/pagemap.h>
#include <linux/highmem.h>
#include <linux/time.h>
#include <linux/mpage.h>
#include <linux/writeback.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/crc32.h>

#include "kern_feature.h"
#include "luci.h"
#include "cluster.h"
#include "compression.h"

static struct comp_ws luci_comp_ws[LUCI_COMPRESS_TYPES];

static const struct luci_compress_op * const luci_compress_op[] = {
	&luci_zlib_compress,
};

static inline void
luci_pageflags_dump(struct page* page, const char *msg)
{
    luci_info("%s : page=%lu Writeback :%d page Dirty :%d page Uptodate %d",
        msg, page->index, PageWriteback(page), PageDirty(page),
        PageUptodate(page));
}

static void
luci_bio_dump(struct bio * bio, const char *msg)
{
#ifdef HAVE_BIO_ITER
     luci_dbg("%s bio : bi_max_vecs :%u bi_vcnt :%d bi_size :%u bi_sector :%lu"
        " bytes: %u index :%lu\n", msg, bio->bi_max_vecs, bio->bi_vcnt,
        bio->bi_iter.bi_size, bio->bi_iter.bi_sector, bio_cur_bytes(bio),
        page_index(bio_page(bio)));
#else
     luci_dbg("%s bio : bi_max_vecs :%u bi_vcnt :%d bi_size :%u bi_sector :%lu"
        " bytes :%u index :%lu\n", msg, bio->bi_max_vecs, bio->bi_vcnt,
        bio->bi_size, bio->bi_sector, bio_cur_bytes(bio),
        page_index(bio_page(bio)));
#endif
     //luci_dump_bytes("bio page", bio_page(bio), PAGE_SIZE);
}

static void
bp_reset(blkptr *bp, unsigned long block, unsigned int size,
    unsigned short flags, u32 checksum) {
    bp->blockno = block;
    bp->length = size;
    bp->flags = flags;
    bp->checksum = checksum;
}

/* compute checksum */
u32 luci_compute_checksum(struct page **pages, int nr_pages, size_t size)
{
    int i;
    u32 crc = ~0U;
    size_t length;
    void *kaddr;

    BUG_ON(size > PAGE_SIZE * nr_pages);
    for (i = 0; i < nr_pages; i++) {
            BUG_ON(!size);
            length = min((size_t)size, (size_t)PAGE_SIZE);
            kaddr = kmap(pages[i]);
            crc = crc32_le(crc, kaddr, length);
            size -= length;
            kunmap(kaddr);
    }
    return crc;
}

/* when we finish reading compressed pages from the disk, we
 * decompress them and then run the bio end_io routines on the
 * decompressed pages (in the inode address space).
 *
 * This allows the checksumming and other IO error handling routines
 * to work normally
 *
 * The compressed pages are freed here, and it must be run
 * in process context
 */
static void
#ifdef HAVE_NEW_BIO_END
luci_end_compressed_bio_read(struct bio *bio)
#else
luci_end_compressed_bio_read(struct bio *bio, int error)
#endif
{
    int i = 0;
    struct bio_vec *bvec;
    // TBD: Check for status associated with each bvec page
    // We do not set any writeback flag, so end_page_writeback(page)
    // is not necessary
    bio_for_each_segment_all(bvec, bio, i) {
        struct page *page = bvec->bv_page;
        page->mapping = NULL;
        luci_pageflags_dump(page, __func__);
        if (PageLocked(page)) {
           unlock_page(page);
        }
        put_page(page);
    }
}

static void
#ifdef HAVE_NEW_BIO_END
luci_end_bio_write_compressed(struct bio *bio)
#else
luci_end_bio_write_compressed(struct bio *bio, int error)
#endif
{
    int i = 0;
    struct bio_vec *bvec;
    struct list_head *ws;
    struct page *page;
    // TBD: Check for status associated with each bvec page
    // We do not set any writeback flag, so end_page_writeback(page) not needed
    // return page back to mempool
    bio_for_each_segment_all(bvec, bio, i) {
        page = bvec->bv_page;
        ws = (struct list_head*) page->private;
        BUG_ON(ws == NULL);
        BUG_ON(page_has_buffers(page));
        BUG_ON(PageLocked(page));
        BUG_ON(PageWriteback(page));
        luci_pageflags_dump(page, __func__);
        luci_pgtrack(page, "write completed for compressed page ");
        luci_zlib_compress.remit_workspace(ws, page);
    }
    bio_put(bio);
}

static void
#ifdef HAVE_NEW_BIO_END
luci_end_bio_write(struct bio *bio)
#else
luci_end_bio_write(struct bio *bio, int error)
#endif
{
    int i = 0;
    struct bio_vec *bvec;
    struct page *page;
    // TBD: Check for status associated with each bvec page
    // We do not set any writeback flag, so end_page_writeback(page)
    // is not necessary
    #ifndef  HAVE_NEW_BIO_END
    BUG_ON(error);
    #endif
    bio_for_each_segment_all(bvec, bio, i) {
        page = bvec->bv_page;
        // L0 blocks are no_bh based, so panic if we see so
        if (page_has_buffers(page)) {
            struct inode *inode = page->mapping->host;
            struct buffer_head *bh = page_buffers(page);
            panic("unexpected page buffer inode :%lu bh (%lu-%s-%s-%s-%u)\n",
                inode->i_ino, bh->b_blocknr,
                buffer_mapped(bh) ? "mapped" : "unmapped",
                buffer_dirty(bh)  ? "dirty" : "clean",
                buffer_locked(bh) ? "locked" : "unlocked",
                atomic_read(&bh->b_count));
        }
        luci_pageflags_dump(page, __func__);
        luci_pgtrack(page, "write completed for uncompressed page ");

        // TBD: In case write fails, check for PageError, we redirty the page

        if (PageWriteback(page))
            end_page_writeback(page);

        // We assume if a page is locked, then it might be due to us
        // when we do grab page to create a batch. So we need to drop
        // the reference. Otherwise, a regular page is already unlocked
        // by write_end
        if (PageLocked(page)) {
            unlock_page(page);
            put_page(page);
        }
    }
    bio_put(bio);
}

static struct bio *
luci_bio_alloc(struct block_device *bdev, unsigned long start,
               unsigned long nr_pages_out)
{
    struct bio *bio;
    BUG_ON(nr_pages_out > BIO_MAX_PAGES);
    bio = bio_alloc(GFP_NOFS, nr_pages_out);
    if (!bio) {
        return NULL;
    }
    bio->bi_vcnt = 0;
    bio->bi_bdev = bdev;
    #ifdef HAVE_BIO_ITER
    bio->bi_iter.bi_sector = start >> 9;
    #else
    bio->bi_sector = start >> 9;
    #endif
    return bio;
}

static struct bio*
luci_prepare_bio(struct inode * inode, struct page **pages,
                 unsigned long total, unsigned long disk_start,
                 bool write, struct list_head *ws)
{
    int ret;
    struct bio *bio;
    unsigned int write_size = 0;
    unsigned long i, aligned_bytes, nr_pages; // align size to device sector, otherwise device rejects write
    struct block_device *bdev = inode->i_sb->s_bdev;

    // catch likely scsi_lib panics for zero phy segments
    BUG_ON(!total);

    aligned_bytes = sector_align(total);
    nr_pages = (aligned_bytes + PAGE_SIZE - 1)/PAGE_SIZE;
    BUG_ON(aligned_bytes > nr_pages * PAGE_SIZE);

    luci_info_inode(inode, "%s nr_pages=%lu aligned_bytes=%lu\n",
                    __func__, nr_pages, aligned_bytes);

    bio = luci_bio_alloc(bdev, disk_start, nr_pages);
    if (!bio) {
        luci_err_inode(inode, "bio alloc failed\n");
        return ERR_PTR(-ENOMEM);
    }

    // construct bio vecs for each PAGE of compressed output
    // Note these pages are anon and do not belong to page cache
    for (i = 0; i < nr_pages; i++) {
       BUG_ON(aligned_bytes == 0);
       write_size = min((unsigned long)PAGE_SIZE, aligned_bytes);

       BUG_ON(!pages[i]);
       if (ws && write) {
           BUG_ON((void *) pages[i]->private != NULL);
           pages[i]->private = (unsigned long) ws;
       }
       ret = bio_add_page(bio, pages[i], write_size, 0);
       if (ret < write_size) {
           luci_err_inode(inode, "bio add page failed");
           bio_put(bio);
           return ERR_PTR(-EIO);
       }
       aligned_bytes -= (unsigned long)write_size;
       luci_info("added page %p to bio, len :%u", pages[i], write_size);
    }

    if (aligned_bytes)
        panic("failed to consume output, left %lu", aligned_bytes);

    #ifdef NEW_BIO_SUBMIT
    bio->bi_opf = write ? REQ_OP_WRITE : REQ_OP_READ;
    #endif
    return bio;
}

/*
 * worker function to build and submit bios for previously compressed pages.
 * The corresponding pages in the inode should be marked for writeback
 * and the compressed pages should have a reference on them for dropping
 * when the IO is complete.
 *
 * This also checksums the file bytes and gets things ready for
 * the end io hooks.
 */

static int
luci_submit_write(struct inode * inode, struct page **pages,
                        unsigned long total_out, unsigned long disk_start,
                        bool compressed, struct list_head *ws)
{
    ktime_t start;
    struct bio *bio;

    // compressed bio
    bio = luci_prepare_bio(inode, pages, total_out, disk_start, true, ws);
    if (IS_ERR(bio)) {
        luci_err("failed to allocate bio for write");
        BUG();
    }

    if (compressed)
        bio->bi_end_io = luci_end_bio_write_compressed;
    else
        bio->bi_end_io = luci_end_bio_write;

    luci_bio_dump(bio, "submitting bio write");

    start = ktime_get();
    #ifdef NEW_BIO_SUBMIT
    bio->bi_opf = REQ_OP_WRITE;
    submit_bio(bio);
    #else
    submit_bio(WRITE, bio);
    #endif
    UPDATE_AVG_LATENCY_NS(dbgfsparam.avg_io_lat, start);
    return 0;
}

/*
 * compress pages and write
 */

static void
__luci_compress_and_write(struct work_struct *work)
{
    ktime_t start;
    int i, err, delta;
    bool compressed = true, redirty_page = false;
    struct list_head *ws;
    struct inode *inode;
    unsigned cluster, blocksize;
    struct page **page_cluster;
    struct comp_write_work *async_work;
    u32 crc32[CLUSTER_NRPAGE];
    blkptr bp_array[CLUSTER_NRBLOCKS_MAX];
    unsigned long start_compr_block, disk_start, block_no, nr_blocks;
    unsigned long nr_pages_out = CLUSTER_NRPAGE, total_in = CLUSTER_SIZE, total_out = CLUSTER_SIZE;

    async_work = container_of(work, struct comp_write_work, work);
    cluster = luci_cluster_no(page_index(async_work->begin_page));

    inode = async_work->begin_page->mapping->host;
    blocksize = 1UL << LUCI_BLOCK_SIZE_BITS(inode->i_sb);

    /* We are nobh. See *_write_end */
    BUG_ON(page_has_buffers(async_work->begin_page));

    BUG_ON(pagevec_count(async_work->pvec) != CLUSTER_NRPAGE);

    //BUG_ON(inode->i_size < page_offset(async_work->begin_page));

    page_cluster = kzalloc(CLUSTER_NRPAGE * sizeof(struct page *), GFP_NOFS);
    if (!page_cluster) {
        luci_err_inode(inode, "failed to allocate page cluster\n");
        return;
    }

    // start compression
    start = ktime_get();

    ws = find_workspace(LUCI_COMPRESS_ZLIB);
    if (IS_ERR(ws)) {
        luci_err_inode(inode, "failed to alloc workspace");
        goto write_error;
    }

    err = luci_zlib_compress.compress_pages(ws,
                                            async_work->begin_page->mapping,
                                            page_offset(async_work->begin_page),
                                            page_cluster,
                                            &nr_pages_out,
                                            &total_in,
                                            &total_out);

    free_workspace(LUCI_COMPRESS_ZLIB, ws);

    if (!err) {
        compressed = true;
        BUG_ON(!nr_pages_out);
        UPDATE_AVG_LATENCY_NS(dbgfsparam.avg_deflate_lat, start);
        LUCI_COMPRESS_RESULT(cluster, page_index(async_work->begin_page),
                             total_in, total_out);
        crc32[0] = luci_compute_checksum(page_cluster, nr_pages_out, total_out);  
    } else {
        compressed = false;
        total_out = CLUSTER_SIZE;
        luci_info_inode(inode, "cannot compress cluster, do regular write\n");

        while (nr_pages_out--) {
             BUG_ON(!page_cluster[nr_pages_out]);
             luci_zlib_compress.remit_workspace(ws, page_cluster[nr_pages_out]);
        }

        nr_pages_out = CLUSTER_NRPAGE;
        for (i = 0; i < nr_pages_out; i++) {
            page_cluster[i] = async_work->pvec->pages[i];
            crc32[i] = luci_compute_checksum(&page_cluster[i], 1, PAGE_SIZE);  
        }
    }

    // FIXME: We COW on a new write.
    nr_blocks = (total_out + blocksize - 1) >> ilog2(blocksize);
    err = luci_new_block(inode,
                         nr_blocks,
                         &start_compr_block);
    if (err < 0)
        panic("failed block allocation for cluster %u, nr_blocks :%lu",
               cluster, nr_blocks);

    for (i = 0, block_no = start_compr_block; i < CLUSTER_NRBLOCKS_MAX; i++) {
        if (compressed)
            bp_reset(&bp_array[i], start_compr_block, total_out, LUCI_COMPR_FLAG, crc32[0]);
        else
            bp_reset(&bp_array[i], block_no++, 0, 0, crc32[i]);
    }

    delta = luci_cluster_update_bp(async_work->begin_page, inode, bp_array);
    LUCI_I(inode)->i_size_comp += delta;
    luci_info_inode(inode, "bptr change(%d)cluster(%d) size=%llu, delta=%d\n",
        compressed, cluster, LUCI_I(inode)->i_size_comp, delta);

    disk_start = start_compr_block * blocksize;
    err = luci_submit_write(inode,
                            page_cluster,
                            total_out,
                            disk_start,
                            compressed,
                            compressed ? ws : NULL);
    if (err < 0) {
        redirty_page = true;
        luci_err_inode(inode, "submit write error for cluster %u", cluster);
        goto write_error;
    } else {
        luci_dbg_inode(inode, "submit write ok for cluster %u(%lu)", cluster,
                page_index(async_work->begin_page));
        goto release;
    }

write_error:
    if (compressed) {
        while (nr_pages_out--)
                luci_zlib_compress.remit_workspace(ws, page_cluster[nr_pages_out]);
    }

release:

    if (!compressed)
        goto exit;

    // release regular pages
    for (i = 0; i < pagevec_count(async_work->pvec); i++) {
        struct page *page = async_work->pvec->pages[i];

        if (PageLocked(page))
            unlock_page(page);

        // FIXME : redirty_page on error
        if (PageWriteback(page))
            end_page_writeback(page);

        // drop ref from grab_cache_page_nowait
        put_page(page);

        // spcl case :drop ref in context of luci_writepage only
        if (async_work->pageout && async_work->pageout == page)
            put_page(page);
    }

exit:
    if (page_cluster)
        kfree(page_cluster);

    if (async_work->pvec)
        kfree(async_work->pvec);

    kfree(async_work);
}

/*
 * This is common code exercised by writepages and writepage.
 * For identifying writepage, we pass the page itself.
 * Core routine which converts page to a gang page write
 *
 * @pageout param can be NULL if invoked via writepages
 */

static pgoff_t
issue_cluster_write(struct address_space *mapping,
                    struct page *pageout,
                    pgoff_t index,
                    struct writeback_control *wbc)
{
    unsigned i, nr_pages, nr_dirty, tag;
    pgoff_t end, next_index = index;
    struct page *page = NULL;
    struct pagevec *page_vec;
    struct inode *inode = mapping->host;
    struct comp_write_work *async_work;
    unsigned cluster = luci_cluster_no(index);

    page_vec = kzalloc(sizeof(struct pagevec), GFP_NOFS);
    if (!page_vec) {
        luci_err_inode(inode, "failed to allocate pagevec");
        return -ENOMEM;
    }

    tag = (wbc->sync_mode == WB_SYNC_ALL || wbc->tagged_writepages) ?
           PAGECACHE_TAG_TOWRITE : PAGECACHE_TAG_DIRTY;

    index = ALIGN(index, CLUSTER_NRPAGE);
    end = index + CLUSTER_NRPAGE - 1;
    // scan page tree from @start to @end (inclusive) and tags all
    // pages that have DIRTY tag set with a special TOWRITE tag.
    if (tag == PAGECACHE_TAG_TOWRITE)
        tag_pages_for_writeback(mapping, index, end);

    pagevec_init(page_vec, 0);
    nr_pages = pagevec_lookup_tag(page_vec,
                                  mapping,
                                  &next_index,
                                  tag,
                                  CLUSTER_NRPAGE);
    BUG_ON(pagevec_count(page_vec) != nr_pages);

    luci_dbg_inode(inode, "scan %u pages in pagevec index range %lu-%lu",
        nr_pages, index, next_index);

    if (!nr_pages) {
        pagevec_release(page_vec);
        kfree(page_vec);
        return index;
    }

    nr_dirty = 0;
    // scan cluster pagevec for dirty pages
    for (i = 0; i < nr_pages; i++) {
        struct page * page = page_vec->pages[i];

        if (cluster != luci_cluster_no(page_index(page))) {
            // Fixed: missing writes for pages not from this cluster
            next_index = page_index(page);
            luci_info_inode(inode, "dirty page (%lu)  does not belong to this "
                "cluster(%u), updating next index", next_index, cluster);
            break;
        }

        // dirty page must have uptodate data
        BUG_ON(!PageUptodate(page));

        // TBD: Its not clear at times why dirty flag is clean, even though its
        // tagged dirty in radix tree. There is no race condition associated,
        // confirmed via log.
        if (!PageDirty(page)) {
            SetPageDirty(page);
            luci_info_inode(inode, "warning: page (%lu) tagged dirty in radix "
                "tree but flag is clean", page_index(page));
            luci_pageflags_dump(page, __func__);
        }

        // page may already been under writeback
        if (PageLocked(page) || PageWriteback(page)) {
            luci_info_inode(inode, "warning: page either locked or already under "
                            "writeback");
            continue;
        }
        nr_dirty++;
    }

    // drops all page ref from pagevec lookup
    pagevec_release(page_vec);

    luci_dbg_inode(inode, "dirty pages:%u in cluster %u(%lu)", nr_dirty,
        cluster, index);

    if (!nr_dirty)
        return next_index;

    // lock pages in the cluster when submitting a write
    for (i = 0; i < CLUSTER_NRPAGE; i++) {
repeat:
        if ((page = grab_cache_page_nowait(mapping, index + i)) == NULL) {
            cond_resched();
            goto repeat;
        }

        if (PageDirty(page)) {
            clear_page_dirty_for_io(page);
            set_page_writeback(page);
        }

        // does not take a refcount
        pagevec_add(page_vec, page);
        luci_pgtrack(page, "locked page for write");
    }

    async_work = (struct comp_write_work *) kmalloc
            (sizeof(struct comp_write_work), GFP_NOFS);
    if (!async_work) {
        kfree(page_vec);
        luci_err_inode(inode, "failed to allocate work item\n");
        return -ENOMEM;
    }

    async_work->pvec = page_vec;
    async_work->pageout = pageout;
    async_work->begin_page = page_vec->pages[0];
    BUG_ON(!async_work->begin_page);
    INIT_WORK(&async_work->work, __luci_compress_and_write);
    queue_work(LUCI_SB(inode->i_sb)->comp_write_wq, &async_work->work);
    dbgfsparam.nrbatches++;
    wbc->nr_to_write -= nr_dirty;
    dbgfsparam.nrwrites += nr_dirty;
    return next_index;
}

// Give a page where data will be copied. The page will be locked.
// This is for buffered writes. Currently, we do not handle partial writes.
// Once compressed read is implemented, we can handle this case correctly.
int
luci_write_compressed_begin(struct address_space *mapping,
                            loff_t pos, unsigned len, unsigned flags,
                            struct page **pagep)
{
    struct page *page = NULL;
    pgoff_t index = pos >> PAGE_CACHE_SHIFT;
    struct inode *inode = mapping->host;

    // vfs limits len to page size
    if (len > PAGE_SIZE) {
        luci_err("write length exceeds page size!");
        return -EINVAL;
    }
    // Find or create a page and returned the locked page.
    page = grab_cache_page_write_begin(mapping, index, flags);
    BUG_ON(page == NULL);
    BUG_ON(!PageLocked(page));

    SetPageUptodate(page);
    *pagep = page;
    luci_pgtrack(page, "grabbed page for inode %lu off %llu-%u",
        inode->i_ino, pos, len);
    return 0;
}

// Data is copied from user space in the page Set appropriate flags and
// unlock the page
int
luci_write_compressed_end(struct address_space *mapping,
    loff_t pos, unsigned len, unsigned flags, struct page *pagep)
{
    struct inode *inode = mapping->host;
    BUG_ON(!PageLocked(pagep));
    SetPageUptodate(pagep);
    // For non buffer-head pages, dirty tag the radix tree
    // It is not clear at this point, even on marking a page descriptor dirty,
    // why on writepages, dirty flag is found to be clean (confirmed via log)
    if (!PageDirty(pagep)) {
        __set_page_dirty_nobuffers(pagep);
        luci_pgtrack(pagep, "copied cache page(%lu) for inode %lu off %llu-%u",
            page_index(pagep), inode->i_ino, pos, len);
    }
    unlock_page(pagep);
    page_cache_release(pagep);
    #ifndef LUCI_ATTRSIZE_COMPRESSED
    // note file inode size is updated here
    if (pos + len > inode->i_size) {
        i_size_write(inode, pos + len);
        mark_inode_dirty(inode);
        luci_dbg_inode(inode, "updating inode new size %llu", inode->i_size);
    }
    #endif
    // Ensure we trigger page writeback once, dirty pages exceeds threshold
    //balance_dirty_pages_ratelimited(mapping);
    return len;
}

// Identify dirty cluster associated with a page, compress it and submit
// compressed write.
// This is invoked by shrink_page_list. See : shrink_page_list and pageout
int
luci_writepage_compressed(struct page *page, struct writeback_control *wbc)
{
    unsigned cluster;
    pgoff_t next_index;
    struct inode *inode = page->mapping->host;

    cluster = luci_cluster_no(page_index(page));
    next_index = issue_cluster_write(page->mapping,
                                               page,
                                               page_index(page),
                                               wbc);
    // Currently cannot handle write errors
    BUG_ON(next_index == ULONG_MAX);
    BUG_ON(PageDirty(page));
    BUG_ON(PageWriteback(page));
    BUG_ON(PagePrivate(page));
    if (PageLocked(page))
        unlock_page(page);

    luci_dbg_inode(inode, "%s cluster :%u(%lu) "WBC_FMT, __func__, cluster,
        page_index(page), WBC_ARGS(wbc));
    return (next_index != ULONG_MAX) ? 0 : -EIO;

}

// Iterate over all pages of the address space, identify dirty clusters,
// compress them and submit compressed writes
int luci_writepages_compressed(struct address_space *mapping,
    struct writeback_control *wbc)
{
    int done = 0, cycled = 0;
    pgoff_t start_index, end, next_index, done_index = 0;
    struct inode *inode = mapping->host;

    luci_dbg_inode(inode, "writing pages "WBC_FMT, WBC_ARGS(wbc));

    if (wbc->range_cyclic) {
        start_index = mapping->writeback_index;
        end = -1;
        if (start_index == 0)
            cycled = 1;
    } else {
        start_index = wbc->range_start >> PAGE_SHIFT;
        end = wbc->range_end >> PAGE_SHIFT;
        // ignore range_cyclic tests
        cycled = 1;
    }

cycle:
    while (!done && start_index <= end) {
        next_index = issue_cluster_write(mapping,
                                                          NULL,
                                                          start_index,
                                                          wbc);
        // Currently cannot handle write errors
        BUG_ON(next_index == ULONG_MAX);
        if (start_index == next_index)
            break;
        done_index = start_index;
        start_index = next_index;
        // For integrity sync, we have to write all pages we tagged
        if (wbc->nr_to_write <= 0 && wbc->sync_mode == WB_SYNC_NONE) {
            luci_info_inode(inode, "ending writepages cycle(%lu-%lu)",
                start_index, next_index);
            done = 1;
        }
        // explicit rescheduling in places that are safe
        cond_resched();
    }

    // we hit last page and there is more work to be done;
    if (!cycled && !done) {
        cycled = 1;
        start_index = 0;
        end = mapping->writeback_index - 1;
        goto cycle;
    }

    // we still have stuff dirty, but that's all we can do for now
    if (wbc->range_cyclic && wbc->nr_to_write > 0) {
        mapping->writeback_index = done_index;
    }

    luci_info_inode(inode, "exiting writing pages compressed(%lu)",
        wbc->nr_to_write);
    return 0;
}

// read a compressed page
// Step 1:
int luci_read_compressed(struct page *page, blkptr *bp)
{
    int i, ret = 0;
    struct page *page_in, *page_out;
    struct list_head *ws;
    struct bio *comp_bio = NULL, *pgtree_bio = NULL;
    struct inode *inode = page->mapping->host;
    // Fixed :pass disk start to bio prepare, not blockno
    u64 disk_start = bp->blockno * LUCI_BLOCK_SIZE(inode->i_sb);
    unsigned long total_in = COMPR_LEN(bp);
    unsigned aligned_bytes = sector_align(total_in);
    unsigned nr_pages = (total_in + PAGE_SIZE - 1)/PAGE_SIZE;
    unsigned long cluster = luci_cluster_no(page_index(page));
    unsigned long pg_index = cluster * CLUSTER_NRPAGE;
    struct page *compressed_pages[CLUSTER_NRPAGE], *pgtree_pages[CLUSTER_NRPAGE];

    #ifdef DEBUG_COMPRESSION
    luci_info_inode(inode, "read, total_in :%lu aligned bytes :%u disk start "
                    ":%llu", total_in, aligned_bytes, disk_start);
    #endif

    memset((char*)compressed_pages, 0, CLUSTER_NRPAGE * sizeof(struct page *));

    // allocate pages for reading compressed blocks
    for (i = 0; i < nr_pages; i++) {
        page_in = alloc_page(GFP_NOFS | __GFP_HIGHMEM);
        if (!page_in) {
            ret = -ENOMEM;
            luci_err("failed to allocate page for compressed read");
            goto free_readpages;
        }
        compressed_pages[i] = page_in;
    }

    comp_bio = luci_prepare_bio(inode,
                                compressed_pages,
                                aligned_bytes,
                                disk_start,
                                false,
                                NULL);
    if (IS_ERR(comp_bio)) {
        ret = -EIO;
        luci_err("failed to allocate comp_bio for read");
        goto free_readpages;
    }

    #ifdef NEW_BIO_SUBMIT
    ret = submit_bio_wait(comp_bio);
    #else
    ret = submit_bio_wait(READ_SYNC, comp_bio);
    #endif
    if (ret) {
    #ifdef HAVE_NEW_BIO_FLAGS
        luci_err("bio error status :0x%x, status :%d", comp_bio->bi_flags, ret);
    #else
        luci_err("bio error status :0x%lx, status :%d", comp_bio->bi_flags, ret);
    #endif
        goto free_readbio;
    }

    // bio for page tree pages
    memset((char*)pgtree_pages, 0, CLUSTER_NRPAGE * sizeof(struct page *));
    for (i = 0; pg_index < (cluster + 1) * CLUSTER_NRPAGE; pg_index++) {
        page_out = find_get_page(page->mapping, pg_index);
        if (!page_out) {
            luci_err_inode(inode, "page %lu not in cache allocating", pg_index);
            page_out = find_or_create_page(page->mapping, pg_index, GFP_KERNEL);
        }
        pgtree_pages[i++] = page_out;
    }

    pgtree_bio = luci_prepare_bio(inode,
                                  pgtree_pages,
                                  CLUSTER_SIZE,
                                  0,
                                  false,
                                  NULL);
    if (IS_ERR(pgtree_bio)) {
        ret = -EIO;
        luci_err("failed to allocate bio for inflate");
        goto free_compbio;
    }

    ws = find_workspace(LUCI_COMPRESS_ZLIB);
    if (IS_ERR(ws)) {
        ret = PTR_ERR(ws);
        luci_err_inode(inode, "failed to alloc workspace");
        goto free_compbio;
    }

    ret = luci_zlib_compress.decompress_pages(ws,
                                              total_in,
                                              comp_bio,
                                              pgtree_bio);
    if (ret)
        panic("decompress failed, ret %d", ret);
    free_workspace(LUCI_COMPRESS_ZLIB, ws);

free_compbio:
    #ifdef HAVE_NEW_BIO_END
    luci_end_compressed_bio_read(comp_bio);
    #else
    luci_end_compressed_bio_read(comp_bio, ret);
    #endif

    for (i = 0; i < CLUSTER_NRPAGE; i++) {
        page_out = pgtree_pages[i];
        if (PageLocked(page_out)) // TBD: check if page can be at all locked
             unlock_page(page_out);
        put_page(page_out);
    }

    if(comp_bio)
        bio_put(comp_bio);

    if (pgtree_bio)
        bio_put(pgtree_bio);

    return ret;

    // TBD: decompress
free_readbio:
    if(comp_bio)
        bio_put(comp_bio);

free_readpages:
    for (i = 0; i < nr_pages; i++) {
        page_in = compressed_pages[i];
        put_page(page_in);
    }
    return ret;
}

/*
 * this finds an available workspace or allocates a new one
 * ERR_PTR is returned if things go bad.
 */
struct list_head *find_workspace(int type)
{
    struct list_head *workspace;
    int cpus = num_online_cpus();
    int idx = type - 1;

    struct list_head *idle_ws = &luci_comp_ws[idx].idle_ws;
    spinlock_t *ws_lock = &luci_comp_ws[idx].ws_lock;
    atomic_t *alloc_ws = &luci_comp_ws[idx].alloc_ws;
    wait_queue_head_t *ws_wait = &luci_comp_ws[idx].ws_wait;
    int *num_ws	= &luci_comp_ws[idx].num_ws;

again:
    spin_lock(ws_lock);
    if (!list_empty(idle_ws)) {
        workspace = idle_ws->next;
	list_del(workspace);
	(*num_ws)--;
	spin_unlock(ws_lock);
	return workspace;
    }

    if (atomic_read(alloc_ws) > cpus) {
        DEFINE_WAIT(wait);

	spin_unlock(ws_lock);
	prepare_to_wait(ws_wait, &wait, TASK_UNINTERRUPTIBLE);
	if (atomic_read(alloc_ws) > cpus && !*num_ws)
	    schedule();
	finish_wait(ws_wait, &wait);
	goto again;
    }

    atomic_inc(alloc_ws);
    spin_unlock(ws_lock);

    workspace = luci_compress_op[idx]->alloc_workspace();
    if (IS_ERR(workspace)) {
	atomic_dec(alloc_ws);
	wake_up(ws_wait);
    }
    return workspace;
}

/*
 * put a workspace struct back on the list or free it if we have enough
 * idle ones sitting around
 */
void free_workspace(int type, struct list_head *workspace)
{
     int idx = type - 1;
     struct list_head *idle_ws	= &luci_comp_ws[idx].idle_ws;
     spinlock_t *ws_lock = &luci_comp_ws[idx].ws_lock;
     atomic_t *alloc_ws = &luci_comp_ws[idx].alloc_ws;
     wait_queue_head_t *ws_wait	= &luci_comp_ws[idx].ws_wait;
     int *num_ws = &luci_comp_ws[idx].num_ws;

     spin_lock(ws_lock);
     if (*num_ws <= num_online_cpus()) {
        list_add(workspace, idle_ws);
	(*num_ws)++;
	spin_unlock(ws_lock);
	goto wake;
     }
     spin_unlock(ws_lock);

     luci_compress_op[idx]->free_workspace(workspace);
     atomic_dec(alloc_ws);
wake:
     /*
      * Make sure counter is updated before we wake up waiters.
      */
     smp_mb();
     if (waitqueue_active(ws_wait))
         wake_up(ws_wait);
}

/*
 * cleanup function for module exit
 */
static void free_workspaces(void)
{
    int i;
    for (i = 0; i < LUCI_COMPRESS_TYPES; i++) {
        while (!list_empty(&luci_comp_ws[i].idle_ws)) {
	    struct list_head *workspace = luci_comp_ws[i].idle_ws.next;
	    list_del(workspace);
	    luci_compress_op[i]->free_workspace(workspace);
	    atomic_dec(&luci_comp_ws[i].alloc_ws);
	}
    }
}

void init_luci_compress(void)
{
    int i;
    for (i = 0; i < LUCI_COMPRESS_TYPES; i++) {
        INIT_LIST_HEAD(&luci_comp_ws[i].idle_ws);
	    spin_lock_init(&luci_comp_ws[i].ws_lock);
	    atomic_set(&luci_comp_ws[i].alloc_ws, 0);
	    luci_comp_ws[i].num_ws = 0;
	    init_waitqueue_head(&luci_comp_ws[i].ws_wait);
    }
}

void exit_luci_compress(void)
{
    free_workspaces();
}
