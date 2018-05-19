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

#include "kern_feature.h"
#include "luci.h"
#include "cluster.h"
#include "compression.h"

static const struct luci_compress_op * const luci_compress_op[] = {
	&luci_zlib_compress,
};

static void
luci_pageflags_dump(struct page* page)
{
    luci_dbg("page Writeback :%d page Dirty :%d page Uptodate %d",
        PageWriteback(page), PageDirty(page), PageUptodate(page));
}

static void
luci_bh_dump(struct buffer_head *bh)
{
    luci_dbg("buffer mapped :%d buffer dirty :%d buffer locked :%d refcount :%d",
        buffer_mapped(bh), buffer_dirty(bh), buffer_locked(bh),
        atomic_read(&bh->b_count));
}

static void
luci_bio_dump(struct bio * bio, const char *msg)
{
#ifdef HAVE_BIO_ITER
     luci_dbg("%s bio : bi_max_vecs :%u bi_vcnt :%d bi_size :%u bi_sector :%lu"
        " bytes: %u", msg, bio->bi_max_vecs, bio->bi_vcnt, bio->bi_iter.bi_size,
        bio->bi_iter.bi_sector, bio_cur_bytes(bio));
#else
     luci_dbg("%s bio : bi_max_vecs :%u bi_vcnt :%d bi_size :%u bi_sector :%lu"
        " bytes :%u", msg, bio->bi_max_vecs, bio->bi_vcnt, bio->bi_size,
        bio->bi_sector, bio_cur_bytes(bio));
#endif
     luci_dump_bytes("bio page", bio_page(bio), PAGE_SIZE);
}

static void
bp_reset(blkptr *bp, unsigned long block, unsigned int size,
    unsigned short flags) {
    bp->blockno = block;
    bp->length = size;
    bp->flags = LUCI_COMPR_FLAG;
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
        luci_pageflags_dump(page);
        if (PageLocked(page)) {
           unlock_page(page);
        }
        put_page(page);
    }
}

/*
 * do the cleanup once all the compressed pages hit the disk.
 * This will clear writeback on the file pages and free the compressed
 * pages.
 *
 * This also calls the writeback end hooks for the file pages so that
 * metadata and checksums can be updated in the file.
 */
static void
#ifdef HAVE_NEW_BIO_END
luci_end_compressed_bio_write(struct bio *bio)
#else
luci_end_compressed_bio_write(struct bio *bio, int error)
#endif
{
    int i = 0;
    struct bio_vec *bvec;
    // TBD: Check for status associated with each bvec page
    // We do not set any writeback flag, so end_page_writeback(page)
    // is not necessary
    bio_for_each_segment_all(bvec, bio, i) {
        struct page * page = bvec->bv_page;
        page->mapping = NULL;
        luci_pageflags_dump(page);
        if (PageLocked(page)) {
           unlock_page(page);
        }
        put_page(page);
    }
}

static void
luci_release_page(struct page * page)
{
    struct buffer_head *bh, *head;
    if (page_has_buffers(page)) {
        head = bh = page_buffers(page);
        do {
            // need get_bh & put_bh since bh can have 0 refcounts
            BUG_ON(buffer_locked(bh));
            lock_buffer(bh);
            get_bh(bh);
            luci_bh_dump(bh);
            clear_buffer_dirty(bh);
            set_buffer_uptodate(bh);
            unlock_buffer(bh);
            put_bh(bh);
            bh = bh->b_this_page;
        } while (bh != head);
    }

    luci_pageflags_dump(page);
    if (PageLocked(page)) {
        unlock_page(page);
    }
    //put_page(page);
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
    // TBD: Check for status associated with each bvec page
    // We do not set any writeback flag, so end_page_writeback(page)
    // is not necessary
    bio_for_each_segment_all(bvec, bio, i) {
        struct page * page = bvec->bv_page;
        luci_release_page(page);
    }
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
     unsigned long total, unsigned long disk_start, bool write)
{
    int ret;
    struct bio *bio;
    struct block_device *bdev = inode->i_sb->s_bdev;
    // align size to device sector, otherwise device rejects write
    unsigned long i = 0, aligned_bytes = sector_align(total);
    unsigned long nr_pages = (aligned_bytes + PAGE_SIZE - 1)/PAGE_SIZE;

    bio = luci_bio_alloc(bdev, disk_start, nr_pages);
    if (!bio) {
        luci_err_inode(inode, "bio alloc failed");
        return ERR_PTR(-ENOMEM);
    }

    // TBD : Assign callbacks to bio caused hanged

    // construct bio vecs for each PAGE of compressed output
    // Note these pages are anon and do not belong to page cache
    while (i < nr_pages) {
       unsigned int length;
       length = min((unsigned long)PAGE_SIZE, aligned_bytes);
       ret = bio_add_page(bio, pages[i], length, 0);
       if (ret < length) {
           luci_err_inode(inode, "bio add page failed");
           bio_put(bio);
           return ERR_PTR(-EIO);
       }
       luci_dbg("added page %p to bio, len :%u", pages[i], length);
       aligned_bytes -= (unsigned long)length;
       i++;
    }

    if (aligned_bytes) {
        luci_err("failed to consume output, left %lu", aligned_bytes);
        BUG();
    }
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
     unsigned long total_out, unsigned long disk_start, bool compressed)
{
    int ret;
    ktime_t start;
    struct bio *bio;
    struct block_device *bdev = inode->i_sb->s_bdev;
    // align size to device sector, otherwise device rejects write
    unsigned long i = 0, aligned_bytes = sector_align(total_out);
    unsigned long nr_pages = (aligned_bytes + PAGE_SIZE - 1)/PAGE_SIZE;

    bio = luci_bio_alloc(bdev, disk_start, nr_pages);
    if (!bio) {
       luci_err_inode(inode, "bio alloc failed");
       return -ENOMEM;
    }

    // TBD : Assign callbacks to bio caused hanged

    // construct bio vecs for each PAGE of compressed output
    // Note these pages are anon and do not belong to page cache
    while (i < nr_pages) {
       unsigned int length;
       length = min((unsigned long)PAGE_SIZE, aligned_bytes);
       ret = bio_add_page(bio, pages[i], length, 0);
       if (ret < length) {
           ret = -EIO;
           luci_err_inode(inode, "bio add page failed");
           goto exit;
       }
       aligned_bytes -= (unsigned long)length;
       i++;
    }

    if (aligned_bytes) {
        luci_err("failed to consume output, left %lu", aligned_bytes);
        BUG();
    }
    luci_bio_dump(bio, "submitting bio write");

    start = ktime_get();
    #ifdef NEW_BIO_SUBMIT
    bio->bi_opf = REQ_OP_WRITE;
    ret = submit_bio_wait(bio);
    #else
    ret = submit_bio_wait(WRITE_SYNC, bio);
    #endif

    if (ret) {
    #ifdef HAVE_NEW_BIO_FLAGS
        luci_err("bio error status :0x%x, status :%d", bio->bi_flags, ret);
    #else
        luci_err("bio error status :0x%lx, status :%d", bio->bi_flags, ret);
    #endif
    } else {
        UPDATE_AVG_LATENCY_NS(dbgfsparam.avg_io_lat, start);
    }

exit:
    if (compressed) {
        #ifdef HAVE_NEW_BIO_END
        luci_end_compressed_bio_write(bio);
        #else
        luci_end_compressed_bio_write(bio, ret);
        #endif
    } else {
        #ifdef HAVE_NEW_BIO_END
        luci_end_bio_write(bio);
        #else
        luci_end_bio_write(bio, ret);
        #endif
    }
    //bio->bi_end_io(bio, ret);
    bio_put(bio);
    return ret;
}


// Give a page where data will be copied. The page will be locked.
// This is for buffered writes. Currently, we do not handle partial writes.
// Once compressed read is implemented, we can handle this case correctly.
int
luci_write_compressed_begin(struct address_space *mapping,
    loff_t pos, unsigned len, unsigned flags, struct page **pagep)
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
    // For non buffer-head pages, tag the radix tree
    if (!PageDirty(pagep)) {
        __set_page_dirty_nobuffers(pagep);
    }
    unlock_page(pagep);
    luci_pgtrack(pagep, "copied cache page for inode %lu off %llu-%u",
        inode->i_ino, pos, len);
    put_page(pagep);
    // note file inode size is updated here
    if (pos + len > inode->i_size) {
        i_size_write(inode, pos + len);
        mark_inode_dirty(inode);
        luci_dbg_inode(inode, "updating inode new size %llu", inode->i_size);
    }
    // Ensure we trigger page writeback once, dirty pages exceeds threshold
    balance_dirty_pages_ratelimited(mapping);
    return len;
}

static int
__luci_write_compressed(struct page * page, struct pagevec *pvec,
    struct writeback_control *wbc)
{
    int ret;
    int i = 0;
    ktime_t start;
    struct list_head * ws;
    struct page **pages_vec;
    pgoff_t index = page_index(page);
    loff_t start_offset = page_offset(page);
    struct inode *inode = page->mapping->host;
    unsigned blockbits, blocksize, cluster;
    unsigned long nr_blocks, nr_pages_out,
        total_in, total_out, start_compr_block, disk_start, block_no;
    blkptr bp_array[CLUSTER_NRBLOCKS_MAX];
    bool compressed = true;

    cluster = luci_cluster_no(index);

    BUG_ON(page_has_buffers(page));
    BUG_ON(!PageLocked(page));
    BUG_ON(pagevec_count(pvec) != CLUSTER_NRPAGE);

    // compressed pages array
    pages_vec = kcalloc(CLUSTER_NRPAGE, sizeof(struct page *), GFP_NOFS);
    if (pages_vec == NULL) {
        return -ENOMEM;
    }

    // compression params
    total_out = total_in = CLUSTER_SIZE;
    nr_pages_out = CLUSTER_NRPAGE;

    //BUG_ON(inode->i_size < start_offset);

    // get workspace, sleep in case we do find any
    ws = find_workspace(LUCI_COMPRESS_ZLIB);
    if (IS_ERR(ws)) {
        luci_err_inode(inode, "failed to alloc workspace");
        ret = PTR_ERR(ws);
        goto exit;
    }

    start = ktime_get();

    ret = luci_zlib_compress.compress_pages(ws,
                                   page->mapping,
                                   start_offset,
                                   pages_vec,
                                   &nr_pages_out,
                                   &total_in,
                                   &total_out);

    free_workspace(LUCI_COMPRESS_ZLIB, ws);

    UPDATE_AVG_LATENCY_NS(dbgfsparam.avg_deflate_lat, start);

    // cannot compress : a) E2BIG  b) page not in page cache
    // TBD : We do not handle this case well, for now return OK.
    if (ret < 0) {
        int i = 0;
        luci_err("failed compression for cluster %u, status :%d", cluster, ret);
        if (ret != -E2BIG) {
            BUG();
        }
        ret = 0;
        compressed = false;
        luci_info("issuing uncompressed write for cluster %u", cluster);
        for (i = 0; i < CLUSTER_NRPAGE; i++) {
            struct page *page = pages_vec[i];
            // free pages allotted to compression, otherwise, we have a leak
            if (page != NULL) {
                put_page(page);
            }
            // assign uncompressed page
            pages_vec[i] = pvec->pages[i];
        }
        total_out = CLUSTER_SIZE;
        // TBD :
        //goto exit;
    } else {
        LUCI_COMPRESS_RESULT(cluster, index, total_in, total_out);
    }

    // allocate blocks needed for the compressed cluster
    blockbits = LUCI_BLOCK_SIZE_BITS(inode->i_sb);
    blocksize = 1UL << blockbits;
    nr_blocks = (total_out + blocksize - 1) >> blockbits;
    ret = luci_new_block(inode, nr_blocks, &start_compr_block);
    if (ret) {
        luci_err("failed block allocation for cluster %u, nr_blocks :%lu",
            cluster, nr_blocks);
        goto exit;
    }

    for (i = 0, block_no = start_compr_block; i < CLUSTER_NRBLOCKS_MAX; i++) {
        if (compressed) {
            bp_reset(&bp_array[i], start_compr_block, total_out, LUCI_COMPR_FLAG);
        } else {
            bp_reset(&bp_array[i], block_no++, 0, 0);
        }
    }

    // Fix me
    luci_cluster_update_bp(page, inode, bp_array);

    // issue compressed write
    disk_start = start_compr_block * blocksize;
    ret = luci_submit_write(inode, pages_vec, total_out, disk_start, compressed);
    if (ret) {
        // TBD: Handle uncompressed write
        luci_err("failed write for cluster %u, status %d", cluster, ret);
        goto failed_write;
    }
    luci_dbg_inode(inode, "submitted cluster %u(%lu)", cluster, index);
    goto exit;

failed_write:
    // TBD: free blocks
exit:
    if (pages_vec) {
        kfree(pages_vec);
    }
    return ret;
}

// Core routine which converts page to a gang page write
static pgoff_t
__luci_cluster_write_compressed(struct address_space *mapping, struct page *pageout,
    pgoff_t index, unsigned int tag, struct writeback_control *wbc)
{
    int ret;
    struct pagevec pvec;
    bool write_failed = false;
    pgoff_t next_index = index;
    unsigned i, nr_pages, nr_dirty;
    struct page *begin_page = NULL;
    unsigned cluster = luci_cluster_no(index);
    const unsigned max_pages = CLUSTER_NRPAGE;

    pagevec_init(&pvec, 0);

    nr_pages = pagevec_lookup_tag(&pvec, mapping, &next_index, tag, max_pages);
    BUG_ON(pagevec_count(&pvec) != nr_pages);

    if (pageout && PageLocked(pageout)) {
       unlock_page(pageout);
    }

    // found no pages dirty
    if (nr_pages == 0) {
        luci_dbg("no dirty pages in range lookup %lu-%lu", index, next_index);
        return index;
    }

    luci_info("dirty pages :%u in range lookup %lu-%lu", nr_pages, index,
        next_index);
    // sanity checks
    for (i = 0, nr_dirty = 0; i < nr_pages; i++) {
        struct page * page = pvec.pages[i];
        // check if dirty page belongs to cluster
        if (cluster != luci_cluster_no(page_index(page))) {
            break;
        }
        // page must be dirty, since radix lookup says it's dirty
        // Otherwise, somebody else wrote it for us
        //BUG_ON(!PageDirty(page));
        if (!PageDirty(page)) {
            luci_info("warning: somebody wrote the page for us");
            continue;
        }
        luci_pgtrack(page, "page dirty cluster :%u", cluster);
        // dirty page must have uptodate data
        BUG_ON(!PageUptodate(page));
        // page may already been under writeback
        if (PageLocked(page) || PageWriteback(page)) {
            luci_info("warning: page either locked/writeback");
            continue;
        }
        nr_dirty++;
    }

    // Fix page leak
    pagevec_release(&pvec);

    //pagevec_reinit(&pvec);
    if (nr_dirty == 0) {
        luci_dbg("no dirty pages in cluster %u(%lu-%lu)", cluster, index,
                next_index);
        goto skip;
    } else {
        luci_info("dirty pages:%u in cluster %u(%lu)", nr_dirty, cluster,
                index);
    }

    // lock pages in the cluster
    for (i = 0; i < max_pages; i++) {
        struct page *page;
        pgoff_t pg = index  + i;
repeat:
        page = grab_cache_page_nowait(mapping, pg);
        if (page == NULL) {
            cond_resched();
            goto repeat;
        }
        if (PageDirty(page)) {
            clear_page_dirty_for_io(page);
            // prepare page under writeout
            set_page_writeback(page);
        }
        if (i == 0) {
            begin_page = page;
        }
        pagevec_add(&pvec, page);
        luci_pgtrack(page, "locked page for write");
    }

    BUG_ON(begin_page == NULL);

    // all pages in the cluster are now in the page cache.
    // do compression and submit write
    ret = __luci_write_compressed(begin_page, &pvec, wbc);
    if (ret) {
        luci_err("compressed write failed :%d", ret);
        write_failed = true;
        next_index = ULONG_MAX;
        // We do not tolerate write failures for now
        // this shall flush printk buffers
        panic("write failed :%d", ret);
    } else {
        wbc->nr_to_write -= nr_dirty;
        dbgfsparam.nrwrites += nr_dirty;
    }

    // unlock pages in the cluster
    for (i = 0; i < pagevec_count(&pvec); i++) {
        struct page *page = pvec.pages[i];
        bool reserved = (pageout && pageout == page);

        //if (!reserved && PageLocked(page)) {
        if (PageLocked(page)) {
            unlock_page(page);
        }
        if (PageWriteback(page)) {
            end_page_writeback(page);
            // In case write fails, we redirty the page
            if (write_failed) {
                redirty_page_for_writepage(wbc, page);
            }
        }
        luci_pgtrack(page, "write completed for page");
        // Fix memory leak
        if (!reserved) {
            put_page(page);
        }
    }

skip:
    //pagevec_release(&pvec);
    return next_index;
}

// This is common code exercised by writepages and writepage.
// For identifying writepage, we pass the page itself.
static pgoff_t
luci_cluster_write_compressed(struct address_space *mapping,
    struct page *pageout, pgoff_t start_index, struct writeback_control *wbc)
{
    int tag;
    pgoff_t end;

    start_index = ALIGN(start_index, CLUSTER_NRPAGE);

    end = start_index + CLUSTER_NRPAGE - 1;

    if (wbc->sync_mode == WB_SYNC_ALL || wbc->tagged_writepages) {
        tag = PAGECACHE_TAG_TOWRITE;
    } else {
        tag = PAGECACHE_TAG_DIRTY;
    }

    // This function scans the page range from @start to @end
    // (inclusive) and tags all pages that have DIRTY tag set
    // with a special TOWRITE tag.
    if (wbc->sync_mode == WB_SYNC_ALL || wbc->tagged_writepages) {
        tag_pages_for_writeback(mapping, start_index, end);
    }

    // do write
    return __luci_cluster_write_compressed(mapping, pageout, start_index,
        tag, wbc);
}

// Identify dirty cluster associated with a page, compress it and submit
// compressed write.
int
luci_writepage_compressed(struct page *page, struct writeback_control *wbc)
{
    unsigned cluster;
    pgoff_t index, next_index;
    struct inode *inode = page->mapping->host;

    index = page_index(page);
    cluster = luci_cluster_no(index);
    luci_info_inode(inode, "writing page for cluster :%u(%lu), wbc: (%llu-%llu) "
        "dirty :%lu", cluster, index, wbc->range_start, wbc->range_end,
        wbc->nr_to_write);
    next_index = luci_cluster_write_compressed(page->mapping, page, index, wbc);
    // This is invoked by shrink_page_list. Either of the below flags, can
    // prevent the page from getting reclaimed.
    // See : shrink_page_list and pageout
    BUG_ON(PageDirty(page));
    BUG_ON(PageWriteback(page));
    BUG_ON(PageLocked(page));
    BUG_ON(PagePrivate(page));
    luci_info_inode(inode, "exiting write pages compressed");
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

    luci_info_inode(inode, "writing pages wbc: (%llu-%llu) dirty :%lu",
        wbc->range_start, wbc->range_end, wbc->nr_to_write);

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
        next_index = luci_cluster_write_compressed(mapping, NULL,
            start_index, wbc);
        // Currently cannot handle write errors
        BUG_ON(next_index == ULONG_MAX);
        if (start_index == next_index) {
            break;
        }
        done_index = start_index;
        start_index = next_index;
        // For integrity sync, we have to write all pages we tagged
        if (wbc->nr_to_write <= 0 && wbc->sync_mode == WB_SYNC_NONE) {
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

    luci_info_inode(inode, "exiting writing pages compressed");
    return 0;
}

// read a compressed page
// Step 1:
int luci_read_compressed(struct page *page, blkptr *bp)
{
    int i, ret = 0;
    struct bio *bio = NULL, *org_bio = NULL;
    struct list_head *ws;
    struct inode *inode = page->mapping->host;
    // Fixed :pass disk start to bio prepare, not blockno
    u64 disk_start = bp->blockno * LUCI_BLOCK_SIZE(inode->i_sb);
    unsigned long total_in = COMPR_LEN(bp);
    unsigned aligned_bytes = sector_align(total_in);
    unsigned nr_pages = (total_in + PAGE_SIZE - 1)/PAGE_SIZE;
    unsigned long cluster = luci_cluster_no(page_index(page));
    unsigned long pg_index = cluster * CLUSTER_NRPAGE;
    struct page *compressed_pages[CLUSTER_NRPAGE], *cached_pages[CLUSTER_NRPAGE];

    luci_info("total_in :%lu aligned bytes :%u disk start :%llu",
            total_in, aligned_bytes, disk_start);

    memset((char*)compressed_pages, 0, CLUSTER_NRPAGE * sizeof(struct page *));
    // allocate pages for compressed blocks
    for (i = 0; i < nr_pages; i++) {
        struct page * page_in = alloc_page(GFP_NOFS | __GFP_HIGHMEM);
        if (page_in == NULL) {
            ret = -ENOMEM;
            luci_err("failed to allocate page for read");
            goto free_readpages;
        }
        compressed_pages[i] = page_in;
    }

    // compressed bio
    bio = luci_prepare_bio(inode, compressed_pages, aligned_bytes, disk_start,
                           false);
    if (IS_ERR(bio)) {
        ret = -EIO;
        luci_err("failed to allocate bio for read");
        goto free_readpages;
    }

    // read compressed blocks
    #ifdef NEW_BIO_SUBMIT
    ret = submit_bio_wait(bio);
    #else
    ret = submit_bio_wait(READ_SYNC, bio);
    #endif
    if (ret) {
    #ifdef HAVE_NEW_BIO_FLAGS
        luci_err("bio error status :0x%x, status :%d", bio->bi_flags, ret);
    #else
        luci_err("bio error status :0x%lx, status :%d", bio->bi_flags, ret);
    #endif
        goto free_readbio;
    }

    memset((char*)cached_pages, 0, CLUSTER_NRPAGE * sizeof(struct page *));
    // pages for buf2pages in page cache
    for (i = 0; pg_index < (cluster + 1) * CLUSTER_NRPAGE; pg_index++) {
        struct page *cachep = find_get_page(page->mapping, pg_index);
        if (cachep == NULL) {
            luci_err("page %lu not found in cache, allocating", pg_index);
            cachep = find_or_create_page(page->mapping, pg_index, GFP_KERNEL);
        }
        cached_pages[i++] = cachep;
    }

    // original bio
    org_bio = luci_prepare_bio(inode, cached_pages, CLUSTER_SIZE, 0, false);
    if (IS_ERR(org_bio)) {
        ret = -EIO;
        luci_err("failed to allocate bio for decompressing pages");
        goto free_compbio;
    }
#if 1
    ws = find_workspace(LUCI_COMPRESS_ZLIB);
    if (IS_ERR(ws)) {
        luci_err_inode(inode, "failed to alloc workspace");
        ret = PTR_ERR(ws);
        goto free_compbio;
    }

    ret = luci_zlib_compress.decompress_bio(ws, total_in, bio, org_bio);
    if (ret) {
        luci_err("decompress failed, ret %d\n", ret);
        BUG();
        //panic("decompress failed, ret %d", ret);
    }
    free_workspace(LUCI_COMPRESS_ZLIB, ws);
#endif

free_compbio:
    #ifdef HAVE_NEW_BIO_END
    luci_end_compressed_bio_read(bio);
    #else
    luci_end_compressed_bio_read(bio, ret);
    #endif

    if(bio) {
        bio_put(bio);
    }

    for (i = 0; i < CLUSTER_NRPAGE; i++) {
        struct page *page_out = cached_pages[i];
        unlock_page(page_out);
        put_page(page_out);
    }

    if (org_bio) {
        bio_put(org_bio);
    }
    return ret;

    // TBD: decompress
free_readbio:
    if(bio) {
        bio_put(bio);
    }
free_readpages:
    for (i = 0; i < nr_pages; i++) {
        struct page *page_in = compressed_pages[i];
        put_page(page_in);
    }
    return ret;
}

/*
 * for a compressed read, the bio we get passed has all the inode pages
 * in it.  We don't actually do IO on those pages but allocate new ones
 * to hold the compressed pages on disk.
 *
 * bio->bi_iter.bi_sector points to the compressed cluster on disk
 * bio->bi_io_vec points to all of the inode pages
 * bio->bi_vcnt is a count of pages
 *
 * After the compressed pages are read, we copy the bytes into the
 * bio we were passed and then call the bio end_io calls
 */
int luci_submit_compressed_read(struct inode *inode, struct bio *bio,
				 int mirror_num, unsigned long bio_flags)
{
    return 0;
}

/*
 * Copy uncompressed data from working buffer to pages.
 *
 * @buf_start is the byte offset we're of the start of our workspace buffer.
 *
 * total_out is the last byte of the buffer
 *
 *                        buf_start (decompressed of total output)
 *                           |
 * decomp status   : |-----------------------------------------------|
 *
 * case 1:                   ws buf         start_byte > buffer_start
 * curr page :               |--buf_offset--|------------------------------------
 *
 * case 2:           (start_byte < buf_start
 * curr_page :       |------------------------------------------
 */
int
luci_util_decompress_buf2page(char *buf, unsigned long deflatebuf_offset,
			      unsigned long total_out, u64 start_page_offset,
			      struct bio *bio)
{
    unsigned long skip_bytes, copy_bytes, bytes;
    unsigned long copied_offset, prev_copied_offset;
    char *raw_page_kaddr;

repeat:
    //start byte is the first byte of the page we are currently copying
    copied_offset = page_offset(bio_page(bio)) - start_page_offset;
    // we have not yet data corresponding to this page
    if (copied_offset >= total_out) {
        return 1;
    }
    // the start of the data we are looking for is offset into the middle
    // of the working buffer
    if (copied_offset < total_out && copied_offset > deflatebuf_offset) {
        skip_bytes = copied_offset - deflatebuf_offset;
    } else {
        skip_bytes = 0;
    }

    /* copy bytes from the working buffer to the pages */
    copy_bytes = total_out - copied_offset;
    luci_info("decompress buf2page params: copy_bytes :%lu, copied_offset :%lu"
        " deflatebuf_offset :%lu, skip_bytes :%lu", copy_bytes, copied_offset,
        deflatebuf_offset, skip_bytes);
    while (copy_bytes > 0) {
        //bytes = min(bio_cur_bytes(bio), copy_bytes);
        unsigned long cur_bytes = bio_cur_bytes(bio);
        bytes = min(cur_bytes, copy_bytes);
        raw_page_kaddr = kmap_atomic(bio_page(bio));
        memcpy(raw_page_kaddr, buf + skip_bytes, bytes);
        kunmap_atomic(raw_page_kaddr);
        flush_dcache_page(bio_page(page));
        skip_bytes += bytes;
        copy_bytes -= bytes;
        // check if we need to pick another page
        bio_advance(bio, bytes);
        #ifdef HAVE_BIO_ITER
        if (!bio->bi_iter.bi_size) {
        #else
        if (!bio->bi_size) {
        #endif
            return 0;
        }
        prev_copied_offset = copied_offset;
        copied_offset = page_offset(bio_page(bio)) - start_page_offset;

        if (prev_copied_offset != copied_offset) {
            goto repeat;
        }
    }
    return 1;
}

/*
 * When uncompressing data, we need to make sure and zero any parts of
 * the biovec that were not filled in by the decompression code.  pg_index
 * and pg_offset indicate the last page and the last offset of that page
 * that have been filled in.  This will zero everything remaining in the
 * biovec.
 */
void luci_util_clear_biovec_end(struct bio_vec *bvec, int vcnt,
				   unsigned long pg_index,
				   unsigned long pg_offset)
{
    while (pg_index < vcnt) {
        struct page *page = bvec[pg_index].bv_page;
	unsigned long off = bvec[pg_index].bv_offset;
	unsigned long len = bvec[pg_index].bv_len;

	if (pg_offset < off)
	    pg_offset = off;

	if (pg_offset < off + len) {
	    unsigned long bytes = off + len - pg_offset;
	    char *kaddr;

	    kaddr = kmap_atomic(page);
	    memset(kaddr + pg_offset, 0, bytes);
	    kunmap_atomic(kaddr);
	}
	    pg_index++;
	    pg_offset = 0;
    }
}

static struct {
    struct list_head idle_ws;
    spinlock_t ws_lock;
    int num_ws;
    atomic_t alloc_ws;
    wait_queue_head_t ws_wait;
} luci_comp_ws[LUCI_COMPRESS_TYPES];

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
     if (*num_ws < num_online_cpus()) {
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

