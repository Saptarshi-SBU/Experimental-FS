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

#include "kern_feature.h"
#include "luci.h"
#include "extent.h"
#include "compression.h"

static const struct luci_compress_op * const luci_compress_op[] = {
	&luci_zlib_compress,
};

static struct bio *
luci_bio_alloc(struct block_device *bdev, unsigned long start,
    struct page **pages_vec, unsigned long nr_pages_out)
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
     luci_dbg("%s bio : bi_max_vecs :%u bi_vcnt :%d bi_size :%u bi_sector :%lu",
        msg, bio->bi_max_vecs, bio->bi_vcnt, bio->bi_iter.bi_size,
        bio->bi_iter.bi_sector);
#else
     luci_dbg("%s bio : bi_max_vecs :%u bi_vcnt :%d bi_size :%u bi_sector :%lu",
        msg, bio->bi_max_vecs, bio->bi_vcnt, bio->bi_size,
        bio->bi_sector);
#endif
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
static void luci_end_compressed_bio_read(struct bio *bio)
{
    return;
}

/*
 * do the cleanup once all the compressed pages hit the disk.
 * This will clear writeback on the file pages and free the compressed
 * pages.
 *
 * This also calls the writeback end hooks for the file pages so that
 * metadata and checksums can be updated in the file.
 */
static void luci_end_compressed_bio_write(struct bio *bio)
{
    return;
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
luci_submit_compressed_write(struct inode * inode, struct page **pages,
     unsigned long total_out, unsigned long disk_start)
{
    int ret;
    struct bio *bio;
    struct bio_vec *bvec;
    struct block_device *bdev = inode->i_sb->s_bdev;
    // align size to device sector, otherwise device rejects write
    unsigned long i, aligned_bytes = sector_align(total_out);
    const unsigned long nr_pages = (aligned_bytes + PAGE_SIZE - 1)/PAGE_SIZE;

    bio = luci_bio_alloc(bdev, disk_start, pages, nr_pages);
    if (!bio) {
       luci_err_inode(inode, "bio alloc failed");
       return -ENOMEM;
    }

    // construct bio vecs for each PAGE of compressed output
    // Note these pages are anon and do not belong to page cache
    i = 0;
    while (i < nr_pages) {
       unsigned int length;
       length = min((unsigned long)PAGE_SIZE, aligned_bytes);
       ret = bio_add_page(bio, pages[i], length, 0);
       if (ret < length) {
           ret = -EIO;
           luci_err_inode(inode, "bio add page failed");
           goto failed_write;
       }
       aligned_bytes -= (unsigned long)length;
       i++;
    }

    if (aligned_bytes) {
        luci_err("failed to consume output, left %lu", aligned_bytes);
        BUG();
    }

    luci_bio_dump(bio, "submitting bio");
    #ifdef NEW_BIO_SUBMIT
    bio->bi_opf = REQ_OP_WRITE;
    ret = submit_bio_wait(bio);
    #else
    ret = submit_bio_wait(WRITE_SYNC, bio);
    #endif

    if (!test_bit(BIO_UPTODATE, &bio->bi_flags)) {
        luci_err("bio error status :0x%lx", bio->bi_flags);
    }

failed_write:
    // TBD: Check for status associated with each bvec page
    // We do not set any writeback flag, so end_page_writeback(page)
    // is not necessary
    i = 0;
    bio_for_each_segment_all(bvec, bio, i) {
        struct page * page = bvec->bv_page;
        page->mapping = NULL;
        luci_pageflags_dump(page);
        if (PageLocked(page)) {
           unlock_page(page);
        }
        put_page(page);
    }
    bio_put(bio);
    return ret;
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

int
luci_write_compressed(struct page * page, struct writeback_control *wbc)
{
    int ret;
    loff_t start_offset;
    struct page **pages_vec;
    struct inode * inode = page->mapping->host;
    struct list_head * ws;
    unsigned long nr_blocks, nr_pages_out,
        total_in, total_out, start_compr_block, disk_start;

    const unsigned blockbits = LUCI_BLOCK_SIZE_BITS(inode->i_sb);
    const unsigned blocksize = LUCI_BLOCK_SIZE(inode->i_sb);

    const unsigned long i_block =
        (sector_t)page->index << (PAGE_SHIFT - blockbits);
    const unsigned int extent = luci_extent_no(i_block);

    BUG_ON(!page_has_buffers(page));
    BUG_ON(!PageLocked(page));

    // compressed pages array
    pages_vec = kcalloc(EXTENT_NRPAGES(inode->i_sb), sizeof(struct page *),
        GFP_NOFS);
    if (pages_vec == NULL) {
        return -ENOMEM;
    }

    // get compression range
    luci_extent_offset(inode, i_block, &start_offset, &total_in);
    BUG_ON(inode->i_size < start_offset);
    total_out = total_in;
    nr_pages_out = (total_in + PAGE_SIZE - 1)/PAGE_SIZE;

    // get workspace, sleep in case we do find any
    ws = find_workspace(LUCI_COMPRESS_ZLIB);
    if (IS_ERR(ws)) {
        luci_err_inode(inode, "failed to alloc workspace");
        ret = PTR_ERR(ws);
        goto exit;
    }
    ret = luci_zlib_compress.compress_pages(ws,
                                   page->mapping,
                                   start_offset,
                                   pages_vec,
                                   &nr_pages_out,
                                   &total_in,
                                   &total_out);

    free_workspace(LUCI_COMPRESS_ZLIB, ws);

    // cannot compress : a) E2BIG  b) page not in page cache
    // TBD : We do not handle this case well, for now return OK.
    if (ret < 0) {
        ret = 0;
        luci_err("failed compression for extent %u, i_block :%lu "
                "start_offset %llu", extent, i_block, start_offset);
        goto exit;
    }

    LUCI_COMPRESS_RESULT(extent, i_block, total_in, total_out);

    nr_blocks = (total_out + blocksize - 1) >> blockbits;
    // allocate blocks needed for the compressed extent
    ret = luci_new_block(inode, nr_blocks, &start_compr_block);
    if (ret) {
        luci_err("failed block allocation for extent %u", extent);
        goto exit;
    }
    luci_update_extent(inode, i_block, start_compr_block);
    disk_start = start_compr_block * blocksize;
    // issue compressed write
    ret = luci_submit_compressed_write(inode,
                                       pages_vec,
                                       total_out,
                                       disk_start);
    if (ret) {
        luci_err("failed write for extent %u, status %d", extent, ret);
        goto failed_write;
    }
    SetPageUptodate(page);
    luci_dbg_inode(inode, "submitted extent %u(%lu)", extent, i_block);
    goto exit;

failed_write:
    // TBD: free blocks
exit:
    if (pages_vec) {
        kfree(pages_vec);
    }
    luci_release_page(page);
    return ret;
}

/*
 * for a compressed read, the bio we get passed has all the inode pages
 * in it.  We don't actually do IO on those pages but allocate new ones
 * to hold the compressed pages on disk.
 *
 * bio->bi_iter.bi_sector points to the compressed extent on disk
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
 * buf_start is the byte offset we're of the start of our workspace buffer.
 *
 * total_out is the last byte of the buffer
 */
int luci_util_decompress_buf2page(char *buf, unsigned long buf_start,
			      unsigned long total_out, u64 disk_start,
			      struct bio_vec *bvec, int vcnt,
			      unsigned long *pg_index,
			      unsigned long *pg_offset)
{
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

