/*
 * Copyright (C) Saptarshi Sen
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
 *
 * Fixes:
 *  +) handle case, where page not in page cache during deflate
 */

#include <linux/bio.h>
#include <linux/slab.h>
#include <linux/zlib.h>
#include <linux/zutil.h>
#include <linux/kernel.h>
#include <linux/vmalloc.h>
#include <linux/pagemap.h>
#include <linux/mempool.h>

#include "kern_feature.h"
#include "compress.h"

struct workspace {
    char *buf;
    z_stream strm;
    mempool_t *pool;
    struct list_head list;
};

void zlib_free_workspace(struct list_head *ws)
{
    struct workspace *workspace;

    workspace = list_entry(ws, struct workspace, list);

    if (workspace->buf)
        kfree(workspace->buf);

    if (workspace->pool)
        mempool_destroy(workspace->pool);

    if (workspace->strm.workspace)
        vfree(workspace->strm.workspace);

    kfree(workspace);
}

struct list_head *zlib_alloc_workspace(void)
{
    int err = -ENOMEM, workspacesize;
    struct workspace *workspace;

    workspace = kzalloc(sizeof(*workspace), GFP_NOFS);
    if (!workspace)
        goto fail;

    workspacesize = max(zlib_deflate_workspacesize(MAX_WBITS, MAX_MEM_LEVEL),
                        zlib_inflate_workspacesize());

    INIT_LIST_HEAD(&workspace->list);
    workspace->strm.workspace = vmalloc(workspacesize);
    workspace->pool = mempool_create_page_pool(ZLIB_MEMPOOL_PAGES, 0);
    workspace->buf = kmalloc(PAGE_SIZE, GFP_NOFS);
    if (!workspace->strm.workspace || !workspace->buf || !workspace->pool)
        goto fail;

    pr_debug("workspace size :%d workspace :%p\n", workspacesize, workspace);
    return &workspace->list;

fail:

    if (workspace)
        zlib_free_workspace(&workspace->list);

    pr_err("failed to initialize zlib workspace\n");
    return ERR_PTR(err);
}

int zlib_compress_pages(struct list_head *ws,
                        struct address_space *mapping,
                        u64 start,
                        struct page **pages,
                        unsigned long *out_pages,
                        unsigned long *total_in,
                        unsigned long *total_out)
{
    int ret, flush = Z_NO_FLUSH;
    char *data_in, *cpage_out;
    int nr_pages = 0, max_pages = *out_pages;
    struct page *in_page = NULL, *out_page = NULL;
    struct workspace *workspace = list_entry(ws, struct workspace, list);

    BUG_ON(!max_pages);

    *out_pages = *total_out = 0;
    workspace->strm.total_in = workspace->strm.total_out = 0;
    workspace->strm.avail_in = workspace->strm.avail_out = 0;

    if (Z_OK != zlib_deflateInit(&workspace->strm, ZLIB_COMPRESSION_LEVEL)) {
        ret = -EIO;
        luci_err("zlib : deflateInit failed\n");
        goto out;
    }

    do {
        if (workspace->strm.total_in >= *total_in) {
            flush = Z_FINISH;
            goto finish_def;
        }

        if (in_page) {
            kunmap(in_page);
            put_page(in_page);
        }

        in_page = find_get_page(mapping, start >> PAGE_SHIFT);
        if (!in_page) {
            ret = -EAGAIN;
            luci_err("cannot find page in page cache :%llu",
                     start >> PAGE_SHIFT);
            goto out;
        }

        data_in = kmap(in_page);
        workspace->strm.next_in = data_in;
        workspace->strm.avail_in = min(*total_in - workspace->strm.total_in,
                                        PAGE_SIZE);

finish_def:

        if (workspace->strm.avail_out)
            goto buff_notfull;

        /* run deflate() on input until output buffer not full */
        do {
               if (nr_pages >= max_pages) {
                   ret = -E2BIG;
                   luci_info_inode(mapping->host, "failed to compress cluster "
                                  "(start = 0x%llx, %d)\n", start, nr_pages);
                   goto out;
               }

               if (out_page)
                   kunmap(out_page);

               out_page = mempool_alloc(workspace->pool, GFP_NOFS | __GFP_HIGHMEM);
               if (!out_page) {
                   ret = -ENOMEM;
                   goto out;
                }

                out_page->private = (unsigned long)NULL;
                cpage_out = kmap(out_page);
                pages[nr_pages++] = out_page;
                workspace->strm.next_out = cpage_out;
                workspace->strm.avail_out = PAGE_SIZE;
buff_notfull:
                ret = zlib_deflate(&workspace->strm, flush);
                BUG_ON(ret == Z_STREAM_ERROR);  /* state not clobbered */

                #ifdef DEBUG_COMPRESSION
                luci_info("zlib: DEFLATE (%u/%d) strm.total in :%lu avail in :%lu "
                        "total out :%lu avail out :%lu start :0x%llx, ret :%u\n",
                        nr_pages, flush,
                        workspace->strm.total_in, workspace->strm.avail_in,
                        workspace->strm.total_out, workspace->strm.avail_out,
                        start, ret);
                luci_dump_bytes("compressed bytes(w)", out_page, PAGE_SIZE);
                #endif

        } while ((ret != Z_STREAM_END) && workspace->strm.avail_out == 0);

        /* all input will be used */
        BUG_ON(workspace->strm.avail_in);
        start += PAGE_SIZE;
    } while (flush != Z_FINISH);

    /* stream must complete */
    BUG_ON(ret != Z_STREAM_END);

    *total_in = workspace->strm.total_in;
    *total_out = workspace->strm.total_out;

    ret = Z_OK;
out:
    *out_pages = nr_pages;

    /* clean up and return */
    (void)zlib_deflateEnd(&workspace->strm);

    if (out_page)
        kunmap(out_page);

    if (in_page) {
        kunmap(in_page);
        put_page(in_page);
    }

    return ret;
}

/*
 * Copy uncompressed data from working buffer to pages.
 *
 */
static int zlib_copybuf2pages(char *buf,
                              unsigned long prev_out,
		              unsigned long total_out,
		              struct bio *bio)
{
    void *va_addr;
    struct page *curr_page;
    unsigned long tocopy, buf_offset, avail_bytes;

    // we have not yet data corresponding to this page
    BUG_ON(prev_out >= total_out);
    /* copy bytes from the working buffer to the pages */
    tocopy = total_out - prev_out;
    // we have data left to consume in workspace buf from previous cycle
    buf_offset = prev_out & (PAGE_SIZE - 1);

repeat:
    #ifdef DEBUG_COMPRESSION
    luci_info("copy params: tocopy :%lu, prev_out :%lu, total_out :%lu "
              "buf_offset :%lu", tocopy, prev_out, total_out, buf_offset);
    #endif

    avail_bytes = min((unsigned long)(bio_cur_bytes(bio)),
        (unsigned long)tocopy);

    // must not exceed workspace buf boundary
    BUG_ON(avail_bytes > (PAGE_SIZE - buf_offset));

    curr_page = bio_page(bio);
    va_addr = kmap(curr_page);
    memcpy(va_addr + buf_offset, buf + buf_offset, avail_bytes);
    #ifdef DEBUG_COMPRESSION
    luci_dump_bytes("uncompressed data(copy):", curr_page, PAGE_SIZE);
    #endif
    kunmap(va_addr);

    flush_dcache_page(curr_page);
    tocopy -= avail_bytes;
    buf_offset += avail_bytes;
    BUG_ON(buf_offset > PAGE_SIZE);

    bio_advance(bio, avail_bytes);
    // check if need another page
    #ifdef HAVE_BIO_ITER
    if (!bio->bi_iter.bi_size) {
    #else
    if (!bio->bi_size) {
    #endif
        return tocopy ? -ENOSPC : 0;
    }

    if (!tocopy)
        return 0;

    // bio must have enough pages to accomodate all of o/p
    BUG_ON(curr_page == bio_page(bio));

    goto repeat;
}

/* cannot tolerate compression failure.
 * We decompress in whole page sizes, so zero filling is not required
 */
int zlib_decompress_pages(struct list_head *ws,
                          unsigned long total_in,
                          struct bio *compr_bio,
                          struct bio *org_bio)
{
    int ret = 0, wbits = MAX_WBITS;
    char *data_in;
    size_t src_len = total_in;
    unsigned long i, consumed_out = 0;
    struct page *pages_in[EXTENT_NRPAGE];
    unsigned long total_pages_in = compr_bio->bi_vcnt;
    struct workspace *workspace = list_entry(ws, struct workspace, list);

    memset((char*)pages_in, 0, EXTENT_NRPAGE * sizeof(struct page*));

    BUG_ON(compr_bio->bi_vcnt == 0);
    for (i = 0; i < compr_bio->bi_vcnt; i++) {
        struct bio_vec* bvec = &compr_bio->bi_io_vec[i];
        pages_in[i] = bvec->bv_page;
    }

    data_in = kmap(pages_in[0]);
    workspace->strm.next_in = data_in;
    workspace->strm.total_in = 0;
    workspace->strm.avail_in = min((unsigned int)src_len, (unsigned int)PAGE_SIZE);
    workspace->strm.avail_out = PAGE_SIZE;
    workspace->strm.total_out = 0;
    workspace->strm.next_out = workspace->buf;

    #ifdef DEBUG_COMPRESSION
    luci_info("%s :total_in :%lu avail_in :%u", __func__, total_in,
        (unsigned int) workspace->strm.avail_in);
    luci_dump_bytes("compressed bytes(r)", pages_in[0], PAGE_SIZE);
    #endif

    /* If it's got no preset dictionary, tell zlib to skip the adler32 check.*/
    if (src_len > 2 && !(data_in[1] & PRESET_DICT) &&
            ((data_in[0] & 0x0f) == Z_DEFLATED) &&
            !(((data_in[0]<<8) + data_in[1]) % 31)) {

        wbits = -((data_in[0] >> 4) + 8);
        workspace->strm.next_in += 2;
        workspace->strm.avail_in -= 2;
    }

    if ((ret = zlib_inflateInit2(&workspace->strm, wbits)) != Z_OK) {
        kunmap(pages_in[i]);
        luci_err("zlib: inflateInit failed, ret :%d\n", ret);
        return -EIO;
    }

    i = 0;
    while (workspace->strm.total_in <= src_len) {

        ret = zlib_inflate(&workspace->strm, Z_NO_FLUSH);
        if (ret != Z_OK && ret != Z_STREAM_END) {
            luci_err("zlib: inflate failed, ret %d\n", ret);
            break;
        }

        #ifdef DEBUG_COMPRESSION
        luci_info("zlib: INFLATE strm.total in :%lu, avail in :%lu "
                "consumed out :%lu total decompressed :%lu avail out :%lu\n",
                workspace->strm.total_in, workspace->strm.avail_in, consumed_out,
                workspace->strm.total_out, workspace->strm.avail_out);
        #endif

        if (consumed_out == workspace->strm.total_out) {
            luci_dbg("zlib: decompression complete\n");
            break;
        }

        // copy decompressed buffer to tree pages
        ret = zlib_copybuf2pages(workspace->buf,
                                 consumed_out,
                                 workspace->strm.total_out,
                                 org_bio);

        BUG_ON(ret != 0);
        consumed_out = workspace->strm.total_out;

        // stream needs input
        if (!workspace->strm.avail_in) {
            kunmap(pages_in[i]);
            i++;
            if (i < total_pages_in) {
                data_in = kmap(pages_in[i]);
                #ifdef DEBUG_COMPRESSION
                luci_dump_bytes("compressed bytes(r)", pages_in[i], PAGE_SIZE);
                #endif
                workspace->strm.next_in = data_in;
                workspace->strm.avail_in = min((unsigned int)(src_len -
                        workspace->strm.total_in), (unsigned int)PAGE_SIZE);
            } else {
                // decompression complete
                data_in = NULL;
                goto done;
            }
        }

        // need to recycle workspace buffer for stream
        if (!workspace->strm.avail_out) {
            workspace->strm.avail_out = PAGE_SIZE;
            workspace->strm.next_out = workspace->buf;
        }
    }

    BUG_ON (ret != Z_STREAM_END);
done:
    ret = zlib_inflateEnd(&workspace->strm);

    if (data_in)
        kunmap(pages_in[i]);

    return ret;
}

void
zlib_remit_workspace(struct list_head *ws, struct page *out_page)
{
    struct workspace *workspace = list_entry(ws, struct workspace, list);
    if (out_page != NULL) {
        mempool_free(out_page, workspace->pool);
    }
}

const struct luci_compress_op luci_zlib_compress = {
    .alloc_workspace    = zlib_alloc_workspace,
    .free_workspace     = zlib_free_workspace,
    .remit_workspace    = zlib_remit_workspace,
    .compress_pages     = zlib_compress_pages,
    .decompress_pages   = zlib_decompress_pages,
};
