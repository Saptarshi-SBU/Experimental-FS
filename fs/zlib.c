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
 * Based on jffs2 zlib code:
 * Copyright © 2001-2007 Red Hat, Inc.
 * Created by David Woodhouse <dwmw2@infradead.org>
 *
 * Based on btrfs zlib code:
 * Copyright © 2008 Red Hat, Inc.
 *
 * Fixes:
 *  +) handle case, where page not in page cache during deflate
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/zlib.h>
#include <linux/zutil.h>
#include <linux/vmalloc.h>
#include <linux/init.h>
#include <linux/err.h>
#include <linux/sched.h>
#include <linux/pagemap.h>
#include <linux/bio.h>

#include "compression.h"
#include "cluster.h"
#include "kern_feature.h"

struct workspace {
    z_stream strm;
    char *buf;
    struct list_head list;
};

void zlib_free_workspace(struct list_head *ws)
{
    struct workspace *workspace = list_entry(ws, struct workspace, list);

    vfree(workspace->strm.workspace);
    kfree(workspace->buf);
    kfree(workspace);
}

struct list_head *zlib_alloc_workspace(void)
{
    struct workspace *workspace;
    int workspacesize;

    workspace = kzalloc(sizeof(*workspace), GFP_NOFS);
    if (!workspace)
        return ERR_PTR(-ENOMEM);

    workspacesize = max(zlib_deflate_workspacesize(MAX_WBITS, MAX_MEM_LEVEL),
            zlib_inflate_workspacesize());
    workspace->strm.workspace = vmalloc(workspacesize);
    workspace->buf = kmalloc(PAGE_SIZE, GFP_NOFS);
    if (!workspace->strm.workspace || !workspace->buf)
        goto fail;

    INIT_LIST_HEAD(&workspace->list);

    printk(KERN_DEBUG "workspace size :%d workspace :%p strm :%p strm.ws :%p "
            "buf :%p", workspacesize, workspace, &workspace->strm,
            workspace->strm.workspace, workspace->buf);
    return &workspace->list;
fail:
    zlib_free_workspace(&workspace->list);
    return ERR_PTR(-ENOMEM);
}

int zlib_compress_pages(struct list_head *ws,
        struct address_space *mapping,
        u64 start,
        struct page **pages,
        unsigned long *out_pages,
        unsigned long *total_in,
        unsigned long *total_out)
{
    struct workspace *workspace = list_entry(ws, struct workspace, list);
    int ret;
    char *data_in;
    char *cpage_out;
    int nr_pages = 0;
    struct page *in_page = NULL;
    struct page *out_page = NULL;
    unsigned long bytes_left;
    unsigned long len = *total_out;
    unsigned long nr_dest_pages = *out_pages;
    const unsigned long max_out = nr_dest_pages * PAGE_SIZE;

    *out_pages = 0;
    *total_out = 0;
    *total_in = 0;

    if (Z_OK != zlib_deflateInit(&workspace->strm, 3)) {
        printk(KERN_ERR "LUCI: deflateInit failed\n");
        ret = -EIO;
        goto out;
    }

    workspace->strm.total_in = 0;
    workspace->strm.total_out = 0;

    in_page = find_get_page(mapping, start >> PAGE_SHIFT);
    // Fixed
    if (in_page == NULL) {
        printk(KERN_ERR "start page not found in page cache, :%llu",
                start >> PAGE_SHIFT);
        ret = -EAGAIN;
        goto out;
    }
    data_in = kmap(in_page);

    out_page = alloc_page(GFP_NOFS | __GFP_HIGHMEM);
    if (out_page == NULL) {
        ret = -ENOMEM;
        goto out;
    }
    cpage_out = kmap(out_page);
    pages[0] = out_page;
    nr_pages = 1;

    workspace->strm.next_in = data_in;
    workspace->strm.next_out = cpage_out;
    workspace->strm.avail_out = PAGE_SIZE;
    workspace->strm.avail_in = min(len, PAGE_SIZE);

    while (workspace->strm.total_in < len) {
        ret = zlib_deflate(&workspace->strm, Z_SYNC_FLUSH);
        if (ret != Z_OK) {
            printk(KERN_ERR "LUCI: deflate in loop returned %d\n",
                    ret);
            zlib_deflateEnd(&workspace->strm);
            ret = -EIO;
            goto out;
        }

        /* we're making it bigger, give up */
        if (workspace->strm.total_in > 8192 &&
                workspace->strm.total_in <
                workspace->strm.total_out) {
            ret = -E2BIG;
            printk(KERN_ERR "abandon deflate may give poor compression ratio");
            goto out;
        }
        /* we need another page for writing out.  Test this
         * before the total_in so we will pull in a new page for
         * the stream end if required
         */
        if (workspace->strm.avail_out == 0) {
            kunmap(out_page);
            if (nr_pages == nr_dest_pages) {
                printk(KERN_INFO "compression failed, cannot "
                        "accomodate in alloted pages %d(%ld)", nr_pages,
                        nr_dest_pages);
                out_page = NULL;
                ret = -E2BIG;
                goto out;
            }
            out_page = alloc_page(GFP_NOFS | __GFP_HIGHMEM);
            if (out_page == NULL) {
                ret = -ENOMEM;
                goto out;
            }
            cpage_out = kmap(out_page);
            pages[nr_pages] = out_page;
            nr_pages++;
            workspace->strm.avail_out = PAGE_SIZE;
            workspace->strm.next_out = cpage_out;
        }
        /* we're all done */
        if (workspace->strm.total_in >= len)
            break;

        /* we've read in a full page, get a new one */
        if (workspace->strm.avail_in == 0) {
            if (workspace->strm.total_out > max_out) {
                printk(KERN_ERR "deflate exceeded limits");
                ret = -E2BIG;
                goto out;
            }

            bytes_left = len - workspace->strm.total_in;
            BUG_ON(bytes_left == 0);
            kunmap(in_page);
            put_page(in_page);

            start += PAGE_SIZE;
            in_page = find_get_page(mapping, start >> PAGE_SHIFT);
            // Fixed
            if (in_page == NULL) {
                printk(KERN_ERR "next page not found in page cache, :%llu",
                        start >> PAGE_SHIFT);
                ret = -EAGAIN;
                goto out;
            }

            data_in = kmap(in_page);
            workspace->strm.avail_in = min(bytes_left, PAGE_SIZE);
            workspace->strm.next_in = data_in;
        }
    }
    workspace->strm.avail_in = 0;
    ret = zlib_deflate(&workspace->strm, Z_FINISH);
    // We may have pending output
    if (ret != Z_STREAM_END) {
        printk(KERN_ERR "deflate failed to finish, status :%d "
                "total_in :%lu total_out:%lu avail_out:%u", ret,
                workspace->strm.total_in, workspace->strm.total_out,
                (unsigned int)workspace->strm.avail_out);
        ret = -E2BIG;
        goto out;
    }

    ret = zlib_deflateEnd(&workspace->strm);
    if (ret != Z_OK) {
        printk(KERN_ERR "deflate cleanup error, status %d(%lu-%lu)", ret,
                workspace->strm.total_in, workspace->strm.total_out);
        ret = -EIO;
        goto out;
    }

    if (workspace->strm.total_out >= workspace->strm.total_in) {
        printk(KERN_ERR "compression failed, out bytes exceeed in :%lu",
                workspace->strm.total_out);
        ret = -E2BIG;
        goto out;
    }

    ret = 0;
    *total_out = workspace->strm.total_out;
    *total_in = workspace->strm.total_in;
out:
    *out_pages = nr_pages;
    if (out_page) {
#       ifdef DEBUG_COMPRESSION
        luci_dump_bytes("compressed bytes(w)", out_page, PAGE_SIZE);
#       endif
        kunmap(out_page);
    }

    if (in_page) {
        kunmap(in_page);
        put_page(in_page);
    }
    return ret;
}

int
zlib_decompress_bio(struct list_head *ws, unsigned long total_in,
        struct bio *compressed_bio, struct bio *org_bio)
{
    struct workspace *workspace = list_entry(ws, struct workspace, list);
    unsigned long i;
    int ret = 0, ret2;
    int wbits = MAX_WBITS;
    char *data_in;
    size_t total_out = 0;
    size_t src_len = total_in;
    unsigned long total_pages_in = compressed_bio->bi_vcnt;
    unsigned long buf_start;
    unsigned long start_page_offset = page_offset(bio_page(org_bio));
    struct page *pages_in[CLUSTER_NRPAGE];

    memset((char*)pages_in, 0, CLUSTER_NRPAGE * sizeof(struct page*));

    BUG_ON(compressed_bio->bi_vcnt == 0);
    for (i = 0; i < compressed_bio->bi_vcnt; i++) {
        struct bio_vec* bvec = &compressed_bio->bi_io_vec[i];
        pages_in[i] = bvec->bv_page;
    }

#   ifdef DEBUG_COMPRESSION
    luci_dump_bytes("compressed bytes(r)", pages_in[0], PAGE_SIZE);
#   endif
    data_in = kmap(pages_in[0]);
    workspace->strm.next_in = data_in;
    workspace->strm.total_in = 0;
#ifdef HAVE_BIO_BVECITER
    workspace->strm.avail_in = min((unsigned int)src_len, (unsigned int)PAGE_SIZE);
#else
    workspace->strm.avail_in = min((unsigned int)src_len, (unsigned int)PAGE_SIZE);
#endif
    workspace->strm.next_out = workspace->buf;
    workspace->strm.avail_out = PAGE_SIZE;
    workspace->strm.total_out = 0;

#   ifdef DEBUG_COMPRESSION
    printk(KERN_INFO "total_in :%lu avail_in :%u", total_in,
        (unsigned int) workspace->strm.avail_in);
#   endif

    /* If it's deflate, and it's got no preset dictionary, then
       we can tell zlib to skip the adler32 check. */
    if (src_len > 2 && !(data_in[1] & PRESET_DICT) &&
            ((data_in[0] & 0x0f) == Z_DEFLATED) &&
            !(((data_in[0]<<8) + data_in[1]) % 31)) {

        wbits = -((data_in[0] >> 4) + 8);
        workspace->strm.next_in += 2;
        workspace->strm.avail_in -= 2;
    }

    i = 0;
    if ((ret = zlib_inflateInit2(&workspace->strm, wbits)) != Z_OK) {
        kunmap(pages_in[i]);
        printk(KERN_WARNING "LUCI: inflateInit failed, ret :%d\n", ret);
        return -EIO;
    }

    while (workspace->strm.total_in < src_len) {
        ret = zlib_inflate(&workspace->strm, Z_NO_FLUSH);
        if (ret != Z_OK && ret != Z_STREAM_END) {
            printk(KERN_ERR "LUCI: inflate failed, ret %d\n", ret);
            break;
        }

        buf_start = total_out;
        total_out = workspace->strm.total_out;
#       ifdef DEBUG_COMPRESSION
        printk(KERN_INFO "LUCI: deflate strm.total in :%lu, buf start :%lu "
            "total decompressed :%lu start_page_offset :%lu\n",
            workspace->strm.total_in, buf_start,
            total_out, start_page_offset);
#       endif

        // we did not make progress in inflate call
        if (buf_start == total_out) {
            break;
        }

        ret2 = luci_util_decompress_buf2page(workspace->buf, buf_start,
                                       total_out, start_page_offset, org_bio);
        if (ret2 == 0) {
            ret = 0;
            goto done;
        }

        workspace->strm.next_out = workspace->buf;
        workspace->strm.avail_out = PAGE_SIZE;

        if (workspace->strm.avail_in == 0) {
            kunmap(pages_in[i]);
            i++;
            if (i > total_pages_in) {
                data_in = NULL;
                break;
            }
            data_in = kmap(pages_in[i]);
            workspace->strm.next_in = data_in;
            workspace->strm.avail_in = min(src_len - workspace->strm.total_in,
                                           PAGE_SIZE);
        }
    }

    if (ret != Z_STREAM_END) {
        printk(KERN_ERR "LUCI: inflate stream did not end, ret :%d\n", ret);
        ret = -EIO;
    } else {
        ret = 0;
        printk(KERN_DEBUG "LUCI: inflate completed\n");
    }

done:
    ret = zlib_inflateEnd(&workspace->strm);
    if (data_in) {
        kunmap(pages_in[i]);
    }
    return ret;
}

int zlib_decompress(struct list_head *ws, unsigned char *data_in,
        struct page *dest_page,
        unsigned long start_byte,
        size_t srclen, size_t destlen)
{
    struct workspace *workspace = list_entry(ws, struct workspace, list);
    int ret = 0;
    int wbits = MAX_WBITS;
    unsigned long bytes_left;
    unsigned long total_out = 0;
    unsigned long pg_offset = 0;
    char *kaddr;

    destlen = min_t(unsigned long, destlen, PAGE_SIZE);
    bytes_left = destlen;

    workspace->strm.next_in = data_in;
    workspace->strm.avail_in = srclen;
    workspace->strm.total_in = 0;

    workspace->strm.next_out = workspace->buf;
    workspace->strm.avail_out = PAGE_SIZE;
    workspace->strm.total_out = 0;
    /* If it's deflate, and it's got no preset dictionary, then
       we can tell zlib to skip the adler32 check. */
    if (srclen > 2 && !(data_in[1] & PRESET_DICT) &&
            ((data_in[0] & 0x0f) == Z_DEFLATED) &&
            !(((data_in[0]<<8) + data_in[1]) % 31)) {

        wbits = -((data_in[0] >> 4) + 8);
        workspace->strm.next_in += 2;
        workspace->strm.avail_in -= 2;
    }

    if (Z_OK != zlib_inflateInit2(&workspace->strm, wbits)) {
        printk(KERN_WARNING "LUCI: inflateInit failed\n");
        return -EIO;
    }

    while (bytes_left > 0) {
        unsigned long buf_start;
        unsigned long buf_offset;
        unsigned long bytes;

        ret = zlib_inflate(&workspace->strm, Z_NO_FLUSH);
        if (ret != Z_OK && ret != Z_STREAM_END)
            break;

        buf_start = total_out;
        total_out = workspace->strm.total_out;

        if (total_out == buf_start) {
            ret = -EIO;
            break;
        }

        if (total_out <= start_byte)
            goto next;

        if (total_out > start_byte && buf_start < start_byte)
            buf_offset = start_byte - buf_start;
        else
            buf_offset = 0;

        bytes = min(PAGE_SIZE - pg_offset,
                PAGE_SIZE - buf_offset);
        bytes = min(bytes, bytes_left);

        kaddr = kmap_atomic(dest_page);
        memcpy(kaddr + pg_offset, workspace->buf + buf_offset, bytes);
        kunmap_atomic(kaddr);

        pg_offset += bytes;
        bytes_left -= bytes;
next:
        workspace->strm.next_out = workspace->buf;
        workspace->strm.avail_out = PAGE_SIZE;
    }

    if (ret != Z_STREAM_END && bytes_left != 0)
        ret = -EIO;
    else
        ret = 0;

    zlib_inflateEnd(&workspace->strm);

    /*
     * this should only happen if zlib returned fewer bytes than we
     * expected.  luci_get_block is responsible for zeroing from the
     * end of the inline extent (destlen) to the end of the page
     */
    if (pg_offset < destlen) {
        kaddr = kmap_atomic(dest_page);
        memset(kaddr + pg_offset, 0, destlen - pg_offset);
        kunmap_atomic(kaddr);
    }
    return ret;
}

const struct luci_compress_op luci_zlib_compress = {
    .alloc_workspace	= zlib_alloc_workspace,
    .free_workspace     = zlib_free_workspace,
    .compress_pages	= zlib_compress_pages,
    .decompress_bio	= zlib_decompress_bio,
    .decompress		= zlib_decompress,
};
