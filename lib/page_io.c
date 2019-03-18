#include <linux/gfp.h>
#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/radix-tree.h>
#include <linux/buffer_head.h>

#include "page_io.h"

#define META_BLOCK_START (1UL << 30)

static atomic_t data_block, meta_block;

static struct radix_tree_root pgtree; // track btree index pages

#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,11,0))
static inline int page_ref_count(struct page *page)
{
        return atomic_read(&page->_count);
}
#endif

static int bump_alloc_backing_pages(unsigned long block, size_t size)
{
        int i, nblocks = size >> PAGE_SHIFT;

        for (i = 0; i < nblocks; i++) {
                struct page *page;

                page = alloc_page(GFP_KERNEL | __GFP_ZERO);
                if (!page)
                        return -ENOMEM;
                if (radix_tree_insert(&pgtree, block + i, page))
                        return -EIO;
                pr_debug("allocating backing page for block:%lu\n", block + i);
                #ifdef DBG_BTREE_PAGE_REFCOUNT
                pr_debug("%s : page 0x%p:%u\n", __func__, page, page_ref_count(page));
                #endif
        }
        return 0;
}

static int bump_release_backing_pages(unsigned long block, size_t size)
{
        int i, nblocks = size >> PAGE_SHIFT;

        for (i = 0; i < nblocks; i++) {
                struct page *page;

                pr_debug("releasing backing page for block:%lu\n", block + i);
                page = radix_tree_lookup(&pgtree, block + i); 
                if (!page) {
                        pr_err("radix tree lookup failed for block :%lu\n", block + i);
                        dump_stack();
                        continue;
                }
                radix_tree_delete(&pgtree, block + i);
                ClearPagePrivate(page);
                #ifdef DBG_BTREE_PAGE_REFCOUNT
                pr_debug("%s: radix tree entry deleted :%lu\n", __func__, block + i);
                pr_debug("%s : page 0x%p:%u\n", __func__, page, page_ref_count(page));
                #endif
                put_page(page);
        }
        return 0;
}

static void bump_scan_backing_pages(struct radix_tree_root *radix_root)
{
        unsigned long i = 0;
        struct radix_tree_iter iter;
        void __rcu **slot;

        if (radix_root->height)
                pr_warn("radix_tree height!! :%d", radix_root->height);

        radix_tree_for_each_slot(slot, radix_root, &iter, 0) {
                struct page *page = (struct page *)radix_tree_deref_slot(slot);
                BUG_ON(radix_tree_exception(page));
                pr_warn("%s :[%lu] leaked block :%lu page :%p(ref :%u)\n",
                                __func__,
                                i++,
                                iter.index,
                                page,
                                page_ref_count(page));
        }
}

struct buffer_head* bump_get_buffer_head(unsigned long block)
{
        struct buffer_head *bh;
        struct page *page;
       
        page = radix_tree_lookup(&pgtree, block); 
        if (!page) {
                pr_err("radix tree lookup failed for block :%lu\n", block);
                dump_stack();
                return NULL;
        }

        if (!page_has_buffers(page)) {
                bh = alloc_page_buffers(page, PAGE_SIZE, 1);
                BUG_ON(atomic_read(&bh->b_count));
                set_page_private(page, (unsigned long)bh);
                SetPagePrivate(page);
        } else {
                bh = page_buffers(page);
                pr_debug("found buffer head :%lu\n", block);
        }

        get_bh(bh);
        return bh;
}

void bump_put_buffer_head(struct buffer_head *bh)
{
        unsigned int count;

        BUG_ON(bh == NULL);
        count = atomic_read(&bh->b_count);

        #ifdef DBG_BTREE_PAGE_REFCOUNT
        pr_debug("%s :bh 0x%p:%u\n", __func__, bh, count);
        #endif

        if (!count) {
                pr_err("invalid bh release");
                dump_stack();
        } else {
                if (count == 1) {
                        brelse(bh);
                        set_page_private(bh->b_page, 0UL);
                        ClearPagePrivate(bh->b_page);
                        free_buffer_head(bh);
                } else
                        brelse(bh);
        }
}

unsigned long bump_alloc_data_block(void)
{
        unsigned long block;

        atomic_inc(&data_block);
        block = atomic_read(&data_block);
        (void) bump_alloc_backing_pages(block, PAGE_SIZE);
        return block;
}

unsigned long bump_alloc_meta_block(void)
{
        unsigned long mblock;

        atomic_inc(&meta_block);
        mblock = atomic_read(&meta_block);
        (void) bump_alloc_backing_pages(mblock, PAGE_SIZE);
        return mblock;
}

void bump_release_block(unsigned long block, size_t size)
{
        bump_release_backing_pages(block, size);
}

void bump_allocator_init(void)
{
        atomic_set(&data_block, 0);
        atomic_set(&meta_block, META_BLOCK_START);
        INIT_RADIX_TREE(&pgtree, GFP_KERNEL);
}

void bump_leak_detector(void)
{
        //bump_scan_backing_pages(&pgtree);
}

void bump_allocator_release(void)
{
        bump_scan_backing_pages(&pgtree);
        atomic_set(&data_block, 0);
        atomic_set(&meta_block, META_BLOCK_START);
}
