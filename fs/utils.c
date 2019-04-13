#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/smp.h>
#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/pagemap.h>

#include "luci.h"

sector_t blkdev_max_block(struct block_device *bdev)
{
        loff_t sz = i_size_read(bdev->bd_inode);
        return sz >> blksize_bits(block_size(bdev));
}

void luci_pageflags_dump(struct page* page, const char *msg)
{
    luci_info("%s : page=%lu Writeback :%d Dirty :%d Uptodate %d",
              msg,
              page->index,
              PageWriteback(page),
              PageDirty(page),
              PageUptodate(page));
}

void luci_dump_bytes(const char *msg,
                     struct page *page,
                     unsigned int len)
{
    void *kaddr;
    bool map_page;

    if (!dbgfsparam.tracedata)
        return;

    map_page = ((page_file_mapping(page)) || page_mapped(page)) ? false : true;

    if (map_page)
        kmap(page);

    kaddr = page_address(page);

    print_hex_dump(KERN_INFO, msg,
                              DUMP_PREFIX_OFFSET,
                              16,
                              1,
                              kaddr,
                              len,
                              true);

    if (map_page)
        kunmap(page); // note :kunmap_atomic takes kaddr
}

void luci_bio_dump(struct bio * bio, const char *msg)
{
#ifdef HAVE_BIO_ITER
     luci_dbg("%s bio : bi_max_vecs :%u bi_vcnt :%d bi_size :%u bi_sector :%lu"
        " bytes: %u index :%lu\n", msg,
                                   bio->bi_max_vecs,
                                   bio->bi_vcnt,
                                   bio->bi_iter.bi_size,
                                   bio->bi_iter.bi_sector,
                                   bio_cur_bytes(bio),
                                   page_index(bio_page(bio)));
#else
     luci_dbg("%s bio : bi_max_vecs :%u bi_vcnt :%d bi_size :%u bi_sector :%lu"
        " bytes :%u index :%lu\n", msg,
                                   bio->bi_max_vecs,
                                   bio->bi_vcnt,
                                   bio->bi_size,
                                   bio->bi_sector,
                                   bio_cur_bytes(bio),
                                   page_index(bio_page(bio)));
#endif
     //luci_dump_bytes("bio page", bio_page(bio), PAGE_SIZE);
}

void copy_pages(struct page *dst_page,
                struct page *src_page,
                unsigned long dst_off,
                unsigned long src_off,
                unsigned long len)
{
    int must_memmove = 0;
    char *src_kaddr;
    char *dst_kaddr = page_address(dst_page);

    if (dst_page != src_page)
        src_kaddr = page_address(src_page);
    else {
        src_kaddr = dst_kaddr;
        if (areas_overlap(src_off, dst_off, len))
            must_memmove = 1;
    }

    if (must_memmove)
        memmove(dst_kaddr + dst_off, src_kaddr + src_off, len);
    else
        memcpy(dst_kaddr + dst_off, src_kaddr + src_off, len);
}

bool areas_overlap(unsigned long src,
                   unsigned long dst,
                   unsigned long len)
{
    unsigned long distance = (src > dst) ? src - dst : dst - src;
    return distance < len;
}

bool
bitmap_find_first_fit(u8 *startb, u8 *endb, int firstzero, int nblocks)
{
        u8 i = firstzero, *p;

        for (p = startb; p <= endb; p++) {
                u8 n = *p;

                while (nblocks && i < 8) {
                        if (n & (1 << i))
                                return false;
                        i++;
                        nblocks--;
                }

                if (!nblocks)
                        break;
                i = 0;
        }

        return nblocks ? false : true;
}

void
bitmap_mark_first_fit(u8 *startb, u8 *endb, int firstzero, int nblocks)
{
        u8 i = firstzero, *p;

        for (p = startb; p <= endb; p++) {
                while (nblocks && i < 8) {
                        BUG_ON(*p & (1 << i));
                        *p |= (1 << i);
                        i++;
                        nblocks--;
                }

                if (!nblocks)
                        break;
                i = 0;
        }
}

static void
bitmap_add_buddy_map(int *buddy_map, int max_order, int nbits) {
        int k, count; 
        for (k = max_order; k >= 0; k--) {
                BUG_ON (nbits < 0);
                count = nbits >> k;
                if (count) {
                        buddy_map[k] += count;
                        nbits = nbits - count * (1U << k) ;
                }
        }
}

void
luci_create_buddy_map(char bitmap[], size_t size_bytes, int *buddy_map, int max_order) {
        volatile size_t i;
        int j, p, nbits, *buddy_temp;
        bool begin = false;

        buddy_temp = kzalloc(sizeof(int) * (max_order + 1), GFP_KERNEL);
        if (!buddy_temp) {
                luci_err("cannot allocate memory");
                return;
        }

        p = 0;
        for (i = 0; i < size_bytes; i++) {
                unsigned char d = bitmap[i];
                for (j = 0; j < 8; j++) {
                        if (!begin) {
                                if (d & (1U << j))
                                        continue;
                                p = i * 8 + j;
                                begin = true;
                        } else {
                                if (!(d & (1U << j)))
                                        continue;
                                nbits = i * 8 + j  - p;
                                bitmap_add_buddy_map(buddy_temp, max_order, nbits);
                                begin = false;
                        }
                }
        }

        // exit case
        if (begin) {
                nbits = size_bytes * 8 - p;
                bitmap_add_buddy_map(buddy_temp, max_order, nbits);
        }

        for (i = 0; i <= max_order; i++)
                buddy_map[i] = buddy_temp[i];

        kfree(buddy_temp);
}
