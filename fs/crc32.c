#include <linux/mm.h>
#include <linux/bio.h>
#include <linux/crc32.h>
#include <linux/pagemap.h>

#include "luci.h"

//#define LUCI_DUMP_CHECKSUM_DATA

/* compute checksum */
u32 luci_compute_data_cksum(void *addr, size_t length, u32 crc_seed)
{
    #ifdef LUCIFS_CHECKSUM
    u32 crc;

    BUG_ON(!length);
    crc = crc32_le(crc_seed, addr, length);
    luci_info("crc for addr, length :%lu crc:0x%x", length, crc);
    return crc;
    #else
    return 0;
    #endif
}

u32 luci_compute_page_cksum(struct page *page, off_t off, size_t length,
                            u32 crc_seed)
{
    #ifdef LUCIFS_CHECKSUM
    u32 crc;
    void *kaddr;

    BUG_ON(!length);
    BUG_ON(off + length > PAGE_SIZE);

    kaddr = kmap(page);
    crc = crc32_le(crc_seed, kaddr + off, length);
    kunmap(kaddr);
    luci_dump_bytes("crc :", page, PAGE_SIZE);
    luci_info("crc for page, off :%lu length :%lu crc:0x%x", off, length, crc);
    return crc;
    #else
    return 0;
    #endif
}

int luci_compute_pages_cksum(struct page **pages, unsigned nr_pages,
                             size_t length)
{
    #ifdef LUCIFS_CHECKSUM
    int i;
    u32 crc = ~0U;
    ssize_t totalb = length, minb;

    for (i = 0; i < nr_pages; i++) {
        BUG_ON(totalb <= 0);
        minb = min((ssize_t)totalb, (ssize_t)PAGE_SIZE);
        crc = luci_compute_page_cksum(pages[i], 0, minb, crc);
        totalb -= minb;
    }

    BUG_ON(totalb);
    return crc;
    #else
    return 0;
    #endif
}

int luci_validate_data_page_cksum(struct page *page, blkptr *bp)
{
    #ifdef LUCIFS_CHECKSUM
    u32 crc32;
    int err = 0;

    BUG_ON(PageError(page));    

    if (PageDirty(page) || PageWriteback(page) || !PageUptodate(page)) {
        err = -EAGAIN;
        goto exit;
    }

    crc32 = luci_compute_page_cksum(page, 0, bp->length, ~0U);
    if (bp->checksum != crc32) {
        err = -EBADE;
        luci_err("blkptr crc mismatch: 0x%x/0x%x", bp->checksum, crc32);
    }

    return err;
exit:
    luci_pageflags_dump(page, "cannot verify checksum for page");
    return err;
    #else
    return 0;
    #endif
}

int luci_validate_data_pages_cksum(struct page **pages, unsigned nr_pages, blkptr *bp)
{
    #ifdef LUCIFS_CHECKSUM
    u32 crc = ~0U;
    int i = 0, err = 0;
    struct page *page = NULL;
    size_t length = bp->length, bytes;

    for (i = 0; i < nr_pages; i++) {
        page = pages[i];
        if (PageDirty(page) || PageWriteback(page) || !PageUptodate(page)) {
            err = -EAGAIN;
            goto exit;
        }

        BUG_ON(length == 0);
        bytes = min((size_t)length, (size_t)PAGE_SIZE);
        crc = luci_compute_page_cksum(page, 0, bytes, crc);
        length -= bytes;
    }

    BUG_ON(length);

    if (bp->checksum != crc) {
        err = -EBADE;
        luci_err("blkptr crc mismatch, nr_pages :%u EXP :0x%x GOT :0x%x "
                 "PageDirty :%d", nr_pages, bp->checksum, crc, PageDirty(pages[0]));
#ifdef LUCI_DUMP_CHECKSUM_DATA
        if (bp->length <= PAGE_SIZE) {
                void *kaddr = kmap(pages[0]);
                print_hex_dump(KERN_INFO, "data block :",
                                      DUMP_PREFIX_OFFSET,
                                      16,
                                      1,
                                      kaddr,
                                      bp->length,
                                      true);
                kunmap(kaddr);
        }
#endif
    }

    return err;
exit:
    if (page)
        luci_pageflags_dump(page, "cannot verify checksum for page");
    return err;
    #else
    return 0;
    #endif
}
