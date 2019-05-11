/*--------------------------------------------------------------
 *
 * Copyright(C) 2016-2017, Saptarshi Sen
 *
 * LUCI dir operations
 *
 * ------------------------------------------------------------*/

#include "luci.h"
#include "kern_feature.h"

#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/buffer_head.h>
#include <linux/version.h>

/*
 *  returns a mapped page, which is unmapped on a luci_put_page
 *  page needs to be mapped for dentry access.
 */
struct page *
luci_get_page(struct inode *dir, unsigned long n)
{
    struct page *page;
#   ifdef DEBUG_DENTRY
    blkptr bp;

    bp = luci_bmap_fetch_L0bp(dir, n);
    luci_info_inode(dir, "mapping page no %lu(%u)", n, bp.blockno);
#   endif

    // makes an internal call to luci_get_block
    page = read_mapping_page(dir->i_mapping, n, NULL);
    if (IS_ERR(page)) {
        luci_err("read mapping page failed, page no %lu", n);
        goto fail;
    }

    // FIXME: check pages
    if (unlikely(!PageChecked(page)) && PageError(page)) {
        luci_err("mapped page with error, page no %lu", n);
        goto fail;
    }

    (void) kmap(page);
    return page;

fail:
    luci_put_page(page);
    return ERR_PTR(-EIO);
}

// must be called in pair with luci_get_page
void inline
luci_put_page(struct page *page)
{
    if (page_mapped(page))
        kunmap(page);

    put_page(page);
}

unsigned inline
luci_rec_len_from_disk(__le16 dlen)
{
    unsigned len = le16_to_cpu(dlen);
    return len;
}

__le16 inline
luci_rec_len_to_disk(unsigned dlen)
{
    return cpu_to_le16(dlen);
}

inline struct
luci_dir_entry_2 *luci_next_entry(struct luci_dir_entry_2 *p)
{
    return (struct luci_dir_entry_2 *)((char *)p +
        luci_rec_len_from_disk(p->rec_len));
}

// Other than last page, return page size
unsigned
luci_last_byte(struct inode *inode, unsigned long page_nr)
{
    unsigned last_byte;

    if (inode->i_size < PAGE_SIZE)
       last_byte = inode->i_size;
    else if (page_nr == (inode->i_size >> PAGE_SHIFT))
       last_byte = inode->i_size & (PAGE_SIZE - 1);
    else
       last_byte = PAGE_SIZE;

    return last_byte;
}

static int
luci_readdir(struct file *file, struct dir_context *ctx)
{
    loff_t pos = ctx->pos;
    unsigned long n = pos >> PAGE_SHIFT;
    struct inode *dir = file_inode(file);
    unsigned long npages = dir_pages(dir);
    unsigned int offset = pos & ~PAGE_MASK;

    #ifdef DEBUG_DENTRY
    luci_dbg("reading directory");
    #endif

    // scan all pages of this dir inode
    for (; n < npages; n++, offset = 0) {
        char *kaddr;
        struct page *page;
        struct luci_dir_entry_2 *de, *limit;

        #ifdef DEBUG_DENTRY
        luci_info_inode(dir, "dentry read page no :%lu(%llu-%u)",
                             n, pos, offset);
        #endif

        page = luci_get_page(dir, n);
        if (IS_ERR(page)) {
            luci_err_inode(dir, "bad dentry page page :%ld err:%ld", n,
	       PTR_ERR(page));
            ctx->pos += PAGE_SIZE - offset;
            return PTR_ERR(page);
        }

        kaddr = page_address(page);
        de = (struct luci_dir_entry_2*) (kaddr + offset);
        limit = (struct luci_dir_entry_2*)
	    ((char*)kaddr + luci_last_byte(dir, n) - LUCI_DIR_REC_LEN(1));

        // lookup dentries in the page
        for (; de <= limit; de = luci_next_entry(de)) {

            if (!de->rec_len) {
                luci_err_inode(dir, "invalid zero record length found at page "
                                    "%lu(%p-%p) pos :%llu inode :%u",
                                    n,
                                    (char*)de,
                                    (char*)limit,
                                    ctx->pos,
                                    de->inode);
                #ifdef DEBUG_DENTRY
                luci_dump_bytes("dentry page", page, PAGE_SIZE);
                #endif
	        luci_put_page(page);
                return -EIO;
            }

            if (de->inode) {
		// The VFS framework will call the iterate member of the struct
		// file_operations. Inside your iterate implementation, use
                // dir_emit() to provide VFS with the contents of the requested
                // directory. VFS will continue to call iterate until your
                // implementation returns without calling dir_emit().
                if (!dir_emit(ctx,
                              de->name,
                              de->name_len,
                              le32_to_cpu(de->inode),
                              DT_UNKNOWN)) {
                    luci_err("failed to emit dentry :%s, inode :%u, namelen :%u reclen :%u pos :%llu",
                              de->name,
                              de->inode,
                              de->name_len,
                              luci_rec_len_from_disk(de->rec_len),
                              ctx->pos);
                    luci_put_page(page);
                    return -EIO;
                }

                #ifdef DEBUG_DENTRY
                luci_info("dentry name :%s, inode :%u/%llu, namelen :%u reclen :%u "
		         "pos :%llu 0x%p/0x%p/0x%p",
                         de->name,
                         de->inode,
                         dir->i_size,
                         de->name_len,
		         luci_rec_len_from_disk(de->rec_len),
                         ctx->pos,
                         de,
                         limit,
                         luci_next_entry(de));
                #endif
            }
            ctx->pos += luci_rec_len_from_disk(de->rec_len);
        }

        // Enable this to check raw dentry entries
        //luci_dump_bytes("dentry page", page, PAGE_SIZE);
        luci_put_page(page);
    }
    return 0;
}

const struct file_operations luci_dir_operations = {
    .llseek   = generic_file_llseek,
    .read     = generic_read_dir,
    .iterate  = luci_readdir,
    .fsync    = generic_file_fsync,
};
