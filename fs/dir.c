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

//Must be called in pair with get page
inline void
luci_put_page(struct page *page)
{
    if (page_mapped(page)) {
        kunmap(page);
    }
    put_page(page);
}

/*
 *  returns a mapped page, which is unmapped on a luci_put_page
 */
struct page *
luci_get_page(struct inode *dir, unsigned long n)
{
#   ifdef DEBUG_DENTRY
    blkptr bp;
#   endif

    struct address_space *mapping = dir->i_mapping;
    // Makes an internal call to luci_get_block
    struct page *page = read_mapping_page(mapping, n, NULL);
    if (IS_ERR(page)) {
        luci_err("read mapping page failed, page no %lu", n);
        return page;
    }

#   ifdef DEBUG_DENTRY
    bp = luci_find_leaf_block(dir, n);
    luci_info_inode(dir, "mapping page no %lu(%u)", n, bp.blockno);
#   endif
    // Currently, we do not check pages, TBD
    if (unlikely(!PageChecked(page))) {
        // Can be set by internal buffer code during failed write
        if (PageError(page)) {
            luci_err("mapped page with error, page no %lu", n);
            goto fail;
        }
    }

    // page has to be mapped for dentry access.
    (void) kmap(page);

    return page;
fail:
    luci_put_page(page);
    return ERR_PTR(-EIO);
}

inline int
luci_match (int len, const char * const name,
        struct luci_dir_entry_2 * de)
{
    if ((len != de->name_len) || (!de->inode)) {
        return 0;
    }
    return !memcmp(name, de->name, len);
}

inline unsigned
luci_rec_len_from_disk(__le16 dlen)
{
    unsigned len = le16_to_cpu(dlen);
    return len;
}

inline __le16
luci_rec_len_to_disk(unsigned dlen)
{
    return cpu_to_le16(dlen);
}

static inline struct
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
    if (inode->i_size < PAGE_SIZE) {
       last_byte = inode->i_size;
    } else if (page_nr == (inode->i_size >> PAGE_SHIFT)) {
       last_byte = inode->i_size & (PAGE_SIZE - 1);
    } else {
       last_byte = PAGE_SIZE;
    }
    return last_byte;
}

/*
 * core function to lookup dentries
 */
struct luci_dir_entry_2 *
luci_find_entry (struct inode * dir, const struct qstr * child,
                 struct page ** res) {
    struct page *page = NULL;
    struct luci_dir_entry_2 *de = NULL;
    unsigned long n, npages = dir_pages(dir);

    for (n = 0; n < npages; n++) {
        struct luci_dir_entry_2 *kaddr, *limit;
        //lookup dentry page
        page = luci_get_page(dir, n);
        if (IS_ERR(page)) {
            luci_err_inode(dir, "bad dentry page page :%ld err:%ld",
               n, PTR_ERR(page));
	    goto fail;
	}
        kaddr = (struct luci_dir_entry_2*) page_address(page);
	// limit takes care of page boundary issues
        limit = (struct luci_dir_entry_2*) ((char*) kaddr +
            luci_last_byte(dir, n) - LUCI_DIR_REC_LEN(child->len));
        // scan dentries
        for (de = kaddr; de <= limit; de = luci_next_entry(de)) {
            if (de->rec_len == 0) {
	        // check page boundary
                // Fixed an issue, where newly created dentry block was alloted
                // to an incorrect index due to a bug in alloc branch
                luci_err_inode(dir, "invalid zero record length found at page "
                    "%lu(%p-%p)", n, (char*)de, (char*)limit);
	        luci_put_page(page);
	        goto fail;
            }

	    if (luci_match(child->len, child->name, de)) {
                luci_dbg("dentry found %s", child->name);
                goto found;
            }

#           ifdef DEBUG_DENTRY
            luci_dbg("dentry name :%s, inode :%u, namelen :%u reclen :%u",
	        de->name, de->inode, de->name_len,
                luci_rec_len_from_disk(de->rec_len));
#           endif
        }
        luci_put_page(page);
    }
fail:
    return NULL;
found:
    *res = page;
    return de;
}

int
luci_empty_dir(struct inode *dir)
{
    unsigned long n;
    unsigned long npages = dir_pages(dir);

    for (n = 0; n < npages; n++) {
        char *kaddr;
        struct page *page;
        struct luci_dir_entry_2 *de, *limit;

        page = luci_get_page(dir, n);
        if (IS_ERR(page)) {
            luci_err_inode(dir, "bad dentry page page :%ld err:%ld", n,
               PTR_ERR(page));
            return -PTR_ERR(page);
        }

        kaddr = page_address(page);
        de = (struct luci_dir_entry_2*)(kaddr);
        limit = (struct luci_dir_entry_2*)
	    ((char*)kaddr + luci_last_byte(dir, n) - LUCI_DIR_REC_LEN(1));

        for (; de <= limit; de = luci_next_entry(de)) {

            if (de->rec_len == 0) {
                luci_err("invalid dir rec length at %p", (char*)de);
	        luci_put_page(page);
                return -EIO;
            }

            if (de->inode) {
                if (de->name[0] != '.') {
		    goto not_empty;
	        }
	        if (de->name_len > 1) {
		    if (de->name[1] != '.') {
                        goto not_empty;
		    }
		    if (de->name_len >= 2) {
                        goto not_empty;
		    }
	        }
	    }
        }
        luci_put_page(page);
    }
    return 1;

not_empty:
    return 0;
}

int
luci_delete_entry(struct luci_dir_entry_2* de, struct page *page)
{
    int err;
    loff_t pos;
    struct inode * inode = page->mapping->host;
    // Fix : an invalid ~, while computing the offset
    unsigned from = ((char*)de - (char*)page_address(page)) &
	    (luci_chunk_size(inode) - 1);
    // Fix : rec_len can be smaller than 'from', since it's an offset
    unsigned length = luci_rec_len_from_disk(de->rec_len);
    pos = page_offset(page) + from;
    luci_dbg("dentry %s pos %llu from %u len %u", de->name, pos, from, length);
    de->inode = 0;
    lock_page(page);
    err = luci_prepare_chunk(page, pos, length);
    BUG_ON(err);
    err = luci_commit_chunk(page, pos, length);
    if (err) {
        luci_err("error in commiting page chunk");
    }
    inode->i_ctime = inode->i_mtime = LUCI_CURR_TIME;
    mark_inode_dirty(inode);
    luci_put_page(page);
    return err;
}

ino_t
luci_inode_by_name(struct inode *dir, const struct qstr *child)
{
    ino_t res = 0;
    struct luci_dir_entry_2 *de;
    struct page *page;
    de = luci_find_entry (dir, child, &page);
    if (de) {
        res = le32_to_cpu(de->inode);
        luci_put_page(page);
    }
    return res;
}

static int
luci_readdir(struct file *file, struct dir_context *ctx)
{
    loff_t pos = ctx->pos;
    struct inode * dir = file_inode(file);
    unsigned int offset = pos & ~PAGE_MASK;
    unsigned long n = pos >> PAGE_SHIFT;
    unsigned long npages = dir_pages(dir);

#   ifdef DEBUG_DENTRY
    luci_dbg("reading directory");
#   endif

    // scan all pages of this dir inode
    for (; n < npages; n++, offset = 0) {
        char *kaddr;
        struct luci_dir_entry_2 *de, *limit;
        struct page *page;

#       ifdef DEBUG_DENTRY
        luci_info_inode(dir, "dentry read page no :%lu(%llu-%u)", n, pos, offset);
#       endif
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
            if (de->rec_len == 0) {
                luci_err_inode(dir, "invalid zero record length found at page "
                  "%lu(%p-%p) pos :%llu inode :%u", n, (char*)de, (char*)limit,
                  ctx->pos, de->inode);
#               ifdef DEBUG_DENTRY
                luci_dump_bytes("dentry page", page, PAGE_SIZE);
#               endif
	        luci_put_page(page);
                return -EIO;
            }

            if (de->inode) {
                unsigned char d_type = DT_UNKNOWN;
		// The VFS framework will call the iterate member of the struct
		// file_operations. Inside your iterate implementation, use dir_emit()
		// to provide VFS with the contents of the requested directory.
		// VFS will continue to call iterate until your implementation
		// returns without calling dir_emit().
                if (!dir_emit(ctx, de->name, de->name_len, le32_to_cpu(de->inode), d_type)) {
	            luci_err("failed to emit dir for :%s", de->name);
                    luci_put_page(page);
                    return 0;
                }

#               ifdef DEBUG_DENTRY
                luci_dbg("dentry name :%s, inode :%u, namelen :%u reclen :%u "
		   "pos :%llu", de->name, de->inode, de->name_len,
		   luci_rec_len_from_disk(de->rec_len), ctx->pos);
#               endif
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
