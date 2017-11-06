/*--------------------------------------------------------------
 *
 * Copyright(C) 2016-2017, Saptarshi Sen
 *
 * LUCI dir operations
 *
 * ------------------------------------------------------------*/

#include "luci.h"

#include <linux/fs.h>
#include <linux/pagemap.h>
#include <linux/buffer_head.h>
#include <linux/version.h>

//Must be called in pair with get page
inline void
luci_put_page(struct page *page)
{
    kunmap(page);
    put_page(page);
}

struct page *
luci_get_page(struct inode *dir, unsigned long n)
{
    struct address_space *mapping = dir->i_mapping;
    // Makes an internal call to luci_get_block
    struct page *page = read_mapping_page(mapping, n, NULL);
    if (IS_ERR(page)) {
        printk (KERN_ERR "luci : read mapping page failed, page no %lu", n);
        return page;
    }
    kmap(page);
    // Currently, we do not check pages, TBD
    if (unlikely(!PageChecked(page))) {
        // Can be set by internal buffer code during failed write
        if (PageError(page)) {
            printk (KERN_ERR "Luci:mapped page with error, page no %lu", n);
            goto fail;
        }
    }
    // page is ok
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

unsigned
luci_last_byte(struct inode *inode, unsigned long page_nr)
{
    // Other than last page, return page size
    unsigned last_byte = PAGE_SIZE;
    if (page_nr == (inode->i_size >> PAGE_SHIFT)) {
        last_byte = inode->i_size & (PAGE_SIZE - 1);
    }
    return last_byte;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,11,8)
static inline unsigned long
dir_pages(struct inode *inode)
{
    return (inode->i_size+PAGE_CACHE_SIZE-1)>>PAGE_CACHE_SHIFT;
}
#endif

struct luci_dir_entry_2 *
luci_find_entry (struct inode * dir,
    const struct qstr * child, struct page ** res) {
    struct page *page = NULL;
    struct luci_dir_entry_2 *de = NULL;
    unsigned long n, npages = dir_pages(dir);

    for (n = 0; n < npages; n++) {
        struct luci_dir_entry_2 *kaddr, *limit;

        page = luci_get_page(dir, n);
        if (IS_ERR(page)) {
            printk(KERN_ERR "luci:bad dentry page inode :%lu page :%ld err:%ld",
	       dir->i_ino, n, PTR_ERR(page));
	    goto fail;
	}

        kaddr = (struct luci_dir_entry_2*) page_address(page);
        limit = (struct luci_dir_entry_2*)
		((char*) kaddr + luci_last_byte(dir, n) - LUCI_DIR_REC_LEN(child->len));

	// limit takes care of page boundary issues
        for (de = kaddr; de <= limit; de = luci_next_entry(de)) {
            if (de->rec_len == 0) {
	        // check page boundary
                printk(KERN_ERR "luci:invalid dir record length at %p", (char*)de);
	        luci_put_page(page);
	        goto fail;
            }

	    if (luci_match(child->len, child->name, de)) {
                printk(KERN_INFO "luci : dentry found %s", child->name);
                goto found;
            }

            printk(KERN_INFO "luci: %s dentry name :%s, inode :%u, reclen :%u",
	       __func__, de->name, de->inode, luci_rec_len_from_disk(de->rec_len));
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
luci_delete_entry(struct luci_dir_entry_2* de, struct page *page)
{
    int err;
    struct inode * inode = page->mapping->host;
    // Fix : an invalid ~, while computing the offset
    unsigned from = ((char*)de - (char*)page_address(page)) &
	    (luci_chunk_size(inode) - 1);
    unsigned to = (char*)de - (char*)page_address(page) +
	    luci_rec_len_from_disk(de->rec_len);
    loff_t pos = page_offset(page) + from;
    de->inode = 0;
    lock_page(page);
    err = luci_prepare_chunk(page, pos, to - from);
    BUG_ON(err);
    err = luci_commit_chunk(page, pos, to - from);
    if (err) {
        printk(KERN_ERR "Luci:error in commiting page chunk");
    }
    inode->i_ctime = inode->i_mtime = current_time(inode);
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

    printk(KERN_INFO "%s", __func__);
    for (; n < npages; n++, offset = 0) {
        char *kaddr;
        struct luci_dir_entry_2 *de, *limit;
        struct page *page = luci_get_page(dir, n);
        if (IS_ERR(page)) {
            printk(KERN_ERR "luci:bad dentry page inode :%lu page :%ld err:%ld",
	       dir->i_ino, n, PTR_ERR(page));
            ctx->pos += PAGE_SIZE - offset;
            return PTR_ERR(page);
        }

        kaddr = page_address(page);
        de = (struct luci_dir_entry_2*) (kaddr + offset);
        limit = (struct luci_dir_entry_2*)
	    ((char*)kaddr + luci_last_byte(dir, n) - LUCI_DIR_REC_LEN(1));
        for (; de <= limit; de = luci_next_entry(de)) {
            if (de->rec_len == 0) {
                printk(KERN_ERR "luci:invalid dir record length at %p", (char*)de);
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
	            printk(KERN_ERR "luci : failed to emit dir for :%s", de->name);
                    luci_put_page(page);
                    return 0;
                }
                printk(KERN_INFO "Luci: dentry name :%s, inode :%u, reclen :%u pos :%llu",
	           de->name, de->inode, luci_rec_len_from_disk(de->rec_len), ctx->pos);
            }
            ctx->pos += luci_rec_len_from_disk(de->rec_len);
        }
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
