/*--------------------------------------------------------------
 *
 * Copyright(C) 2016, Saptarshi Sen
 *
 * LUCI dir operations
 *
 * ------------------------------------------------------------*/

#include "luci.h"
#include <linux/fs.h>
#include <linux/pagemap.h>
#include <linux/buffer_head.h>
#include <linux/version.h>


static inline void
luci_put_page(struct page *page)
{
    kunmap(page);
    put_page(page);
}

static struct page *
luci_get_page(struct inode *dir, unsigned long n)
{
    struct address_space *mapping = dir->i_mapping;
    struct page *page = read_mapping_page(mapping, n, NULL);
    if (!IS_ERR(page)) {
        kmap(page);
        if (unlikely(!PageChecked(page))) {
            if (PageError(page))
                goto fail;
        }
    }
    return page;

fail:
    luci_put_page(page);
    return ERR_PTR(-EIO);
}

static inline unsigned
luci_rec_len_from_disk(__le16 dlen)
{
    unsigned len = le16_to_cpu(dlen);
    return len;
}

static inline int
luci_match (int len, const char * const name,
        struct luci_dir_entry_2 * de)
{
    if (len != de->name_len)
        return 0;
    if (!de->inode)
        return 0;
    return !memcmp(name, de->name, len);
}

static inline struct
luci_dir_entry_2 *luci_next_entry(struct luci_dir_entry_2 *p)
{
    return (struct luci_dir_entry_2 *)((char *)p +
            luci_rec_len_from_disk(p->rec_len));
}

static unsigned
luci_last_byte(struct inode *inode, unsigned long page_nr)
{
    unsigned last_byte = PAGE_SIZE;

    if (page_nr == (inode->i_size >> PAGE_SHIFT))
        last_byte = inode->i_size & (PAGE_SIZE - 1);
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

    struct luci_dir_entry_2 *de = NULL; 
    const char * name = child->name;
    int namelen = child->len;
    unsigned reclen = LUCI_DIR_REC_LEN(namelen);
    unsigned long n;
    unsigned long npages = dir_pages(dir);
    struct page *page = NULL;

    for (n = 0; n < npages; n++) {
        char *kaddr;
        struct luci_dir_entry_2 *limit;
        page = luci_get_page(dir, n);
        if (IS_ERR(page))
            continue;
        kaddr = (char*)page_address(page);
        limit = (struct luci_dir_entry_2*) (kaddr + luci_last_byte(dir, n) - reclen);
        for (de = (struct luci_dir_entry_2*)kaddr; de <= limit; de = luci_next_entry(de)) {
            if (de->rec_len == 0) {
                printk(KERN_ERR "Invalid directory name length");
                goto out;
            } else if (luci_match(namelen, name, de)) {
                printk(KERN_INFO "directory entry found");
                goto found;
            }
        }
        luci_put_page(page);
    }
out:        
    return NULL;
found:
    *res = page;
    return de;
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
    struct inode * inode = file_inode(file);
    unsigned int offset = pos & ~PAGE_MASK;
    unsigned long n = pos >> PAGE_SHIFT;
    unsigned long npages = dir_pages(inode);

    printk(KERN_INFO "%s", __func__);
    for (; n < npages; n++, offset = 0) {
        char *kaddr, *limit;
        struct luci_dir_entry_2 *de;
        struct page *page = luci_get_page(inode, n);
        if (IS_ERR(page)) {
            printk(KERN_ERR "Bad page :%s", __func__);
            ctx->pos += PAGE_SIZE - offset;
            return PTR_ERR(page);
        }   

        kaddr = page_address(page);
        de = (struct luci_dir_entry_2*) (kaddr + offset);
        limit = kaddr + luci_last_byte(inode, n) - LUCI_DIR_REC_LEN(1);
        for (; (char*)de <= limit; de = luci_next_entry(de)) {
            if (de->rec_len == 0) {
                printk(KERN_ERR "zero-length directory entry");
                luci_put_page(page);
                return -EIO;
            }
            if (de->inode) {
                unsigned char d_type = DT_UNKNOWN;
                if (!dir_emit(ctx, de->name, de->name_len, le32_to_cpu(de->inode), d_type)) {
                    luci_put_page(page);
                    return 0;
                }  	    
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
