/*-------------------------------------------------------------
 *
 * Copyright(C) 2016-2017, Saptarshi Sen
 *
 * LUCI File operations
 *
 * -----------------------------------------------------------*/
#include "luci.h"
#include "kern_feature.h"

#include <linux/fs.h>
#include <linux/uio.h>

extern int debug;

loff_t
luci_llseek(struct file * file, loff_t off, int whence) {
   loff_t ret;
   ret = generic_file_llseek(file, off, whence);
   luci_dbg("offset :%llu whence :%d return :%llu", off, whence, ret);
   return ret;
}

ssize_t luci_read(struct file * file, char *buf, size_t size, loff_t *pos) {
   luci_dbg("read file, size :%lu", size);
   return size;
}

ssize_t luci_read_iter(struct kiocb*iocb, struct iov_iter *iter) {
   luci_dbg("read file iter");
   return generic_file_read_iter(iocb, iter);
}

ssize_t luci_write(struct file * file, const char *buf, size_t size, loff_t *pos) {
   luci_dbg("write file, size :%lu", size);
   return size;
}

ssize_t luci_write_iter(struct kiocb*iocb, struct iov_iter *iter) {
   ssize_t ret;
   ret = generic_file_write_iter(iocb, iter);
   luci_dbg("pos %llu count %lu ret %lu", iocb->ki_pos, iov_iter_count(iter), ret);
   return ret;
}

int luci_open(struct inode * inode, struct file * file) {
   luci_dbg("opening file");
   return 1;
}

int luci_iterate(struct file *file, struct dir_context *dir) {
   luci_dbg("iterate");
   return 0;
}

int luci_iterate_shared(struct file *file, struct dir_context *dir) {
   luci_dbg("iterate shared");
   return 0;
}

int luci_mmap (struct file * file, struct vm_area_struct *vma) {
   luci_dbg("mmap file");
   return generic_file_mmap(file, vma);
}

const struct file_operations luci_file_operations = {
        .llseek         = luci_llseek,
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,0,0)
        .read           = do_sync_read,
        .write          = do_sync_write,
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,17,0)
        .read_iter      = luci_read_iter,
#else
        .aio_read       = generic_file_aio_read,
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,17,0)
        .write_iter     = luci_write_iter,
#else
        .aio_write      = generic_file_aio_write,
#endif
        .mmap           = luci_mmap,
        .fsync          = generic_file_fsync,
        .splice_read    = generic_file_splice_read,
};
