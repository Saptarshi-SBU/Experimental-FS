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
#include <linux/types.h>
#include <linux/ktime.h>

loff_t
luci_llseek(struct file * file, loff_t off, int whence) {
   loff_t ret;
   ret = generic_file_llseek(file, off, whence);
   luci_dbg("offset :%llu whence :%d return :%llu", off, whence, ret);
   return ret;
}

#ifdef HAVE_NEW_SYNC_WRITE
ssize_t luci_read(struct file * file, char *buf, size_t size, loff_t *pos) {
   ssize_t ret;
   ktime_t start = ktime_get();
   struct inode *inode = file->f_mapping->host;
   ret = new_sync_read(file, buf, size, pos); // use read_iter not aio_read
   luci_inode_latency(inode, "pos :%llu size :%lu latency(usec) :%llu", *pos,
       size, ktime_us_delta(ktime_get(), start));
   return ret;
}
#endif

#ifdef HAVE_READWRITE_ITER
ssize_t luci_read_iter(struct kiocb*iocb, struct iov_iter *iter) {
   ssize_t ret;
   ret = generic_file_read_iter(iocb, iter);
   luci_dbg("off %llu count %lu size %lu", iocb->ki_pos, iter->count, ret);
   return ret;
}
#endif

#ifdef HAVE_NEW_SYNC_WRITE
ssize_t luci_write(struct file * file, const char *buf, size_t size, loff_t *pos) {
   ssize_t ret;
   ktime_t start = ktime_get();
   struct inode *inode = file->f_mapping->host;
   ret = new_sync_write(file, buf, size, pos); // use write_iter, not aio_write
   luci_inode_latency(inode, "pos :%llu size :%lu latency(usec) :%llu", *pos,
       size, ktime_us_delta(ktime_get(), start));
   return ret;
}
#endif

#ifdef HAVE_READWRITE_ITER
ssize_t luci_write_iter(struct kiocb * iocb, struct iov_iter *iter) {
   ssize_t ret;
   ret = generic_file_write_iter(iocb, iter);
   luci_dbg("off %llu count %lu size %lu", iocb->ki_pos, iter->count, ret);
   return ret;
}
#endif

int luci_open(struct inode * inode, struct file * file) {
   luci_dbg("opening file");
   BUG(); // TBD
   return 0;
}

int luci_iterate(struct file *file, struct dir_context *dir) {
   luci_dbg("iterate");
   BUG(); // TBD
   return 0;
}

int luci_iterate_shared(struct file *file, struct dir_context *dir) {
   luci_dbg("iterate shared");
   BUG(); // TBD
   return 0;
}

int luci_mmap (struct file * file, struct vm_area_struct *vma) {
   luci_dbg("mmap file");
   return generic_file_mmap(file, vma);
}

static int luci_ioctl_getflags(struct file *file, void __user *arg)
{
   unsigned int flags = 0;
   struct luci_inode_info *li = LUCI_I(file_inode(file));

   if (li->i_flags & LUCI_COMPR_FL)
       flags |= FS_COMPR_FL;
   else if (li->i_flags & LUCI_NOCOMP_FL)
       flags |= FS_NOCOMP_FL;

   luci_get_inode_flags(li);
   flags = li->i_flags & LUCI_FL_USER_VISIBLE;

   if (copy_to_user(arg, &flags, sizeof(flags)))
       return -EFAULT;

   return 0;
}

long luci_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
   switch (cmd) {
   case FS_IOC_GETFLAGS:
   case FS_IOC32_GETFLAGS:
           return luci_ioctl_getflags(file, (void __user *)arg);
   case FS_IOC_SETFLAGS:
   case FS_IOC32_SETFLAGS: {
           unsigned int flags = 0;
           struct inode *inode = file_inode(file);
           struct luci_inode_info *li = LUCI_I(inode);

           if (get_user(flags, (int __user *) arg))
               return -EFAULT;

           flags = luci_mask_flags(inode->i_mode, flags);
           flags = flags & LUCI_FL_USER_MODIFIABLE;
           mutex_lock(&inode->i_mutex);
           li->i_flags = flags;
           luci_set_inode_flags(inode);
           inode->i_ctime = LUCI_CURR_TIME;
           mutex_unlock(&inode->i_mutex);

           mark_inode_dirty(inode);
           luci_info("FS_IOC_SETFLAGS, supported ioctl :0x%x\n", cmd);
           break;
   }
   case FS_IOC_GETVERSION:
   case FS_IOC32_GETVERSION:
           luci_err("FS_IOC_GETVERSION, not supported ioctl :0x%x\n", cmd);
           break;
   case FS_IOC_SETVERSION:
   case FS_IOC32_SETVERSION:
           luci_err("FS_IOC_SETVERSION, not supported ioctl :0x%x\n", cmd);
           break;
   case FS_IOC_FIEMAP:
           luci_err("FS_IOC_FIEMAP, not supported ioctl :0x%x\n", cmd);
           break;
   default:
           luci_err("not supported ioctl :0x%x/dir=%u nr=%u size=%u type=0x%x\n",
                cmd, _IOC_DIR(cmd), _IOC_NR(cmd), _IOC_SIZE(cmd), _IOC_TYPE(cmd));
   }
   return -ENOTTY;
}

const struct file_operations luci_file_operations = {
        .llseek         = luci_llseek,
#if defined(HAVE_NEW_SYNC_WRITE)
        .read           = luci_read,
        .write          = luci_write,
#elif defined(HAVE_DO_SYNC_WRITE)
        .read           = do_sync_read,
        .write          = do_sync_write,
#endif

#ifdef HAVE_READWRITE_ITER
        .read_iter      = luci_read_iter,
        .write_iter     = luci_write_iter,
#else
        // internally calls aops writepage/readpage/directIO
        .aio_read       = generic_file_aio_read,
        .aio_write      = generic_file_aio_write,
#endif
        .mmap           = luci_mmap,
        .fsync          = generic_file_fsync,
        .splice_read    = generic_file_splice_read,

        .unlocked_ioctl = luci_ioctl,
};
