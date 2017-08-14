/*-------------------------------------------------------------
 *
 * Copyright(C) 2016, Saptarshi Sen
 *
 * LUCI File operations
 *
 * -----------------------------------------------------------*/

#include <linux/fs.h>
#include "kern_feature.h"

const struct file_operations luci_file_operations = {
        .llseek         = generic_file_llseek,
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,0,0)
        .read           = do_sync_read,
        .write          = do_sync_write,
#endif
#if HAVE_IOV_ITER
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,8)
        .read_iter      = generic_file_read_iter,
#else
        .aio_read       = generic_file_aio_read,
#endif
#endif
#if HAVE_IOV_ITER
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,8)
        .write_iter     = generic_file_write_iter,
#else
        .aio_write       = generic_file_aio_write,
#endif
#endif
        .mmap           = generic_file_mmap,
        .fsync          = generic_file_fsync,
        .splice_read    = generic_file_splice_read,
};

