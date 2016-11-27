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
        .read           = do_sync_read,
#if HAVE_IOV_ITER
        .aio_read       = generic_file_aio_read,
#endif
        .write          = do_sync_write,
#if HAVE_IOV_ITER
        .aio_write      = generic_file_aio_write,
#endif
        .mmap           = generic_file_mmap,
        .fsync          = generic_file_fsync,
        .splice_read    = generic_file_splice_read,
};

