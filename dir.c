/*--------------------------------------------------------------
 *
 * Copyright(C) 2016, Saptarshi Sen
 *
 * LUCI dir operations
 *
 * ------------------------------------------------------------*/

#include <linux/fs.h>

static int luci_readdir(struct file *file, struct dir_context *ctx)
{
    printk(KERN_INFO "%s", __func__);
    return 0;
}

const struct file_operations luci_dir_operations = {
    .llseek   = generic_file_llseek,
    .read     = generic_read_dir,
    .iterate  = luci_readdir,
    .fsync    = generic_file_fsync,
};
