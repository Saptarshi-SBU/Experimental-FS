#ifndef LINUX_BTREE_DEV_H
#define LINUX_BTREE_DEV_H

//#include <linux/compiler.h>
#include <linux/ioctl.h>

#define BTREE_DEV_MAGIC         0xB7

struct btree_ioctl_arg {
        int version;
        int snapid;
        int fanout;
        loff_t offset;
        size_t datalen;
        ssize_t status;
        void *data;
}__attribute__((packed));

#define BTREE_IOCTL_CREATE         _IO(BTREE_DEV_MAGIC,  0)
#define BTREE_IOCTL_DESTROY        _IO(BTREE_DEV_MAGIC,  1)
#define BTREE_IOCTL_SNAP           _IO(BTREE_DEV_MAGIC,  2)
#define BTREE_IOCTL_WRITE          _IOW(BTREE_DEV_MAGIC, 3, struct btree_ioctl_arg)
#define BTREE_IOCTL_READ           _IOR(BTREE_DEV_MAGIC, 4, struct btree_ioctl_arg)
#define BTREE_IOCTL_DELTA          _IO(BTREE_DEV_MAGIC,  5)
#define BTREE_IOCTL_RQUERY         _IO(BTREE_DEV_MAGIC,  6)

//int  btreedev_init(void);
//void btreedev_exit(void);
//long btreedev_ioctl(struct file *file, unsigned cmd, unsigned long arg);

#endif
