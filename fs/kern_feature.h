#ifndef _KERN_FEATURE_H
#define _KERN_FEATURE_H

#include <linux/version.h>
#ifndef LINUX_VERSION_CODE
# include <generated/uapi/linux/version.h>
#endif

#ifdef LINUX_VERSION_CODE

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3,16,0))
    #include <linux/hrtimer.h>
    #define HAVE_IOV_ITER
#else
    #include <linux/timekeeping.h>
    #define HAVE_NEW_SYNC_WRITE
    #define HAVE_NEW_SYNC_READ
    #define HAVE_READWRITE_ITER
    #define HAVE_D_OBTAIN_ROOT
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,0,0))
    #include <linux/dcache.h>
    #define HAVE_CHECKINODEPERM
    #define DENTRY_INODE(dentry) (dentry->d_inode)
#else
    #include <linux/dcache.h>
    #define DENTRY_INODE(dentry) (d_inode(dentry))
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,2,0))
    #include <linux/aio.h>
    #include <linux/pagemap.h>
    static inline unsigned long
    dir_pages(struct inode *inode)
    {
        return (inode->i_size + PAGE_CACHE_SIZE-1) >> PAGE_CACHE_SHIFT;
    }
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,8,0))
    #include <linux/time.h>
    #define LUCI_CURR_TIME CURRENT_TIME
#else
    #include <linux/fs.h>
    #define LUCI_CURR_TIME current_time(inode)
#endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,8))
    #define HAVE_NEW_GETATTR
    #define HAVE_NEW_RENAME
#endif

#endif // LINUX_VERSION_CODE

#endif