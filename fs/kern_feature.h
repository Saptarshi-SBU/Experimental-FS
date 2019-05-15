#ifndef _KERN_FEATURE_H
#define _KERN_FEATURE_H

#include <linux/version.h>
#ifndef LINUX_VERSION_CODE
# include <generated/uapi/linux/version.h>
#endif

#ifdef LINUX_VERSION_CODE

#if (LINUX_VERSION_CODE > KERNEL_VERSION(3,15,0))
    #define HAVE_PRAND
#endif

#if (LINUX_VERSION_CODE > KERNEL_VERSION(3,12,0))
    #define HAVE_BIO_ITER
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3,16,0))
    #include <linux/hrtimer.h>
    #define HAVE_IOV_ITER
    #define HAVE_DO_SYNC_WRITE
    #define HAVE_DO_SYNC_READ
#else
    #include <linux/timekeeping.h>
    #define HAVE_NEW_SYNC_WRITE
    #define HAVE_NEW_SYNC_READ
    #define HAVE_READWRITE_ITER
    #define HAVE_D_OBTAIN_ROOT
    #define HAVE_TRUNCATEPAGES_FINAL
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,0,5))
    #include <linux/dcache.h>
    #define HAVE_CHECKINODEPERM
    #define DENTRY_INODE(dentry) (dentry->d_inode)
#else
    #include <linux/dcache.h>
    #define DENTRY_INODE(dentry) (d_inode(dentry))
    #define NEW_BIO_SUBMIT
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
    #define HAVE_NEW_BIO_END
    #define BIO_UPTODATE 0
    #define PAGE_CACHE_SIZE PAGE_SIZE
    #define PAGE_CACHE_SHIFT PAGE_SHIFT
    #undef HAVE_NEW_SYNC_WRITE
    #undef HAVE_NEW_SYNC_READ
#endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0))
   #define HAVE_BIO_BVECITER
#endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0))
   #define HAVE_NEW_BIO_FLAGS
#endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,15,0))
   #define HAVE_TRACEPOINT_ENABLED
   #define HAVE_WRITE_ONE_PAGE_NEW
   #define HAVE_PAGEVEC_INIT_NEW
   #define HAVE_BIO_SETDEV_NEW
#endif

#endif // LINUX_VERSION_CODE

#endif
