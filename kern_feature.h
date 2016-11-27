#ifndef _KERN_FEATURE_H
#define _KERN_FEATURE_H

#include <linux/version.h>
#ifndef LINUX_VERSION_CODE
# include <generated/uapi/linux/version.h>
#endif

#ifdef LINUX_VERSION_CODE

#ifndef HAVE_D_OBTAIN_ROOT
# define HAVE_D_OBTAIN_ROOT \
    (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 17, 0))
#endif

#ifndef HAVE_IOV_ITER
# define HAVE_IOV_ITER \
    (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 16, 0))
#endif

#endif

#endif
