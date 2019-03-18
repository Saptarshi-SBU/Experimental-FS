#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include "btree_ioctl.h"

#define MAX_KEYS  1000000
//#define MAX_KEYS  4096
#define PAGE_SIZE 4096

int main(void) {
        int fd;
        void *memptr;
        unsigned long i;

        struct btree_ioctl_arg *argp;

        fd = open("/dev/btree-store", 'w');
        if (fd < 0) {
                printf("failed to open device\n");
                return -ENODEV;
        }

        argp = malloc(sizeof(struct btree_ioctl_arg));
        if (!argp)
                return -ENOMEM;

        argp->version = 1;
        argp->fanout  = 32;

        if (ioctl(fd, BTREE_IOCTL_CREATE, argp) < 0) {
                printf("create ioctl failed\n");
                goto exit;
        }

        for (i = 0; i < MAX_KEYS; i++) {
                if (posix_memalign(&memptr, PAGE_SIZE, PAGE_SIZE)) {
                        printf("memory allocation failed\n");
                        goto out;
                } else {
                        argp->offset = i;
                        argp->data = memptr;
                        argp->datalen = PAGE_SIZE;
                        if (ioctl(fd, BTREE_IOCTL_WRITE, argp) < 0) {
                                printf("write ioctl failed\n");
                                goto out;
                        }
#if 0
                        if (ioctl(fd, BTREE_IOCTL_READ, argp) < 0) {
                                printf("read ioctl failed\n");
                                goto out;
                        }
#endif
                        free(memptr);
                }
        }
out:
        if (ioctl(fd, BTREE_IOCTL_DESTROY, argp) < 0) {
                printf("destroy ioctl failed\n");
        }

exit:
        close(fd);
        return 0;
}
