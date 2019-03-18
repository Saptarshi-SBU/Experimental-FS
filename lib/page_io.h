#ifndef LINUX_BUMP_ALLOCATOR_H
#define LINUX_BUMP_ALLOCATOR_H

#include <linux/buffer_head.h>

unsigned long bump_alloc_data_block(void);

unsigned long bump_alloc_meta_block(void);

void bump_release_block(unsigned long, size_t);

struct buffer_head* bump_get_buffer_head(unsigned long block);

void bump_put_buffer_head(struct buffer_head *bh);

void bump_allocator_init(void);

void bump_allocator_release(void);

void bump_leak_detector(void);

#endif

