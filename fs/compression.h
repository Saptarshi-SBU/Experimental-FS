#ifndef __LUCI_COMPRESSION_
#define __LUCI_COMPRESSION_

#include <linux/pagemap.h>
#include "kern_feature.h"
#include "luci.h"

// Updating file size with compressed size may not be correct.
// POSIX applications use file size attribute for accessing logical offsets.
// Use this to verify total blocks alloted against compressed size (TEST).
//#define LUCI_ATTRSIZE_COMPRESSED

#define LUCI_COMPR_FLAG  0x1

#define ZLIB_COMPRESSION_LEVEL 3

#define ZLIB_MEMPOOL_PAGES (4 * 1024) //16 MB

//#define DEBUG_COMPRESSION

#define WBC_FMT  "wbc: (%llu-%llu) dirty :%lu"
#define WBC_ARGS(wbc) wbc->range_start, wbc->range_end, wbc->nr_to_write

typedef enum luci_compression_type {
	LUCI_COMPRESS_NONE  = 0,
	LUCI_COMPRESS_ZLIB  = 1,
	LUCI_COMPRESS_TYPES = 1,
}luci_comp_type;

// Work item for compressed write
struct comp_write_work
{
    struct page *begin_page;
    struct page *pageout;
    struct pagevec *pvec;
    struct work_struct work;
};

struct comp_ws {
    int num_ws;
    atomic_t alloc_ws;
    spinlock_t ws_lock;
    struct list_head idle_ws;
    wait_queue_head_t ws_wait;
};

struct luci_compress_op {
    struct list_head *(*alloc_workspace)(void);

    void (*free_workspace)(struct list_head *workspace);

    /*
     * given an address space and start/len, compress the bytes.
     *
     * pages are allocated to hold the compressed result and stored
     * in 'pages'
     *
     * out_pages is used to return the number of pages allocated.  There
     * may be pages allocated even if we return an error
     *
     * total_in is used to return the number of bytes actually read.  It
     * may be smaller then len if we had to exit early because we
     * ran out of room in the pages array or because we cross the
     * max_out threshold.
     *
     * total_out is used to return the total number of compressed bytes
     *
     * max_out tells us the max number of bytes that we're allowed to
     * stuff into pages
     */
     int (*compress_pages)(struct list_head *workspace,
                           struct address_space *mapping,
			   u64 start,
			   struct page **pages,
			   unsigned long *out_pages,
			   unsigned long *total_in,
			   unsigned long *total_out);

     /*
      * pages_in is an array of pages with compressed data.
      * disk_start is the starting logical offset of this array in the file
      * bvec is a bio_vec of pages from the file that we want to decompress into
      * vcnt is the count of pages in the biovec
      * srclen is the number of bytes in pages_in
      * The basic idea is that we have a bio that was created by readpages.
      * The pages in the bio are for the uncompressed data, and they may not
      * be contiguous.  They all correspond to the range of bytes covered by
      * the compressed extent.
      */
      int (*decompress_pages)(struct list_head *workspace,
                              unsigned long total_in,
                              struct bio *compr_bio,
                              struct bio *uncompr_bio);

      /*
       * return borrowed pages from workspace after work is done.
       */
       void (*remit_workspace)(struct list_head *workspace,
			       struct page *pages);
};

extern const struct luci_compress_op luci_zlib_compress;

int luci_write_compressed_begin(struct address_space *mapping,
    loff_t pos, unsigned len, unsigned flags, struct page **pagep);

int luci_write_compressed_end(struct address_space *mapping,
    loff_t pos, unsigned len, unsigned flags, struct page *pagep);

int luci_writepage_compressed(struct page *page, struct writeback_control *wbc);

int luci_writepages_compressed(struct address_space *mapping,
    struct writeback_control *wbc);

int luci_write_compressed(struct page * page, struct writeback_control *wbc);

int luci_read_compressed(struct page * page, blkptr *bp);

int luci_submit_compressed_read(struct inode *inode, struct bio *bio,
    int mirror_num, unsigned long bio_flags);

struct list_head *find_workspace(int type);

void free_workspace(int type, struct list_head *workspace);

void init_luci_compress(void);

void exit_luci_compress(void);

#endif
