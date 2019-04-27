#ifndef __LUCI_COMPRESSION_H_
#define __LUCI_COMPRESSION_H_

#include <linux/wait.h>
#include <linux/list.h>
#include <linux/types.h>
#include <linux/pagemap.h>
#include <linux/spinlock.h>

#include "kern_feature.h"
#include "luci.h"

//#define DEBUG_COMPRESSION

// Updating file size with compressed size may not be correct.
// POSIX applications use file size attribute for accessing logical offsets.

// zlib parameters
#define ZLIB_COMPRESSION_LEVEL 3

#define ZLIB_MEMPOOL_PAGES     (4 * 1024) //16 MB

// heuristics
#define LUCI_COMPRESSION_HEURISTICS // enables heuristics

#define NR_SYMBOLS_THRESH      225  // core set size

#define SHANNON_ENTROPY_THRESH 7    // 8(bits) means cannot compress

#define COMPRESS_RATIO_LIMIT   30   // acceptable compression ratio (30%)        
                                    // associated with the entropy level

#define LUCI_COMPRESS_RESULT(cluster, index, total_in, total_out) \
    luci_dbg("compress result : cluster %u index %lu in %lu out %lu", cluster, \
        index, total_in, total_out);

typedef enum luci_compression_type {
	LUCI_COMPRESS_NONE  = 0,
	LUCI_COMPRESS_ZLIB  = 1,
	LUCI_COMPRESS_TYPES = 1,
}luci_comp_type;


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

struct luci_context_pool {
    atomic_t count;
    spinlock_t lock;
    wait_queue_head_t waitq;
    const struct luci_compress_op *op;
    struct list_head idle_list;
};

struct luci_compressed_bio_data {
        struct list_head         *ws;
        struct extent_write_work *ext_work;
        size_t total_out;
};

extern struct luci_context_pool ctxpool;

struct list_head *luci_get_compression_context(void);

void luci_put_compression_context(struct list_head *);

void init_luci_compress(void);

void exit_luci_compress(void);

#endif
