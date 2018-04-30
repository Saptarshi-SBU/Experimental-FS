#ifndef __LUCI_COMPRESSION_
#define __LUCI_COMPRESSION_

#include <linux/pagemap.h>

#include "kern_feature.h"

#define LUCI_COMPR_FLAG  0x1

#define ZLIB_COMPRESSION_LEVEL 3

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
      int (*decompress_biovec)(struct list_head *workspace,
                               struct page **pages_in,
		               u64 disk_start,
			       struct bio_vec *bvec,
			       int vcnt,
			       size_t srclen);

      /*
       * a less complex decompression routine.  Our compressed data fits in a
       * single page, and we want to read a single page out of it.
       * start_byte tells us the offset into the compressed data we're interested in
       */
       int (*decompress)(struct list_head *workspace,
			 unsigned char *data_in,
			 struct page *dest_page,
			 unsigned long start_byte,
			 size_t srclen, size_t destlen);
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

int luci_read_compressed(struct page * page);

int luci_submit_compressed_read(struct inode *inode, struct bio *bio,
    int mirror_num, unsigned long bio_flags);

int luci_util_decompress_buf2page(char *buf, unsigned long buf_start,
    unsigned long total_out, u64 disk_start, struct bio_vec *bvec, int vcnt,
    unsigned long *pg_index, unsigned long *pg_offset);

void luci_util_clear_biovec_end(struct bio_vec *bvec, int vcnt,
    unsigned long pg_index, unsigned long pg_offset);

struct list_head *find_workspace(int type);

void free_workspace(int type, struct list_head *workspace);

void init_luci_compress(void);

void exit_luci_compress(void);

#endif
