#ifndef __CLUSTER_H_
#define __CLUSTER_H_

#include <linux/types.h>
#include <linux/pagevec.h>
#include <linux/pagemap.h>

//#include "luci.h"

// Cluster size in terms of file system pages
// Since compression is done at page level, this will make things simple for us.

#define CLUSTER_NRPAGE 4
//#define CLUSTER_NRPAGE 2
//#define CLUSTER_NRPAGE 1

#define CLUSTER_NRBLOCKS_MAX 32

#define CLUSTER_SIZE (CLUSTER_NRPAGE * PAGE_SIZE)

#define CLUSTER_NRBLOCKS(sb) ((CLUSTER_SIZE) / LUCI_BLOCK_SIZE(sb))

#define LUCI_COMPRESS_RESULT(cluster, index, total_in, total_out) \
    luci_dbg("compress result : cluster %u index %lu in %lu out %lu", cluster, \
        index, total_in, total_out);

static inline unsigned long
luci_cluster_no(pgoff_t index) { return index/CLUSTER_NRPAGE; }

//int
//luci_cluster_update_bp(struct page *page, struct inode *inode, blkptr bp[]);

#endif


