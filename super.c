/*-----------------------------------------------------------
 * Copyright(C) 2016-2017, Saptarshi Sen
 *
 * Playground for Luci Super block and namespace operations
 *
 * ----------------------------------------------------------*/

#include <linux/module.h>
#include <linux/blkdev.h>
#include <linux/init.h>
#include <linux/vfs.h>
#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/mm.h>
#include <linux/backing-dev.h>
#include <linux/buffer_head.h>
#include <linux/log2.h>
#include <linux/string.h>
#include <linux/parser.h>
#include "luci.h"
#include "kern_feature.h"

MODULE_AUTHOR("Saptarshi.S");
MODULE_ALIAS_FS("luci");
MODULE_DESCRIPTION("File System for Linux");
MODULE_LICENSE("GPL");

int debug;

static struct kmem_cache* luci_inode_cachep;

static struct inode *
luci_alloc_inode(struct super_block *sb)
{
    struct luci_inode_info *ei;
    ei = (struct luci_inode_info *)kmem_cache_alloc(luci_inode_cachep, GFP_KERNEL);
    if (!ei)
        return NULL;
    return &ei->vfs_inode;
}

static void
luci_i_callback(struct rcu_head *head)
{
    struct inode *inode = container_of(head, struct inode, i_rcu);
    kmem_cache_free(luci_inode_cachep, LUCI_I(inode));
}

static void
luci_destroy_inode(struct inode *inode)
{
    call_rcu(&inode->i_rcu, luci_i_callback);
}

static void
luci_put_super(struct super_block *sb) {
    int i;
    struct luci_sb_info *sbi = sb->s_fs_info;
    for (i = 0; i < sbi->s_gdb_count; i++) {
        brelse(sbi->s_group_desc[i]);
    }
    kfree(sbi->s_group_desc);
    percpu_counter_destroy(&sbi->s_freeblocks_counter);
    percpu_counter_destroy(&sbi->s_freeinodes_counter);
    percpu_counter_destroy(&sbi->s_dirs_counter);
    brelse(sbi->s_sbh);
    sb->s_fs_info = NULL;
    kfree(sbi);
}

// Only leaf blocks affect inode size
static void
luci_dec_size(struct inode *inode, unsigned nr_blocks)
{
   size_t size = nr_blocks * luci_chunk_size(inode);

   BUG_ON(!nr_blocks);
   BUG_ON(!inode->i_size);

   if (inode->i_size >= size) {
      inode->i_size -= size;
   } else {
      BUG_ON(nr_blocks > 1);
      inode->i_size = 0;
   }
   mark_inode_dirty(inode);
}

// Use to free both leaf and internal blocks
static int
luci_free_block(struct inode *inode, unsigned long block)
{
   unsigned int bitpos;
   unsigned block_group;
   struct super_block *sb = inode->i_sb;
   struct luci_sb_info *sbi = sb->s_fs_info;
   struct luci_group_desc *gdesc = NULL;
   struct buffer_head *bh_block = NULL, *bh_desc = NULL;

   BUG_ON(block == 0);
   block_group = (block - 1) / sbi->s_blocks_per_group;
   bitpos = block - (block_group * sbi->s_blocks_per_group);

   luci_dbg("Freeing block %lu in block group :%u", block, block_group);

   bh_block = read_block_bitmap(sb, block_group);
   if (!bh_block) {
      luci_err("Free block :%lu failed. Error reading block "
         "bitmap for group :%u", block, block_group);
      return -EIO;
   }
   if (!(__test_and_clear_bit_le(bitpos, bh_block->b_data))) {
      luci_err("Free block :%lu failed."
         "block marked not in use! : blockbit :%u", block, bitpos);
      return -EIO;
   }
   mark_buffer_dirty(bh_block);
   brelse(bh_block);

   gdesc = luci_get_group_desc(sb, block_group, &bh_desc);
   if (!gdesc) {
      luci_err("Free block :%lu failed. Error reading group "
         "descriptor table for group :%u", block, block_group);
      return -EIO;
   }
   le16_add_cpu(&gdesc->bg_free_blocks_count, 1);
   percpu_counter_add(&sbi->s_freeinodes_counter, 1);
   if (S_ISDIR(inode->i_mode)) {
      le16_add_cpu(&gdesc->bg_used_dirs_count, -1);
      percpu_counter_dec(&sbi->s_dirs_counter);
   }

   mark_buffer_dirty(bh_desc);
   inode->i_blocks -= luci_sectors_per_block(inode);
   mark_inode_dirty(inode);
   // Cannot release group descriptor buffer head
   // brelse(bh_desc);
   return 0;
}

/*
 *  Tree walk to free the leaf block
 *
 */
static int
luci_free_branch(struct inode *inode,
    long current_block,
    long *delta_blocks,
    int depth)
{
    int err = 0;
    int nr_entries;
    uint32_t *p, *q;
    struct buffer_head *bh;
    struct super_block *sb = inode->i_sb;

    if (depth == 0) {
	// Fix : This is a leaf block
        err = luci_free_block(inode, current_block);
	if (!err) {
           luci_dec_size(inode, 1);
           *delta_blocks -= 1;
	}
	return err;
    }

    nr_entries = LUCI_ADDR_PER_BLOCK(sb);
    bh = sb_bread(sb, current_block);
    if (bh == NULL) {
        luci_err("failed to read block :%ld during free branch", current_block);
        return -EIO;
    }
    p = (uint32_t*)bh->b_data;
    q = (uint32_t*)((char*)bh->b_data + bh->b_size) - 1;

    BUG_ON(p > q);
    for (;q >= p; q--) {

       uint32_t entry = *q;

       if (*delta_blocks == 0) {
	   err = 0;
	   luci_dbg("no remaining blocks to free");
           break;
       }

       // track valid entries in indirect block
       nr_entries--;
       if (!*q) {
          continue;
       }

       err = luci_free_branch(inode, *q, delta_blocks, depth - 1);
       if (err) {
          luci_err("failed to free branch at depth:%d block:%d", depth - 1, *q);
          goto out;
       }

       // clear entry
       *q = 0;
       mark_buffer_dirty(bh);
       luci_dbg_inode(inode, "freed indirect block %lu depth %d block[%d] %d "
          "nrblocks :%ld i_size :%llu", current_block, depth, nr_entries, entry,
	  *delta_blocks, inode->i_size);
    }

    // block has entries for block address
    if (nr_entries > 0) {
        goto out;
    }

    // Free the indirect block
    err = luci_free_block(inode, current_block);
    if (err) {
       luci_err_inode(inode, "error freeing indirect block %ld", current_block);
       goto out;
    }

out:
    brelse(bh);
    return err;
}

static int
luci_free_direct(struct inode *inode, long *delta_blocks)
{
    int i; // loop through all direct blocks
    uint32_t cur_block;
    struct luci_inode_info *li = LUCI_I(inode);
    for (i = LUCI_NDIR_BLOCKS - 1; i >= 0 && *delta_blocks; i--) {
       cur_block = li->i_data[i];
       if (cur_block == 0) {
          continue;
       }
       if (luci_free_block(inode, cur_block) < 0) {
           luci_err_inode(inode, "error freeing direct block %d", i);
           return -EIO;
       }
       luci_dec_size(inode, 1);
       // clear entry
       li->i_data[i] = 0;
       mark_inode_dirty(inode);
       *delta_blocks -= 1;
       luci_dbg_inode(inode, "freed i_data[%d] %u nrblocks %ld size :%llu", i,
          cur_block, *delta_blocks, inode->i_size);
    }
    return 0;
}

static int
luci_free_blocks(struct inode *inode, long delta_blocks)
{
    long ret;
    int i, level;
    unsigned long cur_block;
    struct luci_inode_info *li = LUCI_I(inode);

    // Free indirect blocks bottom up
    // Fix : macro represents array index
    for (i = LUCI_TIND_BLOCK, level = 3; level && delta_blocks; i--, level--) {

       cur_block = li->i_data[i];
       if (cur_block == 0) {
          luci_dbg("indirect block[%d] level %d empty", i, level);
          continue;
       }

       ret = luci_free_branch(inode, cur_block, &delta_blocks, level);
       if (ret < 0) {
           luci_err_inode(inode, "error freeing inode indirect block[%d] "
	      "block :%lu level :%d", i, cur_block, level);
          return ret;
       }

       // clear the root block from i_data array
       li->i_data[i] = 0;
       mark_inode_dirty(inode);

       luci_dbg("freed i_data[%d] %lu level :%d for inode :%lu nrblocks :%ld",
          i, cur_block, level, inode->i_ino, delta_blocks);
    }

    // Free direct blocks
    ret = luci_free_direct(inode, &delta_blocks);
    if (ret < 0) {
        luci_err_inode(inode, "error freeing direct blocks");
        return ret;
    }

    BUG_ON(delta_blocks);
    luci_dbg("freed delta blocks for inode :%lu sucessfully", inode->i_ino);
    return 0;
}

static int
luci_grow_blocks(struct inode *inode, long from, long to)
{
 // TBD
    long i;
    int err = 0;

    // i_block is 0-based but from and to are 1-based
    for (i = from; i < to; i++) {
        // We avoid mapping in get_block, so bh is NULL
        err = luci_get_block(inode, i, NULL, 1);
        if (err) {
           luci_err("failed to grow blocks, error in fetching block %lu", i);
	   break;
        }
    }
    return err;
}

int
luci_truncate(struct inode *inode, loff_t size)
{
    struct super_block *sb = inode->i_sb;
    long n_blocks = (size + sb->s_blocksize - 1)/ sb->s_blocksize;
    long i_blocks = (inode->i_size + sb->s_blocksize - 1)/
       sb->s_blocksize;
    long delta_blocks = n_blocks - i_blocks;
    luci_dbg("truncate blocks :%ld blocksize :%lu %lu-%lu",
       delta_blocks, sb->s_blocksize, n_blocks, i_blocks);
    if(!delta_blocks) {
       return 0;
    } else if (delta_blocks > 0) {
       luci_dbg("adding %ld blocks on truncate", delta_blocks);
       return luci_grow_blocks(inode, i_blocks, n_blocks);
    } else {
       luci_dbg("freeing %ld blocks on truncate", delta_blocks);
       return luci_free_blocks(inode, -delta_blocks);
    }
}

// invoked when i_count (in-memory references) drops to zero
static int
luci_drop_inode(struct inode *inode)
{
   luci_dbg("dropping inode %lu, refcount :%d, nlink :%d",
      inode->i_ino, atomic_read(&inode->i_count), inode->i_nlink);
   return generic_drop_inode(inode);
}

// invoked when i_nlink and i_count both drops to zero.
// This shall reclaim all disk blocks
static void
luci_evict_inode(struct inode * inode)
{
   luci_dbg("evicting inode :%lu",  inode->i_ino);

   // dump layout here for sanity
   if (inode->i_size && (luci_dump_layout(inode) < 0)) {
      luci_err("inode invalid layout detected");
   }

   // invalidate the radix tree in page-cache
   truncate_inode_pages_final(&inode->i_data);
   // walk internal and leaf blocks, free, update block-bitmap
   if (!inode->i_nlink && inode->i_size) {
      inode->i_size = 0;
      luci_truncate(inode, 0);
   }
   invalidate_inode_buffers(inode);
   clear_inode(inode);
   // free inode bitmap, update inode-bitmap
   // clear the inode state and update inode-table
   if (!inode->i_nlink) {
      luci_free_inode(inode);
   }
}

static int
luci_statfs(struct dentry *dentry, struct kstatfs *buf)
{
   struct super_block *sb = dentry->d_sb;
   struct luci_sb_info *sbi = LUCI_SB(sb);
   struct luci_super_block *lsb = sbi->s_lsb;
   u64 id = huge_encode_dev(sb->s_bdev->bd_dev);
   buf->f_type = sb->s_magic;
   buf->f_bsize = sb->s_blocksize;
   // TBD : calculate metadata overhead
   buf->f_blocks = lsb->s_blocks_count;
   buf->f_files  = lsb->s_inodes_count;
   buf->f_bfree = percpu_counter_read(&sbi->s_freeblocks_counter);
   buf->f_ffree = percpu_counter_read(&sbi->s_freeinodes_counter);
   buf->f_bavail = buf->f_bfree;
   buf->f_namelen = LUCI_NAME_LEN;
   // TBD : currently we do not use lsb uuid label
   buf->f_fsid.val[0] = (u32)id;
   buf->f_fsid.val[1] = (u32)(id >> 32);
   return 0;
}

static void
init_once(void *foo)
{
    struct luci_inode_info *ei = (struct luci_inode_info *) foo;
    inode_init_once(&ei->vfs_inode);
}

static int
init_inodecache(void)
{
    luci_inode_cachep = kmem_cache_create("luci_inode_cache",
            sizeof(struct luci_inode_info),
            0,
            (SLAB_RECLAIM_ACCOUNT|SLAB_MEM_SPREAD),
            init_once);

    if (luci_inode_cachep == NULL)
        return -ENOMEM;
    return 0;
}

static void
destroy_inodecache(void)
{
    rcu_barrier();
    kmem_cache_destroy(luci_inode_cachep);
}

static const struct super_operations luci_sops = {
    .alloc_inode    = luci_alloc_inode,
    .destroy_inode  = luci_destroy_inode,
    .put_super = luci_put_super,
    .write_inode = luci_write_inode,
    .drop_inode = luci_drop_inode,
    .evict_inode = luci_evict_inode,
    .statfs = luci_statfs,
};

static void
luci_print_sbinfo(struct super_block *sb) {
    if (sb && sb->s_fs_info) {
        struct luci_sb_info *sbi = sb->s_fs_info;
        luci_dbg("desc_per_block :%lu "
                "gdb :%lu blocks_count :%u inodes_count :%u "
                "block_size :%lu blocks_per_group :%lu "
                "first_data_block :%u groups_count :%lu", sbi->s_desc_per_block,
                sbi->s_gdb_count, sbi->s_lsb->s_blocks_count,
                sbi->s_lsb->s_inodes_count, sb->s_blocksize,
                sbi->s_blocks_per_group, sbi->s_lsb->s_first_data_block,
                sbi->s_groups_count);
    }
}

static int
luci_check_descriptors(struct super_block *sb) {
    int i, j;
    uint32_t block_map, inode_map, inode_tbl;
    struct luci_sb_info *sbi = sb->s_fs_info;

    for (i = 0; i < sbi->s_gdb_count; i++) {
        struct buffer_head *bh = sbi->s_group_desc[i];
        for (j = 0; j < sbi->s_desc_per_block; j++) {
            struct luci_group_desc *gdesc;
            luci_fsblk_t first_block, last_block;
            uint32_t gp = (i * sbi->s_desc_per_block) + j + 1;
            if (gp > sbi->s_groups_count) {
                goto done;
            }

            first_block = luci_group_first_block_no(sb, (i + 1)* j);

            if (gp == sbi->s_groups_count - 1) {
                last_block = sbi->s_lsb->s_blocks_count - 1;
            } else {
                last_block = first_block + sbi->s_blocks_per_group - 1;
            }

            gdesc = (struct luci_group_desc*)
                (bh->b_data +  j * sizeof(struct luci_group_desc));

            block_map = le32_to_cpu(gdesc->bg_block_bitmap);
            luci_dbg("block bitmap for group[%u]:%u", gp, block_map);
            if ((block_map < first_block) || (block_map > last_block)) {
                luci_err("failed, block bitmap for group %d invalid block"
                   " no %u", (i + 1) * j, block_map);
                return -EINVAL;
            }

            inode_map = le32_to_cpu(gdesc->bg_inode_bitmap);
            if ((inode_map < first_block) || (inode_map > last_block)) {
                luci_err("failed, inode bitmap for group %d invalid block"
                   " no %u", (i + 1) * j, inode_map);
                return -EINVAL;
            }

            inode_tbl = le32_to_cpu(gdesc->bg_inode_table);
            if ((inode_tbl < first_block) || (inode_tbl > last_block)) {
                luci_err("failed, inode table for group %d invalid block"
                   " no %u", (i + 1) * j, inode_tbl);
                return -EINVAL;
            }
        }
    }

done:
    return 0;
}

static void
luci_dump_blockbitmap(struct super_block *sb) {
   int i = 0;
   struct luci_sb_info *sbi = sb->s_fs_info;
   for (; i < sbi->s_groups_count; i++) {
      read_block_bitmap(sb, i);
      read_inode_bitmap(sb, i);
   }
}

static void
luci_check_superblock_backups(struct super_block *sb) {
    int i, j;
    uint32_t gp;
    struct buffer_head *bh;
    struct luci_super_block *lsb;
    luci_fsblk_t first_block;
    struct luci_sb_info *sbi = sb->s_fs_info;

    for (i = 0; i < sbi->s_gdb_count; i++) {
        for (j = 0; j < sbi->s_desc_per_block; j++) {
            gp = (i * sbi->s_desc_per_block) + j + 1;
            if (gp > sbi->s_groups_count) {
                return;
            }

            if (gp > 1) {
                first_block = luci_group_first_block_no(sb, (i + 1)* j);
                bh = sb_bread(sb, first_block);
                lsb = (struct luci_super_block*)((char*) bh->b_data);
                if (le16_to_cpu(lsb->s_magic) == LUCI_SUPER_MAGIC) {
                    luci_dbg("superblock backup at block %lu group %u ",
                       first_block, (i + 1) *j);
                }
                brelse(bh);
            }
        }
    }
}

static int
luci_runlayoutchecks(struct super_block *sb) {
    luci_print_sbinfo(sb);
    if ((luci_check_descriptors(sb))) {
        return -EINVAL;
    }
    luci_check_superblock_backups(sb);
    return 0;
}

static size_t
luci_file_maxsize(struct super_block *sb) {
    size_t size, dir, indir, dindir, tindir;
    // Calculate the leaves
    dir = LUCI_NDIR_BLOCKS;
    indir = 1 * LUCI_ADDR_PER_BLOCK(sb);
    dindir = indir * LUCI_ADDR_PER_BLOCK(sb);
    tindir = dindir * LUCI_ADDR_PER_BLOCK(sb);
    size = (dir + indir + dindir + tindir) * sb->s_blocksize;
    luci_dbg("maxsize :%lu", size);
    return size;
}

static int
luci_read_superblock(struct super_block *sb) {
    int ret = 0;
    long i;
    unsigned long block_no;
    unsigned long block_of;
    unsigned long block_size;
    struct buffer_head *bh;
    struct luci_super_block *lsb;
    struct luci_sb_info *sbi;

    sbi = kzalloc(sizeof(struct luci_sb_info), GFP_KERNEL);
    if (!sbi) {
        return -ENOMEM;
    }

    // Note : This block number assumes BLOCK_SIZE
    block_no = 1;

    // internally sets sb block_size based on min
    (void) sb_min_blocksize(sb, BLOCK_SIZE);

restart:

    if (sb->s_blocksize != BLOCK_SIZE) {
        block_of = (block_no*BLOCK_SIZE)%sb->s_blocksize;
        block_no = (block_no*BLOCK_SIZE)/sb->s_blocksize;
    } else {
        block_of = 0;
    }

    if (!(bh = sb_bread(sb, block_no))) {
        luci_err("error reading super block");
        ret = -EIO;
        goto failed_sbi;
    }

    if (sb->s_blocksize != bh->b_size) {
        luci_err("invalid block-size in buffer-head");
        brelse(bh);
        ret = -EIO;
        goto failed_sbi;
    }

    // luci on-disk super-block format
    lsb = (struct luci_super_block*)((char*) bh->b_data + block_of);
    sbi->s_lsb = lsb;

    sb->s_magic = le16_to_cpu(lsb->s_magic);
    if (sb->s_magic != LUCI_SUPER_MAGIC) {
        luci_err("invalid magic number on super-block");
        ret = -EINVAL;
        goto failed_mount;
    }

    luci_dbg("magic number on block:%lu(%lu)",block_no, block_of);

    // get the on-disk block size
    block_size = BLOCK_SIZE << le32_to_cpu(lsb->s_log_block_size);
    if (sb->s_blocksize != block_size) {
        brelse(bh);
        if (!sb_set_blocksize(sb, block_size)) {
            ret = -EPERM;
            goto failed_mount;
        }
        luci_dbg("default block size mismatch! re-reading...");
        goto restart;
    }

    sbi->s_sbh = bh;
    sb->s_maxbytes = luci_file_maxsize(sb);
    sb->s_max_links = LUCI_LINK_MAX;

    // inode size
    sbi->s_inode_size = le16_to_cpu(lsb->s_inode_size);
    if ((sbi->s_inode_size < LUCI_GOOD_OLD_INODE_SIZE) ||
            (sbi->s_inode_size > sb->s_blocksize) ||
            (!is_power_of_2(sbi->s_inode_size))) {
        luci_err("invalid inode size in super block :%d", sbi->s_inode_size);
        ret = -EINVAL;
        goto failed_mount;
    }

    sbi->s_inodes_per_block = sb->s_blocksize/sbi->s_inode_size;
    if (sbi->s_inodes_per_block == 0) {
        luci_err("invalid inodes per block");
        ret = -EINVAL;
        goto failed_mount;
    }

    // fragment size
    sbi->s_frag_size = LUCI_MIN_FRAG_SIZE << le32_to_cpu(lsb->s_log_frag_size);
    if (sbi->s_frag_size == 0) {
        luci_err("fragment size invalid");
        ret = -EINVAL;
        goto failed_mount;
    }
    sbi->s_frags_per_block = sb->s_blocksize/sbi->s_frag_size;

    sbi->s_first_ino = le32_to_cpu(lsb->s_first_ino);

    // block group
    sbi->s_frags_per_group = le32_to_cpu(lsb->s_frags_per_group);
    // check based on bits per block
    if ((sbi->s_frags_per_group == 0) ||
            (sbi->s_frags_per_group > sb->s_blocksize * 8)) {
        luci_err("invalid frags per group");
        ret = -EINVAL;
        goto failed_mount;
    }

    sbi->s_blocks_per_group = le32_to_cpu(lsb->s_blocks_per_group);
    // check based on bits per block
    if ((sbi->s_blocks_per_group == 0) ||
            (sbi->s_blocks_per_group > sb->s_blocksize * 8)) {
        luci_err("invalid blocks per group");
        ret = -EINVAL;
        goto failed_mount;
    }
    sbi->s_inodes_per_group = le32_to_cpu(lsb->s_inodes_per_group);
    if ((sbi->s_inodes_per_group == 0) ||
            (sbi->s_inodes_per_group > sb->s_blocksize * 8)) {
        luci_err("invalid inodes per group");
        ret = -EINVAL;
        goto failed_mount;
    }

    // blocks to store inode table
    sbi->s_itb_per_group = sbi->s_inodes_per_group/sbi->s_inodes_per_block;
    // group desc per block
    sbi->s_desc_per_block = sb->s_blocksize/sizeof(struct luci_group_desc);

    sbi->s_mount_state = le16_to_cpu(lsb->s_state);

    sbi->s_addr_per_block_bits = ilog2 (LUCI_ADDR_PER_BLOCK(sb));
    sbi->s_desc_per_block_bits = ilog2 (sbi->s_desc_per_block);

    // nr_groups
    sbi->s_groups_count = ((le32_to_cpu(lsb->s_blocks_count) -
                le32_to_cpu(lsb->s_first_data_block) - 1)/ sbi->s_blocks_per_group) + 1;
    sbi->s_gdb_count =
        (sbi->s_groups_count + sbi->s_desc_per_block - 1)/sbi->s_desc_per_block;
    // bh array
    sbi->s_group_desc = (struct buffer_head **) kmalloc
        (sbi->s_gdb_count * sizeof(struct buffer_head *), GFP_KERNEL);
    if (sbi->s_group_desc == NULL) {
        ret = -ENOMEM;
        luci_err("cannot allocate memory for group descriptors");
        goto failed_mount;
    }

    for (i = 0; i < sbi->s_gdb_count; i++) {
        // Meta-bg not supported
        sbi->s_group_desc[i] = sb_bread(sb, block_no + i + 1);
        if (sbi->s_group_desc[i] == NULL) {
            luci_err("failed to read group descriptors");
            ret = -EIO;
            goto failed_gdb;
        }
    }

    sb->s_fs_info = sbi;

    if (luci_runlayoutchecks(sb)) {
        ret = -EINVAL;
        goto failed_layoutcheck;
    }

    luci_dump_blockbitmap(sb);

    // ready the super-block for any operations
    sb->s_op = &luci_sops;

    // increase mount count
    le16_add_cpu(&lsb->s_mnt_count, 1);

    lsb->s_wtime = cpu_to_le32(get_seconds());
    mark_buffer_dirty(sbi->s_sbh);
    sync_dirty_buffer(sbi->s_sbh);

    luci_dbg("super_block read successfull");
    return 0;

failed_layoutcheck:
    i = sbi->s_gdb_count - 1;
failed_gdb:
    for (;i >= 0; i--) {
        brelse(sbi->s_group_desc[i]);
    }
    kfree(sbi->s_group_desc);
failed_mount:
    sbi->s_sbh = NULL;
    brelse(bh);
failed_sbi:
    kfree(sbi);
    luci_err("luci super block read error");
    return ret;
}

void
luci_free_super(struct super_block * sb) {
    struct luci_sb_info *sbi;

    if (sb->s_root) {
       struct inode * root_inode = d_inode(sb->s_root);
       iput(root_inode);
       sb->s_root = NULL;
    }

    sbi = sb->s_fs_info;
    if (sbi) {
       if (sbi->s_group_desc) {
	  int i;
          for (i = 0; i < sbi->s_gdb_count; i++) {
             struct buffer_head *bh = sbi->s_group_desc[i];
             brelse(bh);
          }
          kfree(sbi->s_group_desc);
       }

       if (sbi->s_sbh) {
          brelse(sbi->s_sbh);
       }
       kfree(sbi);
    }
}

static struct dentry*
luci_read_rootinode(struct super_block *sb) {
    struct dentry *dentry;
    struct inode *root_inode;

    root_inode = luci_iget(sb, LUCI_ROOT_INO);
    if (IS_ERR(root_inode)) {
        luci_err("failed to read root dir inode");
        return ERR_PTR(-EIO);
    }

    if (!S_ISDIR(root_inode->i_mode) || !root_inode->i_blocks ||
            !root_inode->i_size) {
        luci_err("corrupt root dir inode.");
        iput(root_inode);
        return ERR_PTR(-EINVAL);
    }

    root_inode->i_fop = &luci_dir_operations;
    root_inode->i_op = &luci_dir_inode_operations;
    root_inode->i_mapping->a_ops = &luci_aops;

#if HAVE_D_OBTAIN_ROOT
    dentry = d_obtain_root(root_inode);
#else
    dentry = d_make_root(root_inode);
#endif

    if (IS_ERR(dentry)) {
        luci_err("root dir inode dentry error.");
    }

    return dentry;
}

enum {
    Opt_debug, Opt_extents
};

static const match_table_t tokens = {
    {Opt_debug, "debug"},
    {Opt_extents, "extents"},
};

static int parse_options(char *options, struct super_block *sb)
{
    char *p;
    struct luci_sb_info *sbi = LUCI_SB(sb);
    substring_t args[MAX_OPT_ARGS];

    if (!options)
        return 1;

    while ((p = strsep (&options, ",")) != NULL) {
        int token;
        if (!*p)
            continue;

        token = match_token(p, tokens, args);
        switch (token) {
        case Opt_debug:
	    debug = 1;
            set_opt (sbi->s_mount_opt, LUCI_MOUNT_DEBUG);
            break;
	case Opt_extents:
            set_opt (sbi->s_mount_opt, LUCI_MOUNT_EXTENTS);
	    luci_dbg("extent allocation enabled for files");
            break;
	default:
	    luci_err("Unrecognized mount option : %s", p);
	    return 0;
        }
    }
    return 1;
}

static int
luci_fill_super(struct super_block *sb, void *data, int silent)
{
    int ret = 0;
    struct dentry* dentry;

    ret = luci_read_superblock(sb);
    if (ret != 0) {
       goto free_sb;
    }

    if (!parse_options((char *)data, sb)) {
       ret = -EINVAL;
       goto free_sb;
    }

    dentry = luci_read_rootinode(sb);
    if (IS_ERR(dentry)) {
       ret = PTR_ERR(dentry);
       goto free_sb;
    }
    sb->s_root = dentry;
    luci_dbg("luci super block read sucess");
    return 0;

free_sb:
    luci_free_super(sb);
    return ret;
}

static struct dentry *
luci_mount(struct file_system_type *fs_type, int flags,
        const char *dev_name, void *data)
{
    return mount_bdev(fs_type, flags, dev_name, data, luci_fill_super);
}

struct file_system_type luci_fs = {
    .owner    = THIS_MODULE,
    .name     = "luci",
    .mount    = luci_mount,
    .kill_sb  = kill_block_super,
    .fs_flags = FS_REQUIRES_DEV,
};

static int
__init init_luci_fs(void)
{
    int err;

    err = init_inodecache();
    if (err)
        return err;

    err = register_filesystem(&luci_fs);
    if (err)
        goto failed;

    luci_dbg("LUCI FS loaded");
    return 0;

failed:
    destroy_inodecache();
    return err;
}

static void
__exit exit_luci_fs(void)
{
    unregister_filesystem(&luci_fs);
    destroy_inodecache();
}

module_init(init_luci_fs)
module_exit(exit_luci_fs)
