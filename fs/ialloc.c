/*-----------------------------------------------------------
 * Copyright(C) 2016-2017, Saptarshi Sen
 *
 * Luci block allocation
 *
 * ----------------------------------------------------------*/
#include "luci.h"

#include <linux/fs.h>
#include <linux/buffer_head.h>
#include <linux/version.h>
#include <linux/dcache.h>
#include <linux/path.h>
#include <linux/mpage.h>

struct luci_group_desc *
luci_get_group_desc(struct super_block *sb,
   unsigned int block_group, struct buffer_head **bh) {
   unsigned long desc_block, off;
   struct buffer_head *bh_desc;
   struct luci_group_desc *gdesc;
   struct luci_sb_info *sbi =  LUCI_SB(sb);

   if (sbi == NULL) {
      luci_err("super block info not found");
      goto badsuper;
   }

   if (block_group > sbi->s_groups_count) {
      luci_err("Invalid block group :%u", block_group);
      goto badsuper;
   }

   desc_block = block_group >> LUCI_DESC_PER_BLOCK_BITS(sb);
   bh_desc = sbi->s_group_desc[desc_block];
   if (bh_desc == NULL) {
      goto badsuper;
   }
   if (bh != NULL) {
      *bh = bh_desc;
   }
   off = block_group & (LUCI_DESC_PER_BLOCK(sb) - 1);
   // Fix : pointer alignment fixed
   gdesc = (struct luci_group_desc*) (bh_desc->b_data +
      off * sizeof(struct luci_group_desc));
   return gdesc;

badsuper:
   return NULL;
}

struct buffer_head *
read_inode_bitmap(struct super_block *sb, unsigned long block_group) {
   uint32_t bmap_block;
   struct luci_group_desc *gdesc;
   struct buffer_head *bh_bmap;

   if (!(gdesc = luci_get_group_desc(sb, block_group, NULL))) {
      return NULL;
   }
   bmap_block = gdesc->bg_inode_bitmap;
   if (!(bh_bmap = sb_bread(sb, bmap_block))) {
      luci_err("Unable to read inode bitmap for block group :%lu"
         " block no :%u", block_group, bmap_block);
   }
   return bh_bmap;
}

struct buffer_head *
read_block_bitmap(struct super_block *sb, unsigned long block_group) {
#ifdef DEBUG_BMAP
   int i = 0;
#endif
   uint32_t bmap_block;
   struct luci_group_desc *gdesc;
   struct buffer_head *bh_bmap;

   if (!(gdesc = luci_get_group_desc(sb, block_group, NULL))) {
      return NULL;
   }
   bmap_block = gdesc->bg_block_bitmap;
   luci_dbg("block group :%lu nr_free blocks : %u", block_group,
      gdesc->bg_free_blocks_count);
   if (!(bh_bmap = sb_bread(sb, bmap_block))) {
      luci_err("Unable to read block bitmap for block group :%lu"
         " block no :%u", block_group, bmap_block);
      goto out;
   }
#ifdef DEBUG_BMAP
   for (i = 0; i < bh_bmap->b_size/sizeof(uint32_t); i++) {
      luci_dbg("block_group :%ld [%d] : 0x%08x", block_group, i,
         *((uint32_t*)bh_bmap->b_data + i));
   }
#endif
out:
   return bh_bmap;
}

void
luci_free_inode (struct inode * inode) {
   struct super_block *sb;
   struct luci_sb_info *sbi;
   struct luci_group_desc *gdesc;
   unsigned long ino, bit, block_group;
   struct buffer_head *bh_bitmap, *bh;
#ifdef DEBUG_BMAP
   int i;
   char *p;
#endif

   sb = inode->i_sb;
   sbi = LUCI_SB(sb);

   ino = inode->i_ino;
   BUG_ON(ino == 0);
   if (ino < LUCI_FIRST_INO(sb) ||
      ino > sbi->s_lsb->s_inodes_count) {
      luci_err("cannot free inode, reserved inode :%lu",
         ino);
      return;
   }
   // Note -1 takes care of one-based index for inodes
   // Fix : use modulo
   bit = (ino - 1) % (sbi->s_lsb->s_inodes_per_group);

   block_group = ino/(sbi->s_lsb->s_inodes_per_group);
   luci_dbg("freeing inode:%lu in group:%lu", ino, block_group);
   bh_bitmap = read_inode_bitmap(sb, block_group);
   if (bh_bitmap == NULL) {
      luci_err("failed to free inode, error reading inode bitmap");
      return;
   }

#ifdef DEBUG_BMAP
   p = (char*)bh_bitmap->b_data;
   for (i = 0; i < 8; i++) {
      luci_dbg("bitmap :0x%02x", *((unsigned char*)p + i));
   }
#endif

   if (!(__test_and_clear_bit_le(bit, bh_bitmap->b_data))) {
      luci_err("free inode failed, bit already unset :%lu!", ino);
      return;
   }
   mark_buffer_dirty(bh_bitmap);

   gdesc = luci_get_group_desc(sb, block_group, &bh);
   if (gdesc == NULL) {
      luci_err("failed to free inode, erro reading group "
         "descriptor for group :%lu", block_group);
      goto out;
   }

   le16_add_cpu(&gdesc->bg_free_inodes_count, 1);
   if (S_ISDIR(inode->i_mode)) {
      le16_add_cpu(&gdesc->bg_used_dirs_count, -1);
   }
   mark_buffer_dirty(bh);
   if (sb->s_flags & MS_SYNCHRONOUS) {
      sync_dirty_buffer(bh);
      sync_dirty_buffer(bh_bitmap);
   }

out:
   brelse(bh_bitmap);
}

// Behaviour Control Flags based on module parameters
void
luci_init_inode_flags(struct inode *inode) {
   struct luci_sb_info *sbi = LUCI_SB(inode->i_sb);
   if (S_ISREG(inode->i_mode)) {
      struct luci_inode_info *li = LUCI_I(inode);
      li->i_flags |= sbi->s_mount_opt;
   }
}

struct inode *
luci_new_inode(struct inode *dir, umode_t mode, const struct qstr *qstr) {
   ino_t ino;
   int i, group, err;
   struct inode *inode;
   struct buffer_head *bh, *bitmap_bh;
   struct luci_group_desc *gdb;
   struct super_block *sb = dir->i_sb;
   struct luci_sb_info *sbi =  LUCI_SB(sb);
   struct luci_inode_info *li;

   inode = new_inode(sb);
   if (!inode) {
      luci_err("create inode failed, oom!");
      return ERR_PTR(-ENOMEM);
   }

   for (i = 0; i < sbi->s_groups_count; i++) {
      gdb = luci_get_group_desc(sb, i, &bh);
      if (gdb == NULL) {
         continue;
      }
      bitmap_bh = read_inode_bitmap(sb, i);
      if (bitmap_bh == NULL) {
         luci_err("create inode failed, read inode bitmap "
	    "failed for group :%d", i);
         err = -EIO;
         goto fail;
      }

      ino = find_next_zero_bit
	 ((unsigned long*)bitmap_bh->b_data, LUCI_INODES_PER_GROUP(sb), 0);
      if (ino < LUCI_INODES_PER_GROUP(sb)) {
         if (!(__test_and_set_bit_le(ino, bitmap_bh->b_data))) {
            group = i;
            mark_buffer_dirty(bitmap_bh);
            goto gotit;
         }
      }
      brelse(bitmap_bh);
   }
   err = -ENOSPC;
   luci_err("create inode failed, group is full");
   goto fail;

gotit:
   // Fix : note added 1 to ino, dentry maps treat 0 inode as empty
   ino += (group * LUCI_INODES_PER_GROUP(sb)) + 1;
   if (sb->s_flags & MS_SYNCHRONOUS) {
      sync_dirty_buffer(bitmap_bh);
   }
   brelse(bitmap_bh);
   percpu_counter_add(&sbi->s_freeinodes_counter, -1);
   le16_add_cpu(&gdb->bg_free_inodes_count, -1);
   if (S_ISDIR(mode)) {
      percpu_counter_inc(&sbi->s_dirs_counter);
      le16_add_cpu(&gdb->bg_used_dirs_count, 1);
   }
   mark_buffer_dirty(bh);

   inode_init_owner(inode, dir, mode);
   luci_init_inode_flags(inode);
   inode->i_ino = ino;
   luci_dbg("new inode :%lu in group :%d", ino, group);
   inode->i_blocks = 0;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,0,0)
   inode->i_mtime = inode->i_atime = inode->i_ctime = CURRENT_TIME;
#else
   inode->i_mtime = inode->i_atime = inode->i_ctime = current_time(inode);
#endif

   li = LUCI_I(inode);
   memset(li->i_data, 0, sizeof(li->i_data));
   li->i_faddr = 0;
   li->i_frag_no = 0;
   li->i_frag_size = 0;
   li->i_file_acl = 0;
   li->i_dir_acl = 0;
   li->i_dtime = 0;
   li->i_block_alloc_info = NULL;
   li->i_block_group = group;
   li->i_dir_start_lookup = 0;
   li->i_state = LUCI_STATE_NEW;
   inode->i_generation = sbi->s_next_generation++;
   if (insert_inode_locked(inode) < 0) {
      luci_dbg("inode locked during create inode :%lu", ino);
      err = -EIO;
      goto fail;
   }
   mark_inode_dirty(inode);
   return inode;

fail:
   make_bad_inode(inode);
   iput(inode);
   return ERR_PTR(err);
}

int
luci_new_block(struct inode *inode)
{
   int err = 0;
   int block;
   uint32_t gp;
   int block_group;
   struct super_block *sb;
   struct luci_sb_info *sbi;
   struct luci_inode_info *li;
   struct luci_group_desc *gdb = NULL;
   struct luci_super_block *lsb = NULL;
   struct buffer_head *bh = NULL, *bitmap_bh = NULL;

   sb = inode->i_sb;
   sbi = LUCI_SB(sb);
   li = LUCI_I(inode);
   for (gp = 0, block_group = li->i_block_group; gp < sbi->s_groups_count;
      block_group = (block_group + 1) % sbi->s_groups_count, gp++) {
      gdb = luci_get_group_desc(sb, block_group, &bh);
      if (gdb == NULL) {
         err = -EIO;
         goto fail;
      }

      if (gdb->bg_free_blocks_count == 0) {
         continue;
      }

      bitmap_bh = read_block_bitmap(sb, block_group);
      if (bitmap_bh == NULL) {
         luci_err("error reading block bmap gp :%d",block_group);
         err = -EIO;
         goto fail;
      }

      // returns size if no bits are zero
      block = find_next_zero_bit((unsigned long*)bitmap_bh->b_data,
         LUCI_BLOCKS_PER_GROUP(sb), 0);

      #ifdef DEBUG_BMAP
      luci_dbg("Finding zero bit in group %d(%d)", block_group, block);
      luci_dbg("%lx", *(unsigned long*)bitmap_bh->b_data);
      #endif

      if (block < LUCI_BLOCKS_PER_GROUP(sb)) {
         if (!(__test_and_set_bit_le(block, bitmap_bh->b_data))) {
            luci_dbg("found new block %d block_group :%d", block, block_group);
            goto gotit;
         }
      } else {
         luci_dbg("fetch new block failed, no blocks found in block group :%d "
            "nr free blocks :%u", block_group, gdb->bg_free_blocks_count);
      }

      brelse(bitmap_bh);
      //brelse(bh);
   }
   luci_err("create block failed, space is full");
   return -ENOSPC;

gotit:
   mark_buffer_dirty(bitmap_bh);
   if (sb->s_flags & MS_SYNCHRONOUS) {
      sync_dirty_buffer(bitmap_bh);
   }
   brelse(bitmap_bh);

   le16_add_cpu(&gdb->bg_free_blocks_count, -1);
   mark_buffer_dirty(bh);
   //brelse(bh);

   percpu_counter_add(&sbi->s_freeblocks_counter, -1);
   lsb = sbi->s_lsb;
   lsb->s_free_blocks_count--;
   //TBD : We are not updating the super-block across all backups
   mark_buffer_dirty(sbi->s_sbh);

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,0,0)
   inode->i_mtime = inode->i_atime = inode->i_ctime = CURRENT_TIME;
#else
   inode->i_mtime = inode->i_atime = current_time(inode);
#endif
   // sector based (TBD : add a macro for block to sector)
   inode->i_blocks+=luci_sectors_per_block(inode);
   mark_inode_dirty(inode);
   return block + (block_group * sbi->s_blocks_per_group);
fail:
   //brelse(bh);
   return err;
}
