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
      printk(KERN_ERR "luci super block info not found");
      goto badsuper;
   }

   if (block_group > sbi->s_groups_count) {
      printk(KERN_ERR "Invalid block group :%u", block_group);
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
   gdesc = (struct luci_group_desc*) (bh_desc->b_data + off);
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
      printk(KERN_ERR "Unable to read inode bitmap for block group :%lu",
         block_group);
   }
   return bh_bmap;
}

struct buffer_head *
read_block_bitmap(struct super_block *sb, unsigned long block_group) {
#ifdef DEBUG
   int i = 0;
#endif
   uint32_t bmap_block;
   struct luci_group_desc *gdesc;
   struct buffer_head *bh_bmap;

   if (!(gdesc = luci_get_group_desc(sb, block_group, NULL))) {
      return NULL;
   }
   bmap_block = gdesc->bg_block_bitmap;
   if (!(bh_bmap = sb_bread(sb, bmap_block))) {
      printk(KERN_ERR "Unable to read block bitmap for block group :%lu",
         block_group);
      goto out;
   }
#ifdef DEBUG
   for (i = 0; i < bh_bmap->b_size/sizeof(unsigned int); i++) {
      printk(KERN_ERR "%s block_group :%ld [%d] : %x", __func__, block_group, i,
              *((unsigned int*)bh_bmap->b_data + i));
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
#ifdef DEBUG
   int i;
   char *p;
#endif

   sb = inode->i_sb;
   sbi = LUCI_SB(sb);

   ino = inode->i_ino;
   BUG_ON(ino == 0);
   if (ino < LUCI_FIRST_INO(sb) ||
      ino > sbi->s_lsb->s_inodes_count) {
      printk(KERN_ERR "luci : cannot free inode, reserved inode :%lu",
         ino);
      return;
   }
   // Note -1 takes care of one-based index for inodes
   // Fix : use modulo
   bit = (ino - 1) % (sbi->s_lsb->s_inodes_per_group);

   block_group = ino/(sbi->s_lsb->s_inodes_per_group);
   printk(KERN_INFO "luci : freeing inode:%lu in group:%lu", ino, block_group);
   bh_bitmap = read_inode_bitmap(sb, block_group);
   if (bh_bitmap == NULL) {
      printk(KERN_ERR "luci : failed to free inode, error reading inode bitmap");
      return;
   }

#ifdef DEBUG
   p = (char*)bh_bitmap->b_data;
   for (i = 0; i < 8; i++) {
      printk(KERN_INFO "bitmap :0x%02x", *((unsigned char*)p + i));
   }
#endif

   if (!(__test_and_clear_bit_le(bit, bh_bitmap->b_data))) {
      printk(KERN_ERR "luci : free inode failed, bit already unset :%lu!", ino);
      return;
   }
   mark_buffer_dirty(bh_bitmap);

   gdesc = luci_get_group_desc(sb, block_group, &bh);
   if (gdesc == NULL) {
      printk(KERN_ERR "luci : failed to free inode, erro reading group "
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
      printk(KERN_ERR "Luci : create inode failed, oom!");
      return ERR_PTR(-ENOMEM);
   }

   for (i = 0; i < sbi->s_groups_count; i++) {
      gdb = luci_get_group_desc(sb, i, &bh);
      if (gdb == NULL) {
         continue;
      }
      bitmap_bh = read_inode_bitmap(sb, i);
      if (bitmap_bh == NULL) {
         printk(KERN_ERR "Luci : create inode failed, read inode bitmap "
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
   printk (KERN_ERR "Luci : create inode failed, group is full");
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
      le16_add_cpu(&gdb->bg_used_dirs_count, -1);
   }
   mark_buffer_dirty(bh);

   inode_init_owner(inode, dir, mode);
   inode->i_ino = ino;
   printk(KERN_INFO "Luci : new inode :%lu in group :%d", ino, group);
   inode->i_blocks = 0;
   inode->i_mtime = inode->i_atime = inode->i_ctime = current_time(inode);

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
      printk (KERN_ERR "Luci :inode locked during create inode :%lu", ino);
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
   int block_group;
   struct super_block *sb;
   struct luci_sb_info *sbi;
   struct luci_super_block *lsb;
   struct luci_inode_info *li;
   struct luci_group_desc *gdb;
   struct buffer_head *bh, *bitmap_bh;

   li = LUCI_I(inode);
   sb = inode->i_sb;
   block_group = li->i_block_group;
   gdb = luci_get_group_desc(sb, block_group, &bh);
   if (gdb == NULL) {
      err = -EIO;
      goto fail;
   }

   bitmap_bh = read_block_bitmap(sb, block_group);
   if (bitmap_bh == NULL) {
      err = -EIO;
      goto fail;
   }

   block = find_next_zero_bit((unsigned long*)bitmap_bh->b_data,
      LUCI_BLOCKS_PER_GROUP(sb), 0);
#ifdef DEBUG
   printk(KERN_INFO "Finding zero bit in block group %d : %d", block_group, block);
   printk(KERN_INFO "%lx", *(unsigned long*)bitmap_bh->b_data);
#endif
   // Currently we support block allocation from the same block group
   if (block < LUCI_BLOCKS_PER_GROUP(sb)) {
      if (!(__test_and_set_bit_le(block, bitmap_bh->b_data))) {
     printk(KERN_INFO "Luci :found new block %d", block);
         goto gotit;
      }
   } else {
      printk(KERN_ERR "luci : fetch new block failed, no blocks found in "
         "group block bitmap");
   }

   brelse(bitmap_bh);
   //brelse(bh);
   return -ENOSPC;

gotit:
   mark_buffer_dirty(bitmap_bh);
   if (sb->s_flags & MS_SYNCHRONOUS) {
      sync_dirty_buffer(bitmap_bh);
   }
   brelse(bitmap_bh);

   le16_add_cpu(&gdb->bg_free_inodes_count, -1);
   mark_buffer_dirty(bh);
   //brelse(bh);

   sbi = LUCI_SB(inode->i_sb);
   percpu_counter_add(&sbi->s_freeblocks_counter, -1);
   lsb = sbi->s_lsb;
   lsb->s_free_blocks_count--;
   mark_buffer_dirty(sbi->s_sbh);

   inode->i_mtime = inode->i_atime = current_time(inode);
   inode->i_blocks++;
   mark_inode_dirty(inode);
   return block;
fail:
   //brelse(bh);
   return err;
}
