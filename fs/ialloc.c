/*-----------------------------------------------------------
 * Copyright(C) 2016-2017, Saptarshi Sen
 *
 * Luci block allocation
 *
 * ----------------------------------------------------------*/
#include "luci.h"
#include "kern_feature.h"

#include <linux/fs.h>
#include <linux/buffer_head.h>
#include <linux/version.h>
#include <linux/dcache.h>
#include <linux/path.h>
#include <linux/mpage.h>

#include "trace.h"
EXPORT_TRACEPOINT_SYMBOL_GPL(luci_free_block);
EXPORT_TRACEPOINT_SYMBOL_GPL(luci_free_inode);
EXPORT_TRACEPOINT_SYMBOL_GPL(luci_new_inode);

/* 16-bit CRC for group descriptor */
static inline void
luci_bg_update_csum(struct luci_group_desc *gdesc)
{
        u32 crc32, crc32seed = ~0U;

        gdesc->bg_checksum = 0; //clear for checksum
        crc32 = luci_compute_data_cksum((void *)gdesc,
                                         sizeof(struct luci_group_desc),
                                         crc32seed);
        gdesc->bg_checksum = crc32 & 0xFFFF;
}

/* 32-bit CRC of group desciptor block bitmap */
static inline void
luci_bg_block_bitmap_update_csum(struct luci_group_desc *gdesc,
                struct buffer_head *bh_bitmap)
{
        u32 crc32, crc32seed = ~0U;
        crc32 = luci_compute_page_cksum(bh_bitmap->b_page, 0, PAGE_SIZE, crc32seed);
        gdesc->bg_block_bitmap_checksum = crc32 & 0xFFFF;
}

/* 32-bit CRC of group desciptor inode bitmap */
static inline void
luci_bg_inode_bitmap_update_csum(struct luci_group_desc *gdesc,
                struct buffer_head *bh_inode)
{
        u32 crc32, crc32seed = ~0U;
        crc32 = luci_compute_page_cksum(bh_inode->b_page, 0, PAGE_SIZE, crc32seed);
        gdesc->bg_inode_bitmap_checksum = crc32 & 0xFFFF;
}

/* inode attribute */
static void luci_init_inode_flags(struct inode *inode) {
        if (S_ISREG(inode->i_mode)) {
                struct luci_inode_info *li = LUCI_I(inode);
#ifdef LUCIFS_COMPRESSION
                li->i_flags |= LUCI_COMPR_FL;
#else
                li->i_flags |= LUCI_NOCOMP_FL;
#endif
        }
}

static unsigned int
luci_alloc_bitmap(unsigned long *addr,
                unsigned int nr_bits,
                unsigned int max_bits)
{
        u8 *start_bp, *end_bp;
        unsigned int start_bit = 0, end_bit = 0, next_bit = 0, off_bit;

        if (nr_bits > (1 << BYTE_SHIFT)) {
                luci_err("request for more bits than possible in a byte range");
                BUG();
        }

        // loop till you find zero bit position for range to allocate
        do {
                start_bit = find_next_zero_bit(addr, max_bits, next_bit);

                // bitmap range full, no free bit
                if (start_bit >= max_bits) {
                        goto fail;
                }
                end_bit = start_bit + nr_bits - 1;
                // bitmap cannot accomdate range, bail out
                if (end_bit >= max_bits) {
                        goto fail;
                }
                // translate bitpos to a byte nr
                start_bp = (u8 *)addr + (start_bit >> BYTE_SHIFT);

                end_bp = (u8 *)addr + (end_bit >> BYTE_SHIFT);

                off_bit = start_bit % 8;

                if (bitmap_find_first_fit(start_bp, end_bp, off_bit, nr_bits)) {
                        bitmap_mark_first_fit(start_bp, end_bp, off_bit, nr_bits);
                        goto done;
                }

                next_bit = end_bit + 1;
                // skip the last bit for now
        } while (next_bit < max_bits);

fail:
        return max_bits;
done:
        return start_bit;
}

/*
 * block group desciptors are cached for metadata lookups
 * Do NOT need checksum verification here.
 */
struct luci_group_desc *
luci_get_group_desc(struct super_block *sb, unsigned int bg,
                    struct buffer_head **bh) {
        unsigned long bg_index;
        struct buffer_head *bh_bgtbl;
        struct luci_sb_info *sbi =  LUCI_SB(sb);

        BUG_ON(!sbi);

        if (bg > sbi->s_groups_count) {
                luci_err("Invalid block group :%u", bg);
                BUG();
        }

        bh_bgtbl = sbi->s_group_desc[(bg >> LUCI_DESC_PER_BLOCK_BITS(sb))];
        if (!bh_bgtbl) {
                luci_err("null bh for bg :%u", bg);
                goto badsuper;
        }

        if (bh != NULL)
                *bh = bh_bgtbl;

        bg_index = bg & (LUCI_DESC_PER_BLOCK(sb) - 1);
        return (struct luci_group_desc*)
                (bh_bgtbl->b_data + bg_index * sizeof(struct luci_group_desc));
badsuper:

        return NULL;
}

/*
 * read inode bitmap of a block group.
 * The following cases come up with respect to integrity checking here:
 *     1. meta-data is not cached. Need check.
 *     2. meta-data is cached. Do NOT need check.
 *     3. meta-data is dirty. Do NOT need check.
 */
struct buffer_head *
read_inode_bitmap(struct super_block *sb, unsigned long bg) {
        u32 crc;
        bool cached;
        uint32_t bmap_block;
        struct buffer_head *bmap_bh;
        struct luci_group_desc *gdesc;

        gdesc = luci_get_group_desc(sb, bg, NULL);
        if (!gdesc)
                goto err;

        bmap_block = gdesc->bg_inode_bitmap;

        cached = true;
        bmap_bh = sb_find_get_block(sb, bmap_block);
        if (!bmap_bh) {
                cached = false;
                bmap_bh = sb_bread(sb, bmap_block);
        }

        if (!bmap_bh) {
                luci_err("read error inode bitmap :%u/%lu", bmap_block, bg);
                goto err;
        }

        if (!cached && buffer_uptodate(bmap_bh) && trylock_buffer(bmap_bh)) {
                crc = gdesc->bg_inode_bitmap_checksum;
                if (crc) {
                        u32 crc_chk;

                        crc_chk = luci_compute_page_cksum(bmap_bh->b_page, 0, PAGE_SIZE, ~0U) & 0xFFFF;
                        if (crc != crc_chk) {
                                unlock_buffer(bmap_bh);
                                brelse(bmap_bh);
                                luci_err("crc mismatch 0x%x/0x%x bg=%lu block=%u",
                                        crc, crc_chk, bg, bmap_block);
                                goto err;
                        }
                }
                unlock_buffer(bmap_bh);
                luci_info("bg inode bitmap %lu crc OK", bg);
        }
        return bmap_bh;

err:
        return NULL;
}

/*
 * read block bitmap of a block group
 *     1. meta-data is not cached. Need check.
 *     2. meta-data is cached. Do NOT need check.
 *     3. meta-data is dirty. Do NOT need check.
 *
 */
struct buffer_head *
read_block_bitmap(struct super_block *sb, unsigned long bg) {
        u32 crc;
        bool cached;
        uint32_t bmap_block;
        struct luci_group_desc *gdesc;
        struct buffer_head *bmap_bh = NULL;
#ifdef DEBUG_BMAP
        int i = 0;
#endif

        gdesc = luci_get_group_desc(sb, bg, NULL);
        if (!gdesc)
                goto err;

        //luci_dbg("block group :%lu nr_free blocks : %u", bg, gdesc->bg_free_blocks_count);

        bmap_block = gdesc->bg_block_bitmap;

        cached = true;
        bmap_bh = sb_find_get_block(sb, bmap_block);
        if (!bmap_bh) {
                cached = false;
                bmap_bh = sb_bread(sb, bmap_block);
        }

        if (!bmap_bh) {
                luci_err("read error block bitmap :%u/%lu", bmap_block, bg);
                goto err;
        }

        if (!cached && buffer_uptodate(bmap_bh) && trylock_buffer(bmap_bh)) {
                crc = gdesc->bg_block_bitmap_checksum;
                if (crc) {
                        u32 crc_chk;

                        crc_chk = luci_compute_page_cksum(bmap_bh->b_page, 0, PAGE_SIZE, ~0U) & 0xFFFF;
                        if (crc != crc_chk) {
                                unlock_buffer(bmap_bh);
                                brelse(bmap_bh);
                                luci_err("crc mismatch 0x%x/0x%x bg=%lu block=%u",
                                        crc, crc_chk, bg, bmap_block);
                                goto err;
                        }
                }
                unlock_buffer(bmap_bh);
                //luci_dbg("bg block bitmap %lu crc OK", bg);
        }

#ifdef DEBUG_BMAP
        for (i = 0; i < bmap_bh->b_size/sizeof(uint32_t); i++)
                luci_dbg("bg :%ld [%d] : 0x%08x", bg, i,
                                *((uint32_t*)bmap_bh->b_data + i));
#endif
        return bmap_bh;

err:
        return NULL;
}

/*
 * update inode bitmap
 */
void
luci_free_inode (struct inode *inode) {
#ifdef DEBUG_BMAP
        int i;
        char *p;
#endif
        unsigned long bg, bit;
        ino_t ino = inode->i_ino;
        struct luci_group_desc *gdesc;
        struct super_block *sb = inode->i_sb;
        struct luci_sb_info *sbi = LUCI_SB(sb);
        struct buffer_head *bmap_bh, *bg_bh;

        BUG_ON(!ino);

        if (ino < LUCI_FIRST_INO(sb) || ino > sbi->s_lsb->s_inodes_count) {
                luci_err("cannot free reserved inode :%lu", ino);
                return;
        }

        bg = (ino - 1)/(sbi->s_lsb->s_inodes_per_group);

        gdesc = luci_get_group_desc(sb, bg, &bg_bh);
        if (!gdesc) {
                luci_err("free inode, error reading bg desc :%lu", bg);
                return;
        }

        bmap_bh = read_inode_bitmap(sb, bg);
        if (!bmap_bh) {
                luci_err("free inode, error reading inode bitmap");
                return;
        }

        luci_dbg("freeing inode:%lu in group:%lu", ino, bg);

#ifdef DEBUG_BMAP
        p = (char*)bmap_bh->b_data;
        for (i = 0; i < 8; i++)
                luci_dbg("bitmap :0x%02x", *((unsigned char*)p + i));
#endif

        // lock 1 for bg descriptor
        lock_buffer(bg_bh);

        // lock 2 for inode-bitmap block
        lock_buffer(bmap_bh);

        // Note -1 takes care of one-based index for inodes. Fix : use modulo
        bit = (ino - 1) % (sbi->s_lsb->s_inodes_per_group);

#ifdef HAVE_TRACEPOINT_ENABLED
        if (trace_luci_free_inode_enabled())
#endif
           trace_luci_free_inode(inode, bg, bit);

        if (!(__test_and_clear_bit_le(bit, bmap_bh->b_data))) {
                unlock_buffer(bmap_bh);
                unlock_buffer(bg_bh);
                luci_err("free inode error, bit already cleared :%lu!", ino);
                BUG();
                goto out;
        }

        luci_bg_inode_bitmap_update_csum(gdesc, bmap_bh);

        //release lock 2
        unlock_buffer(bmap_bh);

        le16_add_cpu(&gdesc->bg_free_inodes_count, 1);

        if (S_ISDIR(inode->i_mode))
                le16_add_cpu(&gdesc->bg_used_dirs_count, -1);

        luci_bg_update_csum(gdesc);

        //release lock 1
        unlock_buffer(bg_bh);

        mark_buffer_dirty(bmap_bh);
        if (sb->s_flags & MS_SYNCHRONOUS)
                sync_dirty_buffer(bmap_bh);

        mark_buffer_dirty(bg_bh);
        if (sb->s_flags & MS_SYNCHRONOUS)
                sync_dirty_buffer(bg_bh);

out:
        brelse(bmap_bh);
}

/*
 * update inode bitmap
 */
struct inode *
luci_new_inode(struct inode *dir, umode_t mode, const struct qstr *qstr) {
        ino_t ino;
        int i, group, err;
        unsigned long bit;
        struct inode *inode;
        struct buffer_head *bg_bh, *bmap_bh;
        struct luci_group_desc *gdesc;
        struct super_block *sb = dir->i_sb;
        struct luci_sb_info *sbi =  LUCI_SB(sb);
        struct luci_inode_info *li;

#if 0
        if (!(mode & S_IFMT)) {
                luci_err("unknown inode type! 0x%x", mode);
                return ERR_PTR(-EINVAL);
        }

        if (!(mode & S_IRWXU)) {
                luci_err("no permission bits specified for owner! 0x%x", mode);
                return ERR_PTR(-EINVAL);
        }
        if (mode & ~(S_IRWXUGO)) {
                luci_err("invalid mode permission bits 0x%x", mode);
                return ERR_PTR(-EINVAL);
        }
#endif

        inode = new_inode(sb);
        if (!inode) {
                luci_err("create inode failed, oom!");
                return ERR_PTR(-ENOMEM);
        }

        for (i = 0; i < sbi->s_groups_count; i++) {

                gdesc = luci_get_group_desc(sb, i, &bg_bh);
                if (!gdesc) {
                        err = -EIO;
                        luci_err("error getting bg descriptor :%d", i);
                        goto fail;
                }

                bmap_bh = read_inode_bitmap(sb, i);
                if (!bmap_bh) {
                        err = -EIO;
                        luci_err("read inode bitmap failed for group :%d", i);
                        goto fail;
                }

                // lock 1.
                lock_buffer(bg_bh);

                // lock 2.
                lock_buffer(bmap_bh);

                ino = find_next_zero_bit((unsigned long*)bmap_bh->b_data,
                                LUCI_INODES_PER_GROUP(sb),
                                0);

                if (ino < LUCI_INODES_PER_GROUP(sb)) {
                        if (!(__test_and_set_bit_le(ino, bmap_bh->b_data))) {
                                group = i;
                                mark_buffer_dirty(bmap_bh);
                                // unlock 2
                                unlock_buffer(bmap_bh);
                                goto gotit;
                        }
                }

                // unlock 2
                unlock_buffer(bmap_bh);

                // unlock 1
                unlock_buffer(bg_bh);

                brelse(bmap_bh);
        }

        err = -ENOSPC;
        luci_err("create inode failed, group is full");
        goto fail;

gotit:

        luci_bg_inode_bitmap_update_csum(gdesc, bmap_bh);

        le16_add_cpu(&gdesc->bg_free_inodes_count, -1);

        if (S_ISDIR(mode))
                le16_add_cpu(&gdesc->bg_used_dirs_count, 1);

        luci_bg_update_csum(gdesc);

        mark_buffer_dirty(bg_bh);

        // unlock 1
        unlock_buffer(bg_bh);

        bit = ino;
        // Fix : note added 1 to ino, dentry maps treat 0 inode as empty
        ino += (group * LUCI_INODES_PER_GROUP(sb)) + 1;

        inode_init_owner(inode, dir, mode);
        luci_init_inode_flags(inode);
        inode->i_ino = ino;
        inode->i_blocks = 0;
        inode->i_size = 0;
        inode->i_mtime = inode->i_atime = inode->i_ctime = LUCI_CURR_TIME;

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
        li->i_active_block_group = group;
        li->i_dir_start_lookup = 0;
        li->i_state = LUCI_STATE_NEW;
#ifdef LUCIFS_COMPRESSION
        li->i_size_comp = 0;
#endif

        percpu_counter_add(&sbi->s_freeinodes_counter, -1);

        if (S_ISDIR(mode))
                percpu_counter_inc(&sbi->s_dirs_counter);

        if (insert_inode_locked(inode) < 0) {
                inode->i_generation = sbi->s_next_generation++;
                err = -EIO;
                brelse(bmap_bh);
                luci_err("inode locked during create inode :%lu", ino);
                goto free_inode;
        }
        mark_inode_dirty(inode);

        // inode bitmap
        if (sb->s_flags & MS_SYNCHRONOUS)
                sync_dirty_buffer(bmap_bh);

        brelse(bmap_bh);

#ifdef HAVE_TRACEPOINT_ENABLED
        if (trace_luci_new_inode_enabled())
#endif
           trace_luci_new_inode(inode, i, bit);
        luci_info("new inode :%lu mode :0x%x in group :%d", ino, mode, group);
        return inode;

free_inode:
        luci_free_inode(inode);
fail:
        make_bad_inode(inode);
        iput(inode);
        return ERR_PTR(err);
}

/*
 * update block bitmap
 */
int
luci_new_block(struct inode *inode,
                unsigned int nr_blocks,
                unsigned long *start_block)
{
        int err = 0, got_blocks = 0;
        unsigned long block, bg, gp = 0;
        struct super_block *sb = inode->i_sb;
        struct luci_sb_info *sbi = LUCI_SB(sb);
        struct luci_inode_info *li = LUCI_I(inode);
        struct luci_group_desc *gdesc = NULL;
        struct luci_super_block *lsb = NULL;
        struct buffer_head *bg_bh = NULL, *bmap_bh = NULL;
        ktime_t start;

        start = ktime_get();

        read_lock(&li->i_meta_lock);

        bg = li->i_active_block_group;
        read_unlock(&li->i_meta_lock);
        luci_dbg_inode(inode, "active block gp :%lu(%u)",
                        bg,
                        li->i_block_group);

        for (; gp < sbi->s_groups_count; bg = (bg + 1) % sbi->s_groups_count, gp++) {

                gdesc = luci_get_group_desc(sb, bg, &bg_bh);
                if (!gdesc) {
                        err = -EIO;
                        luci_err("new block, error getting bg descriptor :%lu", bg);
                        goto fail;
                }

                if (gdesc->bg_free_blocks_count < nr_blocks)
                        continue;

                bmap_bh = read_block_bitmap(sb, bg);
                if (!bmap_bh) {
                        err = -EIO;
                        luci_err("new block, error reading block bitmap for bg :%lu", bg);
                        goto fail;
                }

                // lock 1.
                lock_buffer(bg_bh);

                // lock 2.
                lock_buffer(bmap_bh);

                // returns size if no bits are zero
                block = luci_alloc_bitmap((unsigned long*)bmap_bh->b_data,
                                           nr_blocks,
                                           LUCI_BLOCKS_PER_GROUP(sb));

#ifdef DEBUG_BMAP
                luci_dbg("finding zero bit in bg %u(%lu) :0x%lx", block, bg,
                                *(unsigned long*)bmap_bh->b_data);
#endif

                if (block < LUCI_BLOCKS_PER_GROUP(sb)) {
                        unsigned new_block;
                        new_block =  block + luci_group_first_block_no(sb, bg);
                        BUG_ON(new_block > blkdev_max_block(sb->s_bdev));
                        *start_block = new_block;
                        goto gotit;
                } else {
                        luci_err("no free blocks found in bg :%lu nr blocks :%u free blocks :%u",
                                        bg, nr_blocks, gdesc->bg_free_blocks_count);
                        luci_dump_bytes("no free blocks:", bmap_bh->b_page, PAGE_SIZE); 
                        brelse(bmap_bh);
                }

                unlock_buffer(bmap_bh);

                unlock_buffer(bg_bh);
        }

        luci_err("create block failed, space is full");
        err = -ENOSPC;
        goto fail;

gotit:
        luci_dbg("found new block :%lu(bg=%lu)", block, bg);

        // block bitmap
        got_blocks = nr_blocks;

        luci_bg_block_bitmap_update_csum(gdesc, bmap_bh);

        mark_buffer_dirty(bmap_bh);

        // unlock 2
        unlock_buffer(bmap_bh);

        le16_add_cpu(&gdesc->bg_free_blocks_count, -got_blocks);

        luci_bg_update_csum(gdesc);

        mark_buffer_dirty(bg_bh);

        // unlock 1
        unlock_buffer(bg_bh);

        if (sb->s_flags & MS_SYNCHRONOUS)
                sync_dirty_buffer(bmap_bh);

        brelse(bmap_bh);

        //writer lock for inode active bg
        write_lock(&li->i_meta_lock);
        li->i_active_block_group = bg;
        write_unlock(&li->i_meta_lock);

        //TBD : We are not updating the super-block across all backups
        lock_buffer(sbi->s_sbh);

        percpu_counter_add(&sbi->s_freeblocks_counter, -got_blocks);

        lsb = sbi->s_lsb;

        lsb->s_free_blocks_count -= got_blocks;

        luci_super_update_csum(sb);

        mark_buffer_dirty(sbi->s_sbh);

        // unlock
        unlock_buffer(sbi->s_sbh);

        // sector based (TBD : add a macro for block to sector)
        inode->i_blocks += (got_blocks * luci_sectors_per_block(inode));

        mark_inode_dirty(inode);

        UPDATE_AVG_LATENCY_NS(dbgfsparam.avg_balloc_lat, start);
fail:
        return err;
}

/*
 * update block bitmap
 * use to free both leaf and internal
 */
int
luci_free_block(struct inode *inode, unsigned long block)
{
        unsigned int bg, bitpos;
        struct luci_group_desc *gdesc;
        struct super_block *sb = inode->i_sb;
        struct luci_sb_info *sbi = sb->s_fs_info;
        struct luci_super_block *lsb = sbi->s_lsb;
        struct buffer_head *bmap_bh = NULL, *bh_desc = NULL;

        BUG_ON(block <= le32_to_cpu(lsb->s_first_data_block));

        bg = (block - le32_to_cpu(lsb->s_first_data_block)) /
                sbi->s_blocks_per_group;

        if (bg > sbi->s_groups_count)
                panic("bogus block group %u(%lu)", bg, sbi->s_groups_count);

        bitpos = (block - le32_to_cpu(lsb->s_first_data_block)) %
                  sbi->s_blocks_per_group;

#ifdef HAVE_TRACEPOINT_ENABLED
        if (trace_luci_free_block_enabled())
#endif
           trace_luci_free_block(inode, block, bg, bitpos);

        gdesc = luci_get_group_desc(sb, bg, &bh_desc);
        if (!gdesc) {
                luci_err("free block, read error bg desc :%lu/%u", block, bg);
                return -EIO;
        }

        bmap_bh = read_block_bitmap(sb, bg);
        if (!bmap_bh) {
                luci_err("free block, read error block bmap :%lu/%u", block, bg);
                return -EIO;
        }

        // lock 1
        lock_buffer(bh_desc);

        // lock 2
        lock_buffer(bmap_bh);

        if (!(__test_and_clear_bit_le(bitpos, bmap_bh->b_data))) {
                unlock_buffer(bmap_bh);
                unlock_buffer(bh_desc);
                brelse(bmap_bh);
                luci_err("free block error, block already freed!, %lu/%u/%u",
                                block, bg, bitpos);
                return -EIO;
        }

        // bg block bitmap
        luci_bg_block_bitmap_update_csum(gdesc, bmap_bh);

        // bg descriptor
        mark_buffer_dirty(bmap_bh);

        // unlock 2
        unlock_buffer(bmap_bh);

        le16_add_cpu(&gdesc->bg_free_blocks_count, 1);

        lsb->s_free_blocks_count++;

        if (S_ISDIR(inode->i_mode))
                le16_add_cpu(&gdesc->bg_used_dirs_count, -1);

        luci_bg_update_csum(gdesc);

        mark_buffer_dirty(bh_desc); // cannot release group descriptor bh

        // unlock 1
        unlock_buffer(bh_desc);

        brelse(bmap_bh);

        // super block update
        lock_buffer(sbi->s_sbh);

        percpu_counter_add(&sbi->s_freeblocks_counter, 1);

        if (S_ISDIR(inode->i_mode))
                percpu_counter_dec(&sbi->s_dirs_counter);

        luci_super_update_csum(sb);

        unlock_buffer(sbi->s_sbh);

        mark_buffer_dirty(sbi->s_sbh);

        inode->i_blocks -= luci_sectors_per_block(inode);

        mark_inode_dirty(inode);

        return 0;
}

void
luci_scan_block_bitmaps(struct luci_sb_info *sbi)
{
        unsigned long bg;
        const int max_order = LUCI_MAX_BUDDY_ORDER;

        for (bg = 0; bg < sbi->s_groups_count; bg++) {
                struct buffer_head *bmap_bh;

                bmap_bh = read_block_bitmap(sbi->sb, bg);
                if (!bmap_bh) {
                        luci_err("new block, error reading block bitmap for bg :%lu", bg);
                        break;
                }

                lock_buffer(bmap_bh);

                luci_create_buddy_map((char *)bmap_bh->b_data,
                                      PAGE_SIZE,
                                      sbi->bg_buddy_map + bg * (max_order + 1),
                                      max_order);

                unlock_buffer(bmap_bh);
                
                #ifdef VERIFY_BGBUDDY_INFO
                if (bg == 0)
                        print_hex_dump(KERN_INFO, "dumping block bitmap",
                              DUMP_PREFIX_OFFSET,
                              16,
                              1,
                              bmap_bh->b_data,
                              PAGE_SIZE,
                              true);
                #endif
        }
}

// TBD: Only reporting till max buddy order 5
static int luci_show_frag_stats(struct seq_file *m, void *data)
{
        unsigned long bg;
        struct super_block *sb;
        struct luci_sb_info *sbi;

        sb = (struct super_block *)m->private;
        if (!sb) {
                luci_err("dbgfs invalid argument");
                return -EBADF;
        }
        sbi = LUCI_SB(sb);

        for (bg = 0; bg < sbi->s_groups_count; bg++) {
                int *bdinfo;
                struct luci_group_desc *gdesc;

                gdesc = luci_get_group_desc(sb, bg, NULL);
                if (!gdesc) {
                        luci_err("failed to read bg descriptor");
                        return -EIO;
                }

                bdinfo = &sbi->bg_buddy_map[bg * (LUCI_MAX_BUDDY_ORDER + 1)];

                seq_printf(m, "bg[%lu]\t%u\t%u\t%u\t%u\t%u\t%u\t%u\n",
                                 bg,
                                 bdinfo[0], bdinfo[1], bdinfo[2],
                                 bdinfo[3], bdinfo[4], bdinfo[5],
                                 gdesc->bg_free_blocks_count);
        }
        return 0;
}

static int luci_debugfs_open(struct inode *inode, struct file *file)
{
        return single_open(file, luci_show_frag_stats, inode->i_private);
}

const struct file_operations luci_frag_ops = {
        .open		= luci_debugfs_open,
        .read		= seq_read,
        .llseek		= no_llseek,
        .release	= single_release,
};
