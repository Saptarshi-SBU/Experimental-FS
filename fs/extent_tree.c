/*--------------------------------------------------------------------
 * Copyright(C) 2016, Saptarshi Sen
 *
 * luci btree implementation 
 *
 * btree grows bottom-up. level increases from leaf to root
 *
 * ------------------------------------------------------------------*/
#include <linux/gfp.h>
#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/highmem.h>
#include <linux/module.h>
#include <linux/buffer_head.h>
#include <linux/radix-tree.h>
#include "extent_tree.h"
#include "../lib/page_io.h"

#define MAX_KEYS 32

enum {
        LEFT_SIBLING,
        RIGHT_SIBLING,
} dir_t;

static struct dentry *dbgfs_dir;

static struct btree_root_node *btree_test_root;

extern int  btreedev_init(void);

extern void btreedev_exit(void);

//long btreedev_ioctl(struct file *file, unsigned cmd, unsigned long arg);

static inline void extent_reset_key(struct btree_key *key)
{
        memset((char *)key, 0, sizeof(struct btree_key));
}

static inline int compare_key(struct btree_key *key, struct btree_node *node)
{
        return (node->header.offset == key->offset);
}

static inline void swap_keys(struct btree_key *keyp, struct btree_key *keyq)
{
        struct btree_key temp;

        memcpy((char *)&temp, (char *)keyp,  sizeof(struct btree_key));
        memcpy((char *)keyp,  (char *)keyq,  sizeof(struct btree_key));
        memcpy((char *)keyq,  (char *)&temp, sizeof(struct btree_key));
}

static inline int extent_node_is_root(struct btree_node *node,
			              struct btree_path *path)
{
	return (node->header.level + 1 == path->depth);
}

static inline bool extent_node_full(struct btree_node *node)
{
        return !(node->header.nr_items < node->header.max_items);
}

static inline bool extent_node_can_merge(struct btree_node *node,
                                         struct btree_node *sib)
{
        int cap = node->header.max_items - 1;

        if (node->header.nr_items && sib->header.nr_items && 
           (node->header.nr_items < cap / 2) &&
           ((node->header.nr_items + sib->header.nr_items) < cap)) {
                btree_node_print("can attempt merge", node);
                return true;
        }

        return false;
}

static inline bool extent_node_can_borrow(struct btree_node *node,
                                          struct btree_node *sib)
{
        int cap = node->header.max_items - 1;

        if (node->header.nr_items && sib->header.nr_items &&
           (node->header.nr_items < cap / 2) && (sib->header.nr_items > cap / 2)) {
                btree_node_print("can steal keys", node);
                return true;
        }

        return false;
}

static inline bool extent_node_has_underflowed(struct btree_node *node)
{
        int cap = node->header.max_items - 1;

	if (IS_BTREE_LEAF(node) || !node->header.nr_items)
		return false;

        if ((node->header.nr_items < cap / 2)) {
                btree_node_print("can attempt rebalance", node);
		return true;
        }

	return false;
}

static inline bool extent_node_has_overflowed(struct btree_node *node)
{
        BUG_ON(node->header.max_items < node->header.nr_items);

        if (IS_BTREE_LEAF(node))
               return (node->header.max_items - node->header.nr_items) == 0;
        else
               return (node->header.max_items - node->header.nr_items) <= 2;
}

static inline int paritition_keys(struct btree_key *keys, int l, int h)
{
        int p = h;
        struct btree_key pivot = keys[h--];

        while (l <= h) {
                if (keys[l].offset > pivot.offset) {
                        swap_keys(&keys[l], &keys[h]);
                        h--;
                } else {
                        l++;
                }
        }

        swap_keys(&keys[l], &keys[p]);
        return l;
}

static inline void extent_node_sort(struct btree_node *node)
{
        int top = 0;
        int stack[MAX_KEYS]; // stack size grows with btree fan-out

        if (!node->header.nr_items)
                return;

        stack[top++] = 0;
        stack[top++] = node->header.nr_items - 1;

        while (top) {
                int p, q, k;

                q = stack[--top];
                p = stack[--top];

                k = paritition_keys(node->keys, p, q);

                if (k > p) {
                       stack[top++] = p;
                       stack[top++] = k - 1;
                }

                if (k < q) {
                       stack[top++] = k + 1;
                       stack[top++] = q;
                }
        }

        node->header.offset = node->keys[0].offset;
}

static struct buffer_head *extent_tree_read_node(struct btree_node *node, int key_index)
{
        struct buffer_head *ebh = NULL;

        if (node->keys[key_index].blockptr) {
                ebh = bump_get_buffer_head(node->keys[key_index].blockptr);
                BUG_ON(!ebh);
        }
        return ebh;
}

static void extent_drop_path_refs(struct btree_path *paths)
{
        int i;

        for (i = 0; i < paths->depth; i++) {
                BUG_ON (paths->bh[i] == NULL);
                bump_put_buffer_head(paths->bh[i]);
                BUG_ON(paths->nodes[i] == NULL);
                paths->nodes[i] = NULL;
        }

        paths->depth = 0;
        kfree(paths);
}

static int extent_index_node_search_keys(struct btree_node *node,
                                         struct btree_key *key)
{
        int i, slot = 0;

        btree_node_print("search node entry", node);

        for (i = 0; i < node->header.nr_items; i++) {
                if (key->offset == node->keys[i].offset)
                        return i;
                else if (key->offset > node->keys[i].offset)
                        slot = i;
                else
                        break;
        }

        btree_node_keys_print(node);
        return slot;
}

static int extent_index_node_lookup(struct btree_node *node,
                                    struct btree_key *key)
{
        int i;

        btree_node_print("lookup parent", node);

        for (i = 0; i < node->header.nr_items; i++) {
                if (key->offset == node->keys[i].offset)
                        return i;
        }
        return -ENOENT;
}

static int extent_index_node_lookup_bptr(struct btree_node *node,
                                         struct btree_key *key)
{
        int i;

        btree_node_print("lookup bptr in parent node", node);

        BUG_ON(key->blockptr == 0);

        for (i = 0; i < node->header.nr_items; i++) {
                if (key->blockptr == node->keys[i].blockptr)
                        return i;
        }
        return -ENOENT;
}

static void extent_node_update_backrefs(struct btree_node *curr_node,
                                        struct btree_path *path)
{
        struct btree_node *parent;
        int slot, level = curr_node->header.level;
        struct btree_key key = {0, 0, curr_node->header.blockptr};

        if (extent_node_is_root(curr_node, path))
                return;

        btree_node_print("updating entries for backrefs of node", curr_node);
        do {
                parent = path->nodes[++level];

                slot = extent_index_node_lookup_bptr(parent, &key);
                if (slot < 0) {
                        pr_debug("blockptr key :%llu\n", key.blockptr);
                        btree_node_print("child bptr not found in parent", parent);
                        btree_node_keys_print(parent);
                        break;
                }

                if (slot == 0)
                        parent->header.offset = curr_node->header.offset;

                if (parent->keys[slot].offset != curr_node->header.offset)
                        parent->keys[slot].offset = curr_node->header.offset;

                key.blockptr = parent->header.blockptr;

                curr_node = parent;
                btree_node_print("updated backref for parent node", parent);

        } while (level < path->depth - 1);
}

static int extent_index_node_insert_key(struct btree_node *parent,
                                        struct btree_node *node)
{
        struct btree_key key;

        SET_KEY_FROM_BTREE_HDR(key, node);

        if (extent_node_full(parent)) {
                pr_err("parent cannot accomodate key\n");
                btree_node_print("node FULL!", node);
                return -ENOSPC;
        }

        parent->header.nr_items++;

        memcpy((char* )&parent->keys[parent->header.nr_items - 1],
               (char*)&key, sizeof(struct btree_key));

        extent_node_sort(parent);

        btree_node_print("added child node", node);

        btree_node_print("parent node", parent);

        btree_node_keys_print(parent);

        return 0;
}

static int extent_index_node_remove_key(struct btree_node *pnode,
                                        struct btree_node *node,
                                        struct btree_path *path,
                                        bool collapse)
{
        int slot, last;
        struct btree_key key;

        do {
                SET_KEY_FROM_BTREE_HDR(key, node);

                btree_node_print("remove index node entry (before)", node);

                bump_release_block(node->header.blockptr, PAGE_SIZE);

                //path->bh[node->header.level] = NULL;

                slot = extent_index_node_lookup_bptr(pnode, &key);
                if (slot < 0) {
                        pr_err("entry not found :%llu-%llu\n", key.offset, key.blockptr);
                        btree_node_keys_print(pnode);
                        WARN_ON(1);
                        return -ENOENT;
                }

                btree_node_keys_print(pnode);

                last = pnode->header.nr_items - 1;

                if (last) {
                        memcpy((char* )&pnode->keys[slot],
                               (char* )&pnode->keys[last], sizeof(struct btree_key));

                        pnode->header.nr_items--;

                        extent_node_sort(pnode);

                        extent_node_update_backrefs(pnode, path);
                } else {
                        pnode->header.nr_items--;

                        BUG_ON(pnode->header.nr_items);
                }

                btree_node_print("parent node entry (after)", pnode);

                btree_node_keys_print(pnode);

                if (extent_node_is_root(pnode, path) || pnode->header.nr_items)
                        break;

                node = pnode;

                pnode = path->nodes[pnode->header.level + 1];

                btree_node_print("pparent node entry (after)", pnode);
        } while (collapse);

        return pnode->header.level;
}

static struct btree_node* extent_node_create(int level,
                                             int max_items,
                                             int flag,
                                             struct buffer_head **bh)
{
        unsigned long block;
        struct buffer_head *ebh;
        struct btree_node *node;
    
        BUG_ON(level >= MAX_BTREE_LEVEL);

        block = bump_alloc_meta_block();

        ebh = bump_get_buffer_head(block);
        if (!ebh)
                return NULL;

        node = (struct btree_node *) (ebh->b_data);
        node->header.level = level;
        node->header.flags = flag;
        node->header.nr_items = 0;
        node->header.offset = 0xFFFFFFFF;
        node->header.blockptr = block;
        node->header.max_items = max_items;
        if (bh)
                *bh = ebh;
        btree_node_print("new node created", node);
        return node;
}

static void extent_node_destroy(struct btree_node *node)
{
        int i, nr_keys = node->header.nr_items;

        btree_node_print("destroying node", node);
        btree_node_keys_print(node);

        if (IS_BTREE_LEAF(node)) {
                for (i = 0; i < nr_keys; i++) {
                        bump_release_block(node->keys[i].blockptr, node->keys[i].size);
                        extent_reset_key(&node->keys[i]);
                        node->header.nr_items--;
                }
        } else {
                for (i = 0; i < nr_keys; i++) {
                        struct buffer_head *ebh;
                        if (node->keys[i].blockptr) {
                                ebh = bump_get_buffer_head(node->keys[i].blockptr);
                                if (!ebh) {
                                        pr_err("blockptr error :%llu\n", node->keys[i].blockptr);
                                        BUG();
                                }
                                extent_node_destroy((struct btree_node *) (ebh->b_data));
                                extent_reset_key(&node->keys[i]);
                                bump_put_buffer_head(ebh);
                                node->header.nr_items--;
                        }
                }
        }

        BUG_ON(node->header.nr_items);
        bump_release_block(node->header.blockptr, PAGE_SIZE);
}

static inline bool extent_tree_can_shrink(struct btree_node *root)
{
        bool shrink = false;
        struct buffer_head *pbh, *qbh;
        struct btree_node *pnode, *qnode;

        if (IS_BTREE_LEAF(root) || (root->header.nr_items != 2))
                return shrink;

        pbh = extent_tree_read_node(root, 0);
        BUG_ON(pbh == NULL);
        pnode = BH2BTNODE(pbh);

        qbh = extent_tree_read_node(root, 1);
        BUG_ON(qbh == NULL);
        qnode = BH2BTNODE(qbh);

        if (pnode->header.nr_items + qnode->header.nr_items <= root->header.max_items)
                shrink = true;

        bump_put_buffer_head(pbh);

        bump_put_buffer_head(qbh);

        return shrink;
}

static struct btree_node* extent_tree_shrink(struct btree_root_node *root,
                                             struct buffer_head **bh)
{
        int i, j;
        struct buffer_head *pbh, *qbh;
        struct btree_node *pnode, *qnode, *merge;

        pbh = extent_tree_read_node(root->node, 0);
        BUG_ON(pbh == NULL);
        pnode = BH2BTNODE(pbh);

        qbh = extent_tree_read_node(root->node, 1);
        BUG_ON(qbh == NULL);
        qnode = BH2BTNODE(qbh);

	BUG_ON(pnode->header.level != qnode->header.level);

        btree_node_print("root node", root->node);
        btree_node_keys_print(root->node);

        btree_node_print("merging node (l)", pnode);
        btree_node_keys_print(pnode);

        btree_node_print("merging node (r)", qnode);
        btree_node_keys_print(qnode);

        merge = extent_node_create(pnode->header.level,
                                   pnode->header.max_items,
                                   pnode->header.flags,
                                   bh);

        for (i = 0; i < pnode->header.nr_items; i++)
                merge->keys[merge->header.nr_items++] = pnode->keys[i];

        for (j = 0; j < qnode->header.nr_items; j++)
                merge->keys[merge->header.nr_items++] = qnode->keys[j];

        extent_node_sort(merge);

        btree_node_print("merged new root node", merge);

        btree_node_keys_print(merge);

        bump_put_buffer_head(pbh);

        bump_release_block(pnode->header.blockptr, PAGE_SIZE);

        bump_put_buffer_head(qbh);

        bump_release_block(qnode->header.blockptr, PAGE_SIZE);

        bump_put_buffer_head(root->bh);

        bump_release_block(root->node->header.blockptr, PAGE_SIZE);

        return merge;
}

static struct btree_node* extent_node_merge_siblings(struct btree_node *pnode,
                                                     struct btree_node *qnode,
                                                     struct btree_path *paths)
{
        int i, j, level;
        struct buffer_head *bh;
        struct btree_node *parent, *merge;
        const bool collapse = false;

	if (pnode->header.level != qnode->header.level) {
		pr_err("merge attempt failed, node levels mismatch! %d/%d",
                                pnode->header.level, qnode->header.level);
		return ERR_PTR(-EINVAL);
	}

	if (pnode->header.level >= paths->depth - 1) {
		pr_err("merge attempt failed, bad node level! %d/%d",
                                pnode->header.level, paths->depth);
		return ERR_PTR(-EINVAL);
	}

        btree_node_print("merging node (l)", pnode);
        btree_node_keys_print(pnode);

        btree_node_print("merging node (r)", qnode);
        btree_node_keys_print(qnode);

        level = pnode->header.level;

        parent = paths->nodes[level + 1];

        merge = extent_node_create(level,
                                   parent->header.max_items,
                                   pnode->header.flags,
                                   &bh);

        for (i = 0; i < pnode->header.nr_items; i++)
                merge->keys[merge->header.nr_items++] = pnode->keys[i];

        for (j = 0; j < qnode->header.nr_items; j++)
                merge->keys[merge->header.nr_items++] = qnode->keys[j];

	extent_node_sort(merge);

	btree_node_print("merged new node", merge);

        btree_node_keys_print(merge);

        (void) extent_index_node_remove_key(parent, pnode, paths, collapse);

        (void) extent_index_node_remove_key(parent, qnode, paths, collapse);

        bump_put_buffer_head(paths->bh[level]);

	paths->nodes[level] = merge;

	paths->bh[level] = bh;

        if (extent_index_node_insert_key(parent, merge) < 0)
                BUG();

        extent_node_update_backrefs(merge, paths);

	// rebalance will attempt further merge on parent if possible
        return merge;
}

static int extent_node_steal_from_sibling(struct btree_node *cur_node,
                                          struct btree_node *sib_node,
                                          struct btree_path *path)
{
        struct btree_key key;
        struct btree_node *parent;
        int r_index_curr, r_index_sib;

        parent = path->nodes[cur_node->header.level];

        SET_KEY_FROM_BTREE_HDR(key, cur_node);
        r_index_curr = extent_index_node_lookup(parent, &key);
        if (r_index_curr < 0)
                return -ENOENT;

        SET_KEY_FROM_BTREE_HDR(key, sib_node);
        r_index_sib = extent_index_node_lookup(parent, &key);
        if (r_index_sib < 0)
                return -ENOENT;

        btree_node_print("stealing keys from adjacent node", cur_node);

        // right sibling
        if (cur_node->header.offset < sib_node->header.offset) {
                int p = cur_node->header.nr_items - 1;
                int q = sib_node->header.nr_items - 1;

                memcpy((char *) &cur_node->keys[p + 1], (char *) &sib_node->keys[0],
                       sizeof(struct btree_key));
                memcpy((char *) &sib_node->keys[0], (char *) &sib_node->keys[q],
                       sizeof(struct btree_key));
                cur_node->header.nr_items++;
                sib_node->header.nr_items--;

                extent_node_sort(sib_node);
                //btree_node_keys_print(sib_node);

                SET_KEY_EMPTY(sib_node->keys[p]);
                sib_node->header.offset = sib_node->keys[0].offset;
                parent->keys[r_index_sib].offset = sib_node->header.offset;
                extent_node_update_backrefs(sib_node, path);
        // left sibling
        } else {
                int p = cur_node->header.nr_items - 1;
                int q = sib_node->header.nr_items - 1;

                memcpy((char *) &cur_node->keys[p + 1], (char *) &sib_node->keys[q],
                       sizeof(struct btree_key));

                cur_node->header.nr_items++;
                sib_node->header.nr_items--;

                extent_node_sort(cur_node);
                //btree_node_keys_print(cur_node);

                SET_KEY_EMPTY(sib_node->keys[q]);
                cur_node->header.offset = cur_node->keys[0].offset;
                parent->keys[r_index_curr].offset = cur_node->header.offset;
                extent_node_update_backrefs(cur_node, path);
        }

        return 0;
}

static struct buffer_head *extent_tree_get_adjacent_node(struct btree_node *node,
                                                         struct btree_node *parent,
                                                         struct btree_path *path,
                                                         int dir)
{
        int slot;
        struct btree_key key;

        SET_KEY_FROM_BTREE_HDR(key, node);

        slot = extent_index_node_lookup_bptr(parent, &key);
        BUG_ON(slot < 0);

        if (dir == LEFT_SIBLING)
                return (slot == 0) ?
                        NULL : bump_get_buffer_head(parent->keys[slot - 1].blockptr);
        else
                return (slot == parent->header.nr_items - 1) ? 
                        NULL : bump_get_buffer_head(parent->keys[slot + 1].blockptr);
}

static void extent_tree_rebalance(struct btree_node *curr_node,
                                  struct btree_path *path)
{
        while (!extent_node_is_root(curr_node, path)) {
                bool continue_balance = false;
                struct btree_node  *parent, *lsib = NULL, *rsib = NULL;
                struct buffer_head *lsib_bh = NULL, *rsib_bh = NULL;

		if (!extent_node_has_underflowed(curr_node))
			break;

                parent = path->nodes[curr_node->header.level + 1];

		btree_node_print("rebalancing node", curr_node);
		btree_node_print("parent for node under rebalance", parent);
                btree_node_keys_print(parent);

                lsib_bh = extent_tree_get_adjacent_node(curr_node, parent, path, LEFT_SIBLING);
		if (lsib_bh) {
                        lsib = BH2BTNODE(lsib_bh); 
                        if (extent_node_can_borrow(curr_node, lsib)) {
                                extent_node_steal_from_sibling(curr_node, lsib, path);
                                continue_balance = true;
                                goto next_round;
                        }
                }

                rsib_bh = extent_tree_get_adjacent_node(curr_node, parent, path, RIGHT_SIBLING);
		if (rsib_bh) {
                        rsib = BH2BTNODE(rsib_bh); 
                        if (extent_node_can_borrow(curr_node, rsib)) {
                                extent_node_steal_from_sibling(curr_node, rsib, path);
                                continue_balance = true;
                                goto next_round;
                        }
                }

                if (lsib && extent_node_can_merge(curr_node, lsib)) {
                        if (IS_ERR(extent_node_merge_siblings(lsib, curr_node, path)))
					BUG();
                        continue_balance = true;
                        goto next_round;
		}

		if (rsib && extent_node_can_merge(curr_node, rsib)) {
                        if (IS_ERR(extent_node_merge_siblings(curr_node, rsib, path)))
					BUG();
                        continue_balance = true;
                        goto next_round;
		}

next_round:
                if (lsib_bh)
                        brelse(lsib_bh);

                if (rsib_bh)
                        brelse(rsib_bh);

                if (!continue_balance) {
		        btree_node_print("node is balanced", curr_node);
                        break;
                }

                curr_node = parent;
        }
}

static struct btree_node* extent_node_split(struct btree_root_node *root_node,
                                            struct btree_path *paths,
                                            int curr_level)
{
        bool new_root = false;  // tree grew
        bool collapse = false;  // replace do not need node adjustments
        struct buffer_head *bh = NULL;
        struct btree_node *pnode= NULL;

        do {
                int i, mid, ret;
                struct buffer_head *lbh, *rbh;
                struct btree_node *node, *l_sib, *r_sib;

                BUG_ON(curr_level >= MAX_BTREE_LEVEL);

                node = paths->nodes[curr_level];

                BUG_ON(curr_level != node->header.level);

                btree_node_print("splitting node", node);

                mid = node->header.nr_items >> 1;

                l_sib = extent_node_create(curr_level,
                                           node->header.max_items,
                                           node->header.flags,
                                           &lbh);
                BUG_ON(l_sib == NULL);

                for (i = 0; i < mid; i++) {
                        memcpy((char *)&l_sib->keys[i],
                               (char *)&node->keys[i], sizeof(struct btree_key));
                        l_sib->header.nr_items++;
                }

                l_sib->header.offset = l_sib->keys[0].offset;

                btree_node_print("created left sibling", l_sib);

                btree_node_keys_print(l_sib);

                r_sib = extent_node_create(curr_level,
                                           node->header.max_items,
                                           node->header.flags,
                                           &rbh);

                BUG_ON(r_sib == NULL);

                for (i = mid; i < node->header.nr_items; i++) {
                        memcpy((char *)&r_sib->keys[i - mid],
                               (char *)&node->keys[i], sizeof(struct btree_key));
                        r_sib->header.nr_items++;
                }

                r_sib->header.offset = r_sib->keys[0].offset;

                btree_node_print("created right sibling", r_sib);

                btree_node_keys_print(r_sib);

                if (curr_level < paths->depth - 1) {
                        pnode = paths->nodes[curr_level + 1];
                        if (extent_index_node_remove_key(pnode, node, paths, collapse) < 0)
                                WARN_ON(1);
                } else {
                        bump_release_block(node->header.blockptr, PAGE_SIZE);
                        //paths->bh[curr_level] = NULL;
                        pnode = extent_node_create(curr_level + 1,
                                                   node->header.max_items,
                                                   INDEX_NODE,
                                                   &bh);
                        paths->nodes[curr_level + 1] = pnode;
                        paths->bh[curr_level + 1] = bh;
                        paths->depth++;
                        btree_node_print("created new parent node", pnode);
                        btree_node_keys_print(pnode);
                        new_root = true;
                }

                ret = extent_index_node_insert_key(pnode, l_sib);
                BUG_ON(ret < 0);
                extent_node_update_backrefs(l_sib, paths);

                ret = extent_index_node_insert_key(pnode, r_sib);
                BUG_ON(ret < 0);
                extent_node_update_backrefs(r_sib, paths);

                bump_put_buffer_head(rbh);

                bump_put_buffer_head(lbh);

                //extent_tree_rebalance(inode, pnode, paths);

                curr_level++;

        } while (extent_node_has_overflowed(pnode));

        if (new_root) {
                // path refs drops the old root
                get_bh(bh);
                root_node->bh = bh;
                root_node->node = pnode;
                root_node->max_level = paths->depth - 1;
        }

        return pnode;
}

static struct btree_node* extent_tree_find_leaf(struct btree_key* key,
                                                struct btree_node* node,
                                                struct buffer_head* bh,
                                                struct btree_path* path)
{
        int slot;
        struct buffer_head* ebh;

        path->nodes[path->level] = node;

        path->bh[path->level] = bh;

        path->depth++;

        if (IS_BTREE_LEAF(node)) {
                BUG_ON(path->level != 0);
                return node;
        }

        path->level--;

        BUG_ON(path->level < 0);

        slot = extent_index_node_search_keys(node, key);

        ebh = bump_get_buffer_head(node->keys[slot].blockptr);
        if (!ebh)
                return ERR_PTR(-EIO);

        return extent_tree_find_leaf(key,
                                     (struct btree_node *)(ebh->b_data),
                                     ebh,
                                     path);
}

long extent_tree_lookup_item(struct btree_root_node *root,
                             loff_t off,
                             unsigned int size)
{
        int slot;
        struct btree_node *leaf;
        struct btree_key key = { off, size, 0xFFFFFFFF };
        struct btree_path *path = kzalloc(sizeof(struct btree_path), GFP_KERNEL);

        pr_debug("lookup request for key :%llu\n", off); 

        path->level = root->max_level;

        get_bh(root->bh);

        leaf = extent_tree_find_leaf(&key, root->node, root->bh, path);
        BUG_ON(!leaf);
        if (IS_ERR(leaf)) {
                pr_err("failed to locate key: %llu, status: %ld\n", off, PTR_ERR(leaf));
                brelse(root->bh);
                kfree(path);
                return -EIO;
        }

        btree_node_print("selected leaf to lookup", leaf);

        slot = extent_index_node_lookup(leaf, &key);
        if (slot < 0) {
                pr_err("offset key :%llu not found\n", key.offset);
                extent_drop_path_refs(path);
                return -ENOENT;
        }

        key.blockptr = leaf->keys[slot].blockptr;
        extent_drop_path_refs(path);
        return key.blockptr;
}

int extent_tree_insert_item(struct btree_root_node *root,
                            loff_t off,
                            unsigned long block,
                            unsigned int size)
{
        int i, ret = 0;
        bool added = false;
        struct btree_node *leaf;
        struct btree_key key = { off, size, block };
        struct btree_path *path = kzalloc(sizeof(struct btree_path), GFP_KERNEL);

        path->level = root->max_level;

        pr_debug("insert request for key :%llu\n", off); 

        pr_debug("root max level :%u\n", root->max_level);

        get_bh(root->bh);

        leaf = extent_tree_find_leaf(&key, root->node, root->bh, path);
        BUG_ON(!leaf);

        if (IS_ERR(leaf)) {
                pr_err("failed to locate key: %llu, status: %ld\n",
                                off, PTR_ERR(leaf));
                brelse(root->bh);
                kfree(path);
                return -EIO;
        }

        btree_node_print("selected leaf to insert", leaf);

        if (!block)
                block = bump_alloc_data_block();

        for (i = 0; i < leaf->header.max_items; i++) {
                if (IS_KEY_EMPTY(leaf->keys[i])) {
                    leaf->keys[i].blockptr = block;
                    leaf->keys[i].offset = off;
                    leaf->keys[i].size = size;
                    leaf->header.nr_items++;
                    btree_info("inserted item[%d/%d] :%llu %u-%u\n",
                            i, leaf->header.nr_items, off,
                            path->level, path->depth);
                    added = true;
                    break;
                }
        }

        if (added) {
                extent_node_sort(leaf);
                //btree_node_keys_print(leaf);
                extent_node_update_backrefs(leaf, path);
                //extent_tree_rebalance(inode, leaf, path);
                if (extent_node_has_overflowed(leaf))
                        extent_node_split(root, path, leaf->header.level);
        } else {
                bump_release_block(block, PAGE_SIZE);
                pr_err("failed to insert key :%llu\n", off);
                ret = -EAGAIN;
        }

        extent_drop_path_refs(path);
        return ret;
}

int extent_tree_delete_item(struct btree_root_node *root,
                            unsigned long offset)
{
        int i;
        bool deleted = false;
        bool collapse = true;
        struct btree_node *leaf, *parent;
        struct btree_key key = { offset, 0, 0 };
        struct btree_path *path = kzalloc(sizeof(struct btree_path), GFP_KERNEL);

        path->level = root->max_level;

        get_bh(root->bh);

        pr_debug("delete request for key :%lu\n", offset); 

        leaf = extent_tree_find_leaf(&key, root->node, root->bh, path);
        BUG_ON(!leaf);

        if (IS_ERR(leaf)) {
                pr_err("failed to locate key: %ld, status: %ld\n",
                                offset, PTR_ERR(leaf));
                brelse(root->bh);
                kfree(path);
                return -EIO;
        }

        btree_node_print("selected leaf to delete", leaf);
        btree_node_keys_print(leaf);

        for (i = 0; i < leaf->header.nr_items; i++) {
                if (leaf->keys[i].offset != key.offset)
                        continue;
                bump_release_block(leaf->keys[i].blockptr, PAGE_SIZE);
                memcpy((char *)&leaf->keys[i],
	               (char *)&leaf->keys[leaf->header.nr_items - 1],
                       sizeof(struct btree_key));
                memset((char *)&leaf->keys[leaf->header.nr_items - 1],
                        0,
                        sizeof(struct btree_key));
                leaf->header.nr_items--;
		BUG_ON(leaf->header.nr_items < 0);
                btree_info("deleted item[%d/%d] :%lu %u-%u/%u\n",
                            i, leaf->header.nr_items, offset,
                            path->level, path->depth, leaf->header.max_items);
                deleted = true;
                break;
        }

        if (!deleted) {
                pr_err("key :%lu not found\n", offset);
                goto out;
        }

        if (extent_node_is_root(leaf, path)) {
                extent_node_sort(leaf);
        } else {
                parent = path->nodes[leaf->header.level + 1];
                if (leaf->header.nr_items) {
                        extent_node_sort(leaf);
                        extent_node_update_backrefs(leaf, path);
                        extent_tree_rebalance(leaf, path);
                } else {
                        int plevel;

                        plevel = extent_index_node_remove_key(parent, leaf, path, collapse);
                        if (plevel < 0)
				BUG();
                        else {
                                parent = path->nodes[plevel];
                                extent_tree_rebalance(parent, path);
                        }
                }
        }

        //btree_node_keys_print(leaf);

        if (extent_tree_can_shrink(root->node)) {
                struct buffer_head *new_bh;

                root->node = extent_tree_shrink(root, &new_bh);
                root->bh = new_bh;
                root->max_level--;
        }
out:
        extent_drop_path_refs(path);
        return 0;
}

// DFS
unsigned long extent_tree_dump(struct seq_file *m, struct btree_node *node, long refcount, int count)
{
        int i;
        unsigned long nr_keys = 0;

        for (i = 0; i <= count; i++)
                seq_printf(m, "-");

        seq_printf(m, "%s Level :%d Blockptr :%llu Offset :%llu NKeys :%d BHCount :%lu\n",
                       node->header.flags == INDEX_NODE ? "BRANCH BLOCK" : "LEAF BLOCK",
                       node->header.level,
                       node->header.blockptr,
                       node->header.offset,
                       node->header.nr_items,
                       refcount);

        for (i = 0; i < node->header.nr_items; i++) {
                int j;
                struct buffer_head *ebh;

                BUG_ON(!node->keys[i].blockptr);

                for (j = 0; j <= count; j++)
                        seq_printf(m, "-");

                seq_printf(m, "[%d] offset :%llu  bptr :%llu\n", i,
                              node->keys[i].offset,
                              node->keys[i].blockptr);

                if (!IS_BTREE_LEAF(node)) {
                        ebh = bump_get_buffer_head(node->keys[i].blockptr);
                        nr_keys += extent_tree_dump(m, (struct btree_node *)(ebh->b_data),
                                        atomic_read(&ebh->b_count), count + 1);
                        bump_put_buffer_head(ebh);
                }
        }

        return (IS_BTREE_LEAF(node)) ? node->header.nr_items : nr_keys;
}

static struct btree_root_node* extent_tree_load(struct inode* inode, struct btree_key *key)
{
        struct btree_root_node *root = NULL;
        struct buffer_head *ebh;

        root = kzalloc(sizeof(struct btree_root_node), GFP_KERNEL);
        if (!root)
                goto exit;

        ebh = bump_get_buffer_head(key->blockptr);
        if (!ebh)
                goto exit;

        memcpy((char*)root->node, ebh->b_data, sizeof(struct btree_node));
        bump_put_buffer_head(ebh);
        return root;
exit:
        kfree(root);
        return NULL;
}

struct btree_root_node* extent_tree_init(int version, int max_keys)
{
        struct btree_root_node *root = NULL;
        struct buffer_head *bh = NULL;

        root = kzalloc(sizeof(struct btree_root_node), GFP_KERNEL);
        if (!root)
                goto exit;

        root->node = extent_node_create(0, max_keys, LEAF_NODE, &bh);
        if (!root->node)
                goto exit;

        root->bh = bh;
        root->inode = NULL;
        root->max_level = 0;
        root->version = version;
        return root;

exit:
        kfree(root);
        return NULL;
}

void extent_tree_destroy(struct btree_root_node *root)
{
        bump_leak_detector();
        extent_node_destroy(root->node);
        BUG_ON(root->node->header.nr_items);
        bump_put_buffer_head(root->bh);
        root->node = NULL;
        kfree(root);
}

#define TEST_ROOT_VERSION 0xFF

static int init_test_root(void)
{
        btree_test_root = extent_tree_init(TEST_ROOT_VERSION, MAX_KEYS);
        if (!btree_test_root) {
                pr_err("failed to initialize tree");
                return -ENODEV;
        }

        dbgfs_dir = btree_debugfs_init(btree_test_root);
        if (!dbgfs_dir)
                return -ENODEV;

        return 0;
}

static void cleanup_test_root(void)
{
        if (btree_test_root) {
                extent_tree_destroy(btree_test_root);
                btree_test_root = NULL;
        }

        if (dbgfs_dir) {
                btree_debugfs_destroy(dbgfs_dir);
                dbgfs_dir = NULL;
        }
}
