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
#include "btree.h"

MODULE_AUTHOR("Saptarshi.S");
MODULE_DESCRIPTION("Linux BTree Implementation");
MODULE_LICENSE("GPL");

#define MAX_KEYS 8

static struct dentry *dbgfs_dir;

static struct btree_root_node *btree_root;

static struct radix_tree_root pgtree; // track btree index pages

#define META_BLOCK_START (1UL << 30)

static unsigned long alloc_data_block(void)
{
        static atomic_t data_block = ATOMIC_INIT(0);

        atomic_inc(&data_block);
        return atomic_read(&data_block);
}

static unsigned long alloc_meta_block(void)
{
        static atomic_t meta_block = ATOMIC_INIT(META_BLOCK_START);

        atomic_inc(&meta_block);
        return atomic_read(&meta_block);
}

static inline int extent_node_is_root(struct btree_node *node,
			              struct btree_path *path)
{
	return (node->header.level + 1 == path->depth);
}

static int extent_alloc_tree_pages(unsigned long block, size_t size)
{
        int i, nblocks = size >> PAGE_SHIFT;

        for (i = 0; i < nblocks; i++) {
                struct page *page;

                page = alloc_page(GFP_KERNEL | __GFP_ZERO);
                if (!page)
                        return -ENOMEM;
                if (radix_tree_insert(&pgtree, block + i, page))
                        return -EIO;
                btree_info("allocating backing page for block:%lu\n", block + i);
        }
        return 0;
}

static int extent_release_tree_pages(unsigned long block, size_t size)
{
        int i, nblocks = size >> PAGE_SHIFT;

        for (i = 0; i < nblocks; i++) {
                struct page *page;

                btree_info("releasing backing page for block:%lu\n", block + i);
                page = radix_tree_lookup(&pgtree, block + i); 
                if (!page) {
                        pr_err("radix tree lookup failed for block :%lu\n", block + i);
                        continue;
                }
                radix_tree_delete(&pgtree, block + i);
        }
        return 0;
}

static struct buffer_head* get_buffer_head(unsigned long block)
{
        struct buffer_head *bh;
        struct page *page;
       
        page = radix_tree_lookup(&pgtree, block); 
        if (!page) {
                pr_err("radix tree lookup failed for block :%lu\n", block);
                dump_stack();
                return NULL;
        }

        if (!page_has_buffers(page)) {
                bh = alloc_page_buffers(page, PAGE_SIZE, 1);
                set_page_private(page, (unsigned long)bh);
                SetPagePrivate(page);
        } else {
                bh = page_buffers(page);
                //btree_info("found buffer head :%lu\n", block);
        }

        get_bh(bh);
        return bh;
}

static void extent_reset_key(struct btree_key *key)
{
        memset((char *)key, 0, sizeof(struct btree_key));
}

static inline bool extent_node_full(struct btree_node *node)
{
        int capacity = node->header.max_items;

        if (IS_BTREE_LEAF(node))
               return capacity - node->header.nr_items == 0;
        else
               return capacity - node->header.nr_items == 1;
}

static inline bool extent_node_attempt_merge(struct btree_node *node,
                                             struct btree_node *sib)
{
        int node_capacity = node->header.max_items - 1;

        if (node->header.nr_items &&
           (node->header.nr_items < node_capacity / 2) &&
           ((node->header.nr_items + sib->header.nr_items) < node_capacity)) {
                btree_node_print("can attempt merge", node);
                return true;
        }

        return false;
}

static inline bool extent_node_attempt_steal(struct btree_node *node,
                                             struct btree_node *sib)
{
        int node_capacity = node->header.max_items - 1;

        if (node->header.nr_items &&
           (node->header.nr_items >= node_capacity) &&
           (sib->header.nr_items < node_capacity)) {
                btree_node_print("can steal keys", node);
                return true;
        }

        return false;
}

static inline bool extent_node_attempt_rebalance(struct btree_node *node)
{
	if (IS_BTREE_LEAF(node) || !node->header.nr_items)
		return false;

        if ((node->header.nr_items <= node->header.max_items - 1) &&
	    (node->header.nr_items > node->header.max_items/2)) {
                btree_node_print("can attempt rebalance", node);
		return false;
        }

	return true;
}

static inline void swap_keys(struct btree_key *keyp, struct btree_key *keyq)
{
        struct btree_key temp;

        memcpy((char *)&temp, (char *)keyp,  sizeof(struct btree_key));
        memcpy((char *)keyp,  (char *)keyq,  sizeof(struct btree_key));
        memcpy((char *)keyq,  (char *)&temp, sizeof(struct btree_key));
}

static inline int compare_key(struct btree_key *key, struct btree_node *node)
{
        return (node->header.offset == key->offset);
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
        int stack[MAX_BTREE_LEVEL];

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

static struct btree_node *extent_tree_get_node(struct btree_node *node, int key_index)
{
        struct buffer_head *ebh;

        if (node->keys[key_index].blockptr) {
                ebh = get_buffer_head(node->keys[key_index].blockptr);
                BUG_ON(!ebh);
                return (struct btree_node *)(ebh->b_data);
        }
        return NULL;
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
        int slot, level;
        struct btree_node *parent;
        struct btree_key key = {0, 0, curr_node->header.blockptr};

        if (extent_node_is_root(curr_node, path))
                return;

        level = curr_node->header.level;

        btree_node_print("updating entries for backrefs of node", curr_node);
        do {
                parent = path->nodes[++level];
                slot = extent_index_node_lookup_bptr(parent, &key);
                if (slot < 0) {
                        pr_info("blockptr key :%llu\n", key.blockptr);
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

static int extent_index_node_insert(struct btree_node *pnode,
                                    struct btree_node *node,
                                    struct btree_path *paths)
{
        struct btree_key key;

        SET_KEY_FROM_BTREE_HDR(key, node);

        if (extent_node_full(pnode)) {
                btree_node_print("node is full", node);
                return -ENOSPC;
        }

        pnode->header.nr_items++;

        memcpy((char* )&pnode->keys[pnode->header.nr_items - 1],
               (char*)&key, sizeof(struct btree_key));

        extent_node_sort(pnode);

        btree_node_print("append index node entry (child)", node);

        btree_node_print("append index node entry (parent)", pnode);

        btree_node_keys_print(pnode);

        return 0;
}

static int extent_index_node_remove(struct btree_node *pnode,
                                    struct btree_node *node,
                                    struct btree_path *path,
                                    unsigned long hdroff,
                                    bool collapse)
{
        int slot, last;
        struct btree_key key;

        do {

                SET_KEY_FROM_BTREE_HDR(key, node);

                btree_node_print("remove index node entry (before)", node);

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

                        extent_release_tree_pages(node->header.blockptr, BLOCK_SIZE);

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

static struct btree_node* extent_node_create(struct inode* inode,
                                             int level,
                                             int max_items,
                                             int flag)
{
        unsigned long block;
        struct buffer_head *ebh;
        struct btree_node *node;
    
        BUG_ON(level >= MAX_BTREE_LEVEL);

        block = alloc_meta_block();

        if (extent_alloc_tree_pages(block, PAGE_SIZE) < 0)
                return NULL;

        ebh = get_buffer_head(block);
        if (!ebh)
                return NULL;

        node = (struct btree_node *) (ebh->b_data);
        node->header.level = level;
        node->header.flags = flag;
        node->header.nr_items = 0;
        node->header.offset = 0xFFFFFFFF;
        node->header.blockptr = block;
        node->header.max_items = max_items;
        btree_node_print("new node created", node);
        return node;
}

static void extent_node_destroy(struct inode *inode,
                                struct btree_node *node)
{
        int i, nr_keys = node->header.nr_items;

        btree_node_print("destroying node", node);
        btree_node_keys_print(node);

        if (IS_BTREE_LEAF(node)) {
                for (i = 0; i < nr_keys; i++) {
                        extent_release_tree_pages(node->keys[i].blockptr,
                                                  node->keys[i].size);
                        extent_reset_key(&node->keys[i]);
                        node->header.nr_items--;
                }
        } else {
                for (i = 0; i < nr_keys; i++) {
                        struct buffer_head *ebh;
                        if (node->keys[i].blockptr) {
                                ebh = get_buffer_head(node->keys[i].blockptr);
                                if (!ebh) {
                                        pr_err("blockptr error :%llu\n", node->keys[i].blockptr);
                                        BUG();
                                }
                                extent_node_destroy(inode, (struct btree_node *) (ebh->b_data));
                                extent_reset_key(&node->keys[i]);
                                brelse(ebh);
                                node->header.nr_items--;
                        }
                }
        }

        BUG_ON(node->header.nr_items);
        extent_release_tree_pages(node->header.blockptr, PAGE_SIZE);
}

static inline bool extent_tree_can_shrink(struct btree_node *root)
{
        struct btree_node *pnode, *qnode;

        if (IS_BTREE_LEAF(root) || (root->header.nr_items != 2))
               goto noshrink;

        pnode = extent_tree_get_node(root, 0);

        qnode = extent_tree_get_node(root, 1);

        if (pnode->header.nr_items + qnode->header.nr_items > root->header.max_items)
                goto noshrink;

        return true;

noshrink:
        return false;
}

static struct btree_node* extent_tree_shrink(struct inode *inode,
                                             struct btree_node *root)
{
        int i, j;
        struct btree_node *pnode, *qnode, *merge;

        pnode = extent_tree_get_node(root, 0);

        qnode = extent_tree_get_node(root, 1);

	BUG_ON(pnode->header.level != qnode->header.level);

        btree_node_print("root node", root);
        btree_node_keys_print(root);

        btree_node_print("merging node (l)", pnode);
        btree_node_keys_print(pnode);

        btree_node_print("merging node (r)", qnode);
        btree_node_keys_print(qnode);

        merge = extent_node_create(inode,
                                   pnode->header.level,
                                   pnode->header.max_items,
                                   pnode->header.flags);

        for (i = 0; i < pnode->header.nr_items; i++)
                merge->keys[merge->header.nr_items++] = pnode->keys[i];

        for (j = 0; j < qnode->header.nr_items; j++)
                merge->keys[merge->header.nr_items++] = qnode->keys[j];

        // TBD: releases the nodes

        merge->header.offset = merge->keys[0].offset;

	btree_node_print("merged new root node", merge);

        btree_node_keys_print(merge);

        return merge;
}

static struct btree_node* extent_node_merge_siblings(struct inode *inode,
                                                     struct btree_path *paths,
                                                     struct btree_node *pnode,
                                                     struct btree_node *qnode)
{
        int i, j, level;
        bool collapse = false;
        struct btree_node *parent, *merge;

        level = pnode->header.level;

	if (level != qnode->header.level) {
		pr_err("merge node levels mismatch!");
		return ERR_PTR(-EINVAL);
	}

	if (level >= paths->depth) {
		pr_err("invalid merge attempt for bad node level!");
		return ERR_PTR(-EINVAL);
	}

	if (level == paths->depth - 1) {
		pr_err("invalid merge attempt for root node!");
		return ERR_PTR(-EINVAL);
        }

        btree_node_print("merging node (l)", pnode);
        btree_node_keys_print(pnode);

        btree_node_print("merging node (r)", qnode);
        btree_node_keys_print(qnode);

        parent = paths->nodes[level + 1];

        merge = extent_node_create(inode,
                                   level,
                                   parent->header.max_items,
                                   pnode->header.flags);

        for (i = 0; i < pnode->header.nr_items; i++)
                merge->keys[merge->header.nr_items++] = pnode->keys[i];

        for (j = 0; j < qnode->header.nr_items; j++)
                merge->keys[merge->header.nr_items++] = qnode->keys[j];

        merge->header.offset = merge->keys[0].offset;

	btree_node_print("merged new node", merge);

        btree_node_keys_print(merge);

        (void) extent_index_node_remove(parent, pnode, paths, pnode->keys[0].offset, collapse);

        //TBD : remove root if single entry
        (void) extent_index_node_remove(parent, qnode, paths, qnode->keys[0].offset, collapse);

	paths->nodes[level] = merge;

        extent_index_node_insert(parent, merge, paths);

        extent_node_update_backrefs(merge, paths);

        btree_node_keys_print(merge);

	// rebalance will attempt further merge on parent if possible
        return merge;
}

static int extent_node_steal_from_sibling(struct btree_node *parent,
                                          struct btree_node *cur_node,
                                          struct btree_node *sib_node)
{
        struct btree_key key;
        int curr_index, sib_index;

        SET_KEY_FROM_BTREE_HDR(key, cur_node);
        curr_index = extent_index_node_lookup(parent, &key);
        if (curr_index < 0)
                return -ENOENT;

        SET_KEY_FROM_BTREE_HDR(key, sib_node);
        sib_index = extent_index_node_lookup(parent, &key);
        if (sib_index < 0)
                return -ENOENT;

        btree_node_print("attempting rebalance from sibling", cur_node);

        // right sibling
        if (cur_node->header.offset < sib_node->header.offset) {
                int p = cur_node->header.nr_items - 1;
                int q = sib_node->header.nr_items - 1;

                memcpy((char *) &sib_node->keys[q + 1], (char *) &cur_node->keys[p],
                       sizeof(struct btree_key));
                cur_node->header.nr_items--;
                sib_node->header.nr_items++;

                extent_node_sort(sib_node);
                //btree_node_keys_print(sib_node);

                SET_KEY_EMPTY(cur_node->keys[p]);
                sib_node->header.offset = sib_node->keys[0].offset;
                parent->keys[sib_index].offset = sib_node->header.offset;
        // left sibling
        } else {
                int p = cur_node->header.nr_items - 1;
                int q = sib_node->header.nr_items - 1;

                memcpy((char *) &sib_node->keys[q + 1], (char *) &cur_node->keys[0],
                       sizeof(struct btree_key));
                memcpy((char *) &cur_node->keys[0], (char *) &cur_node->keys[p],
                       sizeof(struct btree_key));

                cur_node->header.nr_items--;
                sib_node->header.nr_items++;

                extent_node_sort(cur_node);
                //btree_node_keys_print(cur_node);

                SET_KEY_EMPTY(cur_node->keys[p]);
                cur_node->header.offset = cur_node->keys[0].offset;
                parent->keys[curr_index].offset = cur_node->header.offset;
        }

        return 0;
}

static struct btree_node *extent_tree_get_left_sibling(struct btree_node *node,
                                                       struct btree_node *parent,
                                                       struct btree_path *path)
{
        int i;
        struct buffer_head *ebh;
        struct btree_node *sibling = NULL;

	btree_node_print("get sibling node(l)", node);

        // scan parent keys
        for (i = 0; i < parent->header.nr_items; i++) {
                if (parent->keys[i].blockptr != node->header.blockptr)
                                continue;
                if (i == 0)
                        goto nosibling;
                ebh = get_buffer_head(parent->keys[i - 1].blockptr);
                BUG_ON(!ebh);
                sibling = (struct btree_node *)(ebh->b_data);
                goto found;
        }
        return NULL;

nosibling:

	// move up and scan
	if (extent_node_is_root(parent, path)) {
		btree_node_print("parent node", parent);
                pr_info("node has no adjacent(l/r) node");
                return NULL;
        }

        sibling = extent_tree_get_left_sibling(parent, 
                                               path->nodes[parent->header.level + 1],
                                               path);
        if (!sibling) {
                parent = path->nodes[parent->header.level + 1];
                goto nosibling;
        }

	// DFS 
        for (i = sibling->header.level; i > node->header.level; i--) {
	     BUG_ON(!sibling->header.nr_items);
             ebh = get_buffer_head(sibling->keys[sibling->header.nr_items - 1].blockptr);
             BUG_ON(!ebh);
             sibling = (struct btree_node *)(ebh->b_data);
	     BUG_ON(!sibling);
        }
found:
        btree_node_print("sibling found", sibling);
        return sibling;
}

static struct btree_node *extent_tree_get_right_sibling(struct btree_node *node,
                                                        struct btree_node *parent,
                                                        struct btree_path *path)
{
        int i;
        struct buffer_head *ebh;
        struct btree_node *sibling = NULL;

	btree_node_print("get sibling node(r)", node);

        // scan parent keys
        for (i = 0; i < parent->header.nr_items; i++) {
                if (parent->keys[i].blockptr != node->header.blockptr)
                	continue;

                if (i == parent->header.nr_items - 1)
			goto nosibling;

                ebh = get_buffer_head(parent->keys[i + 1].blockptr);
                BUG_ON(!ebh);
                sibling = (struct btree_node *)(ebh->b_data);
                BUG_ON(!sibling);
                goto found;
        }
        return NULL;

nosibling:

	// move up and scan
	if (extent_node_is_root(parent, path)) {
		btree_node_print("parent node", parent);
                pr_info("node is a boundary node, no adjacent(l/r) node!");
                return NULL;
        } 

        sibling =  extent_tree_get_right_sibling(parent, 
                                                 path->nodes[parent->header.level + 1],
                                                 path);
        if (!sibling) {
                parent = path->nodes[parent->header.level + 1];
                goto nosibling;
        }

	// DFS 
        for (i = sibling->header.level;
             i > node->header.level;
             i--) {
	     BUG_ON(!sibling->header.nr_items);
             ebh = get_buffer_head(sibling->keys[0].blockptr);
             BUG_ON(!ebh);
             sibling = (struct btree_node *)(ebh->b_data);
             BUG_ON(!sibling);
        }
found:
        btree_node_print("sibling found", sibling);
        return sibling;
}

// TBD : merge a parent and a child
static void extent_tree_rebalance(struct inode *inode,
                                  struct btree_node *curr_node,
                                  struct btree_path *path)
{
	int i, level = curr_node->header.level;
        struct btree_node *parent, *lsib, *rsib;

        for (i = level; i < path->depth - 1; i++) {

                BUG_ON(extent_node_is_root(curr_node, path));

		if (!extent_node_attempt_rebalance(curr_node))
			break;

		btree_node_print("rebalancing", curr_node);

                parent = path->nodes[i + 1];

		btree_node_print("parent", parent);
                btree_node_keys_print(parent);

                lsib = extent_tree_get_left_sibling(curr_node, parent, path);
		if (lsib) {
			if (extent_node_attempt_steal(curr_node, lsib)) {
                        	extent_node_steal_from_sibling(parent, curr_node, lsib);
                        	curr_node = parent;
				continue;
			} else if (extent_node_attempt_merge(curr_node, lsib)) {
                        	if (IS_ERR(extent_node_merge_siblings(inode, path, lsib, curr_node)))
					BUG();
                        	curr_node = parent;
				continue;
			}
		}

                rsib = extent_tree_get_right_sibling(curr_node, parent, path);
		if (rsib) {
			if (extent_node_attempt_steal(curr_node, rsib)) {
                        	extent_node_steal_from_sibling(parent, curr_node, rsib);
                        	curr_node = parent;
				continue;
			} else if (extent_node_attempt_merge(curr_node, rsib)) {
                        	if (IS_ERR(extent_node_merge_siblings(inode, path, curr_node, rsib)))
					BUG();
                        	curr_node = parent;
				continue;
			}
		}
                btree_info("no rebalance for node\n");
                break;
        }
}

static struct btree_node* extent_node_split(struct inode *inode,
                                            struct btree_root_node *root_node,
                                            struct btree_path *paths,
                                            int curr_level)
{
        bool new_root = false, collapse = false;
        struct btree_node *pnode;

        do {
                int i, mid, ret;
                struct buffer_head *lbh, *rbh;
                struct btree_node *node, *l_sib, *r_sib;

                BUG_ON(curr_level >= MAX_BTREE_LEVEL);

                node = paths->nodes[curr_level];

                BUG_ON(curr_level != node->header.level);

                btree_node_print("splitting node", node);

                mid = node->header.nr_items >> 1;
                l_sib = extent_node_create(inode,
                                           node->header.level,
                                           node->header.max_items,
                                           node->header.flags);

                lbh = get_buffer_head(l_sib->header.blockptr);
                if (!lbh)
                        return NULL;

                for (i = 0; i < mid; i++) {
                        memcpy((char *)&l_sib->keys[i],
                               (char *)&node->keys[i], sizeof(struct btree_key));
                        l_sib->header.nr_items++;
                }

                l_sib->header.offset = l_sib->keys[0].offset;

                if (!l_sib->header.offset) {
                        btree_node_print("split node info (l)", node);
                        btree_node_keys_print(node);
                }

                btree_node_print("created left sibling", l_sib);

                btree_node_keys_print(l_sib);

                brelse(lbh);

                r_sib = extent_node_create(inode,
                                           node->header.level,
                                           node->header.max_items,
                                           node->header.flags);

                rbh = get_buffer_head(r_sib->header.blockptr);
                if (!rbh)
                        return NULL;

                for (i = mid; i < node->header.nr_items; i++) {
                        memcpy((char *)&r_sib->keys[i - mid],
                               (char *)&node->keys[i], sizeof(struct btree_key));
                        r_sib->header.nr_items++;
                }

                r_sib->header.offset = r_sib->keys[0].offset;
                if (!r_sib->header.offset) {
                        btree_node_print("split node info (r)", node);
                        btree_node_keys_print(node);
                }

                btree_node_print("created right sibling", r_sib);

                btree_node_keys_print(r_sib);

                brelse(rbh);

                if (node->header.level < paths->depth - 1) {
                        pnode = paths->nodes[node->header.level + 1];
                        if (extent_index_node_remove(pnode, node, paths, node->keys[0].offset, collapse) < 0)
                                WARN_ON(1);
                } else {
                        pnode = extent_node_create(inode, 
                                                   node->header.level + 1,
                                                   node->header.max_items,
                                                   INDEX_NODE);
                        paths->nodes[node->header.level + 1] = pnode;
                        paths->depth++;
                        new_root = true;
                }

                // update the path as we go up
                if (!IS_BTREE_LEAF(node)) {
                        struct btree_node *cnode = paths->nodes[node->header.level - 1];
                        if (r_sib->header.offset < cnode->header.offset)
                                paths->nodes[node->header.level] = l_sib;
                        else
                                paths->nodes[node->header.level] = r_sib;
                }

                ret = extent_index_node_insert(pnode, l_sib, paths);
                BUG_ON(ret < 0);
                extent_node_update_backrefs(l_sib, paths);
                if (extent_node_full(pnode)) {
                        extent_node_split(inode, root_node, paths, pnode->header.level);
                        BUG_ON(pnode == paths->nodes[node->header.level + 1]);
                        pnode = paths->nodes[node->header.level + 1];
                }

                ret = extent_index_node_insert(pnode, r_sib, paths);
                BUG_ON(ret < 0);
                extent_node_update_backrefs(r_sib, paths);
                if (extent_node_full(pnode)) {
                        extent_node_split(inode, root_node, paths, pnode->header.level);
                        BUG_ON(pnode == paths->nodes[node->header.level + 1]);
                        pnode = paths->nodes[node->header.level + 1];
                }

                if (new_root) {
                        btree_node_print("created new parent node", pnode);
                        btree_node_keys_print(pnode);
                }

                extent_release_tree_pages(node->header.blockptr, BLOCK_SIZE);

                extent_tree_rebalance(inode, pnode, paths);

                curr_level++;

        } while (extent_node_full(pnode));

        if (new_root) {
                root_node->node = pnode;
                root_node->max_level = paths->depth - 1;
        }

        return pnode;
}

static struct btree_node* extent_tree_find_leaf(struct inode* inode,
                                                struct btree_key* key,
                                                struct btree_node* node,
                                                struct btree_path* path)
{
        int slot;
        struct buffer_head* ebh;

        path->nodes[path->level] = node;

        path->depth++;

        if (IS_BTREE_LEAF(node))
                return node;

        path->level--;

        BUG_ON(path->level < 0);

        slot = extent_index_node_search_keys(node, key);

        ebh = get_buffer_head(node->keys[slot].blockptr);
        if (!ebh)
                return ERR_PTR(-EIO);

        return extent_tree_find_leaf(inode,
                                     key,
                                     (struct btree_node *)(ebh->b_data),
                                     path);
}

int extent_tree_insert_item(struct inode* inode,
                            struct btree_root_node *root,
                            unsigned long value,
                            unsigned int size)
{
        int i, ret = 0;
        bool added = false;
        unsigned long block;
        struct btree_node *leaf;
        struct btree_key key = { value, size, 0xFFFFFFFF};
        struct btree_path *path = kzalloc(sizeof(struct btree_path), GFP_KERNEL);

        path->level = root->max_level;

        pr_info("root max level :%u\n", root->max_level);

        leaf = extent_tree_find_leaf(inode, &key, root->node, path);
        BUG_ON(!leaf);

        if (IS_ERR(leaf)) {
                pr_err("failed to locate key: %ld, status: %ld\n",
                                value, PTR_ERR(leaf));
                return -EIO;
        }

        btree_node_print("selected leaf to insert", leaf);

        block = alloc_data_block();

        (void) extent_alloc_tree_pages(block, PAGE_SIZE);

        for (i = 0; i < leaf->header.max_items; i++) {
                if (IS_KEY_EMPTY(leaf->keys[i])) {
                    leaf->keys[i].blockptr = block;
                    leaf->keys[i].offset = value;
                    leaf->keys[i].size = size;
                    leaf->header.nr_items++;
                    btree_info("inserted item[%d/%d] :%lu %u-%u\n",
                            i, leaf->header.nr_items, value,
                            path->level, path->depth);
                    added = true;
                    break;
                }
        }

        if (added) {
                extent_node_sort(leaf);
                //btree_node_keys_print(leaf);
                extent_node_update_backrefs(leaf, path);
                extent_tree_rebalance(inode, leaf, path);
                if (extent_node_full(leaf))
                        extent_node_split(inode, root, path, leaf->header.level);
        } else {
                extent_release_tree_pages(block, PAGE_SIZE);
                pr_err("failed to insert key :%lu\n", value);
                ret = -EAGAIN;
        }

        kfree(path);
        return ret;
}

int extent_tree_delete_item(struct inode* inode,
                            struct btree_root_node *root,
                            unsigned long offset)
{
        int i;
        bool collapse = true;
        struct btree_node *leaf, *parent;
        struct btree_key key = { offset, 0, 0 };
        struct btree_path *path = kzalloc(sizeof(struct btree_path), GFP_KERNEL);

        path->level = root->max_level;

        leaf = extent_tree_find_leaf(inode, &key, root->node, path);
        BUG_ON(!leaf);

        if (IS_ERR(leaf)) {
                pr_err("failed to locate key: %ld, status: %ld\n",
                                offset, PTR_ERR(leaf));
                return -EIO;
        }

        btree_node_print("selected leaf to delete", leaf);
        btree_node_keys_print(leaf);

        for (i = 0; i < leaf->header.nr_items; i++) {
                if (leaf->keys[i].offset != key.offset)
                        continue;
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
                break;
        }

        if (extent_node_is_root(leaf, path)) {
                parent = NULL;
                extent_node_sort(leaf);
        } else {
                parent = path->nodes[leaf->header.level + 1];
                if (leaf->header.nr_items) {
                        extent_node_sort(leaf);
                        extent_node_update_backrefs(leaf, path);
                        extent_tree_rebalance(inode, leaf, path);
                } else {
                        int ret;

                        path->nodes[leaf->header.level] = NULL;
                        ret = extent_index_node_remove(parent, leaf, path, offset, collapse);
                        if (ret < 0)
                                WARN_ON(1);
                        else {
                                parent = path->nodes[ret];
                                extent_tree_rebalance(inode, parent, path);
                        }
                }
        }

        btree_node_keys_print(leaf);

        if (path->depth < root->max_level)
                root->max_level = path->depth;

        if (extent_tree_can_shrink(root->node)) {
                root->node = extent_tree_shrink(inode, root->node);
                root->max_level--;
        }

        kfree(path);
        return 0;
}

// DFS
void extent_tree_dump(struct seq_file *m, struct btree_node *node, int count)
{
        int i, level = node->header.level;

        for (i = 0; i <= count; i++)
                seq_printf(m, "-");

        seq_printf(m, "%s Level :%d Blockptr :%llu Offset :%llu NKeys :%d\n",
                       node->header.flags == INDEX_NODE ? "BRANCH BLOCK" : "LEAF BLOCK",
                       level,
                       node->header.blockptr,
                       node->header.offset,
                       node->header.nr_items);

        for (i = 0; i < node->header.nr_items; i++) {
                int j;

                if (true || node->keys[i].blockptr) {
                        for (j = 0; j <= count; j++)
                                seq_printf(m, "-");
                        seq_printf(m, "[%d] offset :%llu  bptr :%llu\n",
                                        i,
                                        node->keys[i].offset,
                                        node->keys[i].blockptr);
                        if (!IS_BTREE_LEAF(node)) {
                                struct buffer_head *ebh;

                                if (node->keys[i].blockptr) {
                                        ebh = get_buffer_head(node->keys[i].blockptr);
                                        extent_tree_dump(m, (struct btree_node *)(ebh->b_data), count + 1);
                                }
                        }
                }
        }
}

static struct btree_root_node* extent_tree_load(struct inode* inode, struct btree_key *key)
{
        struct btree_root_node *root = NULL;
        struct buffer_head *ebh;

        root = kzalloc(sizeof(struct btree_root_node), GFP_KERNEL);
        if (!root)
                goto exit;

        ebh = get_buffer_head(key->blockptr);
        if (!ebh)
                goto exit;

        memcpy((char*)root->node, ebh->b_data, sizeof(struct btree_node));
        brelse(ebh);
        return root;
exit:
        kfree(root);
        return NULL;
}

static struct btree_root_node* extent_tree_init(struct inode* inode, int max_keys)
{
        struct btree_root_node *root = NULL;

        INIT_RADIX_TREE(&pgtree, GFP_KERNEL);

        root = kzalloc(sizeof(struct btree_root_node), GFP_KERNEL);
        if (!root)
                goto exit;

        root->node = extent_node_create(inode, 0, max_keys, LEAF_NODE);
        if (!root->node)
                goto exit;

        root->inode = inode;
        root->max_level = 0;
        return root;

exit:
        kfree(root);
        return NULL;
}

static void extent_tree_destroy(struct inode* inode, struct btree_root_node *root)
{
        extent_node_destroy(inode, root->node);
        root->node = NULL;
        kfree(root);
}

static int run_tests(void)
{
        btree_root = extent_tree_init(NULL, MAX_KEYS);
        if (!btree_root) {
                pr_err("failed to initialize tree");
                return -ENODEV;
        }

        dbgfs_dir = btree_debugfs_init(btree_root);
        if (!dbgfs_dir)
                return -1;
        return 0;
}

static int
__init init_btree_tests(void)
{
    run_tests();
    btree_info("BTree module loaded");
    return 0;
}

static void
__exit exit_btree_tests(void)
{
    extent_tree_destroy(NULL, btree_root);
    btree_debugfs_destroy(dbgfs_dir);
    btree_info("BTree module removed");
}

module_init(init_btree_tests)
module_exit(exit_btree_tests)
