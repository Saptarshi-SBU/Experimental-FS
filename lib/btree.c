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

static struct dentry *dbgfs_dir;

static struct btree_root_node *btree_root;

static struct radix_tree_root pgtree; // track btree index pages

#define META_BLOCK_START (1UL << 30)

static unsigned long get_data_block(void)
{
        static atomic_t data_block = ATOMIC_INIT(0);

        atomic_inc(&data_block);
        return atomic_read(&data_block);
}

static unsigned long get_meta_block(void)
{
        static atomic_t meta_block = ATOMIC_INIT(META_BLOCK_START);

        atomic_inc(&meta_block);
        return atomic_read(&meta_block);
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

static inline bool extent_nodes_can_merge(struct btree_node *node,
                                          struct btree_node *sib)
{
        int node_capacity = node->header.max_items - 1;

        if ((node->header.nr_items < node_capacity / 2) &&
           ((node->header.nr_items + sib->header.nr_items) < node_capacity))
                return true;

        return false;
}

static inline bool extent_nodes_can_steal(struct btree_node *node,
                                          struct btree_node *sib)
{
        int node_capacity = node->header.max_items - 1;

        if ((node->header.nr_items >= node_capacity) &&
            (sib->header.nr_items < node_capacity))
                return true;

        return false;
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
}

static int extent_index_node_lookup(struct btree_node *node,
                                    struct btree_key *key)
{
        int i, slot = -1;

        btree_node_print("lookupnode entry", node);

        for (i = 0; i < node->header.nr_items; i++) {
                if (key->offset == node->keys[i].offset)
                        return i;
                else if (key->offset > node->keys[i].offset)
                        slot = i;
                else
                        break;
        }

        btree_node_keys_print(node);
        return (slot < 0) ? -ENOENT : slot;
}

static int extent_index_node_insert(struct btree_node *pnode,
                                    struct btree_node *node)
{
        struct btree_key key;

        SET_KEY_FROM_BTREE_HDR(key, node);

        if (extent_node_full(pnode)) {
                btree_node_print("node is full", node);
                return -ENOSPC;
        }

        memcpy((char* )&pnode->keys[pnode->header.nr_items], (char*)&key,
                sizeof(struct btree_key));

        pnode->header.nr_items++;

        //btree_node_print("append index node entry", pnode);

        extent_node_sort(pnode);

        //btree_node_keys_print(pnode);

        return 0;
}

static int extent_index_node_remove(struct btree_node *pnode,
                                    struct btree_node *node)
{
        int slot, last;
        struct btree_key key;

        SET_KEY_FROM_BTREE_HDR(key, node);

        btree_node_print("remove index node entry (before)", node);

        slot = extent_index_node_lookup(pnode, &key);
        if (slot < 0) {
                pr_err("entry not found");
                return -ENOENT;
        }

        if (key.blockptr != pnode->keys[slot].blockptr) {
                pr_err("entry blockptr mismatch");
                return -EINVAL;
        }

        btree_node_keys_print(pnode);

        last = pnode->header.nr_items - 1;
        memcpy((char* )&pnode->keys[slot],
               (char* )&pnode->keys[last], sizeof(struct btree_key));

        pnode->header.nr_items--;

        extent_node_sort(pnode);

        btree_node_print("remove index node entry (after)", pnode);

        btree_node_keys_print(pnode);

        return 0;
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

        block = get_meta_block();

        if (extent_alloc_tree_pages(block, PAGE_SIZE) < 0)
                return NULL;

        ebh = get_buffer_head(block);
        if (!ebh)
                return NULL;

        node = (struct btree_node *) (ebh->b_data);
        node->header.level = level;
        node->header.flags = flag;
        node->header.nr_items = 0;
        node->header.blockptr = block;
        node->header.max_items = max_items;
        //btree_node_print("new node created", node);
        return node;
}

static void extent_node_destroy(struct inode *inode,
                                struct btree_node *node)
{
        int i, nr_keys = node->header.nr_items;

        //btree_node_print("destroying node", node);

        if (IS_BTREE_LEAF(node)) {
                for (i = 0; i < nr_keys; i++) {
                        extent_release_tree_pages(node->keys[i].blockptr,
                                                  node->keys[i].size);
                        extent_reset_key(&node->keys[i]);
                        node->header.nr_items--;
                }
        } else {
                //btree_node_keys_print(node);

                for (i = 0; i < nr_keys; i++) {
                        struct buffer_head *ebh;
                        if (node->keys[i].blockptr) {
                                ebh = get_buffer_head(node->keys[i].blockptr);
                                if (!ebh) {
                                        pr_err("blockptr error :%llu\n", node->keys[i].blockptr);
                                        return;
                                        BUG();
                                }
                                extent_node_destroy(inode, (struct btree_node *) (ebh->b_data));
                                extent_reset_key(&node->keys[i]);
                                brelse(ebh);
                                node->header.nr_items--;
                        }
                }
        }

        //BUG_ON(node->header.nr_items != 0);

        extent_release_tree_pages(node->header.blockptr, PAGE_SIZE);
}

static struct btree_node* extent_node_merge(struct inode *inode,
                                            struct btree_path *paths,
                                            struct btree_node *pnode,
                                            struct btree_node *qnode,
                                            int curr_level)
{
        int i, j;
        struct btree_node *merge;
        struct btree_node *parent;

        parent = paths->nodes[curr_level + 1];

        merge = extent_node_create(inode,
                                   curr_level,
                                   parent->header.max_items,
                                   parent->header.flags);

        for (i = 0; i < pnode->header.nr_items; i++) {
                merge->keys[i] = pnode->keys[i];
                merge->header.nr_items++;
        }

        extent_index_node_remove(parent, pnode);

        extent_release_tree_pages(pnode->header.blockptr, BLOCK_SIZE);

        for (j = 0; j < qnode->header.nr_items; j++) {
                merge->keys[i] = qnode->keys[j];
                merge->header.nr_items++;
        }

        //TBD : remove root if single entry
        extent_index_node_remove(parent, qnode);

        extent_release_tree_pages(qnode->header.blockptr, BLOCK_SIZE);

        extent_index_node_insert(parent, merge);

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

        //btree_node_print("attempting rebalance from sibling", cur_node);

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
                                                       struct btree_node *parent)
{
        int i;

        for(i = 0; i < parent->header.nr_items; i++) {
                struct buffer_head *ebh;

                if (parent->keys[i].blockptr != node->header.blockptr)
                                continue;
                if (i > 0) {
                        ebh = get_buffer_head(parent->keys[i - 1].blockptr);
                        if (!ebh)
                                BUG();
                        return (struct btree_node *)(ebh->b_data);
                }
                break;
        }
        return NULL;
}

static struct btree_node *extent_tree_get_right_sibling(struct btree_node *node,
                                                        struct btree_node *parent)
{
        int i;

        for(i = 0; i < parent->header.nr_items; i++) {
                struct buffer_head *ebh;

                if (parent->keys[i].blockptr != node->header.blockptr)
                                continue;

                if (i < parent->header.nr_items - 1) {
                        ebh = get_buffer_head(parent->keys[i + 1].blockptr);
                        if (!ebh)
                                BUG();
                        return (struct btree_node *)(ebh->b_data);
                }
                break;
        }
        return NULL;
} 

static void extent_tree_rebalance(struct inode *inode,
                                  struct btree_node *curr_node,
                                  struct btree_path *path,
                                  int level)
{
        while (level + 1 < path->depth) {
                struct btree_node *parent = path->nodes[level + 1];

                struct btree_node *lsib =
                        extent_tree_get_left_sibling(curr_node, parent);

                struct btree_node *rsib =
                        extent_tree_get_right_sibling(curr_node, parent);

                if (lsib && extent_nodes_can_steal(curr_node, lsib)) {
                        extent_node_steal_from_sibling(parent, curr_node, lsib);
                        curr_node = parent;
                } else if (rsib && extent_nodes_can_steal(curr_node, rsib)) {
                        extent_node_steal_from_sibling(parent, curr_node, rsib);
                        curr_node = parent;
                } else if (lsib && extent_nodes_can_merge(curr_node, lsib)) {
                        curr_node = extent_node_merge(inode, path, lsib, curr_node, level);
                } else if (rsib && extent_nodes_can_merge(curr_node, rsib)) {
                        curr_node = extent_node_merge(inode, path, curr_node, rsib, level);
                } else
                        break;
                level++;        
        }
}

static struct btree_node* extent_node_split(struct inode *inode,
                                            struct btree_root_node *root_node,
                                            struct btree_path *paths,
                                            int curr_level)
{
        bool new_root = false;
        struct btree_node *pnode;

        do {
                int i, mid, ret;
                struct buffer_head *ebh, *lbh, *rbh;
                struct btree_node *node, *l_sib, *r_sib;

                BUG_ON(curr_level >= MAX_BTREE_LEVEL);

                node = paths->nodes[curr_level];

                BUG_ON(curr_level != node->header.level);

                btree_node_print("splitting node", node);

                ebh = get_buffer_head(node->header.blockptr);
                if (!ebh)
                        return NULL;

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
                        if (extent_index_node_remove(pnode, node) < 0)
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

                ret = extent_index_node_insert(pnode, l_sib);
                BUG_ON(ret < 0);
                if (extent_node_full(pnode)) {
                        extent_node_split(inode, root_node, paths, pnode->header.level);
                        BUG_ON(pnode == paths->nodes[node->header.level + 1]);
                        pnode = paths->nodes[node->header.level + 1];
                }

                ret = extent_index_node_insert(pnode, r_sib);
                BUG_ON(ret < 0);
                if (extent_node_full(pnode)) {
                        extent_node_split(inode, root_node, paths, pnode->header.level);
                        BUG_ON(pnode == paths->nodes[node->header.level + 1]);
                        pnode = paths->nodes[node->header.level + 1];
                }

                btree_node_print("created new parent node", pnode);

                btree_node_keys_print(pnode);

                extent_release_tree_pages(node->header.blockptr, BLOCK_SIZE);

                brelse(ebh);

                extent_tree_rebalance(inode, pnode, paths, pnode->header.level);

                curr_level++;

        } while (extent_node_full(pnode));

        if (new_root) {
                root_node->node = pnode;
                root_node->max_level++;
        }

        return pnode;
}

static int extent_tree_lookup_item(struct inode* inode,
                                   struct btree_root_node *root_node,
                                   struct btree_path *path,
                                   struct btree_key *qkey)
{
        int i;
        struct btree_node *node = root_node->node;

        btree_info("%s :%llu\n", __func__, qkey->blockptr);

next_index:
        if (!IS_BTREE_LEAF(node)) {

            int pslot = 0;
            struct buffer_head *ebh;

            //btree_node_print("searching index node", node);

            BUG_ON(path->depth > MAX_BTREE_LEVEL);
            BUG_ON(path->level < 1);

            path->nodes[path->level] = node; 
            path->level--;
            path->depth++;

            for (i = 0; i < node->header.nr_items; i++) {
                if (qkey->blockptr > node->keys[i].offset) {
                    pslot = i;
                    continue;
                }
                break;
            }

            ebh = get_buffer_head(node->keys[pslot].blockptr);
            BUG_ON(ebh == NULL);
            node = (struct btree_node *)(ebh->b_data);
            goto next_index;

        } else {

            //btree_node_print("searching leaf node", node);

            BUG_ON(path->depth > MAX_BTREE_LEVEL);
            BUG_ON(path->level < 0);

            path->nodes[path->level] = node; 
            path->depth++;

            for (i = 0; i < node->header.nr_items; i++) {
                if (node->keys[i].offset == qkey->offset) {
                    btree_info("found leaf item[%d]:%llu-%llu/%d\n", i,
                            node->keys[i].offset, node->keys[i].offset,
                            path->depth);
                    return path->depth;
                }
            }
        }
        return -ENOENT;
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

        slot = extent_index_node_lookup(node, key);
        if (slot < 0)
                return ERR_PTR(-ENOENT);

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
        int i;
        unsigned long block;
        struct btree_node *leaf;
        struct btree_key key = { value, block, size };
        struct btree_path *path = kzalloc(sizeof(struct btree_path), GFP_KERNEL);

        path->level = root->max_level;
        leaf = extent_tree_find_leaf(inode, &key, root->node, path);
        if (!leaf || IS_ERR(leaf)) {
                pr_err("failed to locate leaf block:%ld, status: %ld\n",
                                block, PTR_ERR(leaf));
                return -EIO;
        }

        block = get_data_block();
        (void) extent_alloc_tree_pages(block, PAGE_SIZE);

        //btree_node_print("selected leaf to insert", leaf);

        for (i = 0; i < leaf->header.max_items; i++) {
                if (IS_KEY_EMPTY(leaf->keys[i])) {
                    leaf->keys[i].blockptr = block;
                    leaf->keys[i].offset = value;
                    leaf->keys[i].size = size;
                    leaf->header.nr_items++;
                    btree_info("inserted item[%d/%d] :%lu %u-%u\n",
                            i, leaf->header.nr_items, value, path->level, path->depth);
                    break;
                }
        }

        //btree_node_keys_print(leaf);

        extent_tree_rebalance(inode, leaf, path, 0);
        if (extent_node_full(leaf))
                extent_node_split(inode, root, path, 0);

        kfree(path);

        return 0;
}

static int extent_tree_delete_item(struct inode *inode,
                                   struct btree_root_node *root,
                                   struct btree_path *path,
                                   struct btree_key *key)
{
        int i;
        struct btree_node *leaf;

        path->level = root->max_level;
        if (extent_tree_lookup_item(inode, root, path, key) < 0)
                goto exit;

        leaf = path->nodes[0];
        for (i = 0; i < leaf->header.nr_items; i++) {
                if (leaf->keys[i].offset != key->offset)
                        continue;
                memcpy((char *)&leaf->keys[i], (char *)&leaf->keys[leaf->header.nr_items - 1],
                        sizeof(struct btree_key));
                leaf->header.nr_items--;
                extent_node_sort(leaf);
                extent_tree_rebalance(inode, leaf, path, 0);
                return 0;
        }
exit:
        return -ENOENT;
}

// DFS
void extent_tree_dump(struct seq_file *m, struct btree_node *node, int count)
{
        int i, level = node->header.level;

        for (i = 0; i <= count; i++)
                seq_printf(m, "-");

        seq_printf(m, "%s Level :%d Blockptr :%llu Offset :%llu\n",
                       node->header.flags == INDEX_NODE ? "BRANCH BLOCK" : "LEAF BLOCK",
                       level,
                       node->header.blockptr,
                       node->header.offset);

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
        btree_root = extent_tree_init(NULL, 8);
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
