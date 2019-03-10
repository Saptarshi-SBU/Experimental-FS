#ifndef _LUCI_BTREE_H_
#define _LUCI_BTREE_H_

#include <linux/fs.h>
#include <linux/types.h>
#include <linux/buffer_head.h>
#include <linux/seq_file.h>

#define MAX_BTREE_LEVEL             8
#define MAX_BKEYS_PER_BLOCK         ((PAGE_SIZE - (sizeof(struct btree_header)))/sizeof(struct btree_key))

#define INDEX_NODE 0
#define LEAF_NODE  1

struct btree_header {
        __u8   level;
        __u16  nr_items;
        __u16  max_items;
        __le32 size;
        __le64 offset;
        __le64 blockptr;
        __le64 flags;
} __attribute__ ((__packed__));

struct btree_key {
        __le64 offset;
        __le32 size;
        __le64 blockptr;
} __attribute__ ((__packed__));

struct btree_node {
        struct btree_header header;
        struct btree_key    keys[MAX_BKEYS_PER_BLOCK];
} __attribute__ ((__packed__));

// in-memory
struct btree_path {
        struct btree_node  *nodes[MAX_BTREE_LEVEL];
        struct buffer_head *bh[MAX_BTREE_LEVEL];
        int                 depth;
        int                 level;
};

struct btree_root_node {
        struct inode* inode;
        struct btree_node* node;
        struct buffer_head *bh;
        int    max_level;
};

struct btree_operations {
        int  (*btree_init)    (struct btree_root_node **root, int max_keys);
        int  (*btree_lookup)  (struct btree_root_node *root, u64 offset, struct btree_key *key);
        int  (*btree_insert)  (struct btree_root_node *root, struct btree_key *key);
        int  (*btree_remove)  (struct btree_root_node *root, u64 offset, size_t size);
        void (*btree_destroy) (struct btree_root_node *root);
        void (*btree_dump)    (struct btree_root_node *root);
};

int extent_tree_insert_item(struct inode* inode,
                            struct btree_root_node *root,
                            unsigned long block,
                            unsigned int size);

int extent_tree_delete_item(struct inode* inode,
                            struct btree_root_node *root,
                            unsigned long key);

unsigned long extent_tree_dump(struct seq_file *m, struct btree_node *node, long refcount, int count);

struct dentry *btree_debugfs_init(struct btree_root_node *btree_root);
int btree_debugfs_destroy(struct dentry *dentry);

#define BH2BTNODE(bh) ((struct btree_node *)(bh->b_data))

#define IS_BTREE_LEAF(node) \
        ((node)->header.flags == LEAF_NODE)

#define IS_KEY_EMPTY(key) \
        (((key).blockptr == 0) || ((key).blockptr == 0xFFFFFFFF))

#define SET_KEY_EMPTY(key) \
        memset((char *)&(key), 0, sizeof(struct btree_key))

#define SET_KEY_FROM_BTREE_HDR(key, node) \
        do { \
                key.offset = node->header.offset; \
                key.size = node->header.size; \
                key.blockptr = node->header.blockptr; \
        } while (0)

#define btree_info(FMT, ...) \
        pr_debug(FMT, ##__VA_ARGS__)

#define btree_node_print(msg, node) \
            pr_debug("%s: %s, offset=%llu bptr=%llu level=%u nr_keys=%u/%u type=%s\n", \
                            __func__,   \
                            msg,        \
                            (node)->header.offset,    \
                            (node)->header.blockptr,    \
                            (node)->header.level,       \
                            (node)->header.nr_items,    \
                            (node)->header.max_items,   \
                            (node)->header.flags == INDEX_NODE ? "INDEX" : "LEAF")

#define btree_node_keys_print(node) \
        do { \
                int i; \
                pr_debug("%s: offset=%llu bptr=%llu level=%u nr_keys=%u type=%s dumping keys: ", \
                        __func__, \
                        (node)->header.offset,    \
                        (node)->header.blockptr, \
                        (node)->header.level,       \
                        (node)->header.nr_items, \
                        (node)->header.flags == INDEX_NODE ? "INDEX" : "LEAF"); \
                for (i = 0; i < (node)->header.nr_items; i++) \
                        pr_debug("bptr=%llu [%u] offset=%llu keybptr=%llu\n", \
                                (node)->header.blockptr, i, \
                                (node)->keys[i].offset, \
                                (node)->keys[i].blockptr);\
        } while (0)

#define btree_level_print(LEVEL, FMT, ...) \
        do { \
                int __i; \
                for (__i = 0; __i <= (LEVEL); __i++) \
                        pr_cont("-"); \
                pr_cont(FMT, ##__VA_ARGS__); \
        } while (0)

#endif
