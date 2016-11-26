#ifndef _LUCI_FS_H
#define _LUCI_FS_H

#define LUCI_ROOT_INODE 1

struct luci_inode_info {
    union {
        __u16 i1_data[16];
        __u32 i2_data[16];
    } u;
    struct inode vfs_inode;
};

static inline struct luci_inode_info *luci_i(struct inode *inode)
{
    return list_entry(inode, struct luci_inode_info, vfs_inode);
}

#endif
