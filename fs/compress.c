#include "compress.h"

// Limiting workspaces was causing a soft lockup and observed a pool of 
// threads were stuck in irqsave/restore. For now, create as many workspaces
// as need be.
//define LUCI_LIMIT_WORKSPACES

struct luci_context_pool ctxpool;

/*
 * initialize workspaces for all compression formats
 */
void init_luci_compress(void)
{
    INIT_LIST_HEAD(&ctxpool.idle_list);
    atomic_set(&ctxpool.count, 0);
    spin_lock_init(&ctxpool.lock);
    init_waitqueue_head(&ctxpool.waitq);
    ctxpool.op = &luci_zlib_compress;
}

/*
 * finds an available workspace or creates one to run compress/decompress.
 */
struct list_head *luci_get_compression_context(void)
{
    DEFINE_WAIT(wait);
    struct list_head *ctx;

#ifdef LUCI_LIMIT_WORKSPACES
repeat:
#endif

    spin_lock(&ctxpool.lock);
    if (!list_empty(&ctxpool.idle_list)) {
        ctx = ctxpool.idle_list.next;
        list_del(ctx);
        spin_unlock(&ctxpool.lock);
        return ctx;
    }

#ifdef LUCI_LIMIT_WORKSPACES
    if (atomic_read(&ctxpool.count) >= num_online_cpus()) {
        spin_unlock(&ctxpool.lock);
        prepare_to_wait(&ctxpool.waitq,
                        &wait,
                        TASK_UNINTERRUPTIBLE);
        if (atomic_read(&ctxpool.count) > num_online_cpus())
            schedule();
        finish_wait(&ctxpool.waitq, &wait);
        goto repeat;
    }
#endif

    atomic_inc(&ctxpool.count);
    spin_unlock(&ctxpool.lock);

    ctx = ctxpool.op->alloc_workspace();
    if (IS_ERR(ctx)) {
        atomic_dec(&ctxpool.count);
        wake_up(&ctxpool.waitq);
    }
    return ctx;
}

/*
 * put a workspace back to the list after work is done
 */
void luci_put_compression_context(struct list_head *ctx)
{
    spin_lock(&ctxpool.lock);
#ifdef LUCI_LIMIT_WORKSPACES
    BUG_ON(atomic_read(&ctxpool.count) > num_online_cpus());
#endif
    list_add(ctx, &ctxpool.idle_list);
    spin_unlock(&ctxpool.lock);

    smp_mb();
    if (waitqueue_active(&ctxpool.waitq))
        wake_up(&ctxpool.waitq);
}

/*
 *  destroy luci workspaces
 */
void exit_luci_compress(void)
{
    while (!list_empty(&ctxpool.idle_list)) {
        struct list_head *ctx = ctxpool.idle_list.next;
	list_del(ctx);
	ctxpool.op->free_workspace(ctx);
	atomic_dec(&ctxpool.count);
    }
}
