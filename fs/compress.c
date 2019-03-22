#include "compress.h"

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
struct list_head *luci_compression_context(void)
{
    DEFINE_WAIT(wait);
    struct list_head *ctx;

repeat:

    spin_lock(&ctxpool.lock);
    if (!list_empty(&ctxpool.idle_list)) {
        ctx = ctxpool.idle_list.next;
        list_del(ctx);
        spin_unlock(&ctxpool.lock);
        return ctx;
    }

    /*
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
    */

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
void put_compression_context(struct list_head *ctx)
{
    spin_lock(&ctxpool.lock);
    //BUG_ON(atomic_read(&ctxpool.count) > num_online_cpus());
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
    pr_info("%s : %u\n", __func__, atomic_read(&ctxpool.count));

    while (!list_empty(&ctxpool.idle_list)) {
        struct list_head *ctx = ctxpool.idle_list.next;
	list_del(ctx);
	ctxpool.op->free_workspace(ctx);
	atomic_dec(&ctxpool.count);
    }
}
