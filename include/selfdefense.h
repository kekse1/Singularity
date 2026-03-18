#ifndef SELFDEFENSE_H
#define SELFDEFENSE_H

notrace int  sd_bootstrap_kprobe_hook(void);
notrace void sd_protect_symbol(const char *symname);
notrace int  selfdefense_init(void);
notrace void selfdefense_exit(void);

#endif