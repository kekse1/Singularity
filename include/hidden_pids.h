#ifndef HIDDEN_PIDS_H
#define HIDDEN_PIDS_H

#define MAX_HIDDEN_PIDS 32

extern int hidden_pids[MAX_HIDDEN_PIDS];
extern int hidden_count;

notrace void add_hidden_pid(int pid);
notrace int is_hidden_pid(const char *d_name);

#endif
