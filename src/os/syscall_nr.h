/*
 * src/os/syscall_nr.h — Linux arch/powerpc 32-bit syscall numbers
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Phase 0 freeze: numbers follow arch/powerpc (syscall.tbl / uapi
 * unistd_32.h). The `sc` convention itself (nr in r0, args r3..r8,
 * CR0.SO error flag) is verified in experiments/E01. Lane L2a (Phase 2)
 * audits this table against syscall.tbl when wiring the dispatchers.
 */

#ifndef PPC32_SYSCALL_NR_H
#define PPC32_SYSCALL_NR_H

/* Process lifecycle / identity */
#define PPC32_NR_EXIT            1U
#define PPC32_NR_FORK            2U
#define PPC32_NR_READ            3U
#define PPC32_NR_WRITE           4U
#define PPC32_NR_OPEN            5U
#define PPC32_NR_CLOSE           6U
#define PPC32_NR_WAITPID         7U
#define PPC32_NR_CREAT           8U
#define PPC32_NR_LINK            9U
#define PPC32_NR_UNLINK          10U
#define PPC32_NR_EXECVE          11U
#define PPC32_NR_CHDIR           12U
#define PPC32_NR_MKNOD           14U
#define PPC32_NR_CHMOD           15U
#define PPC32_NR_LSEEK           19U
#define PPC32_NR_GETPID          20U
#define PPC32_NR_SETUID          23U
#define PPC32_NR_GETUID          24U
#define PPC32_NR_PTRACE          26U
#define PPC32_NR_ACCESS          33U
#define PPC32_NR_SYNC            36U
#define PPC32_NR_KILL            37U
#define PPC32_NR_RENAME          38U
#define PPC32_NR_MKDIR           39U
#define PPC32_NR_RMDIR           40U
#define PPC32_NR_DUP             41U
#define PPC32_NR_PIPE            42U
#define PPC32_NR_TIMES           43U
#define PPC32_NR_BRK             45U
#define PPC32_NR_SETGID          46U
#define PPC32_NR_GETGID          47U
#define PPC32_NR_GETEUID         49U
#define PPC32_NR_GETEGID         50U
#define PPC32_NR_IOCTL           54U
#define PPC32_NR_FCNTL           55U
#define PPC32_NR_SETPGID         57U
#define PPC32_NR_UMASK           60U
#define PPC32_NR_CHROOT          61U
#define PPC32_NR_DUP2            63U
#define PPC32_NR_GETPPID         64U
#define PPC32_NR_GETPGRP         65U
#define PPC32_NR_SETSID          66U
#define PPC32_NR_SIGACTION       67U
#define PPC32_NR_SIGSUSPEND      72U
#define PPC32_NR_SIGPENDING      73U
#define PPC32_NR_SETRLIMIT       75U
#define PPC32_NR_GETRLIMIT       76U
#define PPC32_NR_GETRUSAGE       77U
#define PPC32_NR_GETTIMEOFDAY    78U
#define PPC32_NR_SETTIMEOFDAY    79U
#define PPC32_NR_GETGROUPS       80U
#define PPC32_NR_SETGROUPS       81U
#define PPC32_NR_SELECT          82U
#define PPC32_NR_SYMLINK         83U
#define PPC32_NR_READLINK        85U
#define PPC32_NR_USELIB          86U
#define PPC32_NR_REBOOT          88U

/* Memory management */
#define PPC32_NR_MMAP            90U
#define PPC32_NR_MUNMAP          91U
#define PPC32_NR_TRUNCATE        92U
#define PPC32_NR_FTRUNCATE       93U
#define PPC32_NR_FCHMOD          94U
#define PPC32_NR_MPROTECT        125U
#define PPC32_NR_MSYNC           144U
#define PPC32_NR_MLOCK           150U
#define PPC32_NR_MUNLOCK         151U
#define PPC32_NR_MREMAP          163U
#define PPC32_NR_MMAP2           192U
#define PPC32_NR_MINCORE         218U
#define PPC32_NR_MADVISE         219U

/* Filesystem / stat */
#define PPC32_NR_STATFS          99U
#define PPC32_NR_FSTATFS         100U
#define PPC32_NR_STAT            106U
#define PPC32_NR_LSTAT           107U
#define PPC32_NR_FSTAT           108U
#define PPC32_NR_WAIT4           114U
#define PPC32_NR_SYSINFO         116U
#define PPC32_NR_FSYNC           118U
#define PPC32_NR_LLSEEK          140U
#define PPC32_NR_GETDENTS        141U
#define PPC32_NR_NEWSELECT       142U
#define PPC32_NR_FLOCK           143U
#define PPC32_NR_READV           145U
#define PPC32_NR_WRITEV          146U
#define PPC32_NR_FDATASYNC       148U
#define PPC32_NR_GETCWD          183U
#define PPC32_NR_STAT64          195U
#define PPC32_NR_LSTAT64         196U
#define PPC32_NR_FSTAT64         197U
#define PPC32_NR_GETDENTS64      220U

/* Signals (rt_* arrive with the Phase 4 sigframe lane) */
#define PPC32_NR_SIGRETURN       119U
#define PPC32_NR_SIGPROCMASK     126U
#define PPC32_NR_RT_SIGRETURN    172U
#define PPC32_NR_RT_SIGACTION    173U
#define PPC32_NR_RT_SIGPROCMASK  174U
#define PPC32_NR_RT_SIGPENDING   175U
#define PPC32_NR_RT_SIGTIMEDWAIT 176U
#define PPC32_NR_RT_SIGQUEUEINFO 177U
#define PPC32_NR_RT_SIGSUSPEND    178U
#define PPC32_NR_SIGALTSTACK      185U

/* Threads / futex (clone TLS via CLONE_SETTLS, E06) */
#define PPC32_NR_CLONE           120U
#define PPC32_NR_UNAME           122U
#define PPC32_NR_PRCTL           171U
#define PPC32_NR_PREAD64         179U
#define PPC32_NR_PWRITE64        180U
#define PPC32_NR_VFORK           189U
#define PPC32_NR_FUTEX           221U
#define PPC32_NR_SET_TID_ADDRESS 232U
/* RC2: exit_group is 234 (glibc _exit does li r0,234; the old 272 value
 * belongs to no ppc32 call and sent every guest exit into the ENOSYS
 * trap slot). Grounded against the linked glibc binary + qemu oracle. */
#define PPC32_NR_EXIT_GROUP      234U

/* Sockets / IPC multiplexors */
#define PPC32_NR_SOCKETCALL      102U
#define PPC32_NR_IPC             117U

/* Time */
#define PPC32_NR_NANOSLEEP       162U
#define PPC32_NR_POLL            168U
#define PPC32_NR_SENDFILE        186U

#endif /* PPC32_SYSCALL_NR_H */
