/*
 * src/os/backend.h — Frozen host backend contract (Wave U3 lane U3-ppc32)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * UNIFICATION-PLAN.md Rev 4 section 6 (Pillar 3): the complete host OS
 * backend interface consumed by src/vm/vm32*.c, src/vm/vm_file.c,
 * src/dbt/aot/ and the guest syscall layer. Two implementations ship
 * from the same tree (Goal 3):
 *
 *   Backend 1 (src/os/backend_linux.c): static-PIE aarch64-linux musl
 *   ELF, _build/ppc32rt-linux-aarch64; raw Linux AArch64 svc, the
 *   signal-atomic safe_syscall window, /dev/a32host probing, host
 *   mprotect W^X with IC IALLU.
 *
 *   Backend 2 (src/os/backend_darwin.c): native macOS arm64 Mach-O,
 *   _build/ppc32rt-darwin-arm64; libSystem blr, MAP_JIT APRR W^X with
 *   per-thread pthread_jit_write_protect_np, per-syscall-class
 *   kevent/wake-pipe/__ulock_wait2 signal-atomic blocking.
 *
 * Guest page-size rule: rt_host_page_size() is queried dynamically
 * (4096, 16384, or 65536) and never hardcoded; Regime A1 vs A2 in
 * src/vm/vm32.c keys off it.
 *
 * Curated C11. This header declares; it emits no code and never
 * touches x18.
 */

#ifndef PPC32RT_OS_BACKEND_H
#define PPC32RT_OS_BACKEND_H

#include <signal.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <time.h>

typedef enum {
    RT_BACKEND_LINUX = 1, /* static-PIE aarch64-linux (native or hl) */
    RT_BACKEND_DARWIN = 2 /* standalone macOS arm64 Mach-O */
} rt_backend_kind_t;

/* 1. Identity and dynamic host page size. */
rt_backend_kind_t rt_host_backend_kind(void);
int rt_host_is_hyper_linux(void);
size_t rt_host_page_size(void);

/* 2. Host memory primitives for src/vm/. linux_prot uses PROT_* values;
 * fixed/noreplace/shared select MAP_FIXED / MAP_FIXED_NOREPLACE /
 * MAP_SHARED. Returns 0 with *out set, negative errno otherwise. */
int rt_host_map_anon(void *hint_addr, size_t len, int linux_prot,
    int fixed, int noreplace, void **out_host_addr);
int rt_host_map_file(void *hint_addr, size_t len, int linux_prot,
    int shared, int fixed, int host_fd, uint64_t aligned_file_offset,
    void **out_host_addr);
int rt_host_create_shared_mem(const char *name, size_t size,
    int *out_host_fd);
int rt_host_protect(void *host_addr, size_t len, int linux_prot);
int rt_host_unmap(void *host_addr, size_t len);
int rt_host_msync(void *host_addr, size_t len, int linux_flags);
int rt_host_madvise(void *host_addr, size_t len, int linux_advice);

/* 3. JIT W^X code-cache allocation and thread-local APRR publication.
 * Write via begin_write, seal to RX before execution (with I-cache
 * flush); never map guest data pages executable. */
void *rt_host_jit_alloc(size_t size);
void rt_host_jit_thread_init(void);
void rt_host_jit_begin_write(void *buf, size_t size);
int rt_host_jit_seal_rx(void *buf, size_t size);
void rt_host_jit_free(void *buf, size_t size);

/* 4. Per-worker signal-atomic blocking state and preemption. */
typedef struct {
    _Atomic uint32_t sig_seq;
    _Atomic uint32_t in_commit_window;
    _Atomic uintptr_t ulock_wait_addr;
    int kqueue_fd;
    int wake_pipe_rd;
    int wake_pipe_wr;
    uint64_t host_tid;
} rt_worker_sync_t;

int rt_host_worker_sync_init(rt_worker_sync_t *ws);
void rt_host_worker_sync_destroy(rt_worker_sync_t *ws);
void rt_host_worker_notify_signal(rt_worker_sync_t *ws);
/* Park a chained DBT spin-loop: SIGRTMIN+1 via tgkill (Linux) or
 * SIGUSR2 via pthread_kill (Darwin). */
int rt_host_preempt_worker(uint64_t host_tid);

/* 5. Filesystem and descriptor operations. Potentially blocking calls
 * take the worker sync plus the expected sig_seq so a signal arriving
 * mid-wait wakes them with zero lost-wakeup window. */
int64_t rt_host_openat(int dirfd, const char *path, int linux_flags,
    uint32_t mode, rt_worker_sync_t *ws, uint32_t expected_seq);
int64_t rt_host_close(int fd);
int64_t rt_host_read(int fd, void *buf, size_t count,
    rt_worker_sync_t *ws, uint32_t expected_seq);
int64_t rt_host_write(int fd, const void *buf, size_t count,
    rt_worker_sync_t *ws, uint32_t expected_seq);
int64_t rt_host_pread64(int fd, void *buf, size_t count, int64_t offset);
int64_t rt_host_pwrite64(int fd, const void *buf, size_t count,
    int64_t offset);
int64_t rt_host_lseek(int fd, int64_t offset, int linux_whence);
int64_t rt_host_ftruncate(int fd, int64_t length);
int64_t rt_host_fsync(int fd, int datasync_only);
int64_t rt_host_getdents64(int fd, void *linux_dirent64_buf,
    size_t buf_size);
int64_t rt_host_fcntl(int fd, int linux_cmd, uint64_t arg);
int64_t rt_host_dup(int oldfd);
int64_t rt_host_pipe2(int fds[2], int linux_flags);

/* 6. Canonical futex key with backing pinning (section 4.4/6.7): pin
 * before the bucket lock (Rank 1 mmap -> Rank 7 bucket safe), convert
 * val to host endianness on BE guests, release the VM lease first. */
typedef enum {
    RT_FUTEX_KEY_PRIVATE = 1,
    RT_FUTEX_KEY_SHARED_ANON = 2,
    RT_FUTEX_KEY_SHARED_FILE = 3
} rt_futex_key_kind_t;

typedef struct {
    uint32_t kind;
    uint32_t reserved;
    uint64_t owner_id;
    uint64_t mount_id;
    uint64_t offset;
} rt_futex_key_t;

int64_t rt_host_futex_wait(_Atomic uint32_t *pinned_host_uaddr,
    const rt_futex_key_t *key, uint32_t host_endian_val,
    const struct timespec *timeout, uint32_t bitset,
    rt_worker_sync_t *ws, uint32_t expected_seq);
int64_t rt_host_futex_wake(_Atomic uint32_t *pinned_host_uaddr,
    const rt_futex_key_t *key, int count, uint32_t bitset);
int64_t rt_host_clock_gettime(int linux_clk_id, struct timespec *tp);
int64_t rt_host_clock_nanosleep(int linux_clk_id, int linux_flags,
    const struct timespec *req, struct timespec *rem,
    rt_worker_sync_t *ws, uint32_t expected_seq);

/* 7. Process, thread, and signal delivery. */
int rt_host_spawn_worker(void *(*fn)(void *), void *arg,
    uint64_t *out_host_tid);
int64_t rt_host_fork(void);
int64_t rt_host_wait4(int64_t pid, int *linux_status_out,
    int linux_options, rt_worker_sync_t *ws, uint32_t expected_seq);
int64_t rt_host_kill(int64_t pid, int linux_sig);
int64_t rt_host_tgkill(int64_t tgid, int64_t tid, int linux_sig);
void rt_host_exit_thread(int status);
void rt_host_exit_group(int status);

typedef struct {
    int linux_si_signo;
    int linux_si_code;
    uintptr_t fault_addr;
    uintptr_t host_pc;
    int is_write;
    void *host_ucontext;
} rt_host_sync_fault_t;

typedef struct {
    int linux_si_signo;
    int linux_si_code;
    int32_t sender_pid;
    uint32_t sender_uid;
    int32_t exit_status_or_sig;
} rt_host_async_siginfo_t;

typedef void (*rt_host_sync_fault_fn)(const rt_host_sync_fault_t *fault);
typedef void (*rt_host_async_sig_fn)(const rt_host_async_siginfo_t *sig);
typedef void (*rt_host_preempt_fn)(void *host_ucontext);

int rt_host_install_signal_handlers(rt_host_sync_fault_fn on_sync_fault,
    rt_host_async_sig_fn on_async_sig, rt_host_preempt_fn on_preempt);

#endif /* PPC32RT_OS_BACKEND_H */
