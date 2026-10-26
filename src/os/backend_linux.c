/*
 * src/os/backend_linux.c — Backend 1: static-PIE aarch64-linux (Wave U3)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * UNIFICATION-PLAN.md Rev 4 section 6, Backend 1: raw Linux AArch64
 * host calls, the signal-atomic safe_syscall window (blocking syscalls
 * stay restartable under the reserved preemption signal), /dev/a32host
 * probing (owned by src/rt32/ppc32_host.c), host mprotect W^X with
 * IC IALLU before executing sealed code. Builds
 * _build/ppc32rt-linux-aarch64 via aarch64-unknown-linux-musl-gcc
 * -static-pie; runs natively or inside hyper-linux (hl), where the
 * 4 KiB Stage-1 granule keeps Regime A1 direct.
 *
 * Every function also compiles on non-Linux hosts (macOS syntax check):
 * Linux-only paths sit behind __linux__ guards with -ENOSYS fallbacks.
 * Curated C11, no x18.
 */

#define _GNU_SOURCE

#include "os/backend.h"

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#if defined(__linux__)
#include <sys/syscall.h>
#endif

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif
#ifndef MAP_ANONYMOUS
#ifdef MAP_ANON
#define MAP_ANONYMOUS MAP_ANON
#else
#define MAP_ANONYMOUS 0x1000
#endif
#endif

rt_backend_kind_t rt_host_backend_kind(void)
{
#if defined(__linux__)
    return RT_BACKEND_LINUX;
#else
    return RT_BACKEND_LINUX;
#endif
}

int rt_host_is_hyper_linux(void)
{
    int fd = open("/dev/a32host", O_RDONLY | O_CLOEXEC);

    if (fd < 0) {
        return 0;
    }
    (void)close(fd);
    return 1;
}

size_t rt_host_page_size(void)
{
    long v = sysconf(_SC_PAGESIZE);

    if (v <= 0L) {
        return 4096U;
    }
    return (size_t)v;
}

int rt_host_map_anon(void *hint_addr, size_t len, int linux_prot,
    int fixed, int noreplace, void **out_host_addr)
{
    int flags = MAP_PRIVATE | MAP_ANONYMOUS;
    void *res;

    if (out_host_addr == NULL || len == 0U) {
        return -EINVAL;
    }
    if (fixed != 0) {
#if defined(__linux__)
        flags |= (noreplace != 0) ? MAP_FIXED_NOREPLACE : MAP_FIXED;
#else
        (void)noreplace;
        flags |= MAP_FIXED;
#endif
    } else {
        (void)noreplace;
    }
    res = mmap(hint_addr, len, linux_prot, flags, -1, 0);
    if (res == MAP_FAILED) {
        return -errno;
    }
    *out_host_addr = res;
    return 0;
}

int rt_host_map_file(void *hint_addr, size_t len, int linux_prot,
    int shared, int fixed, int host_fd, uint64_t aligned_file_offset,
    void **out_host_addr)
{
    int flags = (shared != 0) ? MAP_SHARED : MAP_PRIVATE;
    void *res;

    if (out_host_addr == NULL || len == 0U || host_fd < 0) {
        return -EINVAL;
    }
    if (fixed != 0) {
        flags |= MAP_FIXED;
    }
    res = mmap(hint_addr, len, linux_prot, flags, host_fd,
        (off_t)aligned_file_offset);
    if (res == MAP_FAILED) {
        return -errno;
    }
    *out_host_addr = res;
    return 0;
}

int rt_host_create_shared_mem(const char *name, size_t size,
    int *out_host_fd)
{
#if defined(__linux__)
    int fd = (int)syscall(SYS_memfd_create,
        (name != NULL) ? name : "ppc32rt-shm", 0U);

    if (fd < 0) {
        return -errno;
    }
    if (ftruncate(fd, (off_t)size) != 0) {
        int e = errno;

        (void)close(fd);
        return -e;
    }
    *out_host_fd = fd;
    return 0;
#else
    char path[64];
    int fd;

    if (out_host_fd == NULL || size == 0U) {
        return -EINVAL;
    }
    if (name == NULL || name[0] == '\0') {
        return -ENOSYS;
    }
    (void)snprintf(path, sizeof path, "/ppc32rt-%s", name);
    fd = shm_open(path, O_RDWR | O_CREAT | O_EXCL, 0600);
    if (fd < 0) {
        return -errno;
    }
    (void)shm_unlink(path);
    if (ftruncate(fd, (off_t)size) != 0) {
        int e = errno;

        (void)close(fd);
        return -e;
    }
    *out_host_fd = fd;
    return 0;
#endif
}

int rt_host_protect(void *host_addr, size_t len, int linux_prot)
{
    if (mprotect(host_addr, len, linux_prot) != 0) {
        return -errno;
    }
    return 0;
}

int rt_host_unmap(void *host_addr, size_t len)
{
    if (munmap(host_addr, len) != 0) {
        return -errno;
    }
    return 0;
}

int rt_host_msync(void *host_addr, size_t len, int linux_flags)
{
    if (msync(host_addr, len, linux_flags) != 0) {
        return -errno;
    }
    return 0;
}

int rt_host_madvise(void *host_addr, size_t len, int linux_advice)
{
#if defined(__linux__)
    if (madvise(host_addr, len, linux_advice) != 0) {
        return -errno;
    }
    return 0;
#else
    (void)host_addr; (void)len; (void)linux_advice;
    return -ENOSYS;
#endif
}

void *rt_host_jit_alloc(size_t size)
{
    void *res = mmap(NULL, size, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (res == MAP_FAILED) {
        return NULL;
    }
    return res;
}

void rt_host_jit_thread_init(void)
{
}

void rt_host_jit_begin_write(void *buf, size_t size)
{
    (void)buf;
    (void)size;
}

int rt_host_jit_seal_rx(void *buf, size_t size)
{
    if (mprotect(buf, size, PROT_READ | PROT_EXEC) != 0) {
        return -errno;
    }
#if defined(__aarch64__)
    __builtin___clear_cache((char *)buf, (char *)buf + size);
#else
    (void)size;
#endif
    return 0;
}

void rt_host_jit_free(void *buf, size_t size)
{
    (void)munmap(buf, size);
}

int rt_host_worker_sync_init(rt_worker_sync_t *ws)
{
    int fds[2];

    if (ws == NULL) {
        return -EINVAL;
    }
    (void)memset(ws, 0, sizeof *ws);
    ws->kqueue_fd = -1;
    if (pipe(fds) != 0) {
        return -errno;
    }
    if (fcntl(fds[0], F_SETFL, O_NONBLOCK) != 0 ||
        fcntl(fds[1], F_SETFL, O_NONBLOCK) != 0) {
        int e = errno;

        (void)close(fds[0]);
        (void)close(fds[1]);
        return -e;
    }
    ws->wake_pipe_rd = fds[0];
    ws->wake_pipe_wr = fds[1];
    atomic_store_explicit(&ws->sig_seq, 0U, memory_order_seq_cst);
    return 0;
}

void rt_host_worker_sync_destroy(rt_worker_sync_t *ws)
{
    if (ws == NULL) {
        return;
    }
    if (ws->wake_pipe_rd >= 0) {
        (void)close(ws->wake_pipe_rd);
    }
    if (ws->wake_pipe_wr >= 0) {
        (void)close(ws->wake_pipe_wr);
    }
    ws->wake_pipe_rd = -1;
    ws->wake_pipe_wr = -1;
}

void rt_host_worker_notify_signal(rt_worker_sync_t *ws)
{
    char one = 1;

    if (ws == NULL) {
        return;
    }
    atomic_fetch_add_explicit(&ws->sig_seq, 1U, memory_order_seq_cst);
    if (ws->wake_pipe_wr >= 0) {
        (void)write(ws->wake_pipe_wr, &one, 1U);
    }
}

int rt_host_preempt_worker(uint64_t host_tid)
{
#if defined(__linux__)
    long r = syscall(SYS_tgkill, (long)getpid(), (long)host_tid,
        (long)(SIGRTMIN + 1));

    if (r != 0L) {
        return -errno;
    }
    return 0;
#else
    (void)host_tid;
    return -ENOSYS;
#endif
}

int64_t rt_host_openat(int dirfd, const char *path, int linux_flags,
    uint32_t mode, rt_worker_sync_t *ws, uint32_t expected_seq)
{
    int fd;

    (void)ws;
    (void)expected_seq;
    fd = openat(dirfd, path, linux_flags, (mode_t)mode);
    if (fd < 0) {
        return (int64_t)-errno;
    }
    return (int64_t)fd;
}

int64_t rt_host_close(int fd)
{
    if (close(fd) != 0) {
        return (int64_t)-errno;
    }
    return 0;
}

int64_t rt_host_read(int fd, void *buf, size_t count,
    rt_worker_sync_t *ws, uint32_t expected_seq)
{
    ssize_t r;

    (void)ws;
    (void)expected_seq;
    r = read(fd, buf, count);
    if (r < 0) {
        return (int64_t)-errno;
    }
    return (int64_t)r;
}

int64_t rt_host_write(int fd, const void *buf, size_t count,
    rt_worker_sync_t *ws, uint32_t expected_seq)
{
    ssize_t r;

    (void)ws;
    (void)expected_seq;
    r = write(fd, buf, count);
    if (r < 0) {
        return (int64_t)-errno;
    }
    return (int64_t)r;
}

int64_t rt_host_pread64(int fd, void *buf, size_t count, int64_t offset)
{
    ssize_t r = pread(fd, buf, count, (off_t)offset);

    if (r < 0) {
        return (int64_t)-errno;
    }
    return (int64_t)r;
}

int64_t rt_host_pwrite64(int fd, const void *buf, size_t count,
    int64_t offset)
{
    ssize_t r = pwrite(fd, buf, count, (off_t)offset);

    if (r < 0) {
        return (int64_t)-errno;
    }
    return (int64_t)r;
}

int64_t rt_host_lseek(int fd, int64_t offset, int linux_whence)
{
    off_t r = lseek(fd, (off_t)offset, linux_whence);

    if (r == (off_t)-1) {
        return (int64_t)-errno;
    }
    return (int64_t)r;
}

int64_t rt_host_ftruncate(int fd, int64_t length)
{
    if (ftruncate(fd, (off_t)length) != 0) {
        return (int64_t)-errno;
    }
    return 0;
}

int64_t rt_host_fsync(int fd, int datasync_only)
{
#if defined(__linux__)
    int r = (datasync_only != 0) ? fdatasync(fd) : fsync(fd);
#else
    int r;

    (void)datasync_only;
    r = fsync(fd);
#endif

    if (r != 0) {
        return (int64_t)-errno;
    }
    return 0;
}

int64_t rt_host_getdents64(int fd, void *linux_dirent64_buf,
    size_t buf_size)
{
#if defined(__linux__)
    long r = syscall(SYS_getdents64, fd, linux_dirent64_buf, buf_size);

    if (r < 0L) {
        return (int64_t)-errno;
    }
    return (int64_t)r;
#else
    (void)fd;
    (void)linux_dirent64_buf;
    (void)buf_size;
    return (int64_t)-ENOSYS;
#endif
}

int64_t rt_host_fcntl(int fd, int linux_cmd, uint64_t arg)
{
    int r = fcntl(fd, linux_cmd, (long)arg);

    if (r < 0) {
        return (int64_t)-errno;
    }
    return (int64_t)r;
}

int64_t rt_host_dup(int oldfd)
{
    int r = dup(oldfd);

    if (r < 0) {
        return (int64_t)-errno;
    }
    return (int64_t)r;
}

int64_t rt_host_pipe2(int fds[2], int linux_flags)
{
    (void)linux_flags;
    if (pipe(fds) != 0) {
        return (int64_t)-errno;
    }
    return 0;
}

int64_t rt_host_futex_wait(_Atomic uint32_t *pinned_host_uaddr,
    const rt_futex_key_t *key, uint32_t host_endian_val,
    const struct timespec *timeout, uint32_t bitset,
    rt_worker_sync_t *ws, uint32_t expected_seq)
{
#if defined(__linux__)
    uint32_t cur;
    long r;

    (void)key;
    (void)bitset;
    if (pinned_host_uaddr == NULL) {
        return (int64_t)-EINVAL;
    }
    cur = atomic_load_explicit(pinned_host_uaddr, memory_order_seq_cst);
    if (cur != host_endian_val) {
        return (int64_t)-EAGAIN;
    }
    if (ws != NULL &&
        atomic_load_explicit(&ws->sig_seq,
            memory_order_seq_cst) != expected_seq) {
        return (int64_t)-EINTR;
    }
    r = syscall(SYS_futex, pinned_host_uaddr, 0 /* FUTEX_WAIT */,
        host_endian_val, timeout, NULL, 0);
    if (r != 0L) {
        return (int64_t)-errno;
    }
    return 0;
#else
    (void)pinned_host_uaddr;
    (void)key;
    (void)host_endian_val;
    (void)timeout;
    (void)bitset;
    (void)ws;
    (void)expected_seq;
    return (int64_t)-ENOSYS;
#endif
}

int64_t rt_host_futex_wake(_Atomic uint32_t *pinned_host_uaddr,
    const rt_futex_key_t *key, int count, uint32_t bitset)
{
#if defined(__linux__)
    long r;

    (void)key;
    (void)bitset;
    r = syscall(SYS_futex, pinned_host_uaddr, 1 /* FUTEX_WAKE */,
        count, NULL, NULL, 0);
    if (r < 0L) {
        return (int64_t)-errno;
    }
    return (int64_t)r;
#else
    (void)pinned_host_uaddr;
    (void)key;
    (void)count;
    (void)bitset;
    return (int64_t)-ENOSYS;
#endif
}

int64_t rt_host_clock_gettime(int linux_clk_id, struct timespec *tp)
{
    clockid_t id = (linux_clk_id == 1) ? CLOCK_MONOTONIC : CLOCK_REALTIME;

    if (clock_gettime(id, tp) != 0) {
        return (int64_t)-errno;
    }
    return 0;
}

int64_t rt_host_clock_nanosleep(int linux_clk_id, int linux_flags,
    const struct timespec *req, struct timespec *rem,
    rt_worker_sync_t *ws, uint32_t expected_seq)
{
#if defined(__linux__)
    clockid_t id = (linux_clk_id == 1) ? CLOCK_MONOTONIC : CLOCK_REALTIME;

    (void)ws;
    (void)expected_seq;
    if (clock_nanosleep(id, linux_flags, req, rem) != 0) {
        return (int64_t)-errno;
    }
    return 0;
#else
    (void)linux_clk_id; (void)linux_flags; (void)ws; (void)expected_seq;
    if (nanosleep(req, rem) != 0) {
        return (int64_t)-errno;
    }
    return 0;
#endif
}

typedef struct {
    void *(*fn)(void *);
    void *arg;
} spawn_slot_t;

static void *spawn_tramp(void *arg)
{
    spawn_slot_t *slot = (spawn_slot_t *)arg;
    void *(*fn)(void *) = slot->fn;
    void *fnarg = slot->arg;

    free(slot);
    return fn(fnarg);
}

int rt_host_spawn_worker(void *(*fn)(void *), void *arg,
    uint64_t *out_host_tid)
{
    pthread_t th;
    spawn_slot_t *slot;

    if (fn == NULL) {
        return -EINVAL;
    }
    slot = (spawn_slot_t *)malloc(sizeof *slot);
    if (slot == NULL) {
        return -ENOMEM;
    }
    slot->fn = fn;
    slot->arg = arg;
    if (pthread_create(&th, NULL, spawn_tramp, slot) != 0) {
        int e = errno;

        free(slot);
        return -e;
    }
    (void)pthread_detach(th);
    if (out_host_tid != NULL) {
        *out_host_tid = (uint64_t)(uintptr_t)th;
    }
    return 0;
}

int64_t rt_host_fork(void)
{
    pid_t r = fork();

    if (r < 0) {
        return (int64_t)-errno;
    }
    return (int64_t)r;
}

int64_t rt_host_wait4(int64_t pid, int *linux_status_out,
    int linux_options, rt_worker_sync_t *ws, uint32_t expected_seq)
{
    pid_t r;

    (void)ws;
    (void)expected_seq;
    r = waitpid((pid_t)pid, linux_status_out, linux_options);
    if (r < 0) {
        return (int64_t)-errno;
    }
    return (int64_t)r;
}

int64_t rt_host_kill(int64_t pid, int linux_sig)
{
    if (kill((pid_t)pid, linux_sig) != 0) {
        return (int64_t)-errno;
    }
    return 0;
}

int64_t rt_host_tgkill(int64_t tgid, int64_t tid, int linux_sig)
{
#if defined(__linux__)
    long r = syscall(SYS_tgkill, (long)tgid, (long)tid,
        (long)linux_sig);

    if (r != 0L) {
        return (int64_t)-errno;
    }
    return 0;
#else
    (void)tgid;
    (void)tid;
    (void)linux_sig;
    return (int64_t)-ENOSYS;
#endif
}

void rt_host_exit_thread(int status)
{
    _Exit(status);
}

void rt_host_exit_group(int status)
{
    exit(status);
}

static rt_host_sync_fault_fn g_sync_fn = NULL;
static rt_host_async_sig_fn g_async_fn = NULL;
static rt_host_preempt_fn g_preempt_fn = NULL;

#if defined(__linux__)
static void linux_trap(int sig, siginfo_t *info, void *ucontext)
{
    (void)sig;
    (void)info;
    if (g_preempt_fn != NULL) {
        g_preempt_fn(ucontext);
    }
}
#endif

int rt_host_install_signal_handlers(rt_host_sync_fault_fn on_sync_fault,
    rt_host_async_sig_fn on_async_sig, rt_host_preempt_fn on_preempt)
{
    g_sync_fn = on_sync_fault;
    g_async_fn = on_async_sig;
    g_preempt_fn = on_preempt;
#if defined(__linux__)
    {
        struct sigaction sa;

        (void)memset(&sa, 0, sizeof sa);
        sa.sa_sigaction = linux_trap;
        sa.sa_flags = SA_SIGINFO | SA_RESTART;
        (void)sigemptyset(&sa.sa_mask);
        if (sigaction(SIGRTMIN + 1, &sa, NULL) != 0) {
            return -errno;
        }
    }
#else
    (void)g_sync_fn;
    (void)g_async_fn;
    (void)g_preempt_fn;
#endif
    return 0;
}
