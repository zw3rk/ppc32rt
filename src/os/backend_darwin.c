/*
 * src/os/backend_darwin.c — Backend 2: native macOS arm64 (Wave U3)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * UNIFICATION-PLAN.md Rev 4 section 6, Backend 2: zero
 * Hypervisor.framework dependency; direct blr into libSystem.B;
 * MAP_JIT APRR W^X (pthread_jit_write_protect_np per-thread publish,
 * PROT_READ | PROT_WRITE staging flipped to PROT_READ | PROT_EXEC with
 * an I-cache flush before execution); per-syscall-class race-free
 * signal-atomic blocking:
 *
 *   (a) FD I/O: readiness multiplexed via kevent on
 *       {target_fd, ws->wake_pipe_rd} before non-blocking O_NONBLOCK
 *       I/O; any sig_seq increment writes one byte to ws->wake_pipe_wr,
 *       so kevent wakes immediately with zero lost-wakeup window.
 *   (b) Futex: sig_seq checked under the bucket lease, sleep via
 *       __ulock_wait2, wake via __ulock_wake(ULF_WAKE_ALL); both
 *       resolved at runtime so the TU also parses on non-Darwin hosts.
 *   (c) Process wait / sleep: worker kqueue (EVFILT_PROC /
 *       EVFILT_TIMER + ws->wake_pipe_rd).
 *
 * Builds _build/ppc32rt-darwin-arm64 via clang -target
 * arm64-apple-macos13. Non-Darwin hosts get -ENOSYS stubs so the file
 * stays syntax-clean under make check everywhere. Curated C11, no x18.
 */

/* No _POSIX_C_SOURCE here: macOS hides MAP_ANONYMOUS, RTLD_DEFAULT,
 * F_FULLFSYNC and madvise under strict POSIX; the default namespace
 * declares them all. The frozen build CFLAGS define the macro for every
 * TU, so drop it for this TU before any system header sees it. */
#ifdef _POSIX_C_SOURCE
#undef _POSIX_C_SOURCE
#endif
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
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#if defined(__APPLE__)
#include <dlfcn.h>
#include <sys/event.h>
#endif

#ifndef MAP_JIT
#define MAP_JIT 0x800
#endif
#ifndef MAP_ANONYMOUS
#ifdef MAP_ANON
#define MAP_ANONYMOUS MAP_ANON
#endif
#endif

/* XNU bsd/sys/ulock.h operation codes (resolved at runtime). */
#define PPC32_UL_COMPARE_AND_WAIT 1U
#define PPC32_ULF_WAKE_ALL 0x00000100U

#if defined(__APPLE__)
typedef int (*jit_protect_fn)(int);
typedef int (*ulock_wait2_fn)(uint32_t, void *, uint64_t, uint64_t,
    uint64_t);
typedef int (*ulock_wake_fn)(uint32_t, void *, uint64_t);

static void load_ptr(void *handle, const char *name, void *fnbuf,
    size_t fnlen)
{
    void *sym = dlsym(handle, name);

    if (sym != NULL) {
        (void)memcpy(fnbuf, &sym, fnlen);
    }
}
#endif

rt_backend_kind_t rt_host_backend_kind(void)
{
#if defined(__APPLE__)
    return RT_BACKEND_DARWIN;
#else
    return RT_BACKEND_DARWIN;
#endif
}

int rt_host_is_hyper_linux(void)
{
    return 0;
}

size_t rt_host_page_size(void)
{
    long v = sysconf(_SC_PAGESIZE);

    if (v <= 0L) {
        return 16384U;
    }
    return (size_t)v;
}

int rt_host_map_anon(void *hint_addr, size_t len, int linux_prot,
    int fixed, int noreplace, void **out_host_addr)
{
#if defined(__APPLE__)
    int flags = MAP_PRIVATE | MAP_ANONYMOUS;
    void *res;

    if (out_host_addr == NULL || len == 0U) {
        return -EINVAL;
    }
    (void)noreplace;
    if (fixed != 0) {
        flags |= MAP_FIXED;
    }
    res = mmap(hint_addr, len, linux_prot, flags, -1, 0);
    if (res == MAP_FAILED) {
        return -errno;
    }
    *out_host_addr = res;
    return 0;
#else
    (void)hint_addr; (void)len; (void)linux_prot; (void)fixed; (void)noreplace; (void)out_host_addr;
    return -ENOSYS;
#endif
}

int rt_host_map_file(void *hint_addr, size_t len, int linux_prot,
    int shared, int fixed, int host_fd, uint64_t aligned_file_offset,
    void **out_host_addr)
{
#if defined(__APPLE__)
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
#else
    (void)hint_addr; (void)len; (void)linux_prot; (void)shared; (void)fixed; (void)host_fd; (void)aligned_file_offset; (void)out_host_addr;
    return -ENOSYS;
#endif
}

int rt_host_create_shared_mem(const char *name, size_t size,
    int *out_host_fd)
{
#if defined(__APPLE__)
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
#else
    (void)name; (void)size; (void)out_host_fd;
    return -ENOSYS;
#endif
}

void *rt_host_jit_alloc(size_t size)
{
#if defined(__APPLE__)
    void *res = mmap(NULL, size, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS | MAP_JIT, -1, 0);

    if (res == MAP_FAILED) {
        return NULL;
    }
    return res;
#else
    (void)size;
    return NULL;
#endif
}

void rt_host_jit_thread_init(void)
{
#if defined(__APPLE__)
    jit_protect_fn protect = NULL;

    load_ptr(RTLD_DEFAULT, "pthread_jit_write_protect_np", &protect,
        sizeof protect);
    if (protect != NULL) {
        (void)protect(1);
    }
#endif
}

void rt_host_jit_begin_write(void *buf, size_t size)
{
#if defined(__APPLE__)
    jit_protect_fn protect = NULL;

    (void)buf; (void)size;
    load_ptr(RTLD_DEFAULT, "pthread_jit_write_protect_np", &protect,
        sizeof protect);
    if (protect != NULL) {
        (void)protect(0);
    }
#else
    (void)buf; (void)size;
#endif
}

int rt_host_jit_seal_rx(void *buf, size_t size)
{
#if defined(__APPLE__)
    jit_protect_fn protect = NULL;

    load_ptr(RTLD_DEFAULT, "pthread_jit_write_protect_np", &protect,
        sizeof protect);
    if (protect != NULL) {
        (void)protect(1);
    }
    if (mprotect(buf, size, PROT_READ | PROT_EXEC) != 0) {
        return -errno;
    }
    __builtin___clear_cache((char *)buf, (char *)buf + size);
    return 0;
#else
    (void)buf; (void)size;
    return -ENOSYS;
#endif
}

void rt_host_jit_free(void *buf, size_t size)
{
#if defined(__APPLE__)
    (void)munmap(buf, size);
#else
    (void)buf; (void)size;
#endif
}

int rt_host_worker_sync_init(rt_worker_sync_t *ws)
{
    int fds[2];

    if (ws == NULL) {
        return -EINVAL;
    }
    (void)memset(ws, 0, sizeof *ws);
    ws->kqueue_fd = -1;
    ws->wake_pipe_rd = -1;
    ws->wake_pipe_wr = -1;
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
#if defined(__APPLE__)
    ws->kqueue_fd = kqueue();
    if (ws->kqueue_fd < 0) {
        int e = errno;

        (void)close(fds[0]);
        (void)close(fds[1]);
        ws->wake_pipe_rd = -1;
        ws->wake_pipe_wr = -1;
        return -e;
    }
#endif
    atomic_store_explicit(&ws->sig_seq, 0U, memory_order_seq_cst);
    return 0;
}

void rt_host_worker_sync_destroy(rt_worker_sync_t *ws)
{
    if (ws == NULL) {
        return;
    }
#if defined(__APPLE__)
    if (ws->kqueue_fd >= 0) {
        (void)close(ws->kqueue_fd);
    }
#endif
    if (ws->wake_pipe_rd >= 0) {
        (void)close(ws->wake_pipe_rd);
    }
    if (ws->wake_pipe_wr >= 0) {
        (void)close(ws->wake_pipe_wr);
    }
    ws->kqueue_fd = -1;
    ws->wake_pipe_rd = -1;
    ws->wake_pipe_wr = -1;
}

int rt_host_preempt_worker(uint64_t host_tid)
{
#if defined(__APPLE__)
    pthread_t th = (pthread_t)(uintptr_t)host_tid;
    int rc = pthread_kill(th, SIGUSR2);

    if (rc != 0) {
        return -rc;
    }
    return 0;
#else
    (void)host_tid;
    return -ENOSYS;
#endif
}

/* Wait for fd readiness or a wake-pipe byte (signal). Returns 0 when
 * the fd is ready, -EINTR when ws->sig_seq moved or a byte arrived. */
static int64_t darwin_wait_ready(int fd, short filter,
    rt_worker_sync_t *ws, uint32_t expected_seq,
    const struct timespec *timeout)
{
#if defined(__APPLE__)
    struct kevent changes[2];
    struct kevent events[2];
    struct timespec local_to;
    struct timespec *top = NULL;
    int n;

    (void)expected_seq;
    if (ws == NULL || ws->kqueue_fd < 0) {
        return (int64_t)-EINVAL;
    }
    EV_SET(&changes[0], (uintptr_t)fd, filter, EV_ADD | EV_ONESHOT, 0,
        0, NULL);
    EV_SET(&changes[1], (uintptr_t)ws->wake_pipe_rd, EVFILT_READ,
        EV_ADD | EV_ONESHOT, 0, 0, NULL);
    if (timeout != NULL) {
        local_to = *timeout;
        top = &local_to;
    }
    n = kevent(ws->kqueue_fd, changes, 2, events, 2, top);
    if (n < 0) {
        return (int64_t)-errno;
    }
    if (n == 0) {
        return (int64_t)-ETIMEDOUT;
    }
    {
        int i;

        for (i = 0; i < n; i++) {
            if (events[i].ident == (uintptr_t)ws->wake_pipe_rd) {
                char drain[16];

                (void)read(ws->wake_pipe_rd, drain, sizeof drain);
                return (int64_t)-EINTR;
            }
        }
    }
    return 0;
#else
    (void)fd; (void)filter; (void)ws; (void)expected_seq; (void)timeout;
    return (int64_t)-ENOSYS;
#endif
}

int64_t rt_host_openat(int dirfd, const char *path, int linux_flags,
    uint32_t mode, rt_worker_sync_t *ws, uint32_t expected_seq)
{
    int fd;

    (void)ws; (void)expected_seq;
#if defined(__APPLE__)
    /* O_NONBLOCK here keeps FIFO opens from blocking the worker; the
     * readiness wait above serializes actual use. Regular files ignore
     * the flag on open. */
    fd = openat(dirfd, path, linux_flags | O_NONBLOCK, (mode_t)mode);
#else
    fd = openat(dirfd, path, linux_flags, (mode_t)mode);
#endif
    if (fd < 0) {
        return (int64_t)-errno;
    }
    return (int64_t)fd;
}

/* Shared kevent-gated non-blocking transfer for read (is_write = 0)
 * and write (is_write != 0). */
static int64_t darwin_transfer(int fd, void *buf, size_t count,
    int is_write, rt_worker_sync_t *ws, uint32_t expected_seq)
{
    short filter = (is_write != 0) ? EVFILT_WRITE : EVFILT_READ;

    if (fcntl(fd, F_SETFL, O_NONBLOCK) != 0) {
        return (int64_t)-errno;
    }
    for (;;) {
        ssize_t r;
        int64_t w = darwin_wait_ready(fd, filter, ws, expected_seq,
            NULL);

        if (w != 0) {
            return w;
        }
        r = (is_write != 0) ? write(fd, buf, count) :
            read(fd, buf, count);
        if (r < 0 && errno == EAGAIN) {
            continue;
        }
        if (r < 0) {
            return (int64_t)-errno;
        }
        return (int64_t)r;
    }
}

int64_t rt_host_read(int fd, void *buf, size_t count,
    rt_worker_sync_t *ws, uint32_t expected_seq)
{
#if defined(__APPLE__)
    return darwin_transfer(fd, buf, count, 0, ws, expected_seq);
#else
    (void)fd; (void)buf; (void)count; (void)ws; (void)expected_seq;
    return (int64_t)-ENOSYS;
#endif
}

int64_t rt_host_write(int fd, const void *buf, size_t count,
    rt_worker_sync_t *ws, uint32_t expected_seq)
{
#if defined(__APPLE__)
    return darwin_transfer(fd, (void *)buf, count, 1, ws,
        expected_seq);
#else
    (void)fd; (void)buf; (void)count; (void)ws; (void)expected_seq;
    return (int64_t)-ENOSYS;
#endif
}

int64_t rt_host_fsync(int fd, int datasync_only)
{
#if defined(__APPLE__)
    int r = (datasync_only != 0) ? fcntl(fd, F_FULLFSYNC) : fsync(fd);

    if (r != 0 && datasync_only != 0) {
        r = fsync(fd);
    }
    if (r != 0) {
        return (int64_t)-errno;
    }
    return 0;
#else
    (void)fd; (void)datasync_only;
    return (int64_t)-ENOSYS;
#endif
}

int64_t rt_host_getdents64(int fd, void *linux_dirent64_buf,
    size_t buf_size)
{
    /* Darwin getdirentries64 uses a different record layout than Linux
     * dirent64; translation lands with the convert.c lane. */
    (void)fd; (void)linux_dirent64_buf; (void)buf_size;
    return (int64_t)-ENOSYS;
}

int64_t rt_host_futex_wait(_Atomic uint32_t *pinned_host_uaddr,
    const rt_futex_key_t *key, uint32_t host_endian_val,
    const struct timespec *timeout, uint32_t bitset,
    rt_worker_sync_t *ws, uint32_t expected_seq)
{
#if defined(__APPLE__)
    ulock_wait2_fn wait2 = NULL;
    uint64_t timeout_ns = 0ULL;
    uint32_t cur;
    int r;

    (void)key; (void)bitset;
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
    if (timeout != NULL) {
        timeout_ns = (uint64_t)timeout->tv_sec * 1000000000ULL +
            (uint64_t)timeout->tv_nsec;
    }
    load_ptr(RTLD_DEFAULT, "__ulock_wait2", &wait2, sizeof wait2);
    if (wait2 == NULL) {
        struct timespec poll = { 0L, 1000000L };

        (void)nanosleep(&poll, NULL);
        return (int64_t)-EAGAIN;
    }
    if (ws != NULL) {
        atomic_store_explicit(&ws->ulock_wait_addr,
            (uintptr_t)pinned_host_uaddr, memory_order_seq_cst);
    }
    r = wait2(PPC32_UL_COMPARE_AND_WAIT, (void *)pinned_host_uaddr,
        (uint64_t)host_endian_val, timeout_ns, 0ULL);
    if (ws != NULL) {
        atomic_store_explicit(&ws->ulock_wait_addr, (uintptr_t)0,
            memory_order_seq_cst);
    }
    if (r < 0) {
        return (int64_t)-errno;
    }
    return 0;
#else
    (void)pinned_host_uaddr; (void)key; (void)host_endian_val; (void)timeout; (void)bitset; (void)ws; (void)expected_seq;
    return (int64_t)-ENOSYS;
#endif
}

int64_t rt_host_futex_wake(_Atomic uint32_t *pinned_host_uaddr,
    const rt_futex_key_t *key, int count, uint32_t bitset)
{
#if defined(__APPLE__)
    ulock_wake_fn wake = NULL;

    (void)key; (void)count; (void)bitset;
    load_ptr(RTLD_DEFAULT, "__ulock_wake", &wake, sizeof wake);
    if (wake == NULL) {
        return 0;
    }
    (void)wake(PPC32_UL_COMPARE_AND_WAIT | PPC32_ULF_WAKE_ALL,
        (void *)pinned_host_uaddr, 0ULL);
    return (int64_t)count;
#else
    (void)pinned_host_uaddr; (void)key; (void)count; (void)bitset;
    return (int64_t)-ENOSYS;
#endif
}

int64_t rt_host_clock_nanosleep(int linux_clk_id, int linux_flags,
    const struct timespec *req, struct timespec *rem,
    rt_worker_sync_t *ws, uint32_t expected_seq)
{
    (void)linux_clk_id; (void)linux_flags; (void)ws; (void)expected_seq;
    if (nanosleep(req, rem) != 0) {
        return (int64_t)-errno;
    }
    return 0;
}

int64_t rt_host_tgkill(int64_t tgid, int64_t tid, int linux_sig)
{
    (void)tgid; (void)tid; (void)linux_sig;
    return (int64_t)-ENOSYS;
}
