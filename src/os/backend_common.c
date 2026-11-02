/*
 * src/os/backend_common.c — Shared POSIX host primitives for Linux and Darwin
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Platform-neutral POSIX wrappers shared between backend_linux.c and
 * backend_darwin.c (memory protection/unmap, basic descriptor I/O,
 * pthread worker spawn, process fork/wait/kill/exit).
 */

#define _POSIX_C_SOURCE 200809L
#if defined(__linux__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif
#if defined(__APPLE__) && !defined(_DARWIN_C_SOURCE)
#define _DARWIN_C_SOURCE
#endif

#include "os/backend.h"

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

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
    if (madvise(host_addr, len, linux_advice) != 0) {
        return -errno;
    }
    return 0;
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

int64_t rt_host_close(int fd)
{
    if (close(fd) != 0) {
        return (int64_t)-errno;
    }
    return 0;
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

int64_t rt_host_clock_gettime(int linux_clk_id, struct timespec *tp)
{
    clockid_t id = (linux_clk_id == 1) ? CLOCK_MONOTONIC : CLOCK_REALTIME;

    if (clock_gettime(id, tp) != 0) {
        return (int64_t)-errno;
    }
    return 0;
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
    int rc;

    if (fn == NULL) {
        return -EINVAL;
    }
    slot = (spawn_slot_t *)malloc(sizeof *slot);
    if (slot == NULL) {
        return -ENOMEM;
    }
    slot->fn = fn;
    slot->arg = arg;
    rc = pthread_create(&th, NULL, spawn_tramp, slot);
    if (rc != 0) {
        free(slot);
        return -rc;
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

void rt_host_exit_thread(int status)
{
    _Exit(status);
}

void rt_host_exit_group(int status)
{
    exit(status);
}
