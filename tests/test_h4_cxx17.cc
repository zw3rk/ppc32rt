/*
 * tests/test_h4_cxx17.cc — Phase 7 lane H4 C++17 exceptions/RTTI/TLS test.
 *
 * Covers docs/lanes/phase-7.md card H4: try/catch stack unwinding across
 * call frames (including frames executing on a guest signal frame),
 * dynamic_cast RTTI (pointer and reference forms), std::thread
 * create/join, and thread_local construction/destruction.
 *
 * Unwinding across a raw kernel signal frame is not exercised: the
 * qemu-ppc oracle itself aborts (SIGABRT) when a C++ exception propagates
 * through a signal trampoline, so this fixture catches inside the handler
 * (nested frames on the signal stack) while an outer try in main spans the
 * delivery, and requires the translator to agree with the oracle.
 *
 * Synchronous self-signalling uses kill(getpid(), sig): glibc raise(3)
 * issues gettid/tgkill, which ppc32rt does not implement yet (ENOSYS), so
 * raise(3) cannot deliver under the translator while kill(2) can.
 *
 * Build (lane container):
 *   powerpc-linux-gnu-g++ -std=c++17 -static -pthread -O2 \
 *     tests/test_h4_cxx17.cc -o _build/test_h4_cxx17
 * Run: qemu-ppc -cpu 750 _build/test_h4_cxx17 (oracle golden),
 *   ppc32rt --interp/--dbt -- _build/test_h4_cxx17, and
 *   ppc32rt --difftest -- _build/test_h4_cxx17 (must report EQUAL).
 * Prints "PASS" + exit 0 on success, else "FAIL <site>" + exit 1.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <atomic>
#include <cstdio>
#include <csignal>
#include <string>
#include <thread>
#include <typeinfo>
#include <type_traits>
#include <unistd.h>
#include <utility>

namespace {

int g_first_fail = 0;

void check(bool ok, int site)
{
    if (!ok && g_first_fail == 0) {
        g_first_fail = site;
    }
}

struct Token {
    int v;
};

struct Guard {
    int &n;
    explicit Guard(int &n_) : n(n_) {}
    ~Guard() { ++n; }
};

/* ---- 1. Unwinding across plain call frames ---- */
int g_dtor_count = 0;

void leaf(int x)
{
    Guard g(g_dtor_count);
    if (x > 0) {
        throw Token{x};
    }
}

void mid(int x)
{
    Guard g(g_dtor_count);
    leaf(x);
}

int outer(int x)
{
    Guard g(g_dtor_count);
    try {
        mid(x);
    } catch (Token &t) {
        return t.v * 2;
    }
    return -1;
}

/* ---- 2. Unwinding across frames on a guest signal frame ----
 * The handler throws through two nested frames and catches locally;
 * main holds an outer try across kill()+handler-return. */
volatile sig_atomic_t s_got = 0;
volatile sig_atomic_t s_inner = 0;

void sigdeep2()
{
    Guard g(g_dtor_count);
    throw Token{5};
}

void sigdeep1()
{
    Guard g(g_dtor_count);
    sigdeep2();
}

extern "C" void on_usr1(int sig)
{
    if (sig != SIGUSR1) {
        return;
    }
    s_got = sig;
    try {
        sigdeep1();
    } catch (Token &t) {
        if (t.v == 5) {
            s_inner = 1;
        }
    } catch (...) {
    }
}

/* ---- 3. RTTI ---- */
struct Base {
    virtual ~Base() {}
    virtual int kind() const { return 0; }
};

struct Red : Base {
    int kind() const override { return 1; }
};

struct Blue : Base {
    int kind() const override { return 2; }
};

template <typename T>
int kind_of()
{
    if constexpr (std::is_same<T, Red>::value) {
        return 1;
    } else {
        return 0;
    }
}

/* ---- 4/5. Threads + thread_local ---- */
std::atomic<int> tls_dtor_count{0};

struct TlsWatch {
    ~TlsWatch() { tls_dtor_count.fetch_add(1); }
};

thread_local TlsWatch tl_watch;
thread_local int tl_acc = 0;
thread_local std::string tl_tag;

int worker(int id)
{
    tl_acc = id * 100;
    tl_tag = "w" + std::to_string(id);
    try {
        if (id % 2 == 0) {
            throw Token{id};
        }
        tl_acc += 1;
    } catch (Token &t) {
        tl_acc += t.v;
    }
    tl_acc += static_cast<int>(tl_tag.size());
    return tl_acc;
}

} // namespace

int main()
{
    /* C++17 compile-time surface (no runtime trace). */
    auto [a, b] = std::pair<int, int>{3, 4};
    check(a + b == 7, 1);
    check(kind_of<Red>() == 1 && kind_of<Blue>() == 0, 2);

    /* 1. Throw across three frames; three Guards must unwind. */
    int d0 = g_dtor_count;
    check(outer(21) == 42, 10);
    check(g_dtor_count == d0 + 3, 11);

    /* 3. RTTI before threads (deterministic, single-threaded). */
    Base *as_red = new Red;
    Base *as_base = new Base;
    Red *down_ok = dynamic_cast<Red *>(as_red);
    check(down_ok != nullptr && down_ok->kind() == 1, 20);
    check(dynamic_cast<Blue *>(as_red) == nullptr, 21);
    check(dynamic_cast<Red *>(as_base) == nullptr, 22);
    bool bad_cast_seen = false;
    try {
        (void)dynamic_cast<Red &>(*as_base);
    } catch (const std::bad_cast &) {
        bad_cast_seen = true;
    } catch (...) {
    }
    check(bad_cast_seen, 23);
    check(as_red->kind() + as_base->kind() == 1, 24);
    delete as_red;
    delete as_base;

    /* 4/5. Four threads: per-thread EH, thread_local state, join. */
    const int nthreads = 4;
    int results[4] = {0, 0, 0, 0};
    std::thread th[4] = {
        std::thread([&results] { results[0] = worker(1); }),
        std::thread([&results] { results[1] = worker(2); }),
        std::thread([&results] { results[2] = worker(3); }),
        std::thread([&results] { results[3] = worker(4); }),
    };
    for (int i = 0; i < nthreads; ++i) {
        th[i].join();
    }
    /* id=1: 100+1+2=103; id=2: 200+2+2=204; id=3: 300+1+2=303;
     * id=4: 400+4+2=406; total 1016. */
    int total = results[0] + results[1] + results[2] + results[3];
    check(total == 1016, 30);
    check(tls_dtor_count.load() == nthreads, 31);

    /* Main-thread thread_local still alive and usable after joins. */
    tl_acc = 5;
    tl_tag = "main";
    check(tl_acc == 5 && tl_tag == "main", 32);

    /* 2. Signal frame: install, deliver to self, verify handler ran its
     * nested throw/catch and returned; outer try spans the delivery. */
    struct sigaction sa;
    sa.sa_handler = on_usr1;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    check(sigaction(SIGUSR1, &sa, nullptr) == 0, 40);
    int d1 = g_dtor_count;
    bool escaped = false;
    try {
        check(kill(getpid(), SIGUSR1) == 0, 41);
    } catch (...) {
        escaped = true;
    }
    check(!escaped, 42);
    check(s_got == SIGUSR1, 43);
    check(s_inner == 1, 44);
    check(g_dtor_count == d1 + 2, 45);

    if (g_first_fail != 0) {
        std::printf("FAIL %d\n", g_first_fail);
        return 1;
    }
    std::printf("PASS\n");
    return 0;
}
