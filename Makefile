# Self-documenting Makefile for ppc32rt — 32-bit PowerPC -> AArch64 user-mode translator
#
# Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
# SPDX-License-Identifier: Apache-2.0

.DEFAULT_GOAL := help
.PHONY: help all build test check check-line-limits check-abi-invariants clean

BUILD_DIR := _build

# Prefer the aarch64 musl cross compiler when it is on PATH (the nix cross
# shell provides aarch64-unknown-linux-musl-gcc); otherwise fall back to the
# shell's default cc (host syntax checks). An explicit CC always wins.
CROSS_CC := $(shell command -v aarch64-unknown-linux-musl-gcc 2>/dev/null)
ifeq ($(origin CC),default)
  ifneq ($(CROSS_CC),)
    CC := aarch64-unknown-linux-musl-gcc
  else
    CC := cc
  endif
endif
# src/main.c calls setenv(3), which musl hides under strict -std=c11 unless a
# POSIX feature-test macro is visible; expose exactly that (keeps -pedantic
# and every prescribed warning intact).
CFLAGS  ?= -std=c11 -D_POSIX_C_SOURCE=200809L -Wall -Wextra -Werror=vla -pedantic -Os -fPIE -Iinclude -Isrc -Isrc/rt32
LDFLAGS ?= -static-pie
LDLIBS ?= -lm # RC3: interp fp.c fsqrt uses host sqrt(3)

# Until the Phase 2 DBT lands there is no src/dbt/*.c; compile the carried
# a64 emitter out of the JIT-call path so the link never references the
# (not yet existing) ppc32_dbt_invalidate_range.
ifeq ($(wildcard src/dbt/*.c),)
  CFLAGS += -DPPC32RT_NO_DBT
endif

# src/main.c plus every engine/substrate file present; later lanes' globs
# pick up src/interp, src/os, src/dbt automatically (plus src/vm and
# src/dbt/aot when those Wave U3 lanes land; empty wildcards are no-ops).
# Wave U3: exactly one host backend joins the build (both define the same
# rt_host_* symbols). Selected from the compiler target triple so
# cross-builds get backend_linux even when the build host is Darwin.
U3_PROBE_CC := $(or $(CC),cc)
ifeq ($(findstring darwin,$(shell $(U3_PROBE_CC) -dumpmachine 2>/dev/null)),darwin)
U3_BACKEND_SRC := src/os/backend_darwin.c
else
U3_BACKEND_SRC := src/os/backend_linux.c
endif
U3_OS_SRCS := $(filter-out src/os/backend_linux.c src/os/backend_darwin.c,$(wildcard src/os/*.c)) $(U3_BACKEND_SRC)
SRCS := src/main.c $(wildcard src/rt32/*.c) $(wildcard src/interp/*.c) \
        $(U3_OS_SRCS) $(wildcard src/dbt/*.c) \
        $(wildcard src/vm/*.c) $(wildcard src/dbt/aot/*.c)
ASMS := $(wildcard src/dbt/*.S)
HDRS := src/ppc32rt.h include/a32host.h src/os/syscall_nr.h \
        $(wildcard src/rt32/*.h) $(wildcard src/interp/*.h) \
        $(wildcard src/os/*.h) $(wildcard src/dbt/*.h) \
        $(wildcard src/vm/*.h) $(wildcard src/dbt/aot/*.h)

OBJ_DIR    := $(BUILD_DIR)/obj
OBJS       := $(patsubst src/%.c,$(OBJ_DIR)/%.o,$(SRCS)) \
              $(patsubst src/%.S,$(OBJ_DIR)/%.o,$(ASMS))
PPC32RT_BIN := $(BUILD_DIR)/ppc32rt

help: ## Show available build and verification targets
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n\nTargets:\n"} \
		/^[a-zA-Z0-9_-]+:.*?##/ { printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

all: build ## Build everything (currently just the ppc32rt binary)

build: $(PPC32RT_BIN) ## Build static-PIE aarch64-linux ppc32rt binary

$(PPC32RT_BIN): $(OBJS)
	@printf "\033[32m▸ Linking\033[0m $@\n"
	$(CC) $(CFLAGS) $(OBJS) $(LDFLAGS) $(LDLIBS) -o $@
	@ln -sf ppc32rt $(BUILD_DIR)/ppc32rt-binfmt-p

$(OBJ_DIR)/%.o: src/%.c $(HDRS)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR)/%.o: src/%.S
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

test: ## Run the test suite (none yet; fixtures arrive in Phase 1)
	@echo "phase 0: no tests yet"

# macOS hides MAP_ANON (no MAP_ANONYMOUS) once _POSIX_C_SOURCE is
# defined, which would break the host syntax check below; the Linux/musl
# cross shell is unaffected either way. CFLAGS keeps the macro for builds.
ifeq ($(CROSS_CC),)
ifeq ($(shell uname -s),Darwin)
  CHECK_STD := -std=c11
else
  CHECK_STD := -std=c11 -D_POSIX_C_SOURCE=200809L
endif
else
  CHECK_STD := -std=c11 -D_POSIX_C_SOURCE=200809L
endif

# syscall(2) is deprecated on macOS (the /dev/a32host probe only ever runs
# on Linux); keep the deprecation visible but non-fatal for the host check.
check: ## Host-cc syntax check of every src file (no link)
	@for f in $(SRCS); do \
		$(CC) $(CHECK_STD) -Werror=vla -pedantic \
			-Wall -Wextra -Werror -Wno-error=deprecated-declarations \
			-Iinclude -Isrc -Isrc/rt32 \
			$(if $(wildcard src/dbt/*.c),,-DPPC32RT_NO_DBT) \
			-fsyntax-only "$$f" || exit 1; \
	done
	@echo "syntax check OK ($$(echo $(SRCS) | wc -w | tr -d ' ') files)"

check-line-limits: ## Fail if any src .c/.h/.S exceeds 900 lines
	@over=$$(for f in $$(find src -name '*.c' -o -name '*.h' -o -name '*.S'); do \
		n=$$(wc -l < "$$f"); \
		if [ "$$n" -gt 900 ]; then echo "$$f: $$n lines"; fi; \
	done); \
	if [ -n "$$over" ]; then \
		echo "files over the 900-line limit:"; echo "$$over"; exit 1; \
	fi; \
	echo "line limits OK (all src .c/.h/.S <= 900 lines)"

HOST_CC ?= cc

check-abi-invariants: ## Build and run tests/check_abi_invariants (lands with lane L0b)
	@if [ -f tests/check_abi_invariants.c ]; then \
		mkdir -p $(BUILD_DIR) && \
		$(HOST_CC) -std=c11 -D_POSIX_C_SOURCE=200809L -Werror=vla -pedantic \
			-Wall -Wextra -Werror -Iinclude -Isrc \
			tests/check_abi_invariants.c -o $(BUILD_DIR)/check_abi_invariants && \
		./$(BUILD_DIR)/check_abi_invariants; \
	else \
		echo "check-abi-invariants: tests/check_abi_invariants.c not present yet (lane L0b)"; \
	fi

clean: ## Remove build artifacts
	rm -rf $(BUILD_DIR)
