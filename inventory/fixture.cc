// SPDX-FileCopyrightText: 2026 Sophie Smithburg
// SPDX-License-Identifier: GPL-3.0-or-later

#include <cstddef>
#include <cstring>
#include <utility>

#ifndef HANDLERS
#define HANDLERS 1
#endif

extern "C" unsigned leaf(unsigned);
extern "C" unsigned nested(unsigned);
extern "C" unsigned recursive(unsigned);
extern "C" unsigned branch_entry(unsigned);

class BX_CPU_C {
public:
  __attribute__((noipa)) void RETURN() { asm volatile("nop"); }
  __attribute__((noipa)) void DISABLED() {
#if ENABLE_FEATURE
    asm volatile("mov %%rbx, %%rax" ::: "rax");
#endif
  }
  __attribute__((noipa)) unsigned DIRECT(unsigned x) { return nested(x) + 1; }
  __attribute__((noipa)) unsigned TAIL(unsigned x) { return leaf(x); }
  __attribute__((noipa)) unsigned BRANCH(unsigned x) { return branch_entry(x); }
  __attribute__((noipa)) unsigned RECURSIVE(unsigned x) { return recursive(x); }
  __attribute__((noipa)) unsigned INDIRECT(unsigned (*fn)(unsigned), unsigned x) {
    return fn(x);
  }
  __attribute__((noipa)) void EXTERNAL(void *p, std::size_t n) {
    std::memset(p, 0, n);
  }
  // A vector register bit-copy is not FP arithmetic.
  __attribute__((noipa)) void VECTOR_COPY(void *p) {
    asm volatile("movups (%0), %%xmm0; movups %%xmm0, (%0)" :: "r"(p) : "xmm0", "memory");
  }
  template <int N> __attribute__((noipa)) unsigned HANDLE(unsigned x) {
    return nested(x + N) + leaf(x ^ N);
  }
};

template <int... N> unsigned dispatch(BX_CPU_C &cpu, unsigned x, std::integer_sequence<int, N...>) {
  return (cpu.HANDLE<N>(x) + ...);
}

int main(int argc, char **argv) {
  BX_CPU_C cpu;
  cpu.RETURN();
  cpu.DISABLED();
  cpu.EXTERNAL(argv, 0);
  cpu.VECTOR_COPY(argv);
  return cpu.DIRECT(argc) + cpu.TAIL(argc) + cpu.BRANCH(argc) +
         cpu.RECURSIVE(argc) + cpu.INDIRECT(leaf, argc) +
         dispatch(cpu, argc, std::make_integer_sequence<int, HANDLERS>{});
}
