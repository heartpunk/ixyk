// SPDX-FileCopyrightText: 2026 Sophie Smithburg
// SPDX-License-Identifier: GPL-3.0-or-later

extern "C" __attribute__((noipa)) unsigned leaf(unsigned x) {
  asm volatile("" : "+r"(x));
  return (x << 3) ^ 0x1357;
}
extern "C" __attribute__((noipa)) unsigned nested(unsigned x) {
  return leaf(x) + 7;
}
extern "C" __attribute__((noipa)) unsigned recursive(unsigned x) {
  if (x > 2) return recursive(x - 1) ^ leaf(x);
  return leaf(x);
}

asm(".text\n"
    ".globl branch_entry\n.type branch_entry,@function\n"
    "branch_entry:\n test %edi,%edi\n jz leaf\n jmp nested\n"
    ".size branch_entry,.-branch_entry\n");
