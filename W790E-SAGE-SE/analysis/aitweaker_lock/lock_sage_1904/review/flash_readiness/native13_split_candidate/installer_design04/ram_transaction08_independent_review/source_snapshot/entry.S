/* Exact EFI entry RSP/nonvolatile capture before any compiler-generated frame.
 * Stores only to this application's own data, then preserves the native return
 * address by tail-jumping to the C entry. No stack scan or control-flow hook.
 */
.text
.globl efi_main
efi_main:
 movq %rsp,captured_entry(%rip)
 movq %rbp,captured_entry+8(%rip)
 movq %rbx,captured_entry+16(%rip)
 movq %rsi,captured_entry+24(%rip)
 movq %rdi,captured_entry+32(%rip)
 movq %r12,captured_entry+40(%rip)
 movq %r13,captured_entry+48(%rip)
 movq %r14,captured_entry+56(%rip)
 movq %r15,captured_entry+64(%rip)
 movq %rcx,captured_entry+72(%rip)
 movq %rdx,captured_entry+80(%rip)
 jmp app_main
