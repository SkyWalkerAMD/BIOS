/* MODEL PRODUCT ONLY: ABI passthrough to exercise the production gate bytes.
 * Native owner remains fixture05. Real integration supplies its own bound
 * helper from the controlled ConfigAccess bridge. */
.text
.globl ws05_fixture_profile_call
.globl ws05_fixture_profile_return
ws05_fixture_profile_call:
 subq $0x58,%rsp
 movq 0x80(%rsp),%rax
 movq %rax,0x20(%rsp)
 movq 0x88(%rsp),%rax
 movq %rax,0x28(%rsp)
 movq 0x90(%rsp),%rax
 movq %rax,0x30(%rsp)
 call ws05_profile_callback_gate
ws05_fixture_profile_return:
 addq $0x58,%rsp
 ret
 .fill 16,1,0x90
