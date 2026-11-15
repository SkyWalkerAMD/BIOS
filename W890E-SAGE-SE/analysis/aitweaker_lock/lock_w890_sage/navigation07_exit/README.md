# W890E-SAGE SE 0603: early tail cancellation candidate

This separate component refuses an exit request at original AMITSE RVA `1995F`, before the tail render cleanup, buffer free, OEM callbacks, protocol removal, history free, App destruction or ResetSystem. A valid cancellation clears only the known `App+5A == 1` request and resumes the original input loop at `196FF`. The native reset-required marker, protocol handle, current page, input event, nonempty history metadata and opaque history allocation remain intact at that branch.

There is **no complete exit permission path**. Even the deliberately limited Main-only action-4 proof from `navigation06_actions` cannot authorize the earlier OEM, buffer and protocol effects. This is an offline candidate, not an installed lock, aggregate BIOS, flashable image or claim that ordinary BIOS exit works.

## Exact original evidence and scope

`hook_plan.json` and three disassembly files bind the original AMITSE SHA256 `43f80bf738e0b1101431b7319a8a9c0060655e708f22f5b6379620aee862e6fe`. They reuse the genuine REA/Ghidra dossier `ev_71d9b59cf983fb2673094b3f5d8edd32798e7514c23302142b9b7ea0439d003d`, and independently check original bytes. No new REA query or runtime evidence is invented.

The 16-byte original window is `48 8B 05 6A 64 09 00 38 58 5A 0F 84 90 FD FF FF`. Its candidate replacement is an exact 14-byte absolute indirect jump and two NOPs. The original RIP-relative load and branch are not copied to an unrelated address. The guard restores the App value in RAX, the other native registers and XMM registers, then reproduces the original zero comparison's arithmetic flags and jumps to `196FF`.

The guard does **not** cover every tail entry. Original `196F7` branches directly to `19973`; initialization failures also jump to `19994` or `19A76`. These paths require separate phase-specific treatment. An error return from `748C` is insufficient: teardown already started, and the reset path ignores that return. Frozen `exit_control07` retains ten actual original-tail cases proving this ordering.

## Private ownership and ABI

`build.py` reads frozen actions06 and navigation05 inputs and emits new copies/derivatives only here. The new private observer calls original BrowserLoop through `n07_loop_body_call`. The real original prologue pushes eight registers and reserves 0x98 bytes; therefore `[body_rsp+0xD8]` must equal the immutable private helper's return label and RBP must equal `body_rsp+0x79`. The live top frame must remain a real `NO_LOOP` frame with a nonzero private visit, matching depth/epoch and mapped writable stack.

`n07_native_tail` has an inline native ABI, not a callable public permission setter. It saves the original register state and calls `n07_exit_dispatch` at its exact private return label. That function independently validates loaded module/overlay identities, Setup HII identity, private visit, current App/Page, native input object and original input method pointers. Its actual compiled `no_scope_enter(NO_EFFECT,...)` call must be in the immutable consumer-window table. A public direct call, guessed stack, foreign current page, stale epoch or nested effect cannot mint authority.

`n07_bind()` is a one-time local binding before a private loop; it does not install anything or mint an owner. `n07_resume` is checked against the single exact original continuation on every dispatch. The assembly requires the exact FF25 overlay format in this candidate. A future static aggregate using another branch form must provide a separately checked layout contract; it cannot silently substitute this component.

`N07_NATIVE` is 80 bytes. Its ten native-word fields are RSP, RBP, RBX, RSI, RDI, R12, R13, R14, R15 and the address of the private volatile save area. The component validates their actual inline stack relationships, never a caller-supplied allow flag.

## Cancellation and fault behavior

Before clearing the request, the component takes repeated App/input/history/reset/protocol/bypass snapshots under its genuine observer effect ticket. It validates the cached native state again at raised BSP TPL 16, without invoking HII, variables, allocation or native callbacks there. Raised TPL does not exclude AP/SMM activity and does not confer teardown ownership.

If state changes before the write, the request remains unchanged. If state changes after RestoreTPL, the component refuses GUI continuation and reports that its own cancellation write already occurred; it does not claim rollback or undo earlier save/default operations. If EBS or service identity loss occurs, even the cached RestoreTPL pointer is not invoked. That case remains isolated, potentially at raised TPL, rather than pretending to resume a usable GUI.

Fault isolation differs from a successful native cancellation. Only checked UEFI input/output/event services at TPL_APPLICATION may display a message and block in WaitForEvent. An ordinary key keeps waiting. R reruns all native proof; it grants no password privilege. Invalid services or EBS enter the existing non-returning local terminal boundary without reset, variables or cleanup. That terminal is not a normal BIOS return path.

## Validation and remaining work

The final reports and exact build hashes are listed in `component_manifest.json`: 25 tail cases, two actual inline fault-wait/retry cases and one selected original-caller case pass. Tests execute the compiled component, genuine private observer wrappers, the original BrowserLoop prologue, the `1995F` branch and original continuation through `23378` input reset and `232DC` read to the fresh-input backend at `61FE4`. The selected caller case also executes the actual original `B8DC` CALL to `190F4`, instead of supplying its return slot to the wrapper. Earlier caller initialization remains a fixture. GPRs, all 16 XMM registers, RSP/RBP and comparison flags are checked at `196FF`. Nonempty history uses root 70, capacity 416 and count 1 as a bounded preservation fixture; it is not allocator ownership evidence.

The surrounding BrowserLoop initialization/middle, outer App/Page containers, UEFI and CPU mappings are explicit models. Original `4CD14` is a modeled return, and `61FE4` is a modeled new-event boundary. SHA/PBKDF/RDSEED use the existing declared independent oracles. Tests do not execute complete native rendering, all callbacks/destructors, a physical owner or hardware reset. `failure_notes.json` retains development findings, including the corrected void callback assertion and EBS service-pointer issue.

Still required before complete integration: phase-safe treatment of the bypass exits, proven full teardown/OEM/allocation/callback batches, the original initialization and all current-page producers, exact aggregate layout binding, foreign-HII ownership and dynamic callback closure, and complete normal/error GUI lifecycles. The opaque history allocation is preserved, never freed or claimed. Current observer classification is limited to exact Setup HII. Neither this candidate nor the read-only physical snapshots close these gaps.

No BMC connection, firmware write, password change, source-image mutation or frozen-component modification is performed by this directory's build/tests.
