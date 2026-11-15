# W890E-SAGE SE 0603 navigation regression component

This directory contains local source and machine-code regression evidence. It
does not contain a hardware installer or a complete BIOS image. No device,
BMC, update verification or flash operation is performed by these tests.

The original AMITSE is bound by SHA-256
`43f80bf738e0b1101431b7319a8a9c0060655e708f22f5b6379620aee862e6fe`.
Original RVAs are interpreted only inside this exact module. New consumer
return windows must be regenerated after every link; see
`bridges_build/consumer_windows.json` and `static_hook_plan.json`.

## Components and ABI

`build/W890Navigation05.TESTONLY.dll` is the earlier history/Main component,
SHA-256 `bacc474a2d18508704b3f63b73840fb05995aef483b54887b3abd3fd08a35d2e`.
Its 17 actual-PE checks, two original growth-boundary traces and one immutable
parser composition are retained separately. The original growth trace proves
the two callers' size units under the stated fixture; ordinary GUI reachability
of the growth branch is not inferred from that trace.

`bridges_build/W890NavigationBridges05.TESTONLY.dll` adds the actual first-entry,
render, page/frame/control input, menu, hotkey, mouse and callback-batch bridges.
The authoritative digest is in `bridges_build/build.json`; final regression
reports independently bind the bytes loaded at test start.

The aggregate must bind genuine native Loop/SendForm scopes, actual Setup/HII
ownership, immutable installed overlays, the six history lifetime boundaries,
and the caller windows before calling `n05_bind()` and
`n05_bridges_bind()`. The bridge bind functions perform validation and capture
service identities; they do not install foreign pointers or code patches.

- `n05_native_first`: an inline assembly continuation for the exact original
  eight-byte window at `19463`. It preserves volatile registers, XMM0–5 and
  flags, then replays the original instructions and resumes at `1946B`.
- `n05_native_render`, `n05_native_page_input`,
  `n05_native_frame_input`, `n05_native_control_input`: exact native method
  ABIs. Denied input returns zero to consume the event at both native Frame
  and Page levels. Kind-2 fanout is checked for every actual control and does
  not create a password prompt.
- `n05_native_app_input`, `n05_native_extra_input`,
  `n05_native_alt_input`: preserve the original routines after matching
  object ownership, vtable, callback and all copied descriptor fields against
  the original nine hotkeys and seven mouse regions. F7 is absent from those
  nine hotkey records; its original unsupported fallthrough is preserved.
- `n05_native_form_open(raw_page, action, resume_qid)`: supports native
  FormOpen action 3 and FormClose action 2. It preflights every flagged raw
  descriptor through a private effect ticket and canonical IFR, checks the
  protected batch's real provider authorization, and then executes original
  `3F414`. Original callback-phase filtering and return status are retained.
  It is not a transaction rollback guarantee for callback side effects.
- `no_describe_form_callback(ticket, raw_page, raw_control, snapshot)`: the
  observer supplement in `visit/form_descriptor.inc`. It follows actual
  raw table membership and registered IFR through a private native effect
  ticket. It does not accept an external owner flag or invent a control object.
- `n05_native_pending(a,b,c)`: only accepts the original Page return address
  `239EC`. When the queue pointer is null, or the bounded 24-byte head is
  completely empty, it revalidates under TPL_NOTIFY and executes original
  `40094`/`3FED4`'s service-free branch. That branch returns EFI_NOT_FOUND,
  clears AFF20 and sets AFF23. Nonempty queues remain refused.

The owned FormOpen trampoline must contain the exact original 15 bytes plus
an E9 rel32 jump to `3F423`. The equivalent exact FF25 absolute form is also
accepted. The bridge validates both original bytes and destination; an
arbitrary executable pointer is insufficient.

## What the regressions execute

The harness runs actual compiled observer, password/provider/UI, bridge and
original AMITSE instructions in Unicorn. Native history allocation, growth,
parent lookup, free boundaries, the selected Page/Frame dispatch, original
hotkey/mouse functions and FormOpen batch loop are real machine code.

Raw pages, descriptors, IFR and the three new ACTION controls in the parser
tests come from the immutable sibling `integration05/parser-snapshot.zip`
(SHA-256 `4b65d173ec3a9d4a3e8d02aa8d3becbf9ee61abbb688584cc96e18c93f5fdfbb`).
They were produced by the actual original parser and control constructors.
The outer APP/PAGE/FRAME containers, UEFI services and CPU mappings remain
explicit fixtures. SHA/PBKDF/RDSEED use the frozen harness' independent
oracles. This is not an execution of the whole native GUI.

FormOpen tests compare the guarded and original batches under the same
native phase. A page with five flagged controls can legitimately invoke zero
callbacks in phase 2. Explicit phase-0 tests exercise all five Security and
all 56 Ai Tweaker flagged controls. The callback destination `3E700` is a
documented model boundary in this suite; the complete ConfigAccess and
variable effects belong to the separately composed components.

F10 tests execute the actual original hotkey callback up to the save-confirm
destination. Mouse tests execute the actual hit-test up to the native region
callback. These positive checks are not claims of actual storage writes or
full screen drawing.

## Remaining compatibility boundaries

1. The observer recognizes canonical Setup HII only. The hardware inventory
   has 13 form-package handles and 391 forms, of which Setup contributes 82.
   The parser snapshot's 379 entries include 297 unbound HII=0 placeholders;
   the difference between 396 hardware entries and 379 snapshot entries is
   not a count of all external pages. External forms require independent
   module/HII/IFR, variable and cross-page reference classification.
2. Nonempty pending HII batches are not supported. Original `40094` callers
   include `239E7`, `3738A`, `3FA96`, and `4041E`. This bridge covers the first
   caller only. Removal/addition/reconnection may rebuild raw tables and
   invalidate all native tickets. `pending_static_review.json` retains the
   exact callsites and relevant flag references.
3. The earlier `navigation.c` snapshot still binds source HII to Setup and
   searches for Main using that source HII. A future foreign-page derivative
   must instead select the precisely verified Setup Main and cannot silently
   reuse foreign HII as Main's identity.
4. Pre-existing credential FAULT does not yet admit the original browser
   body. The native visit ID is separate from the provider token, but the
   immutable complete-effect catalogue is deliberately incomplete. A failed
   Begin is not treated as an authenticated visit.
5. During an already active visit, normal cancellation or wrong password can
   select the unique verified Main and normalize only tracked history. If
   Main/native ownership cannot be proved, the first-entry bridge displays
   its own recovery message and waits for R. Service identity loss or EBS
   reaches a terminal HLT loop without further UEFI calls or a reset. This is
   explicit fault isolation, not ordinary BIOS usability.
6. TPL_NOTIFY excludes BSP callback reentry; it does not prove exclusion of
   arbitrary AP/SMM writes. No scope or memory-map check grants generic heap
   ownership. Native allocations are tracked only at the exact reviewed
   allocation/free boundaries.

The component therefore must not be described as a complete, deployable or
flashable password-lock BIOS. Aggregate source review and the remaining
native-entry and side-effect bindings are separate work.
