# NATIVE13 split-layout feasibility checkpoint

Status: design investigation only. No installer or hardware-test EFI has been created. NATIVE12/provider12, their reports, and original firmware inputs remain frozen.

## Immediate blocker and evidence being investigated

The physical N12 preflight proved that all nine adjacent extension pages are EfiBootServicesCode. It did not establish an idle native browser or actual page permissions. Separately owning a new guard allocation avoids those adjacent pages but does not resolve safe installation timing.

Root reports a cold power-off/power-on with one-time UEFI CD boot override and no Setup input. This supports a bounded boot-option origin, but it is not sufficient by itself: the exact original BDS/boot-option/StartImage caller chain and its native browser ancestry must be established. A raw stack scan cannot prove that a frame is absent. The next local investigation checks original DXE Core and AMITSE native code and any retained unwind tables. If that supports a complete bounded walk, a separate read-only entry-context probe could capture image identities, exact return addresses and validated unwind data. An installer would still have to repeat that verification in its own invocation; evidence from a prior probe is not transferable current-stack proof.

## Intended ownership and ABI constraints

- Separate the original AMITSE/Setup base and bounds from guard code and state allocation bases. Never derive the original base by subtracting the old payload RVA from a newly allocated payload address.
- Keep the audited twelve gate policies, the save-failure feedback, private password credential semantics, native outer-frame ownership, nested tokens, and EBS revocation. Retain a permanent firmware fallback that denies protected operations if the optional password provider is absent. A driver that merely hopes to run before the unmodified OEM UI is insufficient.
- Treat permanently embedded and RAM-installed layouts as explicit distinct identity profiles. Original module identities, allowed twelve patch locations, patched targets, complete immutable guard code, state allocation, expected native callers/return addresses, and provider code must all be bound. A broad address range or a fabricated LoadedImage path is insufficient.
- The existing public five-method provider interface and 48-byte frame are reusable concepts, but N13 requires a new private region/ownership contract. No new GUID or ABI is frozen at this checkpoint. Existing N12 signatures must not silently accept N13 layouts.
- RAM guard/state must be exclusively allocated to the installer or a loaded driver through standard UEFI ownership, with checked page permissions. MemoryMap type and presence alone do not establish allocator ownership. No foreign allocation is freed, expanded, or overwritten.
- A transaction must verify all original bytes and ownership before the first mutation, serialize callback entry, install only approved detours, validate every patched byte, and either restore all original bytes or retain safe resident code until reboot. It may not free a referenced trampoline, event callback, HII callback, or provider. Current P12 deliberately refuses unload; a new rollback/lifetime design is required rather than reusing an unload assumption.
- Persistent firmware and RAM variants must have separate hashes and test reports. Even shared source or a byte-identical code subsection does not transfer full candidate acceptance across different bindings, relocation, callers, state layout, or initialization paths.

## Conditions required before an executable installer

1. Exact cold-boot call-path and native-browser inactivity evidence that can be checked at installation time, without using stage 7 or app == 0 as proof.
2. A current, read-only observation of page permissions and a supported way to obtain an executable/readable guard and writable private state. No real permission mutation is authorized in this task.
3. A reviewed separate-base guard/provider identity design, including how embedded firmware guards fail closed before provider availability.
4. Mechanical detour/trampoline relocation proof at every one of the twelve sites, including call-return provenance and original/patched content hashes.
5. Failure injection for each install/rollback boundary, native callbacks/reentry, partial activation, HII state, EBS, and resident-code lifetime.

Until these conditions are closed, a local source/byte prototype is permissible only as explicitly incomplete simulation. It must not be packaged as a real-board installer.

## Narrow entry-context probe checkpoint

The original AMITSE, Setup, DXE Core and BDS modules retain section sizes corresponding to exception metadata, but both the candidate runtime-function tables and `.xdata` contents are zero. Their Exception Data Directories are also zero. Generic PE stack unwinding is therefore unavailable.

The original DXE Core Boot Services table points StartImage to RVA `0x8720`. Its normal entry call is at `0x88AC`, returning to `0x88AF`. Actual execution of these original bytes proves that, at the callee's raw entry RSP, offset `0x60` contains the StartImage caller's return address, `0x68` its saved image handle, and `0x78` its saved RBP. This is one known frame, not a general unwinder.

`entry_probe` captures raw entry RSP and registers in a small assembly tail-jump before the C prologue. It identifies a current LoadedImage matching the actual StartImage base, verifies its exact PE bounds and complete normalized text hash including all 257 DIR64 relocations, and requires the exact `0x88AF` return before following the fixed frame. Stack reads are restricted to the explicitly required slots in readable LoaderData or BootServicesData descriptors. It identifies at most one native parent among exact original AMITSE/BDS callsites. It always reports `BROWSER_ABSENCE_PROOF=NO` and cannot install anything.

The initial protocol GUID search confused the adjacent watchdog GUID ending in `3FF5` with BDS ending in `3FF6`; the classification was corrected against the EDK2 protocol headers before the new probe was built. The copied module names and hashes in the final audit reflect the corrected classification.
