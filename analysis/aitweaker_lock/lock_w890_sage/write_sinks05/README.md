# W890E-SAGE SE 0603 Save and action guards

This directory implements authentication gates around original Save, defaults,
and ASUS User Profile operations. The standalone products have no firmware
entry and are not a BIOS or a flash package. The root integration project owns
the actual static binding, native session lifecycle, and complete validation.

`save_guard05.c` and `save_thunk05.S` are the production source inputs. They use
the genuine private native observer and the actual `w890_provider` object. The
fixed request helper has an explicit `ws05_provider_request_return` label for
the observer's exact compiled caller allowlist. There is no owner boolean or
external approval flag that grants access.

At original AMITSE RVA `1FD58`, after native confirmation/validation but before
the first Save notification or write, the guard compares exact actual NV data
with the native pending cache. Full GUID, UTF-16 name, attributes, size, native
descriptor metadata and current private owner are checked. Native descriptors
94, 99 and 95 are OCMR, SocketMemoryConfig and OcSetup; they are not IFR store
numbers. Only protected SocketMemoryConfig bytes require authentication;
ordinary changes still reach the original Save body. A changed OcSetup alias
conservatively requires authentication. Authentication is followed by new
identity, cache, NV, provider and trampoline checks.

An actual `EFI_NOT_FOUND` result is recorded as absence, never an invented old
value. Creating that store is treated as a protected addition and requires a
real grant or the explicitly disabled provider state. A second read must still
return `EFI_NOT_FOUND`; unexpected appearance, disappearance or other read
errors reject Save before its native effects.

Cancellation follows the original `202F4` AL=0 cleanup with the original stack
frame. Allowed Save retains native Boot/Driver and other variable writes,
notifications and error semantics. In particular, original Save can ignore an
individual write failure; this guard is not an I/O transaction engine.

Defaults group `FFFF001D`, direct defaults `1F4AC`, and outer restore-defaults-
and-save API `851A4` authenticate before entering their original bodies. The
last API has two original arguments and writes before calling ordinary Save,
so the outer entry is required. Profile operations use the existing controlled
ConfigAccess bridge before it delegates original Setup callback `2250`:
QIDs `2BFB`, `2BFD`, `2BFE`, `2BFF`, with the original action/type predicates.
The seven-argument gate binds the actual compiled helper return, original
native caller `3E4F0`, the real ConfigAccess object, and private authority. It
does not modify Value or ActionRequest on denial. No Setup code/data patch is
needed for these profile operations. Legacy direct-handler adapters remain
available for isolated tests but are not the selected integration mechanism.

`patch_contract05.json` records four AMITSE windows and replay operands. The
integrator must bind the Save cancellation address before any patched native
code can run, and preserve unrelated FD6C selectors before full initialization.
Early initialization does not itself grant a password or native session.
The integrator may use its `i05_original_*` trampoline aliases for the logical
`ws05_original_*` contract names.

`build/native_save_tests.json` records 62 checks against actual compiled guard
and original vendor machine bytes. This includes native Save effects/order,
register/stack preservation, default/profile routing, callback arguments and
return binding, exact cache lookup, and selected actual Setup notification
consumers. `fixture05.c` and `profile_gate_fixture.S` explicitly model private
owner/provider/service behavior for this test product and are excluded from
production aggregation. These tests do not establish physical native ownership.

`notification_closure05.json` binds 65 successful REA function results and
the exact original modules. It tracks the original pre/post Save callbacks,
OC reset/training notifications, profile-cache import, and ServerSetup BMC
network modules. The scope is the original cooperative BIOS UI; it is not a
defense against arbitrary DXE/SMM code or untrusted third-party callbacks.
Native pending-HII/reconnect and all navigation routes remain separately owned
by the navigation/integration projects. External API calls without a genuine
private UI session do not receive a fabricated owner ticket.

`packaging05_independent_review.json` is a separate read-only review of the
root packager and retained test evidence. It distinguishes a fixture that
actually reaches StartImage from a functional aggregate that has only been
loaded, checked and unloaded. Source hashes that drifted after a test are
listed, not silently treated as the tested version.

All work here is offline. No BMC connection, physical register/variable write,
CAP output, signing key, or flash operation is performed by these tests.
