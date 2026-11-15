# P6 portable IPMI transaction backend

This directory contains C source, a reproducible Windows x64 host DLL build and protocol simulation tests. Nothing here accesses the host's hardware or a network BMC. Passing these tests does not establish compatibility with a physical ASUS card.

`p6_backend.h` is the integration contract. The C module has no UEFI, heap, libc, persistent variable, PCI, SMM, networking or reset dependency. The firmware adapter supplies bounded `exchange` and `delay_ms` callbacks, validates board/card identity, serializes access and gates writes before calling it. The response buffer contains the full KCS response including response netfn/LUN, command and completion code. The module requires LUN zero, exact successful lengths and compatible LAN parameter revisions.

The public API returns the same status as `P6_RESULT.status`. `cause`, `stage` and `completion` retain the original failure when recovery is attempted. `recovery`, `recovery_cause` and `recovery_completion` describe the separate recovery result. Every transport failure or malformed packet ends the call immediately: no additional reads or writes, including rollback. `P6_UNCERTAIN` must never be automatically replayed by the caller.

## Implemented behavior

| Operation | Contract |
|---|---|
| LAN source 0 | No BMC commands. |
| LAN static or DHCP | Explicit channel 1–11, or require one unique LAN medium among 1–11. Snapshot existing source, address, mask and gateway; require SIP complete; acquire and verify SIP; write only the requested fields; commit and complete; read back. |
| LAN recovery | Known completion-code failure or a well-formed mismatching readback can trigger one bounded recovery attempt. Unsupported SIP is rejected before mutation. Unsupported Commit Write is a failure; recovery may use Complete only when no commit was acknowledged, and must then verify the original settings. |
| Watchdog configure | Prepare a stopped OS Load timer, 1–30 minutes, actions 0–3. Clear only its own expiration flag. Never start from this function. |
| Watchdog start | Require the expected prepared values, issue Reset once, then verify running state and countdown bounds. An already matching running timer is not reloaded. |
| Watchdog disable | Stop only use=OS Load, retaining its action, pretimeout, logging flag and initial count. A running timer with another use is refused. |
| Watchdog recovery | If the response remains usable, inspect ownership and stop only OS Load. This does not restore the original remaining countdown. |
| Interrupted-start recovery | On a later boot with a validated pending-start journal, `p6_watchdog_recover_stop` reads the timer, stops only a running OS Load timer matching the recorded action, timeout and logging/pretimeout fields, then verifies it. A stopped timer requires no write. No Reset/start/retry is sent; the integration keeps the failure journal blocked. |
| SEL clear | Require reservation support, reserve, recheck repository metadata, send one erase request, poll at most 30 times with 1-second delays, then inspect metadata. Newly arriving events are not cleared again. |
| SEL delete oldest | Require delete and reserve support, retrieve the first record's actual ID, delete that ID once, verify its absence, then inspect metadata. No numeric ordering of record IDs is assumed. |
| BMC global event logging | Modify only Global Enables bit 3; preserve all other bits. Verify the complete value. Recovery restores only the requested bit while preserving freshly read other bits. |

The last operation is **BMC global event logging**, not Creator's **SEL Components** BIOS POST-event policy. Boot scheduling, one-shot/every-boot/when-full policies and changes to the donor's POST-event producers are outside this backend.

## Deliberate limits

- A Set In Progress flag is not a cross-client mutex. The caller must avoid competing firmware/BMC configuration tools during a change. No atomicity is claimed for a BMC that applies LAN writes immediately.
- The previous LAN source must be static or BMC DHCP. Unknown, unspecified and other dynamic-source modes are refused before mutation. Static addresses require a contiguous `/1`–`/30` mask, a usable unicast host address and either no gateway or a different usable gateway in the same subnet. `/31` and `/32` are not supported.
- DHCP recovery verifies the original DHCP mode, not the exact previous leased address or ignored static-field bytes. `P6_FLAG_DHCP_LEASE_DYNAMIC` makes this explicit. Successful DHCP mode selection is not evidence that a lease has already been acquired.
- A failed recovery may leave SIP in progress; the result is `P6_UNCERTAIN`, not success. There is no blind release of an unknown or externally changed transaction.
- The exchange callback's per-request deadline and total I/O budget still apply. The 30-second SEL polling budget does not include the adapter's initial readiness checks or command time.
- SEL clear/delete cannot be rolled back. `ERASE_COMPLETED` and `RECORD_DELETED` flags describe acknowledged milestones even if a later verification step fails. `entries_after` may be nonzero after a successful clear because new events can arrive.
- No watchdog interrupt is enabled by a new configuration. Disabling an already owned timer preserves its existing interrupt/pretimeout fields while stopping it. No MAC, VLAN, account, BMC reset, SDR deletion or OEM command exists in this module.
- No current “SEL full” inference or boot policy is implemented here. In particular, historical overflow alone must not drive repeated destructive operations.

## Build and tests

Run from the repository root with the installed Python:

```powershell
& 'C:/Users/scka7/AppData/Local/Python/pythoncore-3.14-64/python.exe' -X utf8 analysis/hero_ipmi_p6_20261104/backend/build_backend.py
& 'C:/Users/scka7/AppData/Local/Python/pythoncore-3.14-64/python.exe' -X utf8 analysis/hero_ipmi_p6_20261104/backend/test_backend.py
```

`build_report.json` records the exact compiler/linker commands and hashes. `test_report.json` records the executed tests and hashes. The DLL also compiles the current production `source/command_policy.c` plus a host-only gate variable. Every simulated exchange asserts that the armed whitelist accepts it and the disarmed whitelist rejects configuration, reservation and destructive commands. The report pins the reviewed policy hash.

The tests cover exact static/DHCP payloads, IPv4 rejection, channel ambiguity, SIP busy/unsupported, acknowledged failures, rollback and rollback failure; watchdog ownership, action/count conversion, separate start, disable preservation and compensation; SEL reservation/cancellation, actual record handles, bounded clear timeout, asynchronous new events; global bit preservation; and every success-path request position with transport failure and six malformed-response variants. Field read fixtures are reused only to check response layouts, not as write evidence.

## Primary references and provenance

Command layouts and field definitions were checked against the pinned TianoCore EDK2 `edk2-stable202502` headers:

- [IPMI application commands](https://raw.githubusercontent.com/tianocore/edk2/edk2-stable202502/MdePkg/Include/IndustryStandard/IpmiNetFnApp.h): watchdog and global-enable fields, channel information.
- [IPMI transport commands](https://raw.githubusercontent.com/tianocore/edk2/edk2-stable202502/MdePkg/Include/IndustryStandard/IpmiNetFnTransport.h): LAN Get/Set and parameter selectors.
- [IPMI storage commands](https://raw.githubusercontent.com/tianocore/edk2/edk2-stable202502/MdePkg/Include/IndustryStandard/IpmiNetFnStorage.h): SEL support bits, reservation, clear and delete structures.

The [Intel IPMI v2.0 specification, revision 1.1, errata 6 markup](https://www.intel.com/content/dam/www/public/us/en/documents/product-specifications/ipmi-v2-rev1-1-spec-errata-6-markup.pdf), sections 23.1–23.2, 27.1–27.4 and 31.2–31.9, establishes the interpretation used here: Commit Write is optional; SIP does not lock out other clients; watchdog Set can stop while Reset starts; SEL IDs are handles; reservations can be cancelled by repository changes; clear status is polled separately. The implementation intentionally refuses unsupported or ambiguous cases and adds the conservative limits above.

Existing read-only evidence: `analysis/hero_ipmi_p5_field_20261104/transactions.json`. New write exchanges are simulated only. No real machine, network interface, timer or SEL repository was changed while preparing this backend.
