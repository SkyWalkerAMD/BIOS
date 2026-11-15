# ASUS BMC 1.3.13 Dashboard BIOS identity synchronization

This is offline evidence from the unmodified official `KODO1313.ima`. No BMC
connection, firmware flash, host restart, or real `/conf` write was performed by
this analysis. Runtime observations and any subsequent operation belong to the
parent's separately recorded live session.

## Result

Dashboard identity has a separate legacy metadata path. The existing successful
Redfish System/CPU/Memory upload does not fill these Dashboard values.

The frontend's `/api/Information` calls `getInformation_func` in
`spx_restservice`, which calls `LIBIPMI_HL_Get_BIOSINFO`. That helper reads two
local BMC configuration files on every call:

| File | Content used by Dashboard | Output |
|---|---|---|
| `/conf/biosinfo.fru` | First 5 bytes | `BIOSVersion` |
| `/conf/biosinfo.fru` | Following 11 bytes | `BIOSDate` |
| `/conf/mbinfo.fru` | Second NUL-terminated string in a valid string list | `BIOSModel` |

Helper return zero causes `BIOSVaild` (vendor spelling) to become 1. This flag
does not by itself validate the content; exact expected values must be checked.
The label “BIOS Build Time” obtains the date string. This path contains no
hour/minute field and does not establish a build timestamp.

## Proven command mapping

`PDKGetOEMMsgHndlrMap` at VA `0x8AB0` selects the `oem_MsgHndlrTbl` record at
`0x160F0`: NetFn `0x30`; relocation `0x160F4` resolves to
`g_ASUS_OEM_CmdHndlr`. In this table:

| Command | Record VA | Function VA | Operation |
|---|---|---|---|
| `0x03` | `0x2A644` | `Oemreaddmiinfo`, `0xB970` | Read DMI metadata |
| `0x04` | `0x2A654` | `Oemwritedmiinfo`, `0xBAF4` | Write DMI metadata prefix |

The selector is the first request byte:

| Selector | File |
|---|---|
| 0 | `/conf/biosinfo.fru` |
| 1 | `/conf/sysinfo.fru` |
| 2 | `/conf/mbinfo.fru` |

Selector 1 is unnecessary for the three requested Dashboard fields. This route
is distinct from `OemSetBIOSTable`, remote BIOS settings, flash-update commands,
sensor initialization, or Redfish inventory. Those are not required here.

Read `0x03` takes exactly four request bytes:
`selector, offset-low, offset-high, count`. On success the IPMI completion code
is 0, followed by one returned-count byte and that many content bytes. Wrong
request length returns `0xC7`. Callers must reject failure replies without
interpreting their count byte: the vendor error branch does not initialize it.

Write `0x04` takes `selector` followed by the file prefix. Offset is always zero.
On success the completion code is 0 and the next byte is the actual write count
modulo 256. There is no explicit maximum or empty-request check in the handler;
`(request_length - 1) & 0xFFFF` underflows for an empty request. The global LAN/IPMI
transport maximum has not been established by this analysis. A bounded caller
must reject empty/malformed data and restrict operation to known short payloads.

For the real `.71` SMBIOS fixture, the BIOS data block is exactly 16 bytes:
`3107` plus NUL, then `11/28/2025` plus NUL. The motherboard block is constructed
from Type 2's indexed manufacturer, product, version, and serial strings, each
with its NUL terminator. This is the original Creator AMITSE sender layout
reported independently by the parent team's firmware agent, not an entire raw
SMBIOS structure or an arbitrary concatenation of every string. The offline
emulator reconstructs these indexed fields from the actual capture and checks
the resulting Dashboard values.

## Default NVR I/O and boundaries

`API_ReadNVR` / `API_WriteNVR` in `libipmipdkapi` call `ReadWriteNVR` at VA `0xBEE8`
in `libipmistack`.

* Write uses `O_RDWR|O_CREAT` (flags `0x42`), seeks to the supplied offset, issues
  one write, then closes. It does not truncate old tails or call `fsync`.
* Short writes are returned as short counts, without retry. Completion zero
  alone must not be accepted as successful synchronization.
* Read initially uses `O_RDONLY`. If opening fails, it falls back to
  `O_RDWR|O_CREAT`. Reading a missing metadata file can create an empty file;
  consequently the OEM read command is not strictly free of persistent effects.
* The function checks an optional `g_PDKHandle+0x318` hook before default I/O.
  `g_PDKInitialize` record `0x40E06` binds this slot (index 198) to
  `PDK_ReadWriteNVR`. Official `core_macros` has no alternate PDK-library path;
  the normal `libipmipdk.so.13.8.0` and its direct dependencies do not define this
  symbol. `InitPDKHooks` clears all slots and resolves symbols with `dlsym`.
  Thus the official default image has no implementation replacing this path.
  This is image evidence, not a running-process memory dump.
* No host power, reset, flash-update, network-setting, or watchdog operation is
  called by the metadata handlers/default file path. The persistence mechanism
  itself is BMC configuration file storage. Persistence across sudden power
  loss or BMC restart was not tested here.

Getter boundary findings were checked using its original ARM code. Empty
`mbinfo.fru` returns an empty model safely. An early static inference that an
empty file could underflow the copy length was incorrect and has been withdrawn.
The actual dangerous shape is a full 255-byte read containing the first NUL but
no terminating NUL for the second string; that can pass a negative length to
`memcpy`. Valid short source strings with explicit terminators avoid that path.
Do not accept an arbitrary unchecked raw metadata file as a future publisher's
input.

## Minimal controlled synchronization

1. Bind data to the captured current machine and its BIOS version. Use its
   actual SMBIOS Type 0 and Type 2 indexed strings, not a Creator identity.
2. Preserve obtainable previous metadata with the read-side effect above
   understood. Do not infer semantic validity merely from zero completion or
   zero returned bytes.
3. When data is already identical, skip writing. Otherwise publish the complete
   valid Type 2 block (selector 2), verify exact count and exact bytes, then the
   16-byte Type 0 block (selector 0), again with exact count and byte readback.
   The two files are not an atomic transaction; this order establishes a valid
   model before completing the BIOS display block.
4. After an ambiguous transport result or short write, stop writes and inspect
   readback. Do not automatically repeat the write or overwrite with guessed
   placeholder data. There is no generic restoration-to-nonexistence command in
   the proven protocol.
5. Query `/api/Information` and require `BIOSVaild==1` plus exact Model, Version,
   and Date values. Refreshing this resource rereads the files; no restart is
   required by the observed implementation.

Future automatic firmware integration additionally needs a bounded SMBIOS
builder, current-host gating, compare-before-write, error isolation, and a
validated boot scheduling/transport path. This report is not a claim that an
automatic uploader has been integrated into a flashable BIOS.

## Reproduction and evidence quality

`collect_backend_evidence.py` regenerates source hashes, exact symbol ranges,
dispatch records, paths, and JSON field literals in
`backend-protocol-evidence.json`. `verify_dashboard_backend.py` executes bounded
original ARM functions in Unicorn with every external call replaced by an
in-memory mock. Its 25 scenarios include real `.71` source data, selector and
length behavior, malformed input bounds, exact getter output, missing-file
creation, tail preservation, and short-write handling; see
`dashboard-backend-emulation.json`.

These are Capstone/ELF/Unicorn results. The configured Windows REA backend's
previous capability probe rejected ARM ELF; no REA ARM decompilation success is
claimed. The separate Creator PE analysis can use the supported REA workflow.
None of the emulation scenarios proves live transport, runtime concurrency,
power-loss durability, or automatic BIOS dispatch.

## Subsequent live confirmation recorded by the parent agent

The parent completed the controlled metadata synchronization on `.71` without
restarting the host or flashing firmware. Its
[`dmi-publication-result.json`](../dmi-publication-result.json) records seven
application commands: Device ID, two metadata reads, motherboard write/readback,
and BIOS write/readback. Both previous metadata reads returned zero content
bytes. Write counts were exactly `0x45` (69 motherboard bytes) and `0x10`
(16 BIOS bytes), followed by exact byte readback.

The authenticated REST result
[`005-evaluate.json`](../responses/005-evaluate.json) reports `BIOSVaild=1`,
`BIOSModel=ROG MAXIMUS Z790 HERO`, `BIOSVersion=3107`, and
`BIOSDate=11/28/2025`. After a fresh login the parent also checked the real
Dashboard screenshot [`dashboard-after.png`](../screens/dashboard-after.png).
This confirms live display synchronization for this machine/session. It does
not imply that these writes have been incorporated into automatic BIOS startup,
or that survival across a BMC factory reset has been tested.
