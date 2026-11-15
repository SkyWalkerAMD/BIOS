# NATIVE12 read-only preflight

This directory contains a bootable diagnostic application and ISO. It contains **no native guard installer, no provider, and no modified BIOS capsule**.

The application reads exact original W790E-SAGE SE 1904 LoadedImage identities, the relocation-free text SHA256 of AMITSE and Setup, the twelve original NATIVE12 interception sites, relevant memory-map descriptors, and read-only MemoryAttributeProtocol results when available. All module reads stay within the original declared image sizes. The undeclared tail and adjacent extension pages are inspected through descriptors only; their contents are not read.

The application does not implement AllocatePages, SetMemoryAttributes, SetVariable, RT-table replacement, native SendForm/DXE execution, disk-file writes, persistent events, or a reset operation. Its own temporary pool buffers are freed. Console/GOP output is expected; ESC returns to the caller without leaving hooks installed. QEMU-only debug-port logging is gated by the TCG hypervisor signature. The ISO is unsigned; Secure Boot policy may refuse it.

## Operator sequence

1. Verify the ISO SHA256 against `preflight_manifest.json` and `build/build.json`.
2. Mount `build/SAGE-NATIVE12-READONLY-PREFLIGHT.iso` as the authorized BMC virtual CD and boot it through the maintenance boot menu.
3. Capture every QR page. `N` or Enter advances; `P` goes back; `T` switches to text; `Q` returns to QR.
4. Decode with `decode_probe.py <qr image paths> --output <new log path>`. A directory argument selects only `qr-*.png`. This checks all page CRCs, overall length/CRC, log type, explicit non-overflow status and the unique end marker.
5. ESC exits the diagnostic. There is no subsequent installation action in this package.

Expected log start is `AITWK-P3-KVM` then `SAGE_NATIVE12_READONLY_PREFLIGHT`. Required ending is `SAGE_NATIVE12_PREFLIGHT_END`, preceded by `LOG_COMPLETE=YES`, `LOG_OVERFLOW=NO`, `INSTALLATION_AUTHORIZED_BY_PROBE=NO`, `RuntimeTableChanged=NO`, and `ProviderStarted=NO`. The no-flash/no-hooks/no-variable-writes/no-disk-writes line occurs at both the start and footer. The transport is the existing P3 frame protocol with 768-byte chunks. Maximum log size is 24575 bytes, with 1024 bytes reserved for the footer. An overflow remains decodable at the frame level but is rejected as incomplete by this probe's decoder.

## Evidence and limits

`tests/verification.json` exercises actual compiled EFI bytes against relocated original OEM images and synthetic read-only EFI services. It covers all twelve sites, cross-descriptor reads, overlap, reserved/MMIO/read-protected memory, changed text/slot, duplicate/malformed LoadedImage, malformed/overflowing device paths, unavailable MemoryAttributeProtocol, long HII lists, log overflow, nested collection, memory-map/version/stride and allocation failures. It checks no CPU writes to either OEM image or service tables, no reads outside the original declared image ranges, and no outstanding pool buffers.

`ovmf_report.json` records actual boot of this exact ISO, QR/text/QR display and ESC return. The QR screenshot decodes byte-for-byte to the QEMU debug copy. OVMF has no ASUS AMITSE/Setup, so it does not establish real-board identity, page layout, native browser behavior, password behavior, or RAM-installation safety.

The static NATIVE12 payload requires AMITSE's 192-byte undeclared allocation tail plus five adjacent pages, and Setup's 864-byte undeclared allocation tail plus four adjacent pages. ConventionalMemory is not an allocation grant. The provider binds exact new image sizes, payload hashes and image-relative native return addresses; a separately allocated payload would not satisfy that binding. Mutating either PE SizeOfImage or LoadedImage.ImageSize needs a separate transactional-loader design and rollback review. Neither an AMITSE stage value nor matching SendForm/HII pointers proves that no native browser frame is active. Missing MemoryAttributeProtocol leaves actual page-table permissions unknown. **No result of this probe authorizes installation.**
