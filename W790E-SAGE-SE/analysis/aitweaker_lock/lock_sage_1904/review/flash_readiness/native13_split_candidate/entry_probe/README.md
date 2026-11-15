# Read-only original EFI entry-context probe

This is an evidence-collection ISO, not a NATIVE13 guard installer or BIOS image. It contains no provider, no hooks, and no firmware/variable/disk write implementation. Existing N12/P12 artifacts are unchanged.

The new assembly entry records the incoming RSP and registers to this application's own data before any C prologue and tail-jumps to the C diagnostic. It retains the existing read-only N12 identity/page inventory, then attempts one narrowly defined Core StartImage frame observation.

The fixed frame is accepted only if all of these match: a unique current LoadedImage at the base implied by the current BootServices.StartImage pointer; exact original DXE Core image/header bounds; complete original text SHA256 after validating and normalizing all 257 DIR64 fixups; the exact entry return address Core+0x88AF; bounded stack descriptors of LoaderData/BootServicesData; and the saved image handle matching the actual entry handle. Reads are restricted to the required slots at raw entry RSP offsets 0, 0x60, 0x68 and 0x78. Failed checks stop the frame observation. No arbitrary stack scan or generic unwinder is present.

The result identifies at most the native caller of Core.StartImage and attributes it only to an independently hash-matched AMITSE or BDS module and exact known callsite. It always reports `BROWSER_ABSENCE_PROOF=NO` and `INSTALLATION_AUTHORIZED_BY_CONTEXT=NO`. A prior diagnostic run cannot prove a future installer's current stack state.

## Review and collection

1. Verify `entry_context_manifest.json` and the ISO hash.
2. Use the already authorized cold power-off/power-on and one-time UEFI virtual-CD route. Preserve KVM evidence of that route. The binary itself does not power/reset the machine or call native Setup.
3. Boot `build/SAGE-N13-READONLY-ENTRY-CONTEXT.iso`. Capture every QR page; N/Enter advances, P goes back, T shows text, Q returns to QR, ESC returns to firmware.
4. Decode with `decode_probe.py <image paths> --output <new log file>`. A directory argument selects `qr-*.png`; for `page-*.png`, pass explicit paths. The same P3 768-byte framing applies.

The payload begins `AITWK-P3-KVM` then `SAGE_NATIVE13_ENTRY_CONTEXT_READONLY` and ends `SAGE_NATIVE13_ENTRY_CONTEXT_END`. Require `LOG_COMPLETE=YES` and `LOG_OVERFLOW=NO`, and the existing no-install/no-provider/no-RT-change footer. Logs are bounded to 24575 bytes with 1024 bytes reserved for the footer. An overflow is explicit and rejected by the decoder.

## Local validation

- `../startimage_frame_verification.json`: eight actual original DXE Core frame checks.
- `tests/verification.json`: 21 cases, including original Core calling the actual new assembly entry, exact native parent attribution, changed Core callsite/fixup, missing/duplicate image, wrong size/StartImage/return/saved handle, bad capture, reserved/conventional/read-protected/overlapping stack, and accepted/rejected cross-page frames. The collector cases check no OEM or service-table writes, no reads outside original module ranges, no unexpected stack-slot reads, and no leaked pool buffers.
- `ovmf_report.json`: this exact ISO booted on OVMF; QR/text/QR and ESC worked. Both captured QR pages restore the exact 1189-byte debug log. OVMF correctly does not supply the original ASUS Core identity. This validates transport, not ASUS boot ancestry.

Original PE exception directories and the apparent `.pdata`/`.xdata` contents are zero; this probe does not pretend those are usable unwind records. Protocol classification was checked against [EDK2 Bds.h](https://raw.githubusercontent.com/tianocore/edk2/master/MdePkg/Include/Protocol/Bds.h) and [WatchdogTimer.h](https://raw.githubusercontent.com/tianocore/edk2/master/MdePkg/Include/Protocol/WatchdogTimer.h): BDS is the `665E3FF6` GUID, while the initially adjacent `665E3FF5` search result is watchdog. The final BDS source module is FFS `8F4B8F82-9B91-4028-86E6-F4DB7D4C1DFF`.
