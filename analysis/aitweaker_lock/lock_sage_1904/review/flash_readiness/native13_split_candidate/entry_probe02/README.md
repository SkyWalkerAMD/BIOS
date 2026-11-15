# Entry-context probe 02: exact Core allocation rounding

This is a separately frozen, read-only diagnostic revision. It contains no guard installer, password provider, firmware/variable/disk write path, or original UI call. The previous probe, N12/P12, and their reports remain unchanged.

The first physical entry probe found Core LoadedImage.ImageSize = `0x21000`. Its strict comparison expected the original PE SizeOfImage `0x20E60`, so it stopped before reading the live PE header or normalized text. Independent decoding of the eight original PNGs reproduced all 5726 bytes and CRC `F0CA537A`; see `../entry_hardware_readonly_review.json`. That observation does not itself prove the live PE or Core text identity.

This revision accepts only two exact Core LoadedImage sizes: `0x20E60`, or its precise 4096-byte rounding `0x21000`. The live Core PE SizeOfImage must still be `0x20E60`; entry RVA, architecture, full normalized text SHA256, all 257 DIR64 values, current StartImage address and actual entry-return address remain pinned. The accepted metadata size and PE-header snapshot are rechecked after the normalization-buffer allocation callback. Header and text reads remain bounded to the original PE size. The extra 416 allocation-tail bytes are never read. BDS continues to require its exact original LoadedImage size.

The assembly entry and fixed Core-frame offsets are unchanged. Only four needed stack slots may be read, after the exact original Core callsite and readable LoaderData/BootServicesData bounds have been checked. Stack descriptor type/attributes are now recorded so a refusal is diagnosable. This is not a generic unwinder; the result always retains `BROWSER_ABSENCE_PROOF=NO` and `INSTALLATION_AUTHORIZED_BY_CONTEXT=NO`.

## Validation and use

`tests/verification.json` contains 33 actual-byte cases, including the original Core calling the actual assembly entry; legal rounding; undersized, intermediate, off-by-one and extra-page metadata; wrong PE size, entry and architecture; metadata/header changes during allocation; refusal to extend the rounding rule to BDS; and the prior malformed-frame, memory-map, identity and cross-page cases. Collector tests report zero reads of allocation-tail bytes, zero OEM/service-table writes, and zero outstanding pool buffers.

This exact ISO also booted on OVMF and exercised QR/text/QR/ESC. Both QR screenshots decode to the exact 1193-byte debug log. OVMF does not establish an ASUS Core caller chain or native UI inactivity.

After independent review, the root agent can use the authorized cold power-off/power-on plus one-time virtual-CD route with `build/SAGE-N13-READONLY-ENTRY-CONTEXT02.iso`. Capture every QR page, then ESC returns. N/Enter advances, P goes back, T shows text, Q returns to QR. No device action is performed by this directory's build/tests.

Decode explicit screenshot paths with `decode_probe.py ... --output <new file>`; a directory argument selects `qr-*.png`. P3 768-byte framing is unchanged. Payload start is `AITWK-P3-KVM` followed by `SAGE_NATIVE13_ENTRY_CONTEXT02_READONLY`; the last line is `SAGE_NATIVE13_ENTRY_CONTEXT02_END`. Require `LOG_COMPLETE=YES`, `LOG_OVERFLOW=NO`, and the no-installer/provider/RT-change footer. The no-flash/no-hooks/no-variable-writes/no-disk-writes declaration appears twice, once at each end.

The prior physical refusal is a documented diagnostic compatibility issue, not a passing identity result. A future successful Core/frame observation would still be only one native parent frame, and would not authorize RAM installation or establish a flashable release.
