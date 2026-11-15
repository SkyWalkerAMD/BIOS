# Entry-context probe 03: one bounded AMITSE outer frame

This is a separate read-only diagnostic ISO. It contains no native guard installer, provider, BIOS capsule, variable/disk/flash write path, or original UI invocation. EP1, EP2 and N12/P12 remain frozen.

The independently decoded physical EP2 result established exact original Core/AMITSE/BDS identities, Core's legal rounded allocation metadata, a Type 4 stack, Core return `0x88AF`, and native caller AMITSE+`0xA8E6`. Its saved native RBP equalled raw entry RSP + `0x131`. EP2 did not read the next outer return slot, so it did not establish the outer caller or browser inactivity.

Original AMITSE function `0x9F78..0xAADA` contains 693 instructions. Its entry pushes eight nonvolatile registers, allocates `0xE8` bytes, and sets RBP to its entry RSP minus `0x5F`. No body instruction changes RSP/RBP before the observed StartImage call. Original prologue and callsite bytes, original Core, and the compiled assembly capture were replayed together; the intervening boot-policy body was skipped after its static stack-write audit. This proves the fixed local offsets, not the entire boot path.

EP3 adds only two stack reads: raw entry RSP + `0x188` (saved upper RBP) and + `0x190` (next return address). It first requires all EP2 identity/frame checks, the exact AMITSE+A8E6 caller, a fresh complete hash of the original launch function, and saved native RBP == raw RSP+0x131. The whole required interval must remain within readable LoaderData/BootServicesData descriptors. The returned outer RBP is logged and never dereferenced.

A next return is attributed only to one of five pinned original callsites (`2D7D`, `9025`, `960C`, `9754`, `97C9`) and only after reading its exact CALL instruction and confirming target `9F78`. Unknown or changed callsites stop at observation. There is no further outward walk. `BROWSER_ABSENCE_PROOF=NO` is unconditional in the final footer, including early refusal paths.

## Verification and collection

`tests/verification.json` records 46 actual-byte cases, including original AMITSE prologue/callsite → original Core → actual EP3 entry and collector; all five outer callsites; wrong RBP, fresh-function-hash or CALL-target failures; reserved/read-protected cross-page upper slots; and refusal to dereference arbitrary saved upper RBP. Two separate early-footer cases cover invalid services and memory-map failure. Existing Core rounding, complete hashes, fixed frame, allocation-tail and cleanup checks remain in the regression.

This exact ISO booted on OVMF, exercised QR/text/QR/ESC, and both QR screenshots restored the same 1208-byte debug log. OVMF does not establish ASUS boot ancestry or native UI correctness.

After independent root review, use the authorized cold-boot one-time virtual-CD route with `build/SAGE-N13-READONLY-ENTRY-CONTEXT03.iso`. Capture all QR pages, then ESC returns. N/Enter advances, P goes back, T shows text, Q returns to QR. Decode explicit screenshot paths with `decode_probe.py ... --output <new path>`; a directory selects `qr-*.png` only.

P3 768-byte framing is unchanged. The payload begins `AITWK-P3-KVM` then `SAGE_NATIVE13_ENTRY_CONTEXT03_READONLY`, ends `SAGE_NATIVE13_ENTRY_CONTEXT03_END`, and requires `LOG_COMPLETE=YES`, `LOG_OVERFLOW=NO` and the no-installer/provider/RT-change footer. The no-flash/no-hooks/no-variable-writes/no-disk-writes declaration remains present exactly twice.

Even a successful new outer-return observation does not prove the absence of a still farther native browser frame and does not authorize a RAM installer or permanent firmware deployment.
