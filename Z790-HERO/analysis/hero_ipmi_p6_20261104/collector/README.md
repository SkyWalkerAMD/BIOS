# P6 RC4 resident audit collector

`HERO-P6-RC4-READONLY-LOG.iso` and `USB/` contain only a UEFI application and a marker. No DXE driver, shell, writer, core loader or firmware flasher is included.

The application recognizes P6 GUID `1f771753-bb7b-4e4c-b698-e71e8db25e7a` with version 6 and size 24, reads its `log` and `value` callbacks, and includes all 41 cached values (40 = configuration result). It also reads the unchanged R2 version-2/64-byte audit API through `log`, `status` and `config`. Incompatible or manual-only R2 interfaces are rejected independently. A missing interface does not prevent export of the other.

Only explicit `L` writes a fresh `P6LOGnnn.TXT` on the current application's boot volume after validating `HERO_P6.TAG`. Existing files are never overwritten. The remaining output is RAM-backed QR/text. Complete combined snapshots have a 278528-byte ceiling; individual resident logs must be below 131072 bytes and cached value strings below 160 bytes. Oversized/unterminated content is refused rather than truncated.

The new `HERO-IPMI-P6-QR1` wire marker and bundled `decode_captures.py` separate this larger format from old R2 frames. The decoder validates all pages and whole-snapshot integrity. Its CRC checks detect accidental corruption, not malicious replacement.

The collector does not use BMC commands, configuration callbacks, driver load/start APIs, protocol installation, UEFI variable writes, Shell protocols or **any watchdog API**, including UEFI `SetWatchdogTimer`. The startup screen explicitly instructs the operator to disable OS Watchdog in BIOS before long diagnostics. Firmware boot-time policies remain independent of this application.

Build and validation entry points, all writing only this collector directory:

```powershell
python prepare_source.py
python build.py
python verify_app.py
python verify_capture.py
python run_vm.py
```

`prepare_source.py` refreshes only the copied dependencies, build script and QR/VM helpers; `source/launcher.c` and `verify_app.py` are maintained separately. `build.json`, `app-verification.json`, `capture-verification.json` and `vm-verification.json` pin the tested artifacts. The real delivered PE is executed in Unicorn with forbidden hardware and writer interfaces trapped. OVMF tests cover ISO and USB boot without resident protocols; QR tests decode the compiled C encoder's modules.

These are offline and virtual-machine results. No network BMC or physical motherboard was accessed by this work.
