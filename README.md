# BIOS research and build sources

Source snapshot of local BIOS research projects, including HERO IPMI and Ai Tweaker work for multiple ASUS workstation and desktop boards.

## Status and scope

These are research and experimental build sources, not official ASUS firmware. A newer candidate is not necessarily validated or suitable for flashing. The HERO RC5 R5/S23 CANDIDATE05 records state that final firmware flashing, cold Setup entry, configuration persistence and recovery acceptance are not yet verified.

The original `analysis/` directory layout is preserved. This snapshot intentionally omits firmware images, generated binaries, third-party tools, build caches, raw hardware logs and local configuration. Text files flagged for possible credentials or local network details are also omitted pending manual review. Some scripts require those separately retained local inputs; this repository alone is not a complete runnable firmware toolchain.

`SOURCE-MANIFEST.json` records SHA-256 hashes of the included source files. The complete original project is retained locally pending archival and cleanup approval.

No license is granted for third-party materials. No ASUS signature or hardware compatibility claim is made.
