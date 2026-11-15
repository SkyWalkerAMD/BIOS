"""Execute the shipped RC3 R2 PE to audit one-shot boot readiness behavior.

No network, physical device, NVRAM, or published artifact is accessed for write.
The emulated UEFI/PCI/KCS services and synthetic transitions are NOT target
hardware evidence. Historical hardware E0 -> C0 observations are cited separately.
"""
from pathlib import Path
import hashlib
import json
import sys

sys.dont_write_bytecode = True
OUT = Path(__file__).resolve().parent
ROOT = OUT.parents[2]
R2 = ROOT / 'analysis/hero_ipmi_r2'
sys.path.insert(0, str(R2))
import verify_entry as entry

EXPECTED_PE = '1e206aa41b6133c642d724fa1c6aae2f2cd28eb6010a55a66b22a89c3b354845'
EXPECTED_CAP = '8ffc4b33f6d0e2bb7180c724de01a805f556ad126d08830e7f052b37ce771951'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class TransientVersionDevice(entry.core.Device):
    def __init__(self):
        super().__init__('success', full=True)
        self.unavailable = True
        self.version_flags = []

    def response(self, tx):
        reply = bytearray(super().response(tx))
        if bytes(tx) == bytes.fromhex('10 2D FB'):
            if self.unavailable:
                reply[4] |= 0x20
            else:
                reply[4] &= ~0x20
            self.version_flags.append(reply[4])
        return bytes(reply)


def snapshot(m):
    return {
        'auto_seen': m.u32(m.functions['auto_seen']),
        'requests': len(m.dev.packets),
        'oem_requests': len(m.dev.oem_packets),
        'pci_writes': len(m.pci_writes),
        'nv_writes': len(m.nv_writes),
        'attempt_variable_present': 'HeroIpmiAttempt' in m.vars,
        'pci_command': int.from_bytes(m.config[4:6], 'little'),
    }


def run():
    cap = ROOT / 'analysis/hero_ipmi_rc3_20261104/firmware/HERO-3107-IPMI-P5-R2-RC3-UNSIGNED.CAP'
    pe = R2 / 'USB/EFI/HERO/HeroIpmiR2.efi'
    container_path = ROOT / 'analysis/hero_ipmi_rc3_20261104/container-verification.json'
    container = json.loads(container_path.read_text(encoding='utf-8'))
    extracted = ROOT / container['extracted_payloads'][0]['extracted']
    assert sha(cap) == EXPECTED_CAP
    assert sha(pe) == sha(extracted) == EXPECTED_PE
    m = entry.EntryMachine()
    m.dev = TransientVersionDevice()
    assert m.enter() == 0 and m.created and m.published
    entered = snapshot(m)
    assert entered['requests'] == 0 and entered['auto_seen'] == 0

    m.signal()
    first = snapshot(m)
    first_log = m.audit()
    assert first['auto_seen'] == 1 and first['requests'] > 0
    assert not first['oem_requests'] and not first['nv_writes']
    assert not first['attempt_variable_present'] and first['pci_command'] == 0
    assert m.dev.version_flags == [0xE0]
    assert 'Full, stable SDR baseline or VERSION_ERR validation failed.' in first_log
    assert 'READY_TO_BOOT_AUTO_ENABLED' in first_log

    # Model BMC data becoming valid in the same boot, without reset. The second
    # event is delivered explicitly; the callback is proven to suppress all IO.
    m.dev.unavailable = False
    m.signal()
    second = snapshot(m)
    assert second == first and m.audit() == first_log
    assert m.dev.version_flags == [0xE0]

    # The unchanged image's explicit READ-ONLY API can now read the same fixture.
    # No initialization, protocol loading, variable change or OEM operation.
    read_status = m.call('api_run', 0)
    final = snapshot(m)
    assert read_status == 0 and m.dev.version_flags == [0xE0, 0xC0]
    assert not final['oem_requests'] and not final['nv_writes']
    assert not final['attempt_variable_present'] and final['pci_command'] == 0
    assert 'Status refreshed; no OEM command sent.' in m.audit()
    (OUT / 'synthetic-transient-version-audit.txt').write_text(
        'SYNTHETIC MACHINE-CODE REPLAY / NOT .71 HARDWARE EVIDENCE\n' + m.audit(), encoding='utf-8')

    rows = [{
        'case': 'first_auto_e0_then_c0_second_ready_suppressed',
        'passed': True,
        'entry': entered,
        'after_first_ready_with_e0': first,
        'after_second_ready_after_c0_available': second,
        'after_explicit_read_only_api': final,
        'explicit_read_status': f'{read_status:016X}',
        'version_flags_seen': [f'{x:02X}' for x in m.dev.version_flags],
        'finding': 'One-shot latch survives a reversible pre-OEM sensor-readiness failure; a later ReadyToBoot event does not rescan.',
    }]

    # Entry itself is intentionally independent of SMBIOS presence and performs
    # no queries. This models a POST pause before the first ReadyToBoot event.
    m = entry.EntryMachine()
    count = m.r64(m.st + 0x68)
    assert count > 0
    m.w64(m.st + 0x68, 0)
    assert m.enter() == 0 and m.created and m.published
    before = snapshot(m)
    assert before['requests'] == 0 and before['nv_writes'] == 0
    assert before['auto_seen'] == 0
    m.w64(m.st + 0x68, count)
    m.signal()
    after = snapshot(m)
    assert after['auto_seen'] == 1 and after['oem_requests'] == 4
    assert not after['attempt_variable_present'] and after['pci_command'] == 0
    rows.append({
        'case': 'entry_without_smbios_waits_until_ready_and_redetects',
        'passed': True,
        'before_ready': before,
        'after_ready_with_smbios_restored': after,
        'finding': 'No hardware query occurs merely because the driver has dispatched; identity is detected again when ReadyToBoot runs.',
    })
    (OUT / 'synthetic-wait-for-ready-audit.txt').write_text(
        'SYNTHETIC MACHINE-CODE REPLAY / NOT .71 HARDWARE EVIDENCE\n' + m.audit(), encoding='utf-8')
    result = {
        'all_passed': True,
        'count': len(rows),
        'candidate_sha256': EXPECTED_CAP,
        'executed_pe_sha256': EXPECTED_PE,
        'symbol_map_sha256': sha(R2 / 'driver.map'),
        'container_evidence_sha256': sha(container_path),
        'script_sha256': sha(Path(__file__)),
        'no_network_or_physical_hardware': True,
        'no_published_files_changed': True,
        'cases': rows,
        'limits': [
            'Synthetic UEFI service doubles, recorded baseline and synthetic readiness/post-OEM transitions.',
            'Does not establish .71 current boot driver dispatch, ReadyToBoot signal, or initialization outcome.',
            'Later ReadyToBoot signals are not guaranteed during a normal OS boot; production improvement should not rely on a second event.',
            'The existing behavior is a conservative one-attempt policy, not evidence that an unsafe OEM retry is needed.',
        ],
    }
    (OUT / 'machine-code-readiness-replay.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'all_passed': True, 'cases': [r['case'] for r in rows], 'pe_sha256': EXPECTED_PE}))


if __name__ == '__main__':
    run()
