"""Boot the exact INTEGRATED03 ISO in local OVMF and verify non-target refusal.

Uses regular local firmware/image files, no network or host disks. This does
not exercise ASUS firmware or imply this ISO has run on physical hardware.
"""
from pathlib import Path
import datetime
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = next(p for p in HERE.parents if (p / 'tools/qemu-11.1.0/qemu-system-x86_64.exe').is_file())
OUT = HERE / 'build'
VM_HELPERS = ROOT / 'analysis/aitweaker_lock/uefi_vm_20261015'
QR_HELPERS = ROOT / 'analysis/aitweaker_lock/probe_p3_kvm'
sys.path[:0] = [str(VM_HELPERS), str(QR_HELPERS)]
from run_vm_tests import QMP, ppm_to_png, QEMU, SHARE, CODE, VARS
from decode_captures import read_image, assemble

def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

build = json.loads((OUT / 'build.json').read_text(encoding='utf8'))
assert build['build_id'] == 'ACE1904-INTEGRATED03-RAM'
assert build['production_object_relink_exact_match']
iso = OUT / 'ACE1904-INTEGRATED03-RAM.iso'
assert sha(iso) == build['iso_sha256']
assert sha(OUT / 'BOOTX64.EFI') == build['efi_sha256']
folder = OUT / 'vm' / datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
folder.mkdir(parents=True)
shutil.copyfile(VARS, folder / 'vars.fd')
args = [str(QEMU), '-L', str(SHARE), '-machine', 'q35,accel=tcg', '-cpu', 'max',
        '-m', '512', '-smp', '1', '-nic', 'none', '-display', 'none', '-monitor', 'none',
        '-qmp', 'stdio', '-vga', 'none', '-device', 'VGA,xres=1280,yres=800',
        '-serial', 'file:' + str(folder / 'serial.log'),
        '-drive', 'if=pflash,format=raw,unit=0,readonly=on,file=' + str(CODE),
        '-drive', 'if=pflash,format=raw,unit=1,file=' + str(folder / 'vars.fd'),
        '-drive', 'if=none,id=cd,format=raw,media=cdrom,readonly=on,file=' + str(iso),
        '-device', 'qemu-xhci,id=xhci', '-device', 'usb-storage,drive=cd,bus=xhci.0,bootindex=1']
(folder / 'command.json').write_text(json.dumps(args, indent=2), encoding='utf8')
result = {
    'passed': False, 'build_id': build['build_id'], 'iso_sha256': sha(iso),
    'efi_sha256': sha(OUT / 'BOOTX64.EFI'),
    'production_driver_sha256': build['production_driver_sha256'],
    'build_manifest_sha256': sha(OUT / 'build.json'), 'folder': str(folder),
    'scope': 'Exact INTEGRATED03 RAM application boots from read-only USB CD on non-target OVMF, refuses to install hooks or write credentials, displays a recoverable QR log and exits on Esc.',
    'hardware_tested': False,
    'verification_inputs': {str(p.relative_to(ROOT)): sha(p) for p in [
        VM_HELPERS / 'run_vm_tests.py', VM_HELPERS / 'disk_images.py',
        QR_HELPERS / 'decode_captures.py', QEMU, CODE, VARS, Path(__file__).resolve()]},
}
proc = None
try:
    with (folder / 'stderr.log').open('wb') as err:
        env = os.environ.copy()
        env['PYTHONDONTWRITEBYTECODE'] = '1'
        proc = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=err,
                                text=True, encoding='utf8', env=env,
                                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        qmp = QMP(proc, folder)
        qmp.command('qmp_capabilities', timeout=15)
        deadline = time.monotonic() + 45
        decoded = None
        while time.monotonic() < deadline:
            time.sleep(.5)
            ppm = folder / 'screen.ppm'
            png = folder / 'screen.png'
            qmp.command('screendump', {'filename': str(ppm)})
            ppm_to_png(ppm, png)
            try:
                decoded = read_image(png)
                break
            except ValueError:
                pass
        assert decoded, 'Expected INTEGRATED03 diagnostic QR was not visible'
        data, meta = assemble([decoded])
        (folder / 'RESTORED-LOG.TXT').write_bytes(data)
        assert b'UNSUPPORTED_BOARD_NO_HOOKS_NO_WRITES\r\n' in data
        assert b'Production.SMBIOS.board_match=0x0000000000000000\r\n' in data
        assert b'ACE1904-INTEGRATED03-RAM\r\n' in data
        assert ('DriverSHA256=' + build['production_driver_sha256'] + '\r\n').encode('ascii') in data
        assert b'BlockedSetVariableCalls=0x0000000000000000\r\n' in data
        serial = (folder / 'serial.log').read_bytes()
        assert data == serial.split(b'KVM_LOG_BEGIN\r\n', 1)[1].split(b'KVM_LOG_END\r\n', 1)[0]
        qmp.command('send-key', {'keys': [{'type': 'qcode', 'data': 'esc'}], 'hold-time': 80})
        time.sleep(1)
        assert b'P3 KVM ended.' in (folder / 'serial.log').read_bytes()
        qmp.command('quit')
        assert proc.wait(timeout=10) == 0
        qmp.thread.join(timeout=2)
        assert sha(iso) == result['iso_sha256']
        result.update(passed=True, qr=meta, refusal_verified=True, exit_verified=True,
                      medium_unchanged=True, original_firmware_file_unchanged=sha(CODE) == result['verification_inputs'][str(CODE.relative_to(ROOT))])
finally:
    if proc and proc.poll() is None:
        proc.terminate()
        proc.wait(timeout=5)
    (OUT / 'vm_validation.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf8')
    print(json.dumps(result, indent=2))
