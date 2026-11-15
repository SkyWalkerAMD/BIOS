"""Boot the exact local ISO read-only; verify rejection, QR display and exit.

There is no device passthrough, host disk or network. The synthetic ACE identity
still runs QEMU devices, so controller refusal is expected, not a hardware pass.
"""
from pathlib import Path
import datetime
import hashlib
import json
import shutil
import subprocess
import sys
import time

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = next(p for p in HERE.parents if (p/'tools/pydeps').is_dir())
OUT = HERE/'build'
sys.path[:0] = [str(ROOT/'analysis/aitweaker_lock/uefi_vm_20261015'), str(ROOT/'analysis/aitweaker_lock/probe_p3_kvm')]
from run_vm_tests import QMP, ppm_to_png, QEMU, SHARE, CODE, VARS
from decode_captures import read_image, parse_frame, assemble

sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
def save(path, data): path.write_text(json.dumps(data, indent=2)+'\n', encoding='utf8')
ISO = OUT/'ACE1904-SPI-INVENTORY05.iso'


def run(identity):
    folder = HERE/'vm'/(datetime.datetime.now().strftime('%Y%m%d_%H%M%S')+'_'+identity)
    folder.mkdir(parents=True)
    shutil.copyfile(VARS, folder/'vars.fd')
    immutable = {str(path): sha(path) for path in [ISO, CODE, VARS]}
    cpu = 'max,vendor=GenuineIntel,family=6,model=143,stepping=8' if identity == 'synthetic_ace' else 'max'
    args = [str(QEMU), '-L', str(SHARE), '-machine', 'q35,accel=tcg', '-cpu', cpu, '-m', '512', '-smp', '1',
            '-nic', 'none', '-display', 'none', '-monitor', 'none', '-qmp', 'stdio', '-vga', 'none', '-device', 'VGA,xres=1280,yres=800',
            '-serial', 'file:'+str(folder/'serial.log'),
            '-drive', 'if=pflash,format=raw,unit=0,readonly=on,file='+str(CODE),
            '-drive', 'if=pflash,format=raw,unit=1,file='+str(folder/'vars.fd'),
            '-drive', 'if=none,id=cd,format=raw,media=cdrom,readonly=on,file='+str(ISO),
            '-device', 'ide-cd,drive=cd,bus=ide.0,bootindex=1']
    if identity == 'synthetic_ace':
        args += ['-smbios', 'type=0,vendor=American Megatrends,version=1904', '-smbios', 'type=2,manufacturer=ASUSTeK COMPUTER INC.,product=Pro WS W790-ACE']
    save(folder/'command.json', args)
    result = {'status': 'FAIL', 'case': identity, 'hardware_tested': False, 'efi_sha256': sha(OUT/'BOOTX64.EFI'),
              'iso_sha256': sha(ISO), 'ovmf_code_sha256': sha(CODE), 'original_vars_sha256': sha(VARS)}
    proc = None; start = time.monotonic()
    try:
        with (folder/'stderr.log').open('wb') as err:
            proc = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=err, text=True, encoding='utf8', creationflags=subprocess.CREATE_NO_WINDOW)
            qmp = QMP(proc, folder); qmp.command('qmp_capabilities', timeout=15)
            def serial(): return (folder/'serial.log').read_bytes() if (folder/'serial.log').exists() else b''
            def wait(token, after=0):
                end = time.monotonic()+40
                while time.monotonic() < end:
                    if token in serial()[after:]: return
                    if proc.poll() is not None: raise RuntimeError('QEMU exited')
                    time.sleep(.1)
                raise TimeoutError(repr(token))
            def key(code):
                qmp.command('send-key', {'keys': [{'type': 'qcode', 'data': code}], 'hold-time': 20}); time.sleep(.15)
            def capture(page, name):
                end = time.monotonic()+8
                while time.monotonic() < end:
                    time.sleep(.2); ppm = folder/(name+'.ppm'); png = folder/(name+'.png')
                    qmp.command('screendump', {'filename': str(ppm)}); ppm_to_png(ppm, png)
                    try:
                        frame = read_image(png)
                        if parse_frame(frame)['page'] == page: return frame
                    except ValueError: pass
                raise TimeoutError('QR capture '+name)
            wait(b'QR PAGE 1/')
            first = capture(1, 'qr-1'); pages = parse_frame(first)['pages']; frames = [first]
            for page in range(2, pages+1): key('n'); frames.append(capture(page, f'qr-{page}'))
            log, meta = assemble(frames, require_inventory=False); (folder/'RESTORED-LOG.TXT').write_bytes(log)
            expected = serial().split(b'KVM_LOG_BEGIN\r\n', 1)[1].split(b'KVM_LOG_END\r\n', 1)[0]; assert log == expected
            assert b'Watchdog.disable=0x0000000000000000\r\n' in log
            assert b'actual_component_capacity=null' in log and b'COLLECTION_STATUS=PARTIAL_OR_REFUSED' in log
            assert b'LIVE_DESCRIPTOR_BYTES=NOT_READ' in log and b'FLASH_BYTES_ACQUIRED=0' in log
            if identity == 'default':
                assert b'IDENTITY_GATE_REJECTED_BOARD_OR_BIOS' in log and b'PCI_ENUM_STATUS' not in log
            else:
                assert b'IDENTITY_GATE=Pro WS W790-ACE; BIOS=1904' in log
                assert b'CPU.model=0x8F' in log and b'CPU_GATE_REJECTED' not in log
                assert b'SPI_GATE_REJECTED_OR_AMBIGUOUS' in log and b'HSFSTS_HSFC OFFSET' not in log
            key('home'); assert capture(1, 'home') == first
            before = len(serial()); key('t'); wait(b'TEXT PAGE 1/', before)
            key('q'); assert capture(1, 'return-qr') == first
            before = len(serial()); key('esc'); wait(b'ACE SPI inventory ended.', before)
            qmp.command('quit'); assert proc.wait(timeout=10) == 0; qmp.thread.join(timeout=2)
            assert immutable == {str(path): sha(path) for path in [ISO, CODE, VARS]}
            result.update(status='PASS_LOCAL_OVMF_ONLY', qr_pages=pages, qr_metadata=meta, qr_matches_console=True,
                          checks=['read_only_CD_boot', 'watchdog_disable_success', 'identity_or_missing_controller_refusal', 'QR_CRC_and_exact_log_roundtrip',
                                  'QR_Home', 'text_mode', 'QR_return', 'Escape_returns', 'ISO_OVMF_and_original_vars_unchanged'],
                          restored_log_sha256=sha(folder/'RESTORED-LOG.TXT'), no_writable_data_drive=True)
    except Exception as ex:
        import traceback
        result.update(error=str(ex), traceback=traceback.format_exc())
    finally:
        if proc and proc.poll() is None:
            proc.terminate()
            try: proc.wait(timeout=5)
            except subprocess.TimeoutExpired: proc.kill(); proc.wait(timeout=5)
        result.update(seconds=round(time.monotonic()-start, 2), owned_process_finished=bool(proc and proc.poll() is not None), folder=str(folder.relative_to(HERE)))
        save(folder/'result.json', result)
    print(json.dumps({'case': identity, 'status': result['status'], 'error': result.get('error'), 'seconds': result['seconds']}, indent=2), flush=True)
    return result


cases = [run('default'), run('synthetic_ace')]
report = {'status': 'PASS_LOCAL_OVMF_ONLY' if all(c['status'] == 'PASS_LOCAL_OVMF_ONLY' for c in cases) else 'FAIL',
          'hardware_tested': False, 'efi_sha256': sha(OUT/'BOOTX64.EFI'), 'iso_sha256': sha(ISO), 'test_source_sha256': sha(Path(__file__)),
          'cases': cases, 'scope': __doc__}
save(OUT/'ovmf_verification.json', report)
assert report['status'] == 'PASS_LOCAL_OVMF_ONLY'
