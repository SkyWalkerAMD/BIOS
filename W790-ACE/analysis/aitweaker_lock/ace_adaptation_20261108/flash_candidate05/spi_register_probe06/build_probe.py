"""Build a local ACE inventory application and ISO. Never accesses hardware."""
from pathlib import Path
import hashlib
import io
import json
import os
import subprocess
import sys
import warnings

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = next(p for p in HERE.parents if (p/'tools/pydeps').is_dir())
SOURCE = HERE/'source'
OUT = HERE/'build'
OUT.mkdir(exist_ok=True)
P3 = HERE.parent/'layout_recovery/probe/source/p3'
for folder in ['pydeps', 'vm-pydeps', 'kvm-pydeps']:
    sys.path.insert(0, str(ROOT/'tools'/folder))
warnings.filterwarnings('ignore', message='pkg_resources is deprecated.*')
import pefile
import pycdlib
from pyfatfs.PyFat import PyFat
from pyfatfs.PyFatFS import PyFatFS


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(path, data):
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False)+'\n', encoding='utf8')


reused = {}
for name in ['efi_min.h', 'kvm.h', 'kvm.c', 'probe_core.h', 'probe_core.c',
             'vendor/qrcodegen.c', 'vendor/qrcodegen.h', 'compat/string.h', 'compat/stdlib.h', 'compat/assert.h']:
    source = P3/name
    data = source.read_bytes()
    if name == 'kvm.c':
        replacements = {
            b'ACE1904 SPI INVENTORY05 - KVM LOG': b'ACE1904 SPI PROBE06 - KVM LOG',
            b'ACE SPI inventory05 - register snapshot only': b'ACE SPI probe06 - CPU_IO2 read-only snapshot',
            b'ACE SPI inventory ended. No flash data read or written.': b'ACE SPI probe06 ended. No flash data read or written.',
        }
        for old, new in replacements.items():
            assert old in data
            data = data.replace(old, new)
    target = SOURCE/'p3'/name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)
    reused[name] = {'original_path': source.relative_to(ROOT).as_posix(), 'original_sha256': sha(source),
                    'copied_path': target.relative_to(HERE).as_posix(), 'copied_sha256': sha(target),
                    'scope': 'UI labels only; unchanged QR frame format' if name == 'kvm.c' else 'byte-identical'}

zig = ROOT/'tools/zig-x86_64-windows-0.14.1/zig.exe'
sources = {p.relative_to(HERE).as_posix(): sha(p) for p in sorted(SOURCE.rglob('*')) if p.is_file() and p.name != 'build_identity.h'}
bundle = {'sources': dict(sources), 'builder_sha256': sha(Path(__file__)), 'compiler_sha256': sha(zig),
          'target': 'x86_64-unknown-windows-msvc', 'optimization': '-O2'}
identity = hashlib.sha256(json.dumps(bundle, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
(SOURCE/'build_identity.h').write_text('#define TOOL_SOURCE_SHA256 "'+identity+'"\n', encoding='ascii')
sources['source/build_identity.h'] = sha(SOURCE/'build_identity.h')
env = os.environ.copy()
env.update(ZIG_GLOBAL_CACHE_DIR=str(OUT/'.zig-global'), ZIG_LOCAL_CACHE_DIR=str(OUT/'.zig-local'))
commands, objects = [], []
for path in [SOURCE/'inventory.c', SOURCE/'p3/probe_core.c', SOURCE/'p3/kvm.c', SOURCE/'p3/vendor/qrcodegen.c']:
    obj = OUT/(path.stem+'.obj')
    cmd = [str(zig), 'clang', '-target', 'x86_64-unknown-windows-msvc', '-nostdinc', '-isystem', str(zig.parent/'lib/include'),
           '-I', str(SOURCE), '-I', str(SOURCE/'p3'), '-I', str(SOURCE/'p3/compat'), '-std=c11', '-O2', '-Wall', '-Wextra',
           '-Werror', '-DNDEBUG', '-ffreestanding', '-fno-builtin', '-fno-stack-protector', '-mno-red-zone', '-fshort-wchar',
           '-c', str(path), '-o', str(obj)]
    subprocess.run(cmd, check=True, env=env, cwd=HERE)
    commands.append(cmd); objects.append(str(obj))
efi = OUT/'BOOTX64.EFI'
cmd = [str(zig), 'lld-link', '/subsystem:efi_application', '/entry:efi_main', '/nodefaultlib', '/machine:x64',
       '/dynamicbase', '/fixed:no', '/nxcompat', '/timestamp:0', '/map:'+str(OUT/'inventory.map'), '/out:'+str(efi)]+objects
subprocess.run(cmd, check=True, env=env, cwd=HERE); commands.append(cmd)
pe = pefile.PE(str(efi)); pe.OPTIONAL_HEADER.CheckSum = pe.generate_checksum(); efi.write_bytes(pe.write()); pe.close()
pe = pefile.PE(str(efi))
assert pe.verify_checksum() and pe.OPTIONAL_HEADER.Subsystem == 10 and not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT')
assert pe.OPTIONAL_HEADER.DATA_DIRECTORY[5].Size and not pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size
pe.close()
cmd = [str(zig), 'lld-link', '/dll', '/noentry', '/nodefaultlib', '/machine:x64', '/timestamp:0',
       '/export:kvm_make_frame', '/export:kvm_encode_frame', '/export:probe_crc32',
       '/export:qrcodegen_getSize', '/export:qrcodegen_getModule', '/out:'+str(OUT/'qr_test.dll')]+objects
subprocess.run(cmd, check=True, env=env, cwd=HERE); commands.append(cmd)
boot = OUT/'eltorito.img'; boot.write_bytes(b'')
fat = PyFat(); fat.mkfs(str(boot), fat_type=16, size=16*1024*1024, label='ACEPRB06'); fat.close()
with PyFatFS(str(boot), utc=True) as fs:
    fs.makedirs('/EFI/BOOT', recreate=True); fs.writebytes('/EFI/BOOT/BOOTX64.EFI', efi.read_bytes())
iso = pycdlib.PyCdlib(); iso.new(interchange_level=3, vol_ident='ACE1904_SPIPRB06', joliet=3)
iso.add_file(str(boot), iso_path='/EFIBOOT.IMG;1', joliet_path='/EFIBOOT.IMG')
iso.add_eltorito('/EFIBOOT.IMG;1', bootcatfile='/BOOT.CAT;1', boot_load_size=boot.stat().st_size//512,
                platform_id=0xef, efi=True, media_name='noemul', bootable=True)
for folder in ['/EFI', '/EFI/BOOT']:
    iso.add_directory(iso_path=folder, joliet_path=folder)
iso.add_file(str(efi), iso_path='/EFI/BOOT/BOOTX64.EFI;1', joliet_path='/EFI/BOOT/BOOTX64.EFI')
target = OUT/'ACE1904-SPI-PROBE06.iso'; iso.write(str(target)); iso.close()
verify = pycdlib.PyCdlib(); verify.open(str(target)); buffer = io.BytesIO()
verify.get_file_from_iso_fp(buffer, iso_path='/EFI/BOOT/BOOTX64.EFI;1'); assert buffer.getvalue() == efi.read_bytes()
assert verify.eltorito_boot_catalog.validation_entry.platform_id == 0xef
buffer = io.BytesIO(); verify.get_file_from_iso_fp(buffer, iso_path='/EFIBOOT.IMG;1'); assert buffer.getvalue() == boot.read_bytes()
verify.close()
with PyFatFS(str(boot), read_only=True, utc=True) as fs:
    assert fs.readbytes('/EFI/BOOT/BOOTX64.EFI') == efi.read_bytes()
report = {'status': 'BUILT_AWAITING_LOCAL_VALIDATION_NOT_DEPLOYED', 'build_id': 'ACE1904-SPI-PROBE06',
          'hardware_tested': False, 'bmc_access': False, 'spi_cycles': 0, 'firmware_write_performed': False,
          'source_bundle_sha256': identity, 'identity_preimage': bundle, 'source_files': sources,
          'reused_sources': reused, 'builder_sha256': sha(Path(__file__)), 'compiler_sha256': sha(zig),
          'efi_sha256': sha(efi), 'efi_bytes': efi.stat().st_size, 'iso_sha256': sha(target), 'iso_bytes': target.stat().st_size,
          'iso_and_fat_embed_exact_efi': True, 'linker_map_sha256': sha(OUT/'inventory.map'),
          'qr_test_dll_sha256': sha(OUT/'qr_test.dll'), 'commands': commands,
          'scope': 'Exact observed ACE1904/CPUID/PCI identity. Read14 fixed register addresses through verified original EFI_CPU_IO2.Mem.Read only after fresh MMIO-map/provider/PCI gates. No PCI or SPI writes, SPI cycle, RootBridge fallback or raw application MMIO dereference.',
          'limits': ['QRC/GOP and console are the existing display framework, not a claim that all display-related hardware is untouched.',
                     'Normal firmware boot may modify its own variables; this application does not call SetVariable.',
                     'The result is not a flash dump or complete chip capacity/permission proof.',
                     'BIOS must still boot this unsigned UEFI application; no Secure Boot settings are changed.']}
save(OUT/'build.json', report)
print(json.dumps({k: report[k] for k in ['status', 'efi_sha256', 'efi_bytes', 'iso_sha256', 'iso_bytes', 'source_bundle_sha256']}, indent=2))
