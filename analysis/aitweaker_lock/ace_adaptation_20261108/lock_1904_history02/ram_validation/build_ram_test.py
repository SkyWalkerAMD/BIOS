"""Build ACE1904-HISTORY02-RAM with the exact pinned production COFF objects.

Only local files under ram_validation are written. This creates media and does
not connect to a BMC, mount media, power a host, or flash firmware.
"""
from pathlib import Path
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = next(p for p in HERE.parents if (p / 'tools/zig-x86_64-windows-0.14.1/zig.exe').is_file())
DRIVER = HERE.parent / 'driver'
OUT = HERE / 'build'
SRC = OUT / 'source'
SRC.mkdir(parents=True, exist_ok=True)
EXPECTED_DRIVER = '598daaa53564f9b4610e300946fd588c2108a9842cb5f15cf67ee8e8d0a2fd84'
BUILD_ID = 'ACE1904-HISTORY02-RAM'
for name in ['pydeps', 'vm-pydeps', 'kvm-pydeps']:
    sys.path.insert(0, str(ROOT / 'tools' / name))
import pefile
import pycdlib
from pyfatfs.PyFat import PyFat
from pyfatfs.PyFatFS import PyFatFS

def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def checksum(path):
    pe = pefile.PE(str(path))
    pe.OPTIONAL_HEADER.CheckSum = pe.generate_checksum()
    path.write_bytes(pe.write())
    pe.close()

production_efi = DRIVER / 'build/AiTweakerLock1904.efi'
production_manifest = DRIVER / 'build/build.json'
production = json.loads(production_manifest.read_text(encoding='utf8'))
assert sha(production_efi) == production['efi_sha256'] == EXPECTED_DRIVER
assert production['revision'] == 'ACE1904_HISTORY02'
assert all(sha(HERE.parent / p) == h for p, h in production['sources'].items())
assert all(sha(ROOT / p) == h for p, h in production['external_sources'].items())

zig = ROOT / 'tools/zig-x86_64-windows-0.14.1/zig.exe'
env = os.environ.copy()
env.update(ZIG_GLOBAL_CACHE_DIR=str(OUT / '.zig-global'),
           ZIG_LOCAL_CACHE_DIR=str(OUT / '.zig-local'),
           PYTHONDONTWRITEBYTECODE='1')
commands = []

def run(argv):
    commands.append(argv)
    subprocess.run(argv, check=True, env=env, cwd=HERE,
                   creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))

# Bind the object files to the production binary, not just to a source manifest.
# Re-linking the unchanged production entry + objects must produce its exact
# pinned bytes after the same PE checksum calculation.
relinked = OUT / 'PRODUCTION-RELINK-CHECK.EFI'
relink_cmd = [('/out:' + str(relinked)) if a.startswith('/out:') else
              ('/map:' + str(OUT / 'production-relink-check.map')) if a.startswith('/map:') else a
              for a in production['commands'][-1]]
assert relink_cmd[0] == str(zig) and relink_cmd[1] == 'lld-link'
production_objects = [Path(a) for a in relink_cmd if a.lower().endswith('.obj')]
assert all(p.resolve().is_relative_to((DRIVER / 'build').resolve()) for p in production_objects)
object_hashes = {p.name: sha(p) for p in production_objects}
run(relink_cmd)
checksum(relinked)
assert sha(relinked) == EXPECTED_DRIVER, 'Linked objects do not reproduce the pinned production driver'

source = (DRIVER / 'entry.c').read_text(encoding='utf8')
guid_names = ['loaded_guid', 'browser_guid', 'smbios3_guid', 'smbios_guid', 'tse_guid', 'setup_guid']
guids = '\n'.join(line for line in source.splitlines()
                  if line.startswith(tuple('static GUID ' + n for n in guid_names)))
assert len(guids.splitlines()) == len(guid_names)
functions = source[source.index('static int equal_ascii('):source.index('static void EA discover(')]
assert '"1904"' in functions and '"Pro WS W790-ACE"' in functions
(SRC / 'target_detect.h').write_text(guids + '\n' + functions, encoding='utf8')
(SRC / 'build_identity.h').write_text('#define RAM_TEST_DRIVER_SHA "' + EXPECTED_DRIVER + '"\n', encoding='ascii')
shutil.copyfile(HERE / 'ram_lock_test.c', SRC / 'ram_lock_test.c')
p3 = ROOT / 'analysis/aitweaker_lock/probe_p3_kvm/source'
kvm = (p3 / 'kvm.c').read_text(encoding='utf8').replace('AI TWEAKER P3 - KVM LOG', BUILD_ID)
kvm = kvm.replace('COMPLETE INVENTORY - DIAGNOSTIC ONLY', 'RAM TEST LOG - REVIEW DIAGNOSTICS')
kvm = kvm.replace('PARTIAL INVENTORY - DIAGNOSTIC ONLY', 'RAM TEST LOG - CHECKS FAILED')
(SRC / 'kvm.c').write_text(kvm, encoding='utf8')
external_sources = {str(p.relative_to(ROOT)): sha(p) for p in sorted(p3.rglob('*'))
                    if p.is_file() and p.suffix in {'.c', '.h'}}

objects = []
for file in [SRC / 'ram_lock_test.c', SRC / 'kvm.c', p3 / 'vendor/qrcodegen.c']:
    obj = OUT / (file.stem + '.obj')
    objects.append(str(obj))
    run([str(zig), 'clang', '-target', 'x86_64-unknown-windows-msvc', '-nostdinc',
         '-isystem', str(zig.parent / 'lib/include'), '-I', str(DRIVER), '-I', str(SRC),
         '-I', str(p3), '-I', str(p3 / 'compat'), '-std=c11', '-O2', '-Wall', '-Wextra',
         '-Werror', '-DNDEBUG', '-ffreestanding', '-fno-builtin', '-fno-stack-protector',
         '-mno-red-zone', '-fshort-wchar', '-c', str(file), '-o', str(obj)])
linked = ['services', 'cpu_entropy', 'ui', 'hii', 'policy', 'platform', 'password_core', 'password_crypto', 'probe_core']
objects += [str(DRIVER / 'build' / (name + '.obj')) for name in linked]
assert all(sha(DRIVER / 'build' / (name + '.obj')) == object_hashes[name + '.obj'] for name in linked)
efi = OUT / 'BOOTX64.EFI'
run([str(zig), 'lld-link', '/subsystem:efi_application', '/entry:efi_main', '/nodefaultlib',
     '/machine:x64', '/dynamicbase', '/fixed:no', '/nxcompat', '/timestamp:0',
     '/map:' + str(OUT / 'ram_test.map'), '/out:' + str(efi)] + objects)
checksum(efi)
pe = pefile.PE(str(efi))
assert pe.OPTIONAL_HEADER.Subsystem == 10 and pe.verify_checksum()
assert not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT')
assert pe.OPTIONAL_HEADER.DATA_DIRECTORY[5].Size and not pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size
pe.close()

boot = OUT / 'eltorito.img'
boot.write_bytes(b'')
fat = PyFat()
fat.mkfs(str(boot), fat_type=16, size=16 * 1024 * 1024, label='ACE_HIST02')
fat.close()
with PyFatFS(str(boot), utc=True) as fs:
    fs.makedirs('/EFI/BOOT', recreate=True)
    fs.writebytes('/EFI/BOOT/BOOTX64.EFI', efi.read_bytes())
    assert fs.readbytes('/EFI/BOOT/BOOTX64.EFI') == efi.read_bytes()
target = OUT / (BUILD_ID + '.iso')
iso = pycdlib.PyCdlib()
iso.new(interchange_level=3, vol_ident='ACE1904_H02_RAM', joliet=3)
iso.add_file(str(boot), iso_path='/EFIBOOT.IMG;1', joliet_path='/EFIBOOT.IMG')
iso.add_eltorito('/EFIBOOT.IMG;1', bootcatfile='/BOOT.CAT;1', boot_load_size=boot.stat().st_size // 512,
                platform_id=0xef, efi=True, media_name='noemul', bootable=True)
iso.write(str(target))
iso.close()
iso = pycdlib.PyCdlib()
iso.open(str(target))
extracted = io.BytesIO()
iso.get_file_from_iso_fp(extracted, iso_path='/EFIBOOT.IMG;1')
iso.close()
assert extracted.getvalue() == boot.read_bytes()
assert sha(production_efi) == EXPECTED_DRIVER
assert all(sha(p) == object_hashes[p.name] for p in production_objects)
assert all(sha(ROOT / p) == h for p, h in external_sources.items())
baseline_dir = ROOT / 'analysis/aitweaker_lock/lock_1904/remote_172_20_2_209'
result = {
    'status': 'BUILT_LOCAL_RAM_VALIDATION_MEDIA_NOT_HARDWARE_TESTED',
    'build_id': BUILD_ID,
    'scope': 'Maintenance-only RAM credential and resident hook application. New production objects; temporary hooks require reset to release. No BMC or physical hardware operation performed.',
    'iso': str(target), 'iso_sha256': sha(target), 'iso_bytes': target.stat().st_size,
    'efi_sha256': sha(efi), 'efi_bytes': efi.stat().st_size,
    'production_driver_sha256': EXPECTED_DRIVER,
    'production_manifest_sha256': sha(production_manifest),
    'production_object_relink_exact_match': True,
    'linked_objects': {name: object_hashes[name + '.obj'] for name in linked},
    'all_production_object_hashes': object_hashes,
    'production_sources': production['sources'],
    'production_external_sources': production['external_sources'],
    'external_source_tree_sha256': external_sources,
    'generated_source_sha256': {p.name: sha(p) for p in sorted(SRC.iterdir()) if p.is_file()},
    'local_source_sha256': {p.name: sha(p) for p in sorted(HERE.iterdir()) if p.is_file() and p.suffix in {'.c', '.py'}},
    'baseline_source_sha256': {n: sha(baseline_dir / n) for n in ['ram_lock_test.c', 'build_ram_test.py', 'verify_ram_boot.py']},
    'toolchain': {'zig_exe_sha256': sha(zig), 'version': subprocess.check_output([str(zig), 'version'], env=env).decode().strip()},
    'embedded_efi_matches': True, 'embedded_boot_image_matches': True,
    'credentials': 'Only public self-test fixtures and subsequently entered temporary credentials; AP_ENV read/persist callbacks point to RAM.',
    'runtime_write_guard': 'Runtime Services SetVariable table and original_set_variable are changed to deny_variable before attach_platform. No claim of intercepting SMM, cached pointers or direct hardware access.',
    'target_guard': 'Exact SMBIOS product Pro WS W790-ACE and version 1904, unique loaded module GUIDs, full expected text CRC/RVA/length/entry tuples, native SendForm pointer, then production hook byte/pointer checks.',
    'hardware_tested': False, 'physical_firmware_writes_performed': False,
    'limitations': ['No direct Del/F2 or complete modified-firmware boot validation.', 'No physical persistent credential, defaults/training, flash acceptance or recovery validation.', 'Live BMC reports 1904/Off but live module identity and motherboard inventory remain unconfirmed.', 'Only three named variable hashes are monitored; this is not a whole-NVRAM or whole-SPI comparison.', 'Runtime SetVariable interception does not cover OEM cached pointers, SMM or direct writes.'],
    'commands': commands,
}
(OUT / 'build.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf8')
(OUT / 'SHA256SUMS.txt').write_text('\n'.join(sha(p) + '  ' + p.name for p in [efi, target, boot]) + '\n', encoding='ascii')
print(json.dumps({k: result[k] for k in ['status', 'build_id', 'iso_sha256', 'iso_bytes', 'efi_sha256', 'efi_bytes', 'production_object_relink_exact_match']}, indent=2))
