"""One-time isolated M1f source import; never edits prior releases or shared tools."""
from pathlib import Path
import hashlib,json,shutil
OUT=Path(__file__).resolve().parent;ROOT=OUT.parents[1]
old=OUT.parent/'hero_display_m1e';patch=OUT.parent/'hero_gop_compat_patch_20261102'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
assert not (OUT/'build.json').exists(),'Already built; do not overwrite the reviewed source'
for folder in ('source','reference'):
    shutil.copytree(old/folder,OUT/folder,dirs_exist_ok=True)
for name in ('build.py','verify.py','verify_capture.py','run_vm.py','package.py','decode_captures.py','qr-reuse-provenance.json'):
    shutil.copyfile(old/name,OUT/name)
shutil.copyfile(patch/'source/kvm.c',OUT/'source/kvm.c')
shutil.copyfile(patch/'verify_graphics.py',OUT/'verify_graphics.py')
for p in [*(OUT/'source').glob('*.c'),*(OUT/'source').glob('*.h'),*(OUT).glob('*.py')]:
    if p.name in ('prepare_from_m1e.py','verify_graphics.py'):continue
    s=p.read_text(encoding='utf-8').replace('M1e','M1f').replace('M1E','M1F')
    p.write_text(s,encoding='utf-8',newline='\n')
p=OUT/'source/diag.c';s=p.read_text()
s=s.replace('First pass: D then R. This app does not call SendForm.','First pass: D then C. If QR fails, use R. No SendForm calls.')
p.write_text(s,encoding='utf-8',newline='\n')
p=OUT/'build.py';s=p.read_text()
s=s.replace("str(ROOT/'tools/zig-cache-global')","str(OUT/'zig-cache-global')").replace("str(ROOT/'tools/zig-cache-local')","str(OUT/'zig-cache-local')")
s=s.replace("'/export:kvm_make_frame'","'/export:kvm_present','/export:kvm_make_frame'")
s=s.replace("boot_fat_sha256=sha(boot),","boot_fat_sha256=sha(boot),dll_sha256=sha(OUT/'capture_test.dll'),\n                objects={Path(p).name:sha(Path(p)) for p in objects},")
p.write_text(s,encoding='utf-8',newline='\n')
p=OUT/'verify_graphics.py';s=p.read_text()
s=s.replace("OUT/'kvm_test.dll'","OUT/'capture_test.dll'").replace('HERO-HII-M1E-KVM','HERO-HII-M1F-KVM')
s=s.replace("assert bytes(codes[0].bytes)==bytes(raw[:n])","assert bytes(codes[0].bytes)==upgrade_frame(bytes(raw[:n]))")
s=s.replace("an==bn and a[:an]==b[:bn]","an==bn and a[:an]==upgrade_frame(bytes(b[:bn]))")
s=s.replace("def main():\n rows=[]","def main():\n build=json.loads((OUT/'build.json').read_text())\n assert build['dll_sha256']==sha(OUT/'capture_test.dll')\n assert build['image_sha256']==sha(OUT/'payload/EFI/BOOT/BOOTX64.EFI')\n for name,digest in build['objects'].items():assert sha(OUT/name)==digest\n rows=[]")
s=s.replace("report=dict(dll_sha256=", "report=dict(image_sha256=build['image_sha256'],objects=build['objects'],frame_normalization='Only the initial HERO-M1E-QR1 prefix is upgraded to HERO-M1F-QR1; remaining bytes must match.',dll_sha256=")
s=s.replace("Native test DLL executes the same patched C transport and QR encoder, but is not a complete bootable EFI integration test.","Native DLL links the exact same diag/kvm/qrcodegen objects as the final EFI; separate EFI and optical VM results cover integration.")
s=s.replace("DATA=b'", "def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()\ndef upgrade_frame(raw):\n assert raw.startswith(b'HERO-M1E-QR1\\n')\n return b'HERO-M1F-QR1\\n'+raw[len(b'HERO-M1E-QR1\\n'):]\n\nDATA=b'",1)
p.write_text(s,encoding='utf-8',newline='\n')
evidence=OUT/'evidence';evidence.mkdir(exist_ok=True)
real=OUT.parent/'hero_m1e_result_20261102/M1E-DISPLAY-RESTORED.TXT'
shutil.copyfile(real,evidence/real.name)
for name in ('hii-review.txt','hii-byte-audit.json'):
    shutil.copyfile(patch/name,OUT/'reference'/name)
provenance=json.loads((old/'qr-reuse-provenance.json').read_text())
provenance['M1f_changes']=['Independent M1e copy; same ConOut GOP QueryMode fallback for absent/short Mode.Info metadata.',
    'New M1F frame and snapshot magic; no SendForm, no SetMode, no firmware metadata mutations.',
    'USB-M1c byte-identical file logging retained.']
provenance['M1e_direct_baseline_sha256']={n:sha(old/n) for n in ('source/diag.c','source/kvm.c','source/kvm.h','source/efi_min.h','capture_test.dll')}
provenance['isolated_graphics_patch_sha256']=sha(patch/'source/kvm.c')
(OUT/'qr-reuse-provenance.json').write_text(json.dumps(provenance,indent=2)+'\n',encoding='utf-8')
print('Prepared independent M1f source; no old release modified.')
