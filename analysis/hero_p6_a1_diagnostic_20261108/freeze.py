"""Freeze independently tested application artifacts; never build or touch CAPs."""
from pathlib import Path
import difflib,hashlib,json,zipfile
BASE=Path(__file__).resolve().parent;ROOT=BASE.parents[1]
sha=lambda b:hashlib.sha256(b).hexdigest()
old=ROOT/'analysis/hero_p6_settings21r_20261108';launcher=ROOT/'analysis/hero_p6_ramcheck3_20261108'
build=json.loads((BASE/'build.json').read_text());runtime=json.loads((BASE/'tests/actual-pe.json').read_text());vm=json.loads((BASE/'vm-verification.json').read_text());decoder=json.loads((BASE/'tests/decoder.json').read_text())
assert runtime['passed'] and runtime['cases']==82 and vm['passed'] and decoder['passed']
app=BASE/'USB/EFI/BOOT/BOOTX64.EFI';iso=BASE/'HERO-P6-A1-DIAGNOSTIC.iso'
assert sha(app.read_bytes())==build['launcher_sha256']==runtime['actual_pe_sha256']==vm['launcher_sha256']
assert sha(iso.read_bytes())==build['iso_sha256']==vm['iso_sha256']
assert sha(app.read_bytes())=='232d6f2111a1089a24df8a621539a71ffdeaa91f91fa39439bc44477ec6a35c0'
assert sha(iso.read_bytes())=='fdc72f68d63fc337673292a217c9262a87cc9e43c206c0b089c0a96963c40233'
for name,digest in build['sources'].items():assert sha((BASE/'source'/name).read_bytes())==digest,name
reuse={}
for source,names in ((old,('p1.h','p5.h','probe_core.h','probe_core.c','transport.c','settings.h','presentation.c','expected.h')),(launcher,('efi_min.h','preflight.h','common.c','identity.c','target_identity.h','smbios.c','smbios_bounded.h','crc.c','kvm.h','compat/assert.h','compat/stdlib.h','compat/string.h','vendor/qrcodegen.c','vendor/qrcodegen.h'))):
 for name in names:
  p=BASE/'source'/name;q=source/'source'/name;assert p.read_bytes()==q.read_bytes(),name
  reuse[name]={'source':str(q.relative_to(ROOT)).replace('\\','/'),'sha256':sha(p.read_bytes()),'identical':True}
diff=''
for source,name in ((old,'publisher.c'),(launcher,'preflight.c'),(launcher,'kvm.c')):
 a=(source/'source'/name).read_text().splitlines(True);b=(BASE/'source'/name).read_text().splitlines(True)
 diff+=''.join(difflib.unified_diff(a,b,fromfile=str(source.relative_to(ROOT))+'/source/'+name,tofile='A1/source/'+name))+'\n'
(BASE/'reference/source-differences.patch').write_text(diff,encoding='utf-8',newline='\n')
provenance={'unchanged':reuse,'diagnostic_changes':{'publisher.c':'Application-context before/after synchronous call trace; current-value single probe; preserve per-language configuration-status string during full publication. Original full forms search and matching retained.','preflight.c':'Only diagnostic log wording: missing variables stay absent. Original strict 21/32B defaults and 144B journal predicates retained.','kvm.c':'Only A1 branding/frame prefix. Original bounded 2MiB renderer retained.','diagnostic.c':'Bounded exact target identity adapter, channel0 fixed under safe-default gate, trace counters/last call and RAM summary.','command_policy.c':'Immutable standard GET allowlist; no write_armed override.','app.c':'New explicit B/R/P/P at TPL_APPLICATION; per-stage Enter, once-only/no retry, identity/default/no-resident gates, C full/M summary, Q/Q exit; no callbacks/services installed.'},'not_linked':['settings.c','driver.c','resident_image.h','config writers','OEM candidate/fan helpers'],'limits':['A1 changes call context to application and adds ConOut checkpoints. It cannot establish that production TPL8/AfterBoot callbacks are safe.','HII SetString updates RAM display strings. BMC reads temporarily enable PCI memory decoding if needed and verify handled-exit restoration.','No on-target test was performed by the building agent.']}
(BASE/'reference/provenance.json').write_text(json.dumps(provenance,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
chosen=[app,iso,BASE/'build.json',BASE/'build/BOOTX64.map',BASE/'build.py',BASE/'decode_captures.py',BASE/'run_vm.py',BASE/'vm-verification.json',BASE/'操作与验证说明.txt',BASE/'reference/provenance.json',BASE/'reference/source-differences.patch',BASE/'tests/actual-pe.json',BASE/'tests/decoder.json',BASE/'tests/test_actual_pe.py',BASE/'tests/test_decoder.py']
chosen+=sorted(p for p in (BASE/'source').rglob('*') if p.is_file())
manifest={'kind':'P6-A1 APPLICATION DIAGNOSTIC ONLY','target':'Exact .71 HERO/BIOS3107, safe-default variables only','hardware_tested':False,'CAP_created':False,'resident_callbacks':False,'nv_writes':False,'config_or_oem_commands':False,'hii_ram_display_mutation':True,'tests':{'actual_pe_cases':82,'decoder_cases':8,'ovmf_qr_pages':vm['qr_exact_roundtrip']['pages']},'files':{str(p.relative_to(BASE)).replace('\\','/'):{'bytes':p.stat().st_size,'sha256':sha(p.read_bytes())} for p in chosen}}
(BASE/'FROZEN-ARTIFACTS.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
dest=BASE/'HERO-P6-A1-DIAGNOSTIC.zip'
with zipfile.ZipFile(dest,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=9) as z:
 for p in chosen+[BASE/'FROZEN-ARTIFACTS.json']:z.write(p,str(p.relative_to(BASE)))
with zipfile.ZipFile(dest) as z:
 assert z.testzip() is None
 for name,item in manifest['files'].items():
  b=z.read(name);assert len(b)==item['bytes'] and sha(b)==item['sha256']
report={'zip':dest.name,'bytes':dest.stat().st_size,'sha256':sha(dest.read_bytes()),'zip_readback_all_manifest_files':True,'iso':manifest['files'][iso.name],'pe':manifest['files']['USB/EFI/BOOT/BOOTX64.EFI']}
(BASE/'PACKAGE-HASH.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
