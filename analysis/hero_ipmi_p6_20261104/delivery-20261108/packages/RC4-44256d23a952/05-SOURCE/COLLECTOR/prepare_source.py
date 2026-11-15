"""Copy only audited capture dependencies into this new collector directory."""
from pathlib import Path
import hashlib,json,shutil
P=Path(__file__).resolve().parent;ROOT=P.parents[2]
OLD=ROOT/'analysis/hero_ipmi_rc3_20261104/collector'
S=P/'source';S.mkdir(parents=True,exist_ok=True)
names=['efi_min.h','r2.h','probe_core.h','kvm.h','common.c','compat','vendor']
for name in names:
    src=OLD/'source'/name;dst=S/name
    if src.is_dir():shutil.copytree(src,dst,dirs_exist_ok=True)
    else:shutil.copyfile(src,dst)
kvm=(OLD/'source/kvm.c').read_text()
kvm=kvm.replace('HERO RC3 AUTO LOG','HERO P6 RC4 AUDIT').replace('RC3 log viewer closed.','P6 log viewer closed.')
kvm=kvm.replace('len>131072','len>278528').replace('HERO-IPMI-R2-QR1','HERO-IPMI-P6-QR1')
(S/'kvm.c').write_text(kvm,encoding='utf-8')
build=(OLD/'build.py').read_text()
build=build.replace('RC3 capture application','P6/R2 capture application').replace('HERO_RC3.TAG','HERO_P6.TAG')
build=build.replace('HERO-IPMI-RC3-LOG','HERO-IPMI-P6-LOG').replace('HERO-RC3-AUTO-LOG.iso','HERO-P6-RC4-READONLY-LOG.iso')
build=build.replace('HERO_RC3_AUTO_LOG','HERO_P6_RC4_AUDIT').replace('RC3 AUTO LOG / CAPTURE ONLY','P6 RC4 AUDIT / CAPTURE ONLY')
# The QR encoder is also exported for round-trip tests; no firmware state.
needle="    outputs=[]"
extra="""    cmd=[str(ZIG),'lld-link','/dll','/noentry','/nodefaultlib','/machine:x64','/opt:ref','/timestamp:0',
        '/export:kvm_make_frame','/export:kvm_encode_frame','/export:qrcodegen_getSize','/export:qrcodegen_getModule',
        '/out:'+str(P/'capture_test.dll')]+[str(P/f'{x}.obj') for x in ('common','kvm','qrcodegen')]
    subprocess.run(cmd,check=True,env=env,cwd=ROOT);commands.append(cmd)
"""
build=build.replace("    (P/'USB/HERO_P6.TAG').write_bytes",extra+"    (P/'USB/HERO_P6.TAG').write_bytes")
(P/'build.py').write_text(build,encoding='utf-8')
decoder=(ROOT/'analysis/hero_ipmi_r2/decode_captures.py').read_text()
decoder=decoder.replace('ROOT=OUT.parents[1]','ROOT=OUT.parents[2]').replace('HERO-IPMI-R2','HERO-IPMI-P6')
decoder=decoder.replace('R2 KVM','P6 KVM').replace('R2 snapshot','P6 snapshot').replace('R2 QR','P6 QR').replace('<=131072','<=278528')
(P/'decode_captures.py').write_text(decoder,encoding='utf-8')
verify=(ROOT/'analysis/hero_ipmi_r2/verify_capture.py').read_text()
verify=verify.replace('ROOT=OUT.parents[1]','ROOT=OUT.parents[2]').replace('HERO-IPMI-R2','HERO-IPMI-P6')
verify=verify.replace('65536,131072','65536,131072,278528')
(P/'verify_capture.py').write_text(verify,encoding='utf-8')
vm=(OLD/'run_vm.py').read_text().replace('without R2','without resident P6 or R2')
vm=vm.replace('HERO-RC3-AUTO-LOG.iso','HERO-P6-RC4-READONLY-LOG.iso')
vm=vm.replace('RESIDENT R2 CORE NOT AVAILABLE. No driver will be loaded.','NO RESIDENT P6 OR R2 AUDIT AVAILABLE. No driver will be loaded.')
vm=vm.replace('R2 hardware behavior','P6/R2 hardware behavior')
(P/'run_vm.py').write_text(vm,encoding='utf-8')
provenance={'origin':'analysis/hero_ipmi_rc3_20261104/collector',
 'source_sha256':{str(p.relative_to(OLD/'source')):hashlib.sha256(p.read_bytes()).hexdigest() for p in (OLD/'source').rglob('*') if p.is_file()},
 'changes':['P6 read-only log/value API added alongside R2 cached audit', 'Larger combined snapshots and distinct P6 QR wire marker',
            'Marker and log filenames isolated from RC3', 'Explicit OS watchdog diagnostic warning', 'No firmware writer or driver loader']}
(P/'source-provenance.json').write_text(json.dumps(provenance,indent=2)+'\n',encoding='utf-8')
print('P6 capture dependencies prepared; launcher.c is maintained separately.')
