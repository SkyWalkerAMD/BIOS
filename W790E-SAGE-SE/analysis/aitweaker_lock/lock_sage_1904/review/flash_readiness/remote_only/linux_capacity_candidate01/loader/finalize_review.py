"""Verify and freeze a bounded index of candidate bytes and local evidence.
Caches, QEMU writable vars, temporary raw test disks and repeated PPM captures
are excluded. Their relevant outcomes and before/after hashes remain in reports.
"""
from pathlib import Path
import datetime,json,sys
from build_loader import OUT,ROOT,sha
from run_tests import Q,SHARE,save
sys.path.insert(0,str(OUT.parent))
from decode_linux_log import decode

def main():
    manifest=json.loads((OUT/'candidate/media_manifest.json').read_text());binary=OUT/'candidate/build/BOOTX64.EFI'
    assert sha(binary)==manifest['efi_sha256'] and sha(manifest['iso'])==manifest['iso_sha256']
    assert sha(OUT/'tests/production_rebuild/BOOTX64.EFI')==sha(binary)
    prod=json.loads((OUT/'candidate/build/manifest.json').read_text());fixture=json.loads((OUT/'tests/fixture/loader/manifest.json').read_text())
    for source in ['source\\bootstrap.c','source\\efi_min.h','source\\sha256.c','source\\sha256.h']:
        assert prod['sources'][source]==fixture['sources'][source]==sha(OUT/source)
    evidence=[]
    for p in sorted((OUT/'tests/linux-runs').glob('*/result.json')):
        row=json.loads(p.read_text())
        if row.get('iso_sha256')!=manifest['iso_sha256'] or not row.get('passed'):continue
        assert row['efi_sha256']==manifest['efi_sha256'] and row['cmdline']==manifest['contract']['cmdline'] and row['vm_profile']=='icount'
        semantic=decode((p.parent/'RESTORED-LOG.TXT').read_bytes())
        assert semantic['variant']=='PRODUCTION' and semantic['complete'] and not semantic['dmi_match'] and semantic['stage']==3
        assert semantic['modules']==0 and semantic['userspace_rc10_calls']==0 and semantic['status']=='REFUSED_OR_FAILED'
        save(p.parent/'semantic.json',semantic)
        evidence.append({'transport':row['transport'],'folder':str(p.parent.relative_to(OUT)),'result_sha256':sha(p),'semantic':semantic,'log_sha256':sha(p.parent/'RESTORED-LOG.TXT'),'screenshot_sha256':sha(p.parent/'terminal-qr.png'),'iso_unchanged':row['iso_unchanged']})
    assert {e['transport'] for e in evidence}=={'sata','usb'}
    suites={}
    for name,expected in [('fixture',9),('seed_gate',6),('native_fault',21),('candidate_failure',6)]:
        p=OUT/f'tests/latest_{name}_results.json';r=json.loads(p.read_text());assert r['all_passed'] and len(r['cases'])==expected
        suites[name]={'count':expected,'passed':True,'report':str(p.relative_to(OUT)),'sha256':sha(p)}
    longhalt=json.loads((OUT/'tests/latest_long_halt_result.json').read_text());assert longhalt['passed'] and longhalt['alive_after_marker_seconds']>=315
    report={'status':'FROZEN_LOCAL_REVIEW','scope':'Exact production ISO transport and non-target refusal under deterministic QEMU/OVMF; separate fixture and fault coverage explicitly listed','iso_sha256':manifest['iso_sha256'],'efi_sha256':sha(binary),'cmdline_ascii_sha256':prod['cmdline_ascii_sha256'],'payload_manifest_sha256':manifest['contract']['payload_manifest_sha256'],'production_linux_passed':True,'hardware_passed':False,'production_rebuild_identical':True,'same_bootstrap_source_as_fixture_tests':True,'suites':suites,'long_halt_fixture_seconds':315,'production_iso_tests':evidence,'simulation_limit':'Host-clock TCG provisional ISO runs panicked in early IO-APIC timer detection; exact final ISO passed only the recorded single-thread icount/virtual-RTC profile. No production timer workaround. Not cycle-accurate or a hardware pass.','tools':{str(p.relative_to(ROOT)):sha(p) for p in [Q/'qemu-system-x86_64.exe',SHARE/'edk2-x86_64-code.fd',SHARE/'edk2-i386-vars.fd',ROOT/'tools/zig-x86_64-windows-0.14.1/zig.exe']}}
    save(OUT/'candidate/verification.json',report)
    save(OUT/'verification_summary.json',{'scope':report['scope'],'fixture_bootstrap_sha256':sha(OUT/'tests/fixture/loader/BOOTX64.EFI'),'production_efi_sha256':sha(binary),'production_iso_sha256':manifest['iso_sha256'],'suites':suites,'production_linux_passed':True,'production_linux_transports':['sata','usb'],'hardware_passed':False,'verification_sha256':sha(OUT/'candidate/verification.json')})
    paths=set()
    for pattern in ['*.py','*.md','verification_summary.json','source/*','reference/**/*','candidate/**/*']:
        paths.update(p for p in OUT.glob(pattern) if p.is_file() and '__pycache__' not in p.parts)
    for p in (OUT/'tests').rglob('*'):
        if p.is_file() and '__pycache__' not in p.parts and p.suffix.lower() in {'.py','.c','.json','.log','.txt','.png','.efi','.h'}:paths.add(p)
    # Explicit snapshots document the superseded contract/serial-debug provenance.
    for base in ['production_provisional','production_provisional_serial_debug']:
        for p in (OUT/base).rglob('*'):
            if p.is_file() and p.suffix.lower() in {'.json','.h'}:paths.add(p)
    paths={p for p in paths if p.name!='loader_manifest.json'}
    records=[{'path':str(p.relative_to(OUT)).replace('\\','/'),'bytes':p.stat().st_size,'sha256':sha(p)} for p in sorted(paths)]
    frozen={'status':'FROZEN_LOADER_LOCAL_REVIEW','utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'scope':'Bounded source/candidate/evidence index; caches, writable OVMF vars, temporary raw test images, object/map files outside candidate, and repeated PPM captures excluded','artifact_count':len(records),'iso_sha256':manifest['iso_sha256'],'efi_sha256':sha(binary),'hardware_tested':False,'files':records}
    dest=OUT/'loader_manifest.json';save(dest,frozen)
    print(json.dumps({'manifest':str(dest),'sha256':sha(dest),'count':len(records),'iso':manifest['iso'],'iso_sha256':manifest['iso_sha256'],'efi_sha256':sha(binary),'verification':str(OUT/'candidate/verification.json')},indent=2))
if __name__=='__main__':main()
