"""Package the exact verified B1 EFI, evidence and workspace source."""
from pathlib import Path
import hashlib,json,zipfile
ROOT=Path(__file__).resolve().parent.parent
OUT=ROOT/'analysis/hero_ipmi_init_b1'

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()

def main():
    build=json.loads((OUT/'build.json').read_text())
    verify=json.loads((OUT/'verification.json').read_text())
    exe=OUT/build['image']
    assert sha(exe)==build['sha256']==verify['image_sha256']
    assert len(verify['scenarios'])==72 and all(v['passed'] for v in verify['scenarios'])
    for name,h in build['source_hashes'].items():assert sha(OUT/'source'/name)==h
    assert sha(OUT/'evidence/HEROIPMI-000(1).TXT')==build['real_baseline_sha256']
    manifest=json.loads((ROOT/'analysis/hero_sensor_r1/manifest.json').read_text())
    provenance=dict(note='Candidate parameters and publisher path derived from R1. R1 has an unresolved DEPEX bug; B1 does not load it.',
        donor_cap_sha256=manifest['originals']['ProArt-Z790-CREATOR-WIFI-ASUS-IPMI-3002.CAP'],
        module_hashes=[{k:m[k] for k in ('guid','original_pe_sha256','patched_pe_sha256')} for m in manifest['modules']],
        publisher_guid='68A0D4CA-9022-474C-BA22-483480DC9A0A',publisher_RVA='0xBD8',
        parameter_guid='05602C82-5F85-4735-AF53-053502178D02',
        candidate_parameters={'0x30':1,'0x31':128,'0x52':0,'server_setup_default_bytes':'00 00'},
        packets=build['oem_sequence'],
        r1_verification_sha256=sha(ROOT/'analysis/hero_sensor_r1/verification.json'),
        r1_manifest_sha256=sha(ROOT/'analysis/hero_sensor_r1/manifest.json'),
        no_hardware_validation_of_B1=True)
    for m in provenance['module_hashes']:
        assert sha(ROOT/'analysis/hero_sensor_r1/modules'/m['guid']/'patched.efi')==m['patched_pe_sha256']
    (OUT/'provenance.json').write_text(json.dumps(provenance,indent=2),encoding='utf-8')
    files={p.relative_to(OUT).as_posix():p for folder in ('USB','source','evidence') for p in (OUT/folder).rglob('*') if p.is_file()}
    for name in ('README.md','build.json','verification.json','provenance.json','probe.map',
                 'example-MOCK-accepted_unchanged.txt','example-MOCK-mock_sensor_appears.txt'):
        files[name]=OUT/name
    for name in ('build_hero_ipmi_init_b1.py','verify_hero_ipmi_init_b1.py','package_hero_ipmi_init_b1.py','analyze_hero_a2_log.py','fetch_uefi_probe_tools.py'):
        files['workspace_scripts/'+name]=ROOT/'analysis'/name
    files['provenance/R1-verification.json']=ROOT/'analysis/hero_sensor_r1/verification.json'
    files['provenance/R1-manifest.json']=ROOT/'analysis/hero_sensor_r1/manifest.json'
    files['provenance/R1-known-DEPEX-correction.md']=ROOT/'analysis/hero_sensor_r1/CORRECTION-20260928.md'
    checks=''.join(f'{sha(p)}  {name}\n' for name,p in sorted(files.items()))
    (OUT/'SHA256SUMS.txt').write_text(checks,encoding='utf-8')
    files['SHA256SUMS.txt']=OUT/'SHA256SUMS.txt'
    archive=ROOT/'analysis/HERO-IPMI-INIT-B1-EXPERIMENTAL.zip'
    with zipfile.ZipFile(archive,'w',zipfile.ZIP_DEFLATED,compresslevel=9) as z:
        for name,p in sorted(files.items()):z.write(p,name)
    with zipfile.ZipFile(archive) as z:
        assert z.testzip() is None
        for name,p in files.items():assert hashlib.sha256(z.read(name)).hexdigest()==sha(p)
        assert not any(n.lower().endswith(('.cap','.rom','.bin')) for n in z.namelist())
        assert z.read('USB/HERO-PROBE-USB.TAG')==b'HERO-IPMI-INIT--B1\r\n'
    (archive.with_suffix('.zip.sha256')).write_text(sha(archive)+'  '+archive.name+'\n',encoding='utf-8')
    print(json.dumps(dict(archive=str(archive),bytes=archive.stat().st_size,sha256=sha(archive),entries=len(files)),indent=2))

if __name__=='__main__':main()
