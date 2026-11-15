"""Package the exact verified B2b EFI and evidence; no firmware/device writes."""
from pathlib import Path
import hashlib,json,shutil,zipfile
ROOT=Path(__file__).resolve().parent.parent
OUT=ROOT/'analysis/hero_ipmi_fan_b2b'

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()

def main():
    build=json.loads((OUT/'build.json').read_text())
    verify=json.loads((OUT/'verification.json').read_text())
    arm=json.loads((ROOT/'analysis/bmc_1_3_13_official/fan-handler-verification.json').read_text())
    assert sha(OUT/build['image'])==build['sha256']==verify['image_sha256']
    assert len(verify['scenarios'])==148 and all(v['passed'] for v in verify['scenarios'])
    assert len(arm['scenarios'])==11 and all(v['passed'] for v in arm['scenarios'])
    for name,h in build['source_hashes'].items():assert sha(OUT/'source'/name)==h
    assert (OUT/'USB/HERO-PROBE-USB.TAG').read_bytes()==b'HERO-IPMI-FAN--B2b\r\n'
    b1=ROOT/'analysis/hero_ipmi_b1_result'
    for name in ('HEROIPMI-001.TXT','B1实测结果.md','BIOS-Fan-Monitor.png','BIOS-Monitor-observations.json'):
        shutil.copyfile(b1/name,OUT/'evidence'/name)
    shutil.copyfile(b1/'findings.json',OUT/'evidence/B1-findings.json')
    result003=ROOT/'analysis/hero_ipmi_b2_result_003'
    for name in ('HEROIPMI-003.TXT','B2连接中止分析.md'):
        shutil.copyfile(result003/name,OUT/'evidence'/name)
    shutil.copyfile(result003/'findings.json',OUT/'evidence/B2-003-findings.json')
    assert sha(OUT/'evidence/HEROIPMI-003.TXT')=='47fb98a0ee3cf3a42612509cecb543745270688f398212d0f91e54053b4dc97d'
    result004=ROOT/'analysis/hero_ipmi_b2a_result_004'
    for name in ('HEROIPMI-004.TXT','B2a状态恢复分析.md','B2a-before-S.png'):
        shutil.copyfile(result004/name,OUT/'evidence'/name)
    shutil.copyfile(result004/'findings.json',OUT/'evidence/B2a-004-findings.json')
    assert sha(OUT/'evidence/HEROIPMI-004.TXT')=='d551e47b11c6bc2e7d60a9cbd503c98456973ae06764653c7af52f28b1da5340'
    assert sha(OUT/'evidence/HEROIPMI-001.TXT')=='a3c0bb55983bc243ed403599dba419663087dc664e0ee8f66a01fc6b52b0f534'
    provenance=dict(target='HERO BIOS 3107 / previously recorded BMC 1.3.13 identity',
        B1_real_hardware_evidence=sha(b1/'HEROIPMI-001.TXT'),
        B2_status='REAL_003_STOPPED_ON_FIRST_STATUS_FF_NO_FAN_COMMAND',
        B2a_status='REAL_004_FIRST_FF_THEN_31_ZERO_STATUS_SAMPLES_NO_REQUEST_SENT',
        B2b_status='OFFLINE_TESTED_ONLY_NO_REAL_B2b_RESULT',
        real_003_evidence=sha(result003/'HEROIPMI-003.TXT'),
        real_004_evidence=sha(result004/'HEROIPMI-004.TXT'),
        initial_readiness=build['initial_readiness'],
        donor='ProArt-Z790-CREATOR-WIFI-ASUS-IPMI-3002.CAP',
        donor_sha256='4545835f46e6b499a19f4ea73a21f2aa6baf61b6bbed5118bd56cf51cdeea205',
        source_candidate='Donor tach logical array[2]=1 -> lookup[1]=62; BMC sensor 20 uses g_MBFanRPM[2]',
        HERO_3107_source=json.loads((ROOT/'analysis/hero_3107_official/source.json').read_text()),
        BMC_source=json.loads((ROOT/'analysis/bmc_1_3_13_official/source.json').read_text()),
        no_CAP_or_DXE_boot_validation=True,fan_experiment=build['fan_experiment'])
    (OUT/'provenance.json').write_text(json.dumps(provenance,indent=2),encoding='utf-8')
    files={p.relative_to(OUT).as_posix():p for folder in ('USB','source','evidence') for p in (OUT/folder).rglob('*') if p.is_file()}
    for name in ('README.md','风扇适配依据.md','build.json','verification.json','provenance.json','probe.map',
                 'example-MOCK-B2-accepted_still_unavailable.txt','example-MOCK-B2-mock_rpm_available.txt',
                 'example-MOCK-B2b-one_ff_then_idle.txt','example-MOCK-B2b-persistent_ff.txt',
                 'example-MOCK-B2b-explicit_i_f_after_ready.txt'):
        files[name]=OUT/name
    for name in ('build_hero_ipmi_fan_b2b.py','verify_hero_ipmi_fan_b2b.py','package_hero_ipmi_fan_b2b.py',
                 'bmc_arm_inspect.py','verify_bmc_fan_handler.py','analyze_hero_a2_log.py','analyze_hero_b1_log.py',
                 'analyze_hero_b2_003_log.py','analyze_hero_b2a_004_log.py'):
        files['workspace_scripts/'+name]=ROOT/'analysis'/name
    files['provenance/BMC-ARM-handler-verification.json']=ROOT/'analysis/bmc_1_3_13_official/fan-handler-verification.json'
    files['provenance/HERO-3107-fan-mapping.json']=ROOT/'analysis/hero_3107_official/fan-mapping.json'
    files['provenance/R1-verification.json']=ROOT/'analysis/hero_sensor_r1/verification.json'
    files['provenance/R1-known-DEPEX-correction.md']=ROOT/'analysis/hero_sensor_r1/CORRECTION-20260928.md'
    checks=''.join(f'{sha(p)}  {name}\n' for name,p in sorted(files.items()))
    (OUT/'SHA256SUMS.txt').write_text(checks,encoding='utf-8'); files['SHA256SUMS.txt']=OUT/'SHA256SUMS.txt'
    archive=ROOT/'analysis/HERO-IPMI-FAN-B2b-READY-WAIT.zip'
    with zipfile.ZipFile(archive,'w',zipfile.ZIP_DEFLATED,compresslevel=9) as z:
        for name,p in sorted(files.items()):z.write(p,name)
    with zipfile.ZipFile(archive) as z:
        assert z.testzip() is None
        for name,p in files.items():assert hashlib.sha256(z.read(name)).hexdigest()==sha(p)
        assert not any(n.lower().endswith(('.cap','.rom','.bin','.ima')) for n in z.namelist())
        assert z.read('USB/HERO-PROBE-USB.TAG')==b'HERO-IPMI-FAN--B2b\r\n'
        assert len([n for n in z.namelist() if n.lower().endswith('.efi')])==1
    archive.with_suffix('.zip.sha256').write_text(sha(archive)+'  '+archive.name+'\n',encoding='utf-8')
    print(json.dumps(dict(archive=str(archive),bytes=archive.stat().st_size,sha256=sha(archive),entries=len(files)),indent=2))

if __name__=='__main__':main()
