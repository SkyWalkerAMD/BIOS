"""Rebuild the local live-test evidence index from retained bytes; no network IO."""
from pathlib import Path
import hashlib,importlib.util,json,re,sys

OUT=Path(__file__).resolve().parent
ROOT=OUT.parents[1]
sys.dont_write_bytecode=True
spec=importlib.util.spec_from_file_location('r2decoder',ROOT/'analysis/hero_ipmi_r2/decode_captures.py')
decoder=importlib.util.module_from_spec(spec);spec.loader.exec_module(decoder)
def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def response(name):
    r=json.loads((OUT/'responses'/name).read_text(encoding='utf-8'))
    assert r['ok'],name
    return r['result']
def log(name):return (OUT/name).read_text(encoding='ascii')

captures={}
for name in ['R2-before-full','R2-success-full','R2-final-summary','R2-reload-summary']:
    folder=OUT/'captures'/name
    frames=[]
    for path in sorted(folder.glob('*.qr.bin')):
        raw=path.read_bytes()
        assert decoder.read_image(path.with_name(path.name.replace('.qr.bin','.png')))==raw
        frames.append(raw)
    data,meta=decoder.assemble(frames)
    assert data==(OUT/(name+'.TXT')).read_bytes()
    captures[name]=meta

full=log('R2-success-full.TXT')
final=log('R2-final-summary.TXT')
reload=log('R2-reload-summary.TXT')
expected_oem=[('90','80'),('94','01 01 03 01 17 01 19 01 1A 01 1B 01 1C 01 1D 01 1E 01 1F 01 20 01 21 01 22 01 23 01 24 01 29 01'),('92','00 00'),('02','01')]
actual_oem=re.findall(r'^OEM_TX 30/([0-9A-F]{2}) (.*)$',full,re.M)
assert actual_oem==expected_oem
assert re.findall(r'^OEM_RX (.*)$',full,re.M)==['OK C4 '+command+' 00' for command,_ in expected_oem]
assert full.count('R2_INITIALIZE_BEGIN')==1
assert 'targets=10 readable=08 version_asserted=00' in full
assert 'locked=00 attempted=01 pci_restored=01 kcs_error=00000000' in final
assert 'CONFIG status=0000000000000000 source=01 enabled=01' in final
assert re.findall(r'^CONFIG_SAVE (.*)$',final,re.M)==['enabled=00 status=0000000000000000','enabled=01 status=0000000000000000']
assert 'CONFIG status=0000000000000000 source=01 enabled=01' in reload
assert 'Already initialized: 16 target SDRs present and VERSION_ERR clear. No OEM replay.' in reload
assert 'OEM_TX' not in reload and 'oem_ack=00' in reload and 'locked=00 attempted=00 pci_restored=01' in reload

# Decode names from actual full/compact SDR records, rather than assigning donor names.
names={}
for line in full.splitlines():
    if not line.startswith('RX OK 2C 23 00 '):continue
    packet=bytes.fromhex(line[6:]);record=packet[5:]
    if len(record)<5 or record[3] not in (1,2):continue
    body=record[5:];offset=42 if record[3]==1 else 26
    assert len(body)==record[4] and len(body)>offset
    n=body[offset]&31
    assert len(body)>=offset+1+n
    if body[offset]&0xC0==0xC0:names[body[2]]=body[offset+1:offset+1+n].decode('ascii')

last=final[final.rfind('R2_READ_ONLY_BEGIN'):]
sensors=[]
for number,kind,event,raw,flags in re.findall(r'^SENSOR id=(\w+) type=(\w+) event=(\w+) raw=(\w+) flags=(\w+)$',last,re.M):
    sensor_id=int(number,16)
    sensors.append(dict(id=number,name=names[sensor_id],type=kind,event=event,raw=raw,flags=flags,
                        available_by_r2_check=(int(flags,16)&0x60)==0x40))
assert len(sensors)==17 and len([s for s in sensors if s['id']!='FB' and s['available_by_r2_check']])==8

samples=[]
for name in ['247a-sensor-sample.json','252b-sensor-sample.json','266a-after-unload-sensors.json','282a-final-sensors.json']:
    sample=response(name)
    assert sample['route']=='#sensors' and len(sample['rows'])==8
    samples.append(dict(source='responses/'+name,**sample))
thermal=response('138d-redfish-thermal-later.json')
power=response('137-power-after.json')
assert thermal['status']==power['status']==200
rf={
    'temperatures':[dict(name=s.get('Name'),reading=s.get('ReadingCelsius'),state=s.get('Status',{}).get('State')) for s in thermal['body'].get('Temperatures',[])],
    'voltages':[dict(name=s.get('Name'),reading=s.get('ReadingVolts'),state=s.get('Status',{}).get('State')) for s in power['body'].get('Voltages',[])],
    'interpretation':'These Redfish snapshots did not expose the newly enabled motherboard readings seen in the native BMC UI; cause unverified.'
}
artifacts={
    'HERO-IPMI-R2-CORE-TEST.iso':'6d3cfda2760fcee64e07c4cd0e2bbe4d3fcf3958b25a9ed121f00dd357489f3f',
    'USB/EFI/HERO/HeroIpmiR2.efi':'1e206aa41b6133c642d724fa1c6aae2f2cd28eb6010a55a66b22a89c3b354845',
    'USB/EFI/BOOT/BOOTX64.EFI':'162d786bd7d84aa0f0b01afe03f60c409f390e10dec4737856759dd1a71c600d',
    'HERO-3107-IPMI-R2-UNSIGNED-REVIEW.CAP':'148313f52afdf6dd2e6ea031364e745bcf0b0640cfff08dd809ba72969753be9'
}
for name,expected in artifacts.items():assert digest(ROOT/'analysis/hero_ipmi_r2'/name)==expected
media=response('283-eject-test-iso.json')
assert 'Start Media' in media['text'] and 'Browse File' in media['text']
assert response('285-stop-private-browser.json')['stopping'] is True
checks={
    'date':'2026-11-02','target':'ROG MAXIMUS Z790 HERO','bios':'3107','bmc':'1.3.13',
    'scope':'UEFI ISO manual core testing through authorized BMC KVM; no capsule flash',
    'captures':captures,'artifact_sha256':artifacts,
    'oem_sequence':[dict(netfn='30',command=c,data=d,completion_code='00') for c,d in actual_oem],
    'postcheck':dict(targets=16,readable=8,version_err_asserted=False,pci_restored=True,attempt_lock=False),
    'config':dict(before='default enabled, absent variable',save_disabled_passed=True,save_enabled_passed=True,reloaded_source=1,final_enabled=True,cross_host_reset_tested=False),
    'reload':dict(manual_only=True,already_initialized=True,oem_sent=0,attempted=False,pci_restored=True),
    'sensors':sensors,'native_web_samples':samples,'redfish_observation':rf,
    'cleanup':dict(driver_unload_status='0',session_result='0',host_left_in='BIOS Main',virtual_iso_ejected=True,private_browser_process_exit=0,
                   logout_confirmation_accepted=False,note='Native sign-out confirmation was auto-dismissed by the helper. The private browser and KVM were then closed; immediate server-side logout is not asserted.'),
    'limits':['No modified BIOS flashed; automatic firmware dispatch and ReadyToBoot timing are not tested on hardware.',
              'Cold/warm host boot and OS-stage persistence after initialization are not tested.',
              'Eight motherboard fan/pump records remain unavailable (flags A0); no fan mapping writes were made.',
              'Native ASUS BIOS IPMI settings page is not integrated.',
              'First read had unavailable VERSION_ERR (E0); later standard read passed (C0) without BMC reset. No automatic readiness retry added.',
              'Native BMC web readings and Redfish snapshots differ; no BMC service reset or API cache change performed.']
}
(OUT/'live-verification.json').write_text(json.dumps(checks,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps(dict(verified_capture_pages=sum(x['pages'] for x in captures.values()),sensors_readable=8,reload_oem_sent=0,artifacts_unchanged=True),ensure_ascii=False))
