"""Replay .71 Get responses through the unchanged RC3 R2 x64 binary.

No socket/device access. UEFI, SMBIOS, PCI and NVRAM are synthetic. Execution
stops BEFORE the first OEM response in the initialization-boundary case.
"""
from pathlib import Path
import hashlib, importlib.util, json, re, sys

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
sys.dont_write_bytecode=True
spec=importlib.util.spec_from_file_location('r2_replay_base', ROOT/'analysis/hero_ipmi_r2/verify.py')
r2=importlib.util.module_from_spec(spec)
spec.loader.exec_module(r2)
LIVE=HERE/'probe/live_71_20261108.json'
PE=ROOT/'analysis/hero_ipmi_r2/USB/EFI/HERO/HeroIpmiR2.efi'

class OemBoundary(Exception): pass

class Device(r2.Device):
    def __init__(self, events):
        super().__init__('success',True)
        self.responses={}
        self.boundary=None
        for e in events:
            if e['type']!='read' or 'completion_code' not in e:continue
            key=bytes([e['netfn']<<2,e['command']])+bytes.fromhex(e['request_hex'])
            value=bytes([(e['netfn']+1)<<2,e['command'],e['completion_code']])+bytes.fromhex(e['response_hex'])
            if key in self.responses:assert self.responses[key]==value
            self.responses[key]=value
    def response(self,tx):
        tx=bytes(tx)
        if tx[0]==0xc0:
            self.boundary=tx.hex()
            raise OemBoundary('Offline emulation reached the first OEM boundary; no response simulated')
        assert tx in self.responses,('uncaptured request',tx.hex())
        self.packets.append(tx)
        return self.responses[tx]

def main():
    live=json.loads(LIVE.read_text())
    assert live['return_code']==0 and not live['hard_timeout']
    summary=next(e for e in live['events'] if e['type']=='summary')
    assert summary['sdr']['snapshot_consistent_observed']
    rows=[]
    for initialize in [0,1]:
        m=r2.Machine('success',True)
        m.vars={}  # Documented firmware default enabled, no prior attempt lock.
        m.dev=Device(live['events'])
        boundary=False
        try:status=m.call('engine_run',initialize)
        except OemBoundary:boundary=True;status=None
        log=m.audit()
        name='initialization_boundary' if initialize else 'read_only_baseline'
        (HERE/(name+'.txt')).write_text('OFFLINE REPLAY, NOT A LOG FROM THE TARGET HOST\n'+log)
        parsed=re.search(r'SDR_SNAPSHOT_END targets=([0-9A-F]+) readable=([0-9A-F]+) version_asserted=([0-9A-F]+)',log)
        assert parsed,log[-1800:]
        counters=dict(zip(('target_records','readable_targets','version_asserted'),(int(s,16) for s in parsed.groups())))
        if initialize:
            assert boundary and m.dev.boundary and 'HeroIpmiAttempt' in m.vars
            assert 'Fresh identity/VERSION_ERR check failed' not in log
        else:
            assert status==0 and not boundary and not m.nv_writes
            assert m.config[4]&2==0
        rows.append({'case':name,'passed':True,'status':status,'captured_read_commands_replayed':len(m.dev.packets),
                     'first_oem_boundary_reached':boundary,'oem_response_simulated':False,
                     'synthetic_nv_writes':m.nv_writes,'baseline_counters':counters})
    report={'passed':True,'r2_pe_sha256':hashlib.sha256(PE.read_bytes()).hexdigest(),
        'live_capture_sha256':hashlib.sha256(LIVE.read_bytes()).hexdigest(),
        'cases':rows,'sdr_records':summary['sdr']['captured_records'],
        'sensor_read_completions_all_zero':all(e['completion_code']==0 for e in live['events'] if e['type']=='read' and e['netfn']==4 and e['command']==0x2d),
        'interpretation':'The captured LAN read payloads pass the existing R2 SDR/identity gates when replayed through synthetic healthy KCS, correct SMBIOS/PCI, default-enabled settings and no pending attempt lock.',
        'not_established':['R2 actually dispatched on .71','Real boot SMBIOS or PCI address','Real KCS readiness at ReadyToBoot','Real EFI configuration/attempt lock','Any OEM initialization command accepted','Sensor restoration on .71'],
        'next_evidence':'Resident R2 log/status/config from the included read-only collector at an approved maintenance boot.'}
    (HERE/'r2-baseline-replay.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))

if __name__=='__main__':main()
