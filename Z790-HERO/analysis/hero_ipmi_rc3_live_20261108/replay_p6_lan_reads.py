"""Actual P6 x64 preflight against captured .71 LAN GET payloads; offline only."""
from pathlib import Path
import hashlib, importlib.util, json, sys
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[1]
P6=ROOT/'analysis/hero_ipmi_p6_20261104'
sys.dont_write_bytecode=True
spec=importlib.util.spec_from_file_location('p6_capture_replay',P6/'verify_runtime.py')
p6=importlib.util.module_from_spec(spec);spec.loader.exec_module(p6)
LIVE=HERE/'probe/live_71_lan_admin_20261108.json'

def main():
    data=json.loads(LIVE.read_text());assert data['return_code']==0
    captured={}
    for e in data['events']:
        if e['type']=='read':
            k=(e['netfn'],e['command'],bytes.fromhex(e['request_hex']))
            captured[k]=bytes([(e['netfn']+1)<<2,e['command'],e['completion_code']])+bytes.fromhex(e['response_hex'])
    rows=[]
    for channel in [1,0]:
        m=p6.Machine(p6.cfg(source=2,channel=channel))
        def response(f,c,q):
            assert (f,c,q) in captured,('uncaptured or write request',f,c,q.hex())
            return captured[(f,c,q)]
        m.dev.fault=response
        m.boot();m.no_leak();assert not m.dev.mutations
        state=m.vars['HeroIpmiState'][1]
        blocked=p6.pending(state)
        if channel==1:
            assert not blocked and state[24:26]==bytes([2,1])
            assert 'Configuration applied/unchanged.' in m.audit()
        else:
            assert blocked
            assert any(p[:2]==bytes([0x18,0x42]) and p[2:]==b'\x03' for p in m.dev.packets)
        name='explicit_channel1_dhcp_no_change' if channel else 'auto_channel_refused_on_unavailable_channel3'
        (HERE/(name+'.txt')).write_text('OFFLINE REPLAY, NOT A LOG FROM THE TARGET HOST\n'+m.audit())
        rows.append({'case':name,'passed':True,'bmc_configuration_writes':len(m.dev.mutations),
                     'persistent_failure_lock_in_simulator':blocked,'captured_reads_replayed':len(m.dev.packets)})
    report={'passed':True,'driver_sha256':hashlib.sha256((P6/'HeroIpmiP6.efi').read_bytes()).hexdigest(),
        'capture_sha256':hashlib.sha256(LIVE.read_bytes()).hexdigest(),'cases':rows,
        'field_choice':'Use channel 1 for the current .71 management port, verified against its current IP and MAC; do not use Auto for this card.',
        'scope':'Captured authenticated LAN GET response bodies replayed over simulated PCI/KCS/UEFI. No target write, native F10 test, commit support or real KCS equivalence is established.'}
    (HERE/'p6-lan-read-replay.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))

if __name__=='__main__':main()
