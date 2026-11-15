"""Offline state-machine/transport allowlist tests; sockets denied throughout."""
from pathlib import Path
import hashlib
import importlib.util
import json
import socket
import sys

P = Path(__file__).resolve().parent
socket_calls = []
def forbidden_socket(*args, **kwargs):
    socket_calls.append(1)
    raise AssertionError('network is forbidden in offline tests')
socket.socket = forbidden_socket
spec = importlib.util.spec_from_file_location('fan_trial_tested', P/'fan_map_trial.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class Fake:
    def __init__(self):
        self.gate = m.Gate()
        self.events = []
        self.requests = []
        self.sleep_calls = []
        self.tables = list(m.BASELINE)
        self.hook = None
        self.label = None
        self.sample = bytes.fromhex('16c00000')
        self.effect = {'candidate': True, 'restore': True}
        self.trial = m.Trial(self.exchange, self.emit, self.sleep_calls.append, self.gate)

    def emit(self, event):
        self.events.append(event)
        if event['type'] == 'intent':
            self.label = event['label']

    def exchange(self, netfn, command, payload):
        # Exactly as the actual inherited wire guard: it consumes a write arm
        # once, before a request is handed to the transport.
        self.gate.validate(netfn, command, payload)
        self.requests.append((self.label, netfn, command, payload))
        pair = (netfn, command)
        if pair == (6, 1):
            data = m.IDENTITY
        elif pair == (6, 0x25):
            data = bytes(8)
        elif pair == (0x0c, 2):
            data = b'\x11'+m.MAC
        elif pair == (0x0a, 0x20):
            data = bytes.fromhex('515100ffff000000000000000000')
        elif pair == (0x0a, 0x23):
            data = b'\x23\x00'+m.SDR_RECORD
        elif pair == (4, 0x2d):
            if payload == b'\xfb':
                data = bytes.fromhex('00c00080')
            elif self.label == 'sensor20_before':
                data = bytes.fromhex('00a0c000')
            else:
                data = self.sample
        elif pair == (0x30, 0x9a):
            if len(payload) == 2 and payload[1] == 0:
                data = self.tables[payload[0]]
            else:
                stage = 'candidate' if payload == m.WRITES['candidate'] else 'restore'
                if self.effect[stage]:
                    self.tables[1] = payload[2:]
                data = payload[2:]
        else:
            raise AssertionError('unexpected fake command')
        response = dict(netfn=netfn+1, command=command, code=0, data=data)
        if self.hook:
            response = self.hook(self, response) or response
        return response

    def run(self):
        r = self.trial.run()
        assert len(self.requests) <= 64
        assert all(e.get('retry') is False for e in self.events if e['type']=='intent')
        assert all(n != 0x30 or c != 0x94 for _,n,c,_ in self.requests)
        assert all((n,c) not in ((6,2),(6,3),(6,0x24),(6,0x22)) for _,n,c,_ in self.requests)
        return r


cases = []
def check(name, run):
    run()
    cases.append(dict(case=name, passed=True))

def success(unavailable=False):
    f=Fake()
    if unavailable: f.sample=bytes.fromhex('00a0c000')
    r=f.run()
    assert r['state']=='observed' and not r['requires_review']
    assert r['sent_writes']==['candidate','restore']
    assert r['map_restored'] and r['control_tables_restored'] and r['sdr_unchanged']
    assert f.tables==list(m.BASELINE) and f.sleep_calls==[1.0]*4
    assert len(r['samples'])==5
    assert all(s['usable'] is not unavailable for s in r['samples'])
    assert all(s['rpm']==(None if unavailable else 2640) for s in r['samples'])
    assert [p for _,n,c,p in f.requests if (n,c)==(0x30,0x9a) and len(p)==17]==list(m.WRITES.values())
check('candidate_five_readings_then_exact_restore',success)
check('unavailable_five_readings_no_enable_fallback',lambda:success(True))

def reject_preflight(label, value, error, code=0):
    f=Fake()
    f.hook=lambda self,r:dict(r,data=value,code=code) if self.label==label else r
    r=f.run()
    assert r['error']==error, r
    assert not f.gate.sent and not r['candidate_attempted']
    assert f.tables==list(m.BASELINE)
for label,value,error in [
    ('device_id', bytes(15),'identity_mismatch'),
    ('lan1_mac',b'\x11'+bytes(6),'MAC_mismatch'),
    ('lan1_mac',m.MAC,'MAC_mismatch'),
    ('watchdog',b'\x40'+bytes(7),'watchdog_not_stopped'),
    ('watchdog',bytes(7),'watchdog_not_stopped'),
    ('repository_before',bytes(13),'repository_length'),
    ('target_SDR_before',b'\x23\0'+m.SDR_RECORD[:-1],'target_SDR_changed_or_not_visible'),
    ('target_SDR_before',b'\x23\0'+m.SDR_RECORD[:7]+b'\x21'+m.SDR_RECORD[8:],'target_SDR_changed_or_not_visible'),
    ('version_error',bytes.fromhex('00c01080'),'R3_initialization_not_confirmed'),
    ('sensor20_before',bytes.fromhex('16c00000'),'sensor20_baseline_changed'),
    ('sensor20_before',bytes(3),'sensor20_length'),
    ('fresh_baseline_0',b'\1','baseline_tables_changed'),
    ('fresh_baseline_1',m.CANDIDATE,'baseline_tables_changed'),
    ('fresh_baseline_2',b'\1'+bytes(14),'baseline_tables_changed'),
    ('fresh_baseline_3',bytes(15),'baseline_tables_changed'),
    ('fresh_baseline_1',bytes(14),'map_length'),
]:
    check('preflight_'+label+'_'+error,lambda l=label,v=value,e=error:reject_preflight(l,v,e))
check('preflight_completion_reject',lambda:reject_preflight('device_id',b'','completion_D4',0xd4))

def candidate_failure(kind, applied=True):
    f=Fake();f.effect['candidate']=applied
    def hook(self,r):
        if self.label=='candidate_RPM_once':
            if kind=='timeout': raise TimeoutError('mock dropped reply')
            if kind=='completion': return dict(r,code=0xc0)
            if kind=='header': return dict(r,command=0)
            if kind=='echo': return dict(r,data=bytes(15))
        return r
    f.hook=hook;r=f.run()
    assert r['requires_review'] and r['map_restored'] and r['control_tables_restored']
    assert f.tables==list(m.BASELINE)
    assert r['sent_writes']==(['candidate','restore'] if applied else ['candidate'])
    assert not r['samples']
for kind in ('timeout','completion','header','echo'):
    check('candidate_'+kind+'_applied_restore',lambda k=kind:candidate_failure(k))
check('candidate_timeout_not_applied_no_extra_set',lambda:candidate_failure('timeout',False))

def drift(table, at='candidate_sample_4', final_compare=False):
    f=Fake()
    def hook(self,r):
        if self.label==at:
            if table==1: self.tables[1]=b'\x66'+m.CANDIDATE[1:]
            elif table==0: self.tables[0]=b'\1'
            elif table==2: self.tables[2]=b'\1'+bytes(14)
            elif table==3: self.tables[3]=bytes(15)
            if final_compare:return dict(r,data=self.tables[1])
        return r
    f.hook=hook;r=f.run()
    assert r['sent_writes']==['candidate'] and r['requires_review']
    assert not r['restore_attempted'] and not r['map_restored']
    assert r['restore_error']==('restore_map_drift_no_write' if table==1 else 'restore_control_drift_no_write')
for table in range(4):check('concurrent_table_'+str(table)+'_not_overwritten',lambda t=table:drift(t))
check('immediate_restore_compare_drift_no_write',lambda:drift(1,'restore_RPM_final_compare',True))

def restore_failure(applied):
    f=Fake();f.effect['restore']=applied
    def hook(self,r):
        if self.label=='restore_original_RPM_once':raise TimeoutError('mock restore reply dropped')
        return r
    f.hook=hook;r=f.run()
    assert r['sent_writes']==['candidate','restore']
    assert r['map_restored']==applied and r['control_tables_restored']==applied
    assert sum(label=='restore_original_RPM_once' for label,*_ in f.requests)==1
    assert not r['restore_error'] if applied else r['restore_error']=='restore_not_verified_no_retry'
check('restore_timeout_applied_readback_no_retry',lambda:restore_failure(True))
check('restore_timeout_not_applied_stop_no_retry',lambda:restore_failure(False))

def read_failure(label, failure):
    f=Fake()
    def hook(self,r):
        if self.label==label:
            if failure=='timeout':raise TimeoutError('mock read timeout')
            if failure=='long':return dict(r,data=bytes(263))
            if failure=='completion':return dict(r,code=0xd4)
            if failure=='badbyte':return dict(r,data=[256])
            if failure=='short':return dict(r,data=bytes(3))
        return r
    f.hook=hook;r=f.run()
    assert r['requires_review']
    if label.startswith('restore_gate'):
        assert r['sent_writes']==['candidate'] and not r['map_restored']
    else:
        assert r['sent_writes']==['candidate','restore'] and r['map_restored']
for failure in ('timeout','long','completion','badbyte','short'):
    check('sample_'+failure+'_restored',lambda k=failure:read_failure('candidate_sample_0',k))
check('restore_gate_timeout_no_blind_set',lambda:read_failure('restore_gate_1','timeout'))

def deny_commands():
    g=m.Gate();rejected=0
    for sub in range(256):
        for body in ([sub,1],[sub,0,0],[sub]):
            try:g.validate(0x30,0x9a,body)
            except (m.base.PolicyError,ValueError):rejected+=1
            else:raise AssertionError('unexpected command admitted')
    for n,c,p in ((0x30,0x94,b'\x20\0'),(0x30,0x94,b'\x20\1'),(6,2,b''),(6,0x24,bytes(6)),(0x30,0x9a,m.WRITES['candidate'])):
        try:g.validate(n,c,p)
        except m.base.PolicyError:rejected+=1
        else:raise AssertionError('unarmed/unrelated write admitted')
    assert rejected==773
    for sub in range(4):g.validate(0x30,0x9a,[sub,0])
    g.ready=True;g.arm('candidate');g.validate(0x30,0x9a,m.WRITES['candidate'])
    for stage in ('candidate',):
        try:g.arm(stage)
        except m.Stop:pass
        else:raise AssertionError('write rearmed')
    for stage in ('candidate','restore'):
        try:g.validate(0x30,0x9a,m.WRITES[stage])
        except m.base.PolicyError:pass
        else:raise AssertionError('unarmed resend admitted')
    g.arm('restore');g.validate(0x30,0x9a,m.WRITES['restore'])
    try:g.arm('restore')
    except m.Stop:pass
    else:raise AssertionError('restore rearmed')
check('wire_gate_773_denied_payloads_and_one_use_arms',deny_commands)

def request_limit():
    f=Fake();f.trial.sequence=64
    try:f.trial.req('too_many',6,1)
    except m.Stop as e:assert str(e)=='request_limit'
    else:raise AssertionError('request limit not enforced')
    assert not f.requests
check('request_limit_before_wire',request_limit)

def authentic_guard():
    deps=m.verify_wrappers()
    assert deps['wheels']==4 and deps['executable_files_checked']>0
    m.base.validate_read=m.Gate().validate
    cls=m.fan.admin_session_class()
    raw=cls.__bases__[0].__bases__[0]
    original=raw._send_ipmi_net_payload
    sent=[]
    try:
        raw._send_ipmi_net_payload=lambda self,*a,**k:sent.append((a,k))
        instance=object.__new__(cls)
        instance.reads_enabled=True;instance.ipmiversion=2.0;instance.sent_reads=0
        instance._send_ipmi_net_payload(6,0x38,[0x8e,4],retry=True)
        instance._send_ipmi_net_payload(6,0x3b,[4],retry=True)
        for sub in range(4):instance._send_ipmi_net_payload(0x30,0x9a,[sub,0],retry=False)
        assert len(sent)==6
        gate=m.Gate();gate.ready=True;m.base.validate_read=gate.validate
        gate.arm('candidate')
        instance._send_ipmi_net_payload(0x30,0x9a,m.WRITES['candidate'],retry=False)
        assert gate.sent==['candidate'] and len(sent)==7
        for kw in ({'retry':True},{'retry':False,'bridge_request':{}},{'retry':False,'rslun':1}):
            try:instance._send_ipmi_net_payload(0x30,0x9a,[1,0],**kw)
            except m.base.PolicyError:pass
            else:raise AssertionError('wire boundary not enforced')
        for payload in (m.WRITES['candidate'],m.WRITES['restore'],b'\0\1\0',b'\2\1'+bytes(15),b'\3\1'+bytes(15)):
            try:instance._send_ipmi_net_payload(0x30,0x9a,payload,retry=False)
            except m.base.PolicyError:pass
            else:raise AssertionError('unexpected write admitted by real wrapper')
        assert len(sent)==7
    finally:raw._send_ipmi_net_payload=original
check('pinned_runtime_actual_wire_guard_without_sockets',authentic_guard)
assert not socket_calls
report=dict(passed=True,cases=cases,count=len(cases),network_calls=0,hardware_test=False,
    exact_vendor_arm_test='arm-verification.json',
    source_sha256=hashlib.sha256((P/'fan_map_trial.py').read_bytes()).hexdigest(),
    test_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
(P/'trial-offline-verification.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
print(json.dumps(dict(passed=True,count=len(cases),network_calls=0)))
