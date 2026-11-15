"""One BMC reset with a pure validation policy and one-shot transport boundary.

V1 consumed its grant during Collector prevalidation and refused in the actual
Session guard, before the raw transport was reached. V1 evidence is retained.
"""
from pathlib import Path
import getpass, hashlib, importlib.util, json, sys

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('r4_reset_v1', HERE/'reset_bmc_for_r4_once.py')
old=importlib.util.module_from_spec(spec);spec.loader.exec_module(old)
base=old.base

class Gate:
    def __init__(self): self.armed=False
    def validate(self, netfn, command, data=(), sensor_ids=()):
        if (netfn,command)==(6,2) and not bytes(data):
            if not self.armed: raise base.PolicyError('Reset not armed')
            return
        old.Gate().validate(netfn,command,data,sensor_ids)

def session_class(gate):
    Parent=old.fan.admin_session_class()
    class Once(Parent):
        reset_transport_attempted=False
        def _send_ipmi_net_payload(self,netfn=None,command=None,data=(),code=0,
                                  bridge_request=None,retry=None,delay_xmit=None,
                                  timeout=None,rslun=0):
            is_reset=(netfn,command)==(6,2)
            if is_reset:
                gate.validate(netfn,command,data)
                if self.reset_transport_attempted or code or bridge_request is not None or rslun or retry is not False:
                    raise base.PolicyError('Reset replay or unexpected transport metadata')
                self.reset_transport_attempted=True
            try:
                return super()._send_ipmi_net_payload(netfn,command,data,code,bridge_request,retry,delay_xmit,timeout,rslun)
            finally:
                if is_reset: gate.armed=False
    return Once

def worker():
    c=None;gate=Gate()
    try:
        password=json.loads(sys.stdin.buffer.readline(4097))
        if not isinstance(password,str) or not 0<len(password)<=128:raise base.PolicyError('Credential input')
        base.verify_dependencies();base.validate_read=gate.validate
        Session=session_class(gate)
        c=Session(bmc=base.HOST,userid=base.USER,password=password,port=623,privlevel=4,keepalive=False)
        password=None
        if c.ipmiversion!=2.0 or c.privlevel!=4:raise base.PolicyError('Authenticated ADMIN LAN+ required')
        c.reads_enabled=True
        collector=base.Collector(c,base.emit)
        old.preflight(collector)
        gate.armed=True
        base.emit(dict(type='reset_authorized_after_9_reads',netfn=6,command=2,retry=False))
        collector.read('bmc_cold_reset_reply',6,2)
        return 0 if c.reset_transport_attempted and collector.last_completion==0 else 2
    except Exception as e:
        base.emit(dict(type='stopped',exception_type=type(e).__name__,
                       reason=str(e) if isinstance(e,base.ProbeStop) else 'transport_or_policy'))
        return 2
    finally:
        password=None
        if c is not None:
            base.emit(dict(type='transport_summary',reset_transport_attempted=c.reset_transport_attempted,reset_grant_remaining=gate.armed))
            if not c.reset_transport_attempted:
                try:c.logout()
                except Exception:pass

def offline():
    from unittest.mock import patch
    base.verify_dependencies()
    calls=[]
    def bottom(self,netfn=None,command=None,data=(),*args,**kw):
        calls.append((netfn,command,bytes(data)))
        return dict(netfn=netfn+1,command=command,code=0,data=[])
    def raw(self,netfn=None,command=None,data=(),retry=None):
        return self._send_ipmi_net_payload(netfn,command,data,retry=retry)
    # Exercise both actual Collector and actual Session validation sites.
    v1=old.Gate();v1.armed=True;base.validate_read=v1.validate
    OldSession=old.fan.admin_session_class();Raw=OldSession.__mro__[2]
    with patch.object(Raw,'_send_ipmi_net_payload',bottom),patch.object(Raw,'raw_command',raw):
        c=object.__new__(OldSession);c.reads_enabled=True;c.ipmiversion=2.0;c.sent_reads=0
        try:base.Collector(c,lambda e:None).read('original',6,2)
        except base.ProbeStop:pass
        else:raise AssertionError('V1 must reproduce refusal')
        assert calls==[], 'V1 must not reach transport'
        gate=Gate();base.validate_read=gate.validate;Session=session_class(gate)
        c=object.__new__(Session);c.reads_enabled=True;c.ipmiversion=2.0;c.sent_reads=0
        collector=base.Collector(c,lambda e:None)
        for _ in range(3):
            try:collector.read('unarmed',6,2)
            except base.PolicyError:pass
            else:raise AssertionError('Unarmed reset allowed')
        assert not calls
        gate.armed=True
        collector.read('one',6,2)
        assert calls==[(6,2,b'')] and c.reset_transport_attempted and not gate.armed
        gate.armed=True
        try:collector.read('repeat',6,2)
        except base.ProbeStop:pass
        else:raise AssertionError('Reset replay allowed')
        assert len(calls)==1
    report=dict(passed=True,original_actual_guarded_transport_calls=0,
                corrected_actual_guarded_transport_calls=1,no_network=True,
                second_reset_denied=True,unarmed_reset_denied=True,
                source_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    (HERE/'bmc-r4-reset-v2-guard-tests.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report))

def main():
    if sys.argv[1:]==['--worker']:return worker()
    if sys.argv[1:]==['--offline-check']:return offline()
    if sys.argv[1:]!=['--fresh-r4-test']:raise SystemExit('Explicit fixed R4 test required')
    previous=HERE/'bmc-r4-fresh-result.json'
    assert hashlib.sha256(previous.read_bytes()).hexdigest()=='3807c0adcea77474715b0c5dd666b2f8cbe3f8a6799ef9e6168efee9e66b56ae'
    checked=json.loads((HERE/'bmc-r4-reset-v2-guard-tests.json').read_text())
    assert checked['passed'] and checked['original_actual_guarded_transport_calls']==0
    assert checked['source_sha256']==hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    attempt=HERE/'bmc-r4-fresh-v2-attempt.json';result=HERE/'bmc-r4-fresh-v2-result.json'
    if attempt.exists() or result.exists():raise SystemExit('Already attempted; inspect evidence, no replay')
    base.verify_dependencies()
    print('One BMC reset for R4. V1 was confirmed locally blocked before transmission.')
    password=getpass.getpass('IPMI password (not saved): ')
    if not password:raise SystemExit('Empty credential')
    secret=(json.dumps(password)+'\n').encode();password=None
    with attempt.open('x') as f:json.dump(dict(target=base.HOST,started_utc=base.utc_now(),prior_reset_wire_calls=0),f)
    code,timeout,raw,stderr_count=base.bounded_child([sys.executable,'-I','-S','-B',str(Path(__file__).resolve()),'--worker'],secret,60)
    secret=None;events=[]
    for line in raw.decode('utf-8',errors='replace').splitlines():
        try:
            event=json.loads(line)
            if isinstance(event,dict) and 'type' in event:events.append(event)
        except ValueError:pass
    with result.open('x') as f:json.dump(dict(target=base.HOST,finished_utc=base.utc_now(),return_code=code,hard_timeout=timeout,stderr_bytes_not_saved=stderr_count,events=events),f,indent=2)
    print(json.dumps(dict(file=str(result),return_code=code,hard_timeout=timeout,events=len(events))))
    return code

if __name__=='__main__':raise SystemExit(main())
