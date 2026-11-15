"""Feed exact helper05 F7 bytes through pinned original ARM receiver/dispatch.

Reuse reviewed in-memory fixture; no fixture/body changes or OS driver calls.
"""
from pathlib import Path
import hashlib, importlib.util, json, struct, sys
sys.dont_write_bytecode = True
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
from test_helper05 import active, h
prior=HERE.parent/'media_reconnect_review07/replay_disconnect.py'
spec=importlib.util.spec_from_file_location('reviewed_disconnect',prior)
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
old_frame=m.frame
candidate=h.disconnect_frame(active())
assert candidate==(HERE/'f7-public-frame.bin').read_bytes()
cases=[]
for name,packet,unbind,accept in [
    ('helper05_exact_f7_keep_udc',candidate,False,True),
    ('helper05_exact_f7_unbind',candidate,True,True),
    ('truncated_f7_not_accepted',candidate[:-1],False,False),
    ('oversized_f7_not_accepted',candidate[:12]+struct.pack('<I',0x2001f)+candidate[16:],False,False),
]:
    m.frame=lambda op:packet if op==0xf7 else old_frame(op)
    c=m.run(name,'f7',unbind)
    calls=[x['call'] for x in c['calls']]
    if accept:
        assert calls.count('hdisk_stop_boundary')==calls.count('nbd_disconnect')==1
        assert calls.index('hdisk_stop_boundary')<calls.index('nbd_disconnect')<calls.index('shutdown')
        assert c['final']['gadget_slot']==c['final']['nbd_slot']==0xffffffff
    else:
        assert 'hdisk_stop_boundary' not in calls and 'nbd_disconnect' not in calls
    assert c['final']['session_active']==0 and c['final']['socket']==0xffffffff
    assert c['network_or_device_operations_executed']==0
    c.update(status='PASS',expected_explicit_f7_cleanup=accept,packet_bytes=len(packet),packet_sha256=hashlib.sha256(packet).hexdigest())
    cases.append(c)
report={'status':'PASS','cases':len(cases),'results':cases,
        'scope':'Actual original ARM receiver and main dispatch/common cleanup. Synthetic socket/session state; gadget, NBD, thread and system operations are trapped. Not a running BMC proof.',
        'helper_sha256':hashlib.sha256(Path(h.__file__).read_bytes()).hexdigest(),
        'original_elf_sha256':hashlib.sha256(m.m.IMAGE.read_bytes()).hexdigest(),
        'reused_fixture_sha256':hashlib.sha256(prior.read_bytes()).hexdigest(),
        'test_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
(HERE/'arm_f7_tests.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({'status':'PASS','cases':len(cases),'helper_sha256':report['helper_sha256']}))
