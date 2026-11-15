"""One real wrong-password/native-history/Main/ordinary-input composition."""
from pathlib import Path
import hashlib,json,time
import verify_bridges as b
from verify_bridges import H,O,VM,TSE,DATA,I,SHA,ns
sources={str(p.relative_to(H)):hashlib.sha256(p.read_bytes()).hexdigest()for p in [Path(__file__),H/'verify_bridges.py',H/'verify_navigation.py',H/'bridges.c',H/'navigation.c',H/'first_bridge.S',H/'visit/observer_visit05.c']}
start=time.time();v=VM();v.ready();v.extra_fixture(0x11);v.w(v.app+0x28,I(2));v.queue('bad-Test\r!')
v.loop([(TSE+0x1b928,[1,2]),v.partial_first(),('n05_native_app_input',[v.app,v.ev])])
assert v.main_ok()and v.sequence_values[-1]==ns['ERR'](3)and 0x1946b in v.observe_native and not v.terminal and not v.set_count
assert 'password was not accepted'in v.transcript.lower()and v.hist()not in v.free_trace,{'transcript':v.transcript,'history':v.hist(),'free':v.free_trace}
out={'status':'PASS','checks':1,'component_sha256':SHA,'sources':sources,'seconds':round(time.time()-start,3),'path':'actual history1B928 -> actual first inline guard -> real masked UI wrong public password and acknowledgment -> owned Main fallback -> original initial continuation -> ordinary F7 native unsupported fallthrough','models':['UEFI services/CPU mappings/outer App-Page containers','SHA/PBKDF/RDSEED independent oracles','status-report helper only'],'hardware':False}
(O/'error_return_tests.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(out,indent=2))
