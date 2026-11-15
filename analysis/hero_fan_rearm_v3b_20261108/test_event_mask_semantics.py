"""Exact ARM load-defaults/get-enable semantics vs a pinned live GET fixture."""
from pathlib import Path
import hashlib,importlib.util,json
P=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('corrected_transitions',P/'test_scanner_transitions.py')
t=importlib.util.module_from_spec(spec);spec.loader.exec_module(t)
rows=[]
def done(name,**kw):rows.append(dict(case=name,passed=True,**kw))
s=t.State();a=s.core;s.copy_in(a);record_addr=0x6004000;a.u.mem_write(record_addr,t.SDR)
a.call('SR_LoadSDRDefaults',[record_addr,a.globals['g_BMCInfo']+t.INFO,1,0]);s.copy_out(a)
assert bytes(a.u.mem_read(record_addr,59))==t.SDR
assert s.bytes[t.INFO+0x24:t.INFO+0x28]==bytes.fromhex('05700570')
assert s.bytes[t.INFO+0x10]==1 and s.bytes[t.INFO+0x11]==0x77 and s.bytes[t.INFO+0x38]==0x68
assert all(name=='memset' for name,_ in a.calls)
done('actual_SR_LoadSDRDefaults_preserves_SDR_little_endian_mask_bytes',stored_masks_hex=s.bytes[t.INFO+0x24:t.INFO+0x28].hex(),
 source_masks_hex=t.SDR[14:18].hex(),event_reading_type=s.bytes[t.INFO+0x10])
s.bytes[t.CONTROL]=0xa0
reply=s.sensor_event_get()
fixture=(P/'fixtures/sensor20-event-enable.bin').read_bytes()
assert reply==b'\0'+fixture and fixture==bytes.fromhex('8005000500')
done('actual_threshold_GET_matches_independent_live_fixture',wire_data_hex=reply[1:].hex())
for event_type,expected in ((1,'8005000500'),(2,'8005700570')):
 s.bytes[t.INFO+0x10]=event_type;s.bytes[t.INFO+0x24:t.INFO+0x28]=t.SDR[14:18]
 reply=s.sensor_event_get();assert reply[1:].hex()==expected
 done('actual_GET_mask_bound_for_type_'+str(event_type),input_masks_hex=t.SDR[14:18].hex(),wire_data_hex=reply[1:].hex())
s.bytes[t.INFO+0x10]=1;s.bytes[t.INFO+0x24:t.INFO+0x28]=bytes.fromhex('70057005')
reply=s.sensor_event_get();assert reply[1:]==bytes.fromhex('8070057005') and reply[1:]!=fixture
done('old_transposed_model_reproduced_and_distinguished_from_live',old_wire_data_hex=reply[1:].hex())
for masks in (bytes.fromhex('05000500'),bytes.fromhex('05700570')):
 s.bytes[t.INFO+0x24:t.INFO+0x28]=masks;assert s.sensor_event_get()[1:]==fixture
 done('masked_GET_does_not_disclose_private_upper_bits_'+masks.hex())
out=dict(passed=True,count=len(rows),cases=rows,hardware_test=False,live_fixture_sha256=hashlib.sha256(fixture).hexdigest(),
 exact_bodies=['SR_LoadSDRDefaults@0x4EE10','GetSensorEventEnable@0x523B8'],
 source='audit/sources/libipmimsghndlr.so.13.22.0',
 source_sha256=hashlib.sha256((P/'audit/sources/libipmimsghndlr.so.13.22.0').read_bytes()).hexdigest(),
 limitations=['Local default-load and GET only; no device call.',
 'Live GET proves exposed masks 0x0005, not the current internal upper bits, which are discarded.'])
(P/'event-mask-verification.json').write_text(json.dumps(out,indent=2)+'\n')
print(json.dumps(dict(passed=True,count=len(rows))))
