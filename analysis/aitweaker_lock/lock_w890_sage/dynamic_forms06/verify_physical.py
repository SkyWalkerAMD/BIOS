"""Verify captured full forms and replay their observed IDs through original x64.

This program never synthesizes capture bytes. The caller must supply an actual
captured/reconstructed forms file and its independently captured complete SHA256.
Transport reconstruction and capture provenance remain the collector's job.
Only files in dynamic_forms06 are written; physical inputs are read-only.
"""
from replay_nvme import VM,H,hashlib,json,Path,struct
from replay_socket import SocketVM
import argparse

def verify(module,captured,expected_sha):
 raw=Path(captured).read_bytes();actual=hashlib.sha256(raw).hexdigest()
 assert len(expected_sha)==64 and actual==expected_sha.lower(),'captured bytes do not match independently captured full SHA256'
 original=(H/'inputs'/(module+'.forms.bin')).read_bytes()
 insert_at,help_id=(184,0x1c)if module=='NvmeDynamicSetup'else(4761,0)
 delta=len(raw)-len(original)
 assert delta>0 and delta%7==0,'not the original subtitle insertion pattern'
 if module=='NvmeDynamicSetup':assert delta==7
 assert raw[3]==2 and int.from_bytes(raw[:3],'little')==len(raw)
 assert raw[4:insert_at]==original[4:insert_at] and raw[insert_at+delta:]==original[insert_at:],'other form bytes changed outside the identified native label interval'
 inserted=raw[insert_at:insert_at+delta];ids=[]
 for at in range(0,delta,7):
  op=inserted[at:at+7]
  assert op[:2]==b'\x02\x07' and op[4:]==struct.pack('<HB',help_id,0),'not unscoped native subtitle'
  ids.append(int.from_bytes(op[2:4],'little'))
 if module=='NvmeDynamicSetup':
  vm=VM(ids[0]);target='0x2b30';synthetic_slots=None
 else:
  assert len(ids)<=16
  # Full source has an 8x2 loop. Slot positions are synthetic witnesses, not
  # recovered DIMM identity; text doesn't reside in the forms byte stream.
  synthetic_slots=[(i//2,i%2)for i in range(len(ids))]
  vm=SocketVM(slots=synthetic_slots,string_ids=ids);target='0x61b0'
 outputs=vm.run();assert len(outputs)==1 and outputs[0]==raw,'original native output does not match complete captured forms'
 r={'status':'PASS_FULL_CAPTURED_FORMS_REPLAY_UNDER_EXPLICIT_MODEL','module':module,
    'captured_input_path':str(Path(captured).resolve()),'captured_bytes':len(raw),'captured_sha256':actual,
    'expected_sha256':expected_sha.lower(),'source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    'original_forms_sha256':hashlib.sha256(original).hexdigest(),
    'native_target_rva':target,'original_pe_sha256':hashlib.sha256(vm.pe_bytes).hexdigest(),
    'original_code_patches':0,'insert_package_offset':insert_at,'insertion_bytes':delta,
    'observed_inserted_bytes_hex':inserted.hex(),'observed_prompt_ids':ids,
    'generated_full_sha256':hashlib.sha256(outputs[0]).hexdigest(),'full_byte_equality':True,
    'services':dict(vm.calls),'native_entries':dict(getattr(vm,'native_calls',{})),
    'model_inputs':getattr(vm,'model_inputs',{'LocateHandleBuffer_for_original_AMI_protocol':'EFI_NOT_FOUND',
       'language':'en-US','HII_database':'original forms plus END','NewString_ID':ids[0]}),
    'modeled_slot_positions_not_physical':synthetic_slots,
    'limitations':['Observed form prompt IDs are supplied as NewString return values; no actual string-database allocator is replayed.',
       'Socket memory topology and text remain synthetic. Forms equality does not recover DIMM attributes or string contents.',
       'This reproduces the isolated native update, not complete firmware initialization, real callback behavior, or full boot.',
       'Capture transport/provenance and full package-list identification require separate collector review.'],
    'physical_hardware_actions':0,'authorization':False}
 out=H/(module+'.physical_replay.json');out.write_text(json.dumps(r,indent=2)+'\n');return r

if __name__=='__main__':
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('module',choices=['NvmeDynamicSetup','SocketSetup']);ap.add_argument('captured_file');ap.add_argument('captured_full_sha256');a=ap.parse_args()
 r=verify(a.module,a.captured_file,a.captured_full_sha256)
 print(json.dumps({k:r[k]for k in ('status','module','captured_sha256','observed_prompt_ids','full_byte_equality')}))
