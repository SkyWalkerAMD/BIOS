"""Pin REA evidence and verify isolated model outputs, without physical-byte claims."""
from pathlib import Path
import json,hashlib,struct,sys
H=Path(__file__).resolve().parent;ROOT=H.parents[3]
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile
from replay_nvme import VM
from replay_socket import experiment

sha=lambda b:hashlib.sha256(b).hexdigest()
def dump(p,obj):p.write_text(json.dumps(obj,indent=2)+'\n')
def main():
 inputs=json.loads((H/'inputs.json').read_text())
 for mod in inputs['modules']:
  name=mod['module'];original=ROOT/mod['original_pe_path'];local=H/'inputs'/(name+'.efi')
  assert sha(original.read_bytes())==sha(local.read_bytes())==mod['original_pe_sha256']
  assert sha((H/'inputs'/(name+'.forms.bin')).read_bytes())==mod['forms'][0]['sha256']
 edir=H/'rea_extracts';edir.mkdir(exist_ok=True);index=[];windows=[];failures=[]
 for response in sorted((H/'rea05').glob('response-*.json')):
  n=int(response.stem.split('-')[-1]);res=json.loads(response.read_text());s=res.get('structuredContent')
  if res.get('isError'):
   failures.append({'response':response.name,'expected_seed_remedy':n==19});continue
  if not s or not s.get('subject'):continue
  cmd=json.loads((response.parent/response.name.replace('response','command')).read_text(encoding='utf-8-sig'))
  item={'response':response.name,'response_sha256':sha(response.read_bytes()),
    'operation':s['operation'],'parameters':s['parameters'],'evidence_id':s['evidence_id'],
    'subject':s['subject']['name'],'subject_sha256':s['subject']['digest']['sha256'],
    'provider':s['provider'],'import_mode':s['analysis_profile']['parameters'].get('import_mode'),
    'analysis_seeds':s['analysis_profile']['parameters'].get('analysis_seeds')}
  index.append(item);normal=s['normalized_result'];module=s['subject']['name'].replace('.efi','')
  if 'pseudocode'in normal:
   loc=s['parameters'].get('procedure',str(n))
   text='REA evidence '+s['evidence_id']+'\nOriginal PE SHA256 '+item['subject_sha256']+'\n'
   text+='Actual REA/Ghidra output; caller seeds are metadata assertions, not firmware edits.\n\n'+normal['pseudocode']
   (edir/(module+'_'+loc+'.txt')).write_text(text)
  if s['operation']=='read_bytes':
   data=bytes.fromhex(normal['bytes_hex']);rva=int(s['parameters']['address'],16)
   p=pefile.PE(data=(H/'inputs'/s['subject']['name']).read_bytes());original=p.get_data(rva,len(data))
   assert normal['complete']and original==data
   windows.append({'module':module,'rva':hex(rva),'bytes':len(data),'sha256':sha(data),
      'REA_equal_original_file':True,'evidence_id':s['evidence_id']})
 assert failures==[{'response':'response-019.json','expected_seed_remedy':True}]
 assert len(windows)==2
 assert not json.loads((H/'rea05/final-close.json').read_text()).get('isError')
 dump(H/'rea_index.json',{'operations':index,'expected_metadata_query_failure':failures,
    'failure_remedy':'Socket 754C was not a discovered function; reopened the immutable PE with exact original code start as analysis metadata seed, then analyzed it successfully.',
    'original_byte_windows':windows,'closed':True,'target_mutations':0})
 # Native replay outcomes are checked against independent expected package
 # splices. These expected splices are assertions, not replacements for x64.
 nvm=VM(30);nvm_out=nvm.run()[0]
 nvm_orig=nvm.forms;ins=b'\x02\x07'+struct.pack('<HHB',30,0x1c,0)
 expected=(len(nvm_orig)+7).to_bytes(3,'little')+nvm_orig[3:184]+ins+nvm_orig[184:]
 assert nvm_out==expected
 nvm_error=VM(30,locate_error=7);out_error=nvm_error.run()[0];assert out_error==nvm_out
 dump(H/'nvme_model_error7.json',{'status':'PASS_ORIGINAL_NATIVE_ERROR_BRANCH_SAME_FORMS',
    'original_pe_sha256':sha(nvm_error.pe_bytes),'locate_handle_buffer_error':'EFI_DEVICE_ERROR',
    'modeled_NewString_id':30,'generated_forms_sha256':sha(out_error),
    'same_forms_as_EFI_NOT_FOUND':True,'native_entries':dict(nvm_error.native_calls),
    'services':dict(nvm_error.calls),'scope':'Isolated original 2B30; any failure from 1958 can produce this message, so no-device text is not proof of absent NVMe hardware.',
    'authorization':False,'hardware_actions':0})
 cases=[('socket_model_zero',()),('socket_model_four',((0,0),(2,0),(4,0),(6,0))),
        ('socket_model_disabled_channel',((0,0),(2,0),(4,0),(6,0)),(2,)),
        ('socket_model_excluded_slot',((0,0),(2,0),(4,0),(6,0)),(),((4,0),))]
 native=[]
 for c in cases:
  result=experiment(*c);assert result['status'].startswith('PASS_');output=(H/(c[0]+'.forms.bin')).read_bytes()
  original=(H/'inputs/SocketSetup.forms.bin').read_bytes();count=result['generated_forms']['modeled_subtitles']
  inserted=b''.join(b'\x02\x07'+struct.pack('<HHB',0x7000+i,0,0)for i in range(count))
  expected=(len(original)+len(inserted)).to_bytes(3,'little')+original[3:4761]+inserted+original[4761:]
  assert output==expected
  native.append({'case':c[0],'status':result['status'],'generated_forms':result['generated_forms'],
    'original_unchanged_outside_package_length_and_label_interval':True,
    'native_code_sha256_unchanged_after_execution':True})
 review={'status':'ORIGINAL_DYNAMIC_BUILDERS_REPRODUCED_WITH_EXPLICIT_MODELS_PHYSICAL_BYTES_PENDING',
  'inputs_sha256':sha((H/'inputs.json').read_bytes()),'actual_REA_operations':len(index),'REA_closed':True,
  'original_byte_windows':windows,
  'NvmeDynamicSetup':{
    'control_flow':'119C registers event 2B30; 2B30 calls1958; error branch16FC(NewString),4CAC(7-byte SUBTITLE),5064/4DC0(HiiUpdateForm)→DB+10 UpdatePackageList.',
    'condition':'Any EFI error from1958. Model specifically invokes original LocateHandleBuffer with original GUID afa4cf3f-af71-4c30-a4fb-2910e771f9b0 and returns EFI_NOT_FOUND; EFI_DEVICE_ERROR tested separately produces same forms.',
    'target_form':1,'label_start':1000,'label_end':1001,'insert_offset_original_package':184,
    'opcode':'02 07 <NewString-ID:LE16> 1C 00 00','static_bytes':259,'HII06_physical_bytes':266,
    'physical_full_sha256':'06213876bb686f42b602d87fc5c6b10682bb3d20bc6f5bdea02e6d84791d0861',
    'modeled_id30_full_sha256':sha(nvm_out),'model_matches_physical':False,
    'inference_limit':'Neither length +7 nor no-device text proves the actual controller inventory or physical runtime string ID.'},
  'SocketSetup':{
    'control_flow':'77BC registers754C;754C→63C8→61B0;61B0→AE38/AE68(HOB),5ECC(format),B87C(NewString),CB70(SUBTITLE),CED8/CC24(HiiUpdateForm)→DB+10 UpdatePackageList.',
    'hob_guid':'f8870015-6994-4b98-95a2-bd56da91c07f','cached_hob_global_rva':'0x14d58',
    'memory_pointer':'GUID HOB payload +0x18','loop':'socket0;channels0..7;slots0..1',
    'condition':'MemoryInfo[0x405E+channel*0x104]==1 && MemoryInfo[0x4071+channel*0x104+slot*0x79]==1 && MemoryInfo[0x4072+channel*0x104+slot*0x79]!=1',
    'formset_guid':'516d5a04-c0d5-4657-b908-e4fb1d935ef0','target_form':'0x574',
    'label_start':'0x2345','label_end':'0x2346','insert_offset_original_package':4761,
    'opcode_per_selected_slot':'02 07 <NewString-ID:LE16> 00 00 00','static_bytes':135794,
    'HII06_physical_bytes':135822,'physical_full_sha256':'ad272dae6eb1713db3f3a2364bb546bc1d694e7f7f4d435d769f43320177267e',
    'inference_limit':'+28 is consistent with four native subtitles; until actual delta is captured, other changed bytes or source are not excluded.',
    'native_models':native},
  'callback_review':{
    'Nvme_2EB8':'Accepts Action0 CHANGING; dispatches original device/namespace QID ranges to269C/1EEC or updates local variable buffer. No current dynamic-insertion proof from callback identity alone.',
    'Socket_3E80':'Action/QID dispatcher includes variable/browser state paths. It is not a safe read-only probe. Native61B0 direct caller in REA is63C8; this does not grant authority for all callback transitive paths.',
    'unsafe_to_execute_as_readonly':'Module startup119C writesNvmeDynamicSetupVar. Socket init77BC uses CMOS/variables; event754C and caller63C8 have state-writing paths. Only isolated2B30(no-device modeled services)/61B0 are replayed locally.'},
  'model_boundaries':[
    'All target instructions are from pinned original PE images; normal PE relocation only, no target code patches.',
    'UEFI AllocatePool/FreePool, HiiString and HiiDatabase calls are explicit host substitutes. Unsupported service calls fail closed.',
    'HII database has original forms plus END, not full original strings or actual package list. Supplied NewString IDs do not simulate the physical allocator.',
    'Socket HOB, DIMM attributes, SPD selector and string text are synthetic. Bounded modeled object reads and original .text immutability are checked.',
    'After the isolated Socket call, four opcode allocations remain in modeled state; lifetime cleanup/full module execution was not evaluated. No leak or safe-full-lifecycle claim.',
    'Native package equality in a model is neither callback authorization nor proof of whole boot or password interception.'],
  'next_required':'Run verify_physical.py only with actual Delta07 forms reconstruction and independently captured complete SHA. It rejects bytes outside identified label intervals and then passes observed prompt IDs to original x64; actual runtime slots remain explicitly synthetic.',
  'hardware_actions':0,'firmware_mutations':0,'authorization':False}
 dump(H/'review.json',review)
 print(json.dumps({'status':review['status'],'actual_REA_operations':len(index),'native_cases':len(native)+2,'original_byte_windows':len(windows)}))
if __name__=='__main__':main()
