"""Independently re-decode physical QR images and replay frozen original builders.
Only this new review directory is written. No BMC/device connection is made.
"""
from pathlib import Path
import base64,hashlib,json,re,struct,sys,uuid,zlib
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;BASE=HERE.parent;ROOT=HERE.parents[3]
for d in ('pydeps','kvm-pydeps','vm-pydeps'):sys.path.insert(0,str(ROOT/'tools'/d))
from PIL import Image
import zxingcpp
def sha(b):return hashlib.sha256(b).hexdigest()
def bind(p):
    b=p.read_bytes();return {'path':p.relative_to(ROOT).as_posix(),'bytes':len(b),'sha256':sha(b)}
def verify_entries(entries,root):
    for e in entries:
        p=root/e['path'];b=p.read_bytes()
        assert sha(b)==e['sha256'],str(p)
        assert len(b)==e.get('bytes',e.get('size',len(b))),str(p)
    return len(entries)
hardware=BASE/'hardware_delta07/component_manifest.json'
assert bind(hardware)['sha256']=='b46cc932ae102b3af307ed71d959e5340d2f0e147e7ce4ac6b22f0cd7526f767'
hm=json.loads(hardware.read_text());counts={}
counts['physical_manifest_files']=verify_entries(hm['files'],ROOT)
counts['physical_manifest_external']=verify_entries(hm['external_bindings'],ROOT)
for name in ['diagnostic_delta07','spf_sampler06']:
    m=json.loads((BASE/name/'component_manifest.json').read_text())
    counts[name+'_files']=verify_entries(m['files'],ROOT)
    for k in ['external_bindings','dependencies','external_read_only_inputs']:
        if k in m:counts[name+'_'+k]=verify_entries(m[k],ROOT)
dyn=BASE/'dynamic_forms06';dm=json.loads((dyn/'manifest.json').read_text())
assert sha((dyn/'manifest.json').read_bytes())=='aadeb51126d829a8d49e8a29b34d7e0c69027979dc7000bfc51270c4a4f92561'
counts['dynamic_frozen_files']=verify_entries(dm['files'],dyn)
counts['dynamic_external']=verify_entries(dm['external_read_only_inputs'],ROOT)
appendix=dyn/'physical_appendix07/manifest.json';am=json.loads(appendix.read_text())
counts['physical_appendix_bindings']=verify_entries(am['bindings'],ROOT)
CAP=BASE/'hardware_delta07/capture_6e7a57f9729b082c'
rec=json.loads((CAP/'reconciled.json').read_text())
logpath=ROOT/rec['log']['path'];folder=logpath.parent
expected_log=logpath.read_bytes()
assert sha(expected_log)=='6e7a57f9729b082ce15931a063d94a32a56f51d78c9dc8097a80984e9487aa00'

# Independently read every original screenshot and validate complete page coverage,
# offsets, individual page CRCs, total length and the complete log CRC.
pat=re.compile(rb'AITWK-P3-KVM\nT=(\d+);C=([0-9A-F]{8});P=(\d+)/(\d+);O=(\d+);N=(\d+);D=([0-9A-F]{8})\n\n')
parts={};images=[]
for path in sorted(folder.glob('qr-*.png')):
    with Image.open(path) as img:
        found=zxingcpp.read_barcodes(img.convert('RGB'),formats=zxingcpp.BarcodeFormat.QRCode)
    valid=[bytes(x.bytes) for x in found if bytes(x.bytes).startswith(b'AITWK-P3-KVM\n')]
    assert len(valid)==1,path
    raw=valid[0];m=pat.match(raw);assert m
    total,page,pages,offset,n=map(int,(m[1],m[3],m[4],m[5],m[6]))
    assert total==12989 and pages==17 and int(m[2],16)==0xabfb51bc
    assert 1<=page<=17 and page not in parts and offset==768*(page-1)
    data=raw[m.end():]
    assert n==len(data)==min(768,total-offset) and zlib.crc32(data)==int(m[7],16)
    parts[page]=data;images.append({'source':bind(path),'page':page,'payload_bytes':n,'payload_crc32':m[7].decode()})
assert sorted(parts)==list(range(1,18))
log=b''.join(parts[i] for i in range(1,18));assert log==expected_log and zlib.crc32(log)==0xabfb51bc
assert log.startswith(b'AITWEAKER-PROBE-P3-KVM\r\nW890_DELTA07_DIAGNOSTIC_ONLY\r\n')
assert log.endswith(b'D7 EXPORTED=5 PLANNED=5 STATUS=COMPLETE\r\nCOLLECTION_STATUS=PARTIAL\r\nPROBE_COMPLETE\r\n')

selection=json.loads((BASE/'diagnostic_delta07/selection_hardware02.json').read_text());payload=selection['payload']
assert sha(json.dumps(payload,ensure_ascii=True,sort_keys=True,separators=(',',':')).encode())==selection['selection_sha256']
assert selection['selection_sha256']=='fb9dae754fbacaff55d2278cc6bc552133d6c141467b6aa2d87d707ce75bd48d'
targets={}
for t in payload['targets']:
    for k in range(t['expected_instances']):targets[t['artifact_base']+k]=t
assert sorted(targets)==[1,2,3,4,5]
baseline_names={1:'GetCpuInfo',2:'NvmeDynamicSetup',5:'SocketSetup'}
blobs={n:(BASE/'foreign_hii05/blobs'/f'{name}_0.forms.bin').read_bytes() for n,name in baseline_names.items()}
for n,b in blobs.items():assert sha(b)==targets[n]['baseline_sha256']
objects=[];seen=set();sources=[]
objpat=re.compile(rb'D7 OBJ=([0-9A-F]{8}) N=(\d+) SHA=([0-9a-f]{64}) PRESENT\r\n((?:D7\+ [A-Za-z0-9+/=]+\r\n)+)')
def parse_ifr(raw):
    assert int.from_bytes(raw[:4],'little')==len(raw)|(2<<24)
    at=4;stack=[];forms=[];fs=[];records=[]
    while at<len(raw):
        op=raw[at];n=raw[at+1]&127;scope=raw[at+1]>>7
        assert n>=2 and at+n<=len(raw)
        if op==0x0e:
            assert not stack and scope and n>=23;fs.append(str(uuid.UUID(bytes_le=raw[at+2:at+18])))
        if op==1:
            assert scope and n==6 and stack;forms.append(int.from_bytes(raw[at+2:at+4],'little'))
        if op==0x29:
            assert n==2 and not scope and stack;stack.pop()
        elif scope:stack.append(op)
        records.append((at,op,n));at+=n
    assert at==len(raw) and not stack and len(fs)==1
    return fs,forms,records
for m in objpat.finditer(log):
    n=int(m[1],16);assert n in targets and n not in seen;seen.add(n);t=targets[n]
    encoded=b''.join(x[4:] for x in m[4].split(b'\r\n')if x)
    packet=base64.b64decode(encoded,validate=True)
    assert len(packet)==int(m[2]) and sha(packet).encode()==m[3]
    assert packet[:8]==b'AITD07\0\0' and struct.unpack_from('<H',packet,8)[0]==1
    kind=struct.unpack_from('<H',packet,10)[0];assert kind==t['kind']
    assert struct.unpack_from('<I',packet,12)[0]==224 and packet[216:220]==bytes(4)
    assert zlib.crc32(packet[:220])==struct.unpack_from('<I',packet,220)[0]
    artifact,index,hii=struct.unpack_from('<IIQ',packet,16)
    assert artifact==n and index==t['package_index'] and hii
    assert packet[48:80].hex()==payload['source_log_sha256'] and packet[80:112].hex()==selection['selection_sha256']
    guid=str(uuid.UUID(bytes_le=packet[32:48]));assert guid==t['package_list_guid']
    bn,size,pre,suf,body_n,crc,total,flags,instances,instance_index=struct.unpack_from('<10I',packet,176)
    body=packet[224:];assert total==len(packet) and len(body)==body_n and zlib.crc32(body)==crc
    assert instances==t['expected_instances'] and artifact==t['artifact_base']+instance_index
    if kind==2:
        assert not bn and not pre and not suf and packet[112:144]==bytes(32) and flags==5
        forms=body
    else:
        assert flags==(3 if kind==1 else 1)
        original=blobs[n];assert bn==len(original) and packet[112:144].hex()==sha(original)
        assert pre<=bn-4 and suf<=bn-4-pre and 4+pre+body_n+suf==size
        forms=struct.pack('<I',size|(2<<24))+original[4:4+pre]+body+(original[-suf:]if suf else b'')
    assert len(forms)==size==t['result_bytes'] and sha(forms)==packet[144:176].hex()==t['result_sha256']
    assert forms==(CAP/f'object_{n:02}.forms.bin').read_bytes()
    formsets,formids,records=parse_ifr(forms)
    assert len(formids)==rec['objects'][n-1]['forms']
    for key in ['current_hii','package_list_guid','sha256']:
        expected={'current_hii':f'{hii:016X}','package_list_guid':guid,'sha256':sha(forms)}[key]
        assert rec['objects'][n-1][key]==expected
    objects.append({'artifact':n,'hii':f'{hii:016X}','guid':guid,'bytes':len(forms),'sha256':sha(forms),'forms':len(formids),'formsets':formsets,'form_ids':formids,'kind':kind,'packet_crc_sha_ok':True,'native_authority':False})
assert seen==set(targets) and len({x['hii'] for x in objects})==5
assert objects[2]['sha256']==objects[3]['sha256'] and objects[2]['hii']!=objects[3]['hii']

sm=re.search(rb'D7 SPF A=([0-9A-F]{140}) B=([0-9A-F]{140}) CRC=([0-9A-F]{8}) SHA=([0-9a-f]{64}) E=COMPLETE_OBSERVATION\r\n',log);assert sm
pair=bytes.fromhex((sm[1]+sm[2]).decode());assert len(pair)==140 and pair[:70]==pair[70:]
assert zlib.crc32(pair)==int(sm[3],16) and sha(pair).encode()==sm[4]
f=struct.unpack('<5Q3IQ3HI',pair[:70]);source,pages,guids,current,current_pages,size,count,first,page0,parent,guidindex,formid,status=f
assert status==0x3ffff and size==0xf245c and count==379 and first==0x650
assert pages==source+0x60 and guids==source+0xf2394
assert page0==0 and parent==0 and guidindex==0x210 and formid==0
slot=pages-source+4+4*count;candidate=guids-source+20*guidindex+18
assert slot==first and candidate==0xf4ce6 and candidate+2>size
assert b'D7 ENV ISSUES=0 MAP=READY TSE_COUNT=1\r\n' in log
for key,val in zip(('source','source_pages','source_guids','current_blob','current_pages','declared_size','source_page_count','first_page_offset','source_page0_hii','header_parent_field','header_guid_index','header_form_id'),f[:-1]):
    assert rec['spf']['a']['fields'][key]==rec['spf']['b']['fields'][key]==val

# Reuse the frozen, reviewed UEFI substitute model, but invoke only VM.run() and
# compare the full generated bytes here; do not call author scripts that write
# into frozen directories. The original x64 builders are actually executed.
sys.path.insert(0,str(dyn));from replay_nvme import VM
from replay_socket import SocketVM
native=[]
for name,num,offset,helpid in [('NvmeDynamicSetup',2,184,0x1c),('SocketSetup',5,4761,0)]:
    captured=(CAP/f'object_{num:02}.forms.bin').read_bytes();original=blobs[num];delta=len(captured)-len(original)
    assert delta>0 and delta%7==0 and captured[4:offset]==original[4:offset] and captured[offset+delta:]==original[offset:]
    inserted=captured[offset:offset+delta];ids=[]
    for at in range(0,len(inserted),7):
        op=inserted[at:at+7];assert op[:2]==b'\x02\x07' and op[4:]==struct.pack('<HB',helpid,0);ids.append(int.from_bytes(op[2:4],'little'))
    vm=VM(ids[0]) if num==2 else SocketVM(slots=[(i//2,i%2)for i in range(len(ids))],string_ids=ids)
    output=vm.run();assert len(output)==1 and output[0]==captured
    frozen=json.loads((dyn/(name+'.physical_replay.json')).read_text())
    assert sha(output[0])==frozen['generated_full_sha256'] and ids==frozen['observed_prompt_ids']
    native.append({'module':name,'observed_prompt_ids':ids,'target_rva':frozen['native_target_rva'],'full_output_equals_physical_forms':True,'output_sha256':sha(output[0]),'unmodified_original_PE':sha(vm.pe_bytes),'native_entries':dict(vm.native_calls),'modeled_services':dict(vm.calls),'model_not_hardware_replay':True})

state=json.loads((BASE/'remote_172_20_2_245/collection-state07-1794118563252.json').read_text())
system=next(x['data']for x in state['reads']if x['uri']=='/redfish/v1/Systems/Self')
assert system['BiosVersion']=='0603' and system['PowerState']=='On' and system['Boot']['BootNext']is None and system['Boot']['BootSourceOverrideEnabled']=='Disabled'
logout=json.loads((BASE/'remote_172_20_2_245/inventory-session-logout-1794118592059.json').read_text());assert logout['status']==200
result={
 'status':'PASS_INDEPENDENT_PHYSICAL_REDECODE_AND_BOUNDED_NATIVE_REPLAY',
 'hardware_manifest':bind(hardware),'physical_appendix_manifest':bind(appendix),'bindings_verified':counts,
 'log':{'bytes':len(log),'pages':len(parts),'crc32':f'{zlib.crc32(log):08X}','sha256':sha(log),'equal_to_root_log':True},
 'images':images,'selected_objects':objects,'complete_selected_objects':5,'omitted':0,'refused':0,
 'selection_scope':'Five selected instances, four unique content GUIDs; this is not the complete 13-instance firmware inventory. The outer PARTIAL diagnostic label is intentional.',
 'spf':{'both_70_byte_reads_exactly_equal':True,'crc32':f'{zlib.crc32(pair):08X}','sha256':sha(pair),'status_mask':hex(status),'source':hex(source),'source_pages':hex(pages),'source_guids':hex(guids),'current_blob':hex(current),'current_pages':hex(current_pages),'declared_size':hex(size),'source_count':count,'first_page':hex(first),'candidate_low32':page0&0xffffffff,'one_past_slot_relative':hex(slot),'header_parent':parent,'header_guid_index':guidindex,'header_form_id':formid,'computed_guid_read_relative_only':hex(candidate),'computed_read_inside_declared_size':False,'computed_address_dereferenced':False,'first_parser_state_proven':False,'pool_ownership_proven':False},
 'native_builder_replays':native,
 'closure':{'saved_redfish_status':{'BiosVersion':system['BiosVersion'],'PowerState':system['PowerState'],'BootNext':system['Boot']['BootNext'],'BootOverride':system['Boot']['BootSourceOverrideEnabled']},'logout_HTTP_status':logout['status'],'visual_review':'screen-95 shows original Exit page after collector; screen-96 shows original Main 0603 and Browse File / Start Media (media detached).','zero_password_or_flash_operations':'Consistent with collector code and saved session artifacts; not a proof that ordinary OEM boot/maintenance itself made no NVRAM writes.'},
 'limits':[
  'Post-Setup source/current pointers are not evidence of first-parser allocation, parent pool ownership, or every boot path.',
  'Computed 0xF4CE6 lies outside the declared 0xF245C source extent. The collector did not read it. This review does not turn the parser boundary into an accepted firmware patch.',
  'Two equal NIC forms blobs remain distinct HII/producer instances; their external callbacks remain unaudited and are not authorized by these bytes.',
  'NVMe/Socket original builders ran under the existing explicit UEFI models and observed NewString IDs. String allocator history, actual DIMM topology/text and hardware enumeration failure causes are not established.',
  'No password operation, full integrated original startup, updater acceptance, or bootability of a modified image is tested.'
 ],
 'hardware_actions_by_this_review':0,'input_files_changed':False,'runtime_authority':False,'release_ready':False,
 'review_source':bind(Path(__file__))
}
# Verify frozen inputs again after the read-only decoder/model work.
verify_entries(hm['files']+hm['external_bindings'],ROOT)
verify_entries(dm['files'],dyn);verify_entries(dm['external_read_only_inputs'],ROOT);verify_entries(am['bindings'],ROOT)
out=HERE/'physical_review.json';out.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps({'report':bind(out),'selected_objects':5,'QR_pages':17,'native_builder_full_equalities':len(native),'bindings':counts},ensure_ascii=False))
