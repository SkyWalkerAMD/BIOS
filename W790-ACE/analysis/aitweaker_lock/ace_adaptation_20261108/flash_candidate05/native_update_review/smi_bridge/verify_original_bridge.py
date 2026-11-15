"""Static byte proof of ACE1904's SW-SMI1f request-to-signature-gate bridge.

Re-extract only the two known PEs from the pinned official capsule in memory.
No firmware execution, REA session, hardware request, or input modification.
"""
from pathlib import Path
import datetime, hashlib, json, lzma, struct, sys, uuid

HERE=Path(__file__).resolve().parent
CASE=HERE.parent.parent
ROOT=next(p for p in HERE.parents if (p/'tools/pydeps').is_dir())
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile
import capstone
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP

sha=lambda b:hashlib.sha256(b).hexdigest()
ref=lambda p:{'path':Path(p).relative_to(ROOT).as_posix(),'sha256':sha(Path(p).read_bytes()),'bytes':Path(p).stat().st_size}
checks=[]
def check(value,label):
    if not value:raise ValueError(label)
    checks.append(label)

official=ROOT/'analysis/aitweaker_lock/official_W790_ACE_1904/W790_ACE_1904/Pro-WS-W790-ACE-ASUS-1904.CAP'
source=official.read_bytes()
check(sha(source)=='03e4330430b2510d5e9e5c9868ca64c730844992b82c6a272b815aef3d20bf29','official ACE1904 capsule exact identity')
inventory_path=CASE/'update_path_reference/ace_update_module_inventory.json'
inventory=json.loads(inventory_path.read_text(encoding='utf8'))
check(inventory['source_sha256']==sha(source),'existing extraction inventory source identity')
section=0x3181078+24
size=int.from_bytes(source[section:section+3],'little')
check(source[section+3]==2 and uuid.UUID(bytes_le=source[section+4:section+20])==uuid.UUID('ee4e5898-3914-4259-9d6e-dc7bd79403cf'),'known main DXE guided LZMA section')
expanded=lzma.decompress(source[section+24:section+size],format=lzma.FORMAT_ALONE)
check(sha(expanded)==inventory['decompressed_sha256'],'original main DXE expansion exact identity')
names={'sec':('3370a4bd-8c23-4565-a2a2-065feede6080','bff5fca82753c1076d00efbf6aefa3f27affc91d4a24530914aecc0b1a256da0'),
       'dxe':('97af1d95-203c-42de-8d6b-d13eb7e5a55a','dd8fced031578ef8c767d5aafe4b06609b876b7b14c009cab09d31d2fc36b912')}
modules={}
for key,(guid,expected) in names.items():
    row=next(r for r in inventory['selected_modules'] if r['guid']==guid)
    start=row['inner_offset'];ffs=expanded[start:start+row['ffs_bytes']]
    check(str(uuid.UUID(bytes_le=ffs[:16]))==guid and sha(ffs)==row['ffs_sha256'],key+' original ACE FFS GUID and bytes')
    off=24+row['derivation']['section_offset'];pe_size=int.from_bytes(ffs[off:off+3],'little')
    check(ffs[off+3]==0x10 and pe_size==row['derivation']['section_size'],key+' known PE section layout')
    raw=ffs[off+4:off+pe_size];path=ROOT/row['pe_path']
    check(sha(raw)==expected==row['pe_sha256'] and raw==path.read_bytes(),key+' working PE is byte-identical to official CAP extraction')
    pe=pefile.PE(data=raw);modules[key]={'pe':pe,'image':pe.get_memory_mapped_image(),'path':path,'guid':guid,'ffs_offset':start,'section_offset_in_ffs':off,'raw':raw}

md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);md.detail=True
def instruction(module,address):return next(md.disasm(modules[module]['image'][address:address+16],address,count=1))
def immediate(module,address):return next(o.imm for o in instruction(module,address).operands if o.type==X86_OP_IMM)
def rip(module,address):
    i=instruction(module,address);o=next(o for o in i.operands if o.type==X86_OP_MEM and o.mem.base==X86_REG_RIP)
    return i.address+i.size+o.mem.disp
def text(module,address):
    i=instruction(module,address);return i.mnemonic+' '+i.op_str
def call(module,address,target):check(instruction(module,address).mnemonic=='call' and immediate(module,address)==target,f'{module} direct call {address:x}->{target:x}')
def block(module,start,end,label):
    m=modules[module];raw=m['image'][start:end];offset=m['pe'].get_offset_from_rva(start)
    check(m['raw'][offset:offset+len(raw)]==raw,label+' original file bytes map to RVA')
    return {'label':label,'module':module,'start_rva':hex(start),'end_rva_exclusive':hex(end),'image_base':hex(m['pe'].OPTIONAL_HEADER.ImageBase),'start_va':hex(m['pe'].OPTIONAL_HEADER.ImageBase+start),'file_offset':hex(offset),'bytes':len(raw),'sha256':sha(raw),'raw_hex':raw.hex(),
            'instructions':[{'rva':hex(i.address),'bytes':i.bytes.hex(),'instruction':i.mnemonic+' '+i.op_str} for i in md.disasm(raw,start)]}

# Registration loop and GUID are original bytes, not a decompiler reachability inference.
check(rip('sec',0x2d77)==0x91b0,'registration locates protocol GUID at91b0')
sw_guid=str(uuid.UUID(bytes_le=modules['sec']['image'][0x91b0:0x91c0]))
check(sw_guid=='18a3c6dc-5eea-48c8-a1c1-b53389f98999','actual SW Dispatch2 protocol GUID')
check(immediate('sec',0x2db2)==0x1d and immediate('sec',0x2ddb)==0x1f,'registration loop covers SW values1d through1f')
check(rip('sec',0x2dc7)==0x28d4 and text('sec',0x2dd1)=='call qword ptr [rax]','registration callback and actual protocol method call')
check(text('sec',0x2979)=='mov sil, byte ptr [rdi + 8]' and immediate('sec',0x29a9)==0x1d and immediate('sec',0x29ae)==1 and immediate('sec',0x29b3)==1,'dispatcher distinguishes SW1d,1e,1f from supplied context')
call('sec',0x29bb,0x1df8)
call('sec',0x1e3b,0x1b9c)
check(text('sec',0x1e0d)=='mov edx, 0x24' and immediate('sec',0x1e23)==0x1d,'receiver validates0x24 and copies0x1d bytes')
check(modules['sec']['image'][0x91d0:0x91d2]==b'\x07\x07','original policy mode masks both07')
check(rip('sec',0x1bd4)==0x91d1 and rip('sec',0x1be6)==0x91d0,'request flags choose original mask checks')
check(immediate('sec',0x1bf5)==1 and immediate('sec',0x1bfe)==1 and immediate('sec',0x1c03)==2,'mode branch admits1,2,4 and rejects other modes')
call('sec',0x1caf,0x3b68)
call('sec',0x3d6e,0x397c)
check(immediate('sec',0x1cd8)&0xffffffffffffffff==0x8000000000000019,'only EFI25 has the visible exceptional tolerance branch')
check(text('sec',0x1d08)=='test rbx, rbx' and immediate('sec',0x1d0b)==0x1dd3,'EFI26 remains an error after the EFI25 comparison')
check(text('sec',0x1e4e)=='mov byte ptr [rbx + 0x1d], 0' and text('sec',0x1e58)=='mov byte ptr [rbx + 0x1d], 1','receiver reports success0 or failure1 at request+1d')

# DXE structure, same-buffer aliases, register transfer and status consumption.
check(rip('dxe',0xa1f)==0x5ff8 and rip('dxe',0xa3a)==0x5fb8 and text('dxe',0xa1f).endswith(', rax') and text('dxe',0xa3a).endswith(', rax'),'successful initialization binds request aliases5ff8 and5fb8 to same RAX')
check(rip('dxe',0xd54)==0x5fb8 and rip('dxe',0xdb0)==0x5ff8,'request construction and SMI use the initialized aliases')
check(immediate('dxe',0xd67)==0x10 and immediate('dxe',0xd6b)==7 and immediate('dxe',0xd7a)==2 and immediate('dxe',0xd7c)==2,'DXE mode10 builds request mode4 with flags7')
check(immediate('dxe',0xdb7)==0x1f,'DXE invokes SW SMI1f')
call('dxe',0xdbc,0xa68);call('dxe',0xac2,0x4b40)
check(text('dxe',0x4b5d)=='mov ebx, dword ptr [r9 + 4]' and text('dxe',0x4b61)=='mov ecx, dword ptr [r9 + 8]','trigger loads pointer low/high halves into EBX/ECX')
check(text('dxe',0x4b83)=='out dx, al' and modules['dxe']['image'][0x5d90:0x5d92]==b'\xb2\x00','normal byte OUT uses original default SMI portB2')
check(text('dxe',0xde7)=='cmp byte ptr [rdi + 0x1d], bl' and text('dxe',0xdea)=='sete bl','DXE treats response byte+1d zero as success')

engineering_path=CASE/'engineering_signature/W790-ACE-1904-CANDIDATE05-ENGINEERING-NONOEM-NOT-FLASH-READY.CAP'
engineering=engineering_path.read_bytes()
check(sha(engineering)=='e330039ecd2c334c4f9d502589e7f9503000b34462a7e21f6b97b1b581794d08','candidate05 engineering CAP identity unchanged')
alt_guid=modules['sec']['image'][0x9070:0x9080]
check(engineering[0x28:0x38]!=alt_guid and engineering[0x28:0x38]==source[0x28:0x38],'engineering certificate type selects397c branch, not alternate37d0')

ranges=[('dxe',0x918,0xa68,'successful_request_alias_initialization'),('dxe',0xd24,0xe08,'normal_mode4_request_and_status'),('dxe',0xa68,0xad2,'SMI_pointer_register_descriptor'),('dxe',0x4b40,0x4ba6,'SMI_OUT_transfer'),
 ('sec',0x29f0,0x2a07,'correct_registration_function_prologue'),('sec',0x2d6a,0x2de1,'SW_SMI_registration_loop'),('sec',0x28d4,0x29ee,'SW_dispatch_and_saved_pointer'),('sec',0x1df8,0x1e6c,'request_receiver_and_return_status'),('sec',0x1b9c,0x1df8,'mode4_verification_dispatch_and_error_propagation'),('sec',0x3d41,0x3d85,'certificate_format_gate_selection')]
blocks=[block(*r) for r in ranges]
report={'status':'STATIC_ORIGINAL_ACE1904_SMI1F_MODE4_BRIDGE_CONFIRMED','created_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'checks':len(checks),'check_names':checks,
 'scope':'Known official ACE1904 modules only. Re-extracted two PEs in memory, decoded exact original instructions, and checked the specified bridge. No REA session or firmware execution.',
 'sources':{'official_cap':ref(official),'module_inventory':ref(inventory_path),'engineering_cap':ref(engineering_path),'script':ref(Path(__file__))},
 'modules':{k:{**ref(v['path']),'ffs_guid':v['guid'],'ffs_offset_in_expanded_original_dxe':hex(v['ffs_offset']),'pe_section_offset_in_ffs':hex(v['section_offset_in_ffs']),'image_base':hex(v['pe'].OPTIONAL_HEADER.ImageBase),'official_pe_bytes_identical':True} for k,v in modules.items()},
 'registration':{'function_entry_rva':'0x29f0','not_function_entry':'0x2a00 is inside the prologue/body','sw_dispatch2_guid':sw_guid,'guid_rva':'0x91b0','loop_rvas':['0x2db2','0x2db7','0x2dd1','0x2ddb','0x2ddf'],'sw_values':['0x1d','0x1e','0x1f'],'handler_rva':'0x28d4','actual_indirect_register_call_rva':'0x2dd1'},
 'bridge':['PEFirmwareUpdateDxe:d24(mode0x10)->request byte0=4, DWORD+1=7','PEFirmwareUpdateDxe:db7/dbc->a68(SW0x1f, same request pointer)->4b40 OUT','SecSMIFlash:registered SW0x1f->28d4; reconstruct saved pointer using CPU-state indices0x27/0x28','SecSMIFlash:29bb->1df8->1b9c','SecSMIFlash:mode4 permitted by original07 masks->1caf->3b68','SecSMIFlash:certificate GUID differs from alternate type->3d6e->397c','EFI_SECURITY_VIOLATION26 survives the EFI25-only exception;1df8 writes request+1d=1','PEFirmwareUpdateDxe:de7/dea checks byte+1d and returns false for1'],
 'request_geometry':{'dxe_clears_bytes':'0x22','smm_validates_pointer_bytes':'0x24','smm_local_copy_bytes':'0x1d','status_byte_offset':'0x1d','same_buffer_aliases':['DXE5ff8','DXE5fb8'],'pointer_alias_condition':'Successful initialized path stores the same RAX at a1f and a3a with no intervening RAX write.'},
 'policy':{'mask_rvas':['0x91d0','0x91d1'],'original_bytes_hex':'0707','normal_request_mode':4,'normal_request_flags':7,'exceptional_error_code':25,'rejected_key_error_code':26,'error26_tolerated':False},
 'candidate_certificate_type':{'engineering_guid':str(uuid.UUID(bytes_le=engineering[0x28:0x38])),'alternate37d0_guid':str(uuid.UUID(bytes_le=alt_guid)),'selected_gate_rva':'0x397c'},
 'limitations':['Static registration identifies the original code path; live customized firmware root/key and exact current flash bytes are not read here.','Reachability assumes normal successful initialization/protocol discovery and valid communication buffers. Failures can stop earlier and do not imply acceptance.','The cryptographic rejection of e330 is separately established by the existing native-root gate replay; this report supplies its missing caller/dispatcher/status bridge, not a new signature replay.','A decompiler can discard the registration tail after poorly modeled LocateProtocol outputs. Original instruction bytes and indirect-call arguments are the registration evidence.','Module display names may originate from a GUID-name catalog; the byte proof independently re-extracts official ACE1904 and does not borrow W890 behavior.'],
 'blocks':blocks,'new_rea_session':False,'firmware_executed':False,'hardware_access':False,'trust_or_image_modified':False}
out=HERE/'original_byte_bridge.json';out.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf8')
print(json.dumps({'status':report['status'],'checks':len(checks),'report_sha256':sha(out.read_bytes()),'path':str(out),'hardware_access':False}))
