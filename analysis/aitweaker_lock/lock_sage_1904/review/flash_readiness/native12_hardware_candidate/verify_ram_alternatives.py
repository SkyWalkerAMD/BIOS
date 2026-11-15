"""Narrow offline counterexamples for unchanged NATIVE12/provider12 RAM reuse.

This executes frozen machine code against synthetic LoadedImage services.
It creates no installer and never calls original DXE/SendForm or hardware.
"""
from pathlib import Path
import hashlib,json,sys
HERE=Path(__file__).resolve().parent;CASE=HERE.parents[2];P12=HERE.parent/'native_provider12_candidate'
sys.path.insert(0,str(P12));import verify_native_owner as f
from unicorn.x86_const import UC_X86_REG_RAX,UC_X86_REG_RIP,UC_X86_REG_RSP
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
ROWS=[]
def no_write(v):assert v.variable_writes==0
def call_raw(v,address):
    v.stop=f.STOP;sp=f.STACK+0x180000-0x108;v.w(sp,f.u64(f.STOP)+bytes(0x100));v.u.reg_write(UC_X86_REG_RSP,sp);v.u.emu_start(address,0,count=10000);assert v.u.reg_read(UC_X86_REG_RIP)==f.STOP;return v.u.reg_read(UC_X86_REG_RAX)
def originals(v):
    for name,base,li in [('AMITSE',f.TSE,v.li1),('Setup',f.SETUP,v.li2)]:
        path=CASE/'analysis/modules'/f'{name}.efi';p=f.pefile.PE(str(path));p.relocate_image(base)
        v.w(base,bytes(f.BIND[name]['image_bytes']));v.w(base,p.get_memory_mapped_image());v.w(li+0x48,f.u64(p.OPTIONAL_HEADER.SizeOfImage))
def row(name,details):ROWS.append({'case':name,'passed':True,**details})
v=f.VM();assert v.call('native_browser_state')==1;no_write(v);row('baseline_exact_frozen_modules_bind',{'browser_state':'verified idle in synthetic wrapper head only'})
v=f.VM();originals(v);assert v.call('native_browser_state')&0xffffffff==0xffffffff;no_write(v);row('original_loaded_sizes_refused',{'browser_state':'unknown','provider12_accepts_original_modules':False})
for name,original_base,detached in [('AMITSE',f.TSE,0x70000000),('Setup',f.SETUP,0x71000000)]:
    v=f.VM();b=f.BIND[name];payload=v.r(original_base+b['payload_rva'],b['payload_bytes']);assert hashlib.sha256(payload).hexdigest()==b['payload_sha256'];v.map(detached,len(payload));v.w(detached,payload)
    assert call_raw(v,original_base+b['payload_rva']+0x50)==original_base
    got=call_raw(v,detached+0x50);assert got==detached-b['payload_rva'] and got!=original_base;no_write(v)
    row(f'{name}_unchanged_detached_payload_wrong_base',{'copied_payload_sha256':hashlib.sha256(payload).hexdigest(),'detached_address':hex(detached),'gate_base_result':hex(got),'required_original_base':hex(original_base)})
v=f.VM();payloads=[]
for name,base,at in [('AMITSE',f.TSE,0x70000000),('Setup',f.SETUP,0x71000000)]:
    b=f.BIND[name];raw=v.r(base+b['payload_rva'],b['payload_bytes']);v.map(at,len(raw));v.w(at,raw);payloads.append(sha(Path(b['module_file'])))
originals(v);assert v.call('native_browser_state')&0xffffffff==0xffffffff;no_write(v);row('detached_payload_presence_does_not_bind_provider',{'provider12_accepts_original_modules_with_elsewhere_payload':False})
for order in ['original_first','shadow_first']:
    v=f.VM();other={};old_handles=[]
    for i,(name,base)in enumerate([('AMITSE',0x70000000),('Setup',0x71000000)]):
        path=CASE/'analysis/modules'/f'{name}.efi';v.map_image(path,base);pe=f.pefile.PE(str(path));li=f.HEAP+0x8000+i*0x100;dp=v.dp1 if i==0 else v.dp2
        v.w(li+0x20,f.u64(dp));v.w(li+0x40,f.u64(base)+f.u64(pe.OPTIONAL_HEADER.SizeOfImage));h=0x444+i;other[h]=li;old_handles.append(h)
    sequence=old_handles+[0x111,0x222]if order=='original_first'else[0x111,0x222]+old_handles
    def handles():v.w(v.arg(3),f.u64(4));v.w(v.arg(4),f.u64(v.handles));v.w(v.handles,b''.join(f.u64(h)for h in sequence));return 0
    old_handle=v.handle
    def handle():
        if v.arg(0)in other:v.w(v.arg(2),f.u64(other[v.arg(0)]));return 0
        return old_handle()
    v.bsfn(0x138,'locate_handles_both',handles);v.bsfn(0x98,'handle_protocol_both',handle)
    assert v.call('native_browser_state')&0xffffffff==0xffffffff;no_write(v);row('full_shadow_plus_original_'+order,{'loaded_image_handles':4,'provider12_accepts':False})
report={'status':'PASS_UNCHANGED_BINARY_RAM_ROUTE_COUNTEREXAMPLES','case_count':len(ROWS),'cases':ROWS,'provider_sha256':sha(f.EFI),'guard_modules':{name:b['module_sha256']for name,b in f.BIND.items()},'test_source_sha256':sha(Path(__file__)),'imported_fixture_sha256':sha(P12/'verify_native_owner.py'),'scope':'Actual frozen provider identity code and actual guard gate_base bytes; synthetic memory maps/UEFI protocols, no native browser body, no hardware, no installer.','conclusion':'These routes cannot validate the same NATIVE12/provider12 pair unchanged. This is not a proof that no different RAM architecture can ever work.'}
(HERE/'ram_alternatives_verification.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'status':report['status'],'cases':len(ROWS)}))
