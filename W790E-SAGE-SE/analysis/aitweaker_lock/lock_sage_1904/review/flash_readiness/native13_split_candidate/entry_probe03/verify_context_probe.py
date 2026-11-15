"""Actual compiled entry probe, bounded synthetic EFI/frame failure cases."""
from pathlib import Path
import hashlib,json,re,struct,sys
HERE=Path(__file__).resolve().parent;N13=HERE.parent;N12=HERE.parents[1]/'native12_hardware_candidate'
sys.dont_write_bytecode=True;sys.path.insert(0,str(N12));import verify_probe as f
from unicorn import UC_HOOK_CODE,UC_HOOK_MEM_READ,UC_PROT_READ,UC_PROT_EXEC
from unicorn.x86_const import *
f.EFI=HERE/'build/SageNative13EntryContext03.efi';f.sy={m[0]:int(m[1],16)for m in re.findall(r'^\s+\d{4}:[0-9a-f]+\s+(\S+)\s+([0-9a-f]{16})',(HERE/'build/probe.map').read_text(),re.M)}
CORE=0x5000000;BDS=0x6000000;ROWS=[];OUT=HERE/'tests';OUT.mkdir(exist_ok=True)
class VM(f.VM):
 def __init__(self):
    super().__init__();self.extra_lis={3:f.HEAP+0x7500,4:f.HEAP+0x7600};self.inventory=[1,2,3,4]
    for h,name,base,pathaddr,g in [(3,'DxeCore',CORE,f.HEAP+0x7800,'d6a2cb7f-6a18-4e2f-b43b-9920a733700a'),(4,'BdsArch',BDS,f.HEAP+0x7900,'8f4b8f82-9b91-4028-86e6-f4db7d4c1dff')]:
        p=f.pefile.PE(str(N13/'boot_context'/f'{name}.original.efi'));size=(p.OPTIONAL_HEADER.SizeOfImage+4095)&~4095;self.u.mem_map(base,size);p.relocate_image(base);self.w(base,p.get_memory_mapped_image());self.desc.append((3,base,size,0));li=self.extra_lis[h];self.w(li+0x20,f.q(pathaddr));self.w(li+0x40,f.q(base)+f.q(p.OPTIONAL_HEADER.SizeOfImage));self.w(pathaddr,b'\x04\x06\x14\0'+f.guid(g)+b'\x7f\xff\x04\0')
    self.w(self.bs+0xd0,f.q(CORE+0x8720));self.before[0]=self.r(self.bs,0x178)
    self.parent_rsp=f.STACK+0x80008;self.entry_image=0x555;self.w(f.sy['captured_entry'],struct.pack('<11Q',self.parent_rsp,0x12345,0x23456,0x34567,0x45678,0x56789,0x6789a,0x789ab,0x89abc,self.entry_image,self.st));self.w(self.parent_rsp,f.q(CORE+0x88af));self.w(self.parent_rsp+0x60,f.q(f.TSE+0xa8e6));self.w(self.parent_rsp+0x68,f.q(self.entry_image));self.w(self.parent_rsp+0x70,f.q(0x11223344));self.w(self.parent_rsp+0x78,f.q(self.parent_rsp+0x131));self.w(self.parent_rsp+0x188,f.q(0x55667788));self.w(self.parent_rsp+0x190,f.q(f.TSE+0x9025));self.stack_reads=[]
    self.u.hook_add(UC_HOOK_MEM_READ,lambda u,access,a,n,v,data:self.stack_reads.append((a-self.parent_rsp,n)),begin=self.parent_rsp,end=self.parent_rsp+0x1ff)
    self.allocation_tail_reads=[]
    for start,end in [(CORE+0x20e60,CORE+0x21000),(BDS+0x1cc20,BDS+0x1d000)]:self.u.hook_add(UC_HOOK_MEM_READ,lambda u,access,a,n,v,data:self.allocation_tail_reads.append([a,n]),begin=start,end=end-1)
 def handle(self):
    if self.arg(0)in getattr(self,'extra_lis',{}):self.w(self.arg(2),f.q(self.extra_lis[self.arg(0)]));return 0
    return super().handle()
 def run(self,name,check):
    sp=f.STACK+0xf0008;self.w(sp,f.q(f.STOP));self.u.reg_write(UC_X86_REG_RSP,sp);self.u.reg_write(UC_X86_REG_RCX,self.st);self.u.emu_start(f.sy['collect'],f.STOP+1,count=100000000);assert self.u.reg_read(UC_X86_REG_RIP)==f.STOP
    size=self.q(f.sy['probe_log_bytes']);raw=self.r(f.sy['probe_log'],size);log=raw.decode();assert raw.endswith(b'SAGE_NATIVE13_ENTRY_CONTEXT03_END\r\n')and b'LOG_COMPLETE=YES'in raw
    assert not self.live and not self.protected_writes and not self.outside_image_reads and not self.allocation_tail_reads
    assert self.r(self.bs,0x178)==self.before[0]and self.r(self.rt,0x88)==self.before[1]
    allowed=set(range(0,8))|set(range(0x60,0x70))|set(range(0x78,0x80))|set(range(0x188,0x198));assert all(set(range(a,a+n))<=allowed for a,n in self.stack_reads),self.stack_reads
    assert check(log),name+'\n'+log
    (OUT/(name+'.log')).write_bytes(raw);ROWS.append({'case':name,'passed':True,'log_sha256':hashlib.sha256(raw).hexdigest(),'log_bytes':size,'observed_stack_read_offsets':sorted({a for a,n in self.stack_reads}),'zero_oem_service_table_writes':True,'zero_outstanding_pool_buffers':True,'allocation_tail_reads':0})
def actual_entry_chain():
    v=VM();priv=f.HEAP+0xa000;jump=f.HEAP+0xb000;oldsp=f.STACK+0xe0008;ret=f.TSE+0xa8e6;oldrbp=0x31415926
    v.w(v.extra_lis[3]+0x48,f.q(0x21000))
    v.w(priv+0x20,f.q(f.sy['efi_main']));v.w(priv+0x38,f.q(v.st));v.w(priv+0xd0,struct.pack('<H',0x8664));v.w(oldsp,f.q(ret));v.u.reg_write(UC_X86_REG_RSP,oldsp);v.u.reg_write(UC_X86_REG_RBP,oldrbp);v.u.reg_write(UC_X86_REG_RCX,v.entry_image);v.u.reg_write(UC_X86_REG_RDX,0);v.u.reg_write(UC_X86_REG_R8,0)
    reached=[]
    def callback(u,a,n,data):
        if a==f.sy['probe_main']:reached.append(a);u.emu_stop();return
        value={CORE+0x7e50:priv,CORE+0x10808:jump,CORE+0x280:0,CORE+0x11258:0}[a];s=u.reg_read(UC_X86_REG_RSP);u.reg_write(UC_X86_REG_RAX,value);u.reg_write(UC_X86_REG_RIP,v.q(s));u.reg_write(UC_X86_REG_RSP,s+8)
    for a in [CORE+0x7e50,CORE+0x10808,CORE+0x280,CORE+0x11258,f.sy['probe_main']]:v.u.hook_add(UC_HOOK_CODE,callback,begin=a,end=a)
    v.u.emu_start(CORE+0x8720,0,count=100000);assert reached
    capture=struct.unpack('<11Q',v.r(f.sy['captured_entry'],88));s=capture[0]
    assert s==oldsp-0x60 and v.q(s)==CORE+0x88af and v.q(s+0x60)==ret and v.q(s+0x68)==v.entry_image and v.q(s+0x78)==oldrbp
    assert capture[9]==v.entry_image and capture[10]==v.st and v.u.reg_read(UC_X86_REG_RSP)==s
    ROWS.append({'case':'original_Core_StartImage_calls_actual_compiled_entry_assembly','passed':True,'saved_rsp_before_C_prologue':hex(s),'same_native_return_address_preserved':True,'captured_entry_handle_and_table':True,'scope':'Original Core prologue/call and actual probe entry shim execute; internal dependencies synthetic.'})
def actual_launch_chain():
    v=VM();v.u.mem_protect(f.TSE,0xb0000,UC_PROT_READ|UC_PROT_EXEC);p=f.STACK+0xd0008;v.w(p,f.q(f.TSE+0x9025));v.u.reg_write(UC_X86_REG_RSP,p);v.u.reg_write(UC_X86_REG_RBP,0x31415926);v.u.reg_write(UC_X86_REG_RCX,0);v.u.reg_write(UC_X86_REG_RDX,0);v.u.reg_write(UC_X86_REG_R8,0);v.u.reg_write(UC_X86_REG_R9,0)
    h=v.u.hook_add(UC_HOOK_CODE,lambda u,a,n,d:u.emu_stop(),begin=f.TSE+0x9f9e,end=f.TSE+0x9f9e);v.u.emu_start(f.TSE+0x9f78,0,count=1000);v.u.hook_del(h)
    assert v.u.reg_read(UC_X86_REG_RSP)==p-0x128 and v.u.reg_read(UC_X86_REG_RBP)==p-0x5f
    v.w(f.TSE+0x83308,f.q(v.bs));v.w(p-0x5f-0x79,f.q(v.entry_image));priv=f.HEAP+0xa000;jump=f.HEAP+0xb000;v.w(priv+0x20,f.q(f.sy['efi_main']));v.w(priv+0x38,f.q(v.st));v.w(priv+0xd0,struct.pack('<H',0x8664));reached=[]
    def hook(u,a,n,data):
        if a==f.sy['probe_main']:reached.append(a);u.emu_stop();return
        value={CORE+0x7e50:priv,CORE+0x10808:jump,CORE+0x280:0,CORE+0x11258:0}[a];sp=u.reg_read(UC_X86_REG_RSP);u.reg_write(UC_X86_REG_RAX,value);u.reg_write(UC_X86_REG_RIP,v.q(sp));u.reg_write(UC_X86_REG_RSP,sp+8)
    for a in [CORE+0x7e50,CORE+0x10808,CORE+0x280,CORE+0x11258,f.sy['probe_main']]:v.u.hook_add(UC_HOOK_CODE,hook,begin=a,end=a)
    v.u.emu_start(f.TSE+0xa8d0,0,count=100000);assert reached
    v.parent_rsp=v.q(f.sy['captured_entry']);assert v.parent_rsp==p-0x190;v.u.hook_add(UC_HOOK_MEM_READ,lambda u,access,a,n,value,data:v.stack_reads.append((a-v.parent_rsp,n)),begin=v.parent_rsp,end=v.parent_rsp+0x1ff)
    v.run('original_AMITSE_Core_actual_EP3_entry_and_collector',lambda s:'LaunchOuterReturnRVA=0000000000009025'in s and'PASS exact outer CALL target9F78 and return RVA'in s)
    ROWS[-1]['scope']='Original AMITSE prologue and callsite, original Core and actual EP3 entry/collector execute; intervening launch-policy body is skipped after static stack audit; services and outer return value synthetic.'
def main():
 actual_entry_chain()
 actual_launch_chain()
 v=VM();v.run('exact_amitse_native_parent',lambda s:'PASS exact fixed Core StartImage frame'in s and'NativeCallerModule=AMITSE'in s and'PASS exact known native StartImage callsite'in s)
 v=VM();v.w(v.parent_rsp+0x60,f.q(BDS+0xf60b));v.run('exact_bds_native_parent',lambda s:'NativeCallerModule=BdsArch'in s and'PASS exact known native StartImage callsite'in s)
 v=VM();v.w(CORE+0x88ac,b'\xcc');v.run('changed_core_callsite_refused',lambda s:not v.stack_reads and'WARN context module normalized complete text SHA256'in s)
 v=VM();v.w(CORE+0x548,f.q(CORE+1));v.run('changed_core_text_relocation_refused',lambda s:not v.stack_reads and'WARN context module normalized complete text SHA256'in s)
 v=VM();v.inventory=[1,2,4];v.run('missing_core_loadedimage_refused',lambda s:not v.stack_reads and'WARN exact DXE Core image available'in s)
 v=VM();v.inventory=[1,2,3,3,4];v.run('duplicate_core_loadedimage_refused',lambda s:not v.stack_reads)
 v=VM();v.w(v.extra_lis[3]+0x48,f.q(1));v.run('wrong_core_loaded_size_refused',lambda s:not v.stack_reads)
 v=VM();v.w(v.bs+0xd0,f.q(CORE+0x8721));v.before[0]=v.r(v.bs,0x178);v.run('different_startimage_pointer_refused',lambda s:not v.stack_reads)
 v=VM();v.w(v.parent_rsp,f.q(CORE+0x88b0));v.run('wrong_entry_return_stops_unwind',lambda s:'WARN original Core entry CALL return address'in s and all(a<8 for a,n in v.stack_reads))
 v=VM();v.w(v.parent_rsp+0x68,f.q(0));v.run('wrong_saved_image_handle_stops_parent_read',lambda s:'WARN Core saved handle equals entry image'in s and not any(0x60<=a<0x68 or a>=0x78 for a,n in v.stack_reads))
 v=VM();v.w(f.sy['captured_entry'],f.q(v.parent_rsp+1));v.run('unaligned_capture_refused',lambda s:not v.stack_reads)
 v=VM();v.w(f.sy['captured_entry']+80,f.q(0));v.run('wrong_captured_system_table_refused',lambda s:not v.stack_reads)
 for name,second_type in [('cross_page_frame_allowed',4),('cross_page_frame_second_reserved_refused',0)]:
    v=VM();old=v.parent_rsp;v.parent_rsp=f.STACK+0x80ff8;v.w(v.parent_rsp,v.r(old,0x80));v.w(f.sy['captured_entry'],f.q(v.parent_rsp));v.desc=[row for row in v.desc if row[1]!=f.STACK];v.desc.extend([(4,f.STACK,0x81000,0),(second_type,f.STACK+0x81000,0x7f000,0)])
    v.u.hook_add(UC_HOOK_MEM_READ,lambda u,access,a,n,value,data:v.stack_reads.append((a-v.parent_rsp,n)),begin=v.parent_rsp,end=v.parent_rsp+0x1ff)
    v.run(name,lambda s:'PASS exact fixed Core StartImage frame'in s if second_type==4 else'WARN fixed Core frame within data descriptors'in s and all(a<8 for a,n in v.stack_reads))
 for name,typ,attrs in [('reserved_stack',0,0),('conventional_stack',7,0),('read_protected_stack',4,0x2000)]:
    v=VM();v.desc=[(typ,a,n,attrs)if a==f.STACK else(t,a,n,x)for t,a,n,x in v.desc];v.run(name,lambda s:not v.stack_reads)
 v=VM();v.desc.append((4,v.parent_rsp&~4095,4096,0));v.run('overlapping_stack_map_refused',lambda s:not v.stack_reads)
 v=VM();v.w(v.parent_rsp+0x60,f.q(0x77777777));v.run('unknown_native_parent_remains_unknown',lambda s:'NativeCallerModule=UNKNOWN'in s and'BROWSER_ABSENCE_PROOF=NO'in s)
 v=VM();v.w(BDS+0x1000,b'\xcc');v.w(v.parent_rsp+0x60,f.q(BDS+0xf60b));v.run('unverified_bds_parent_not_attributed',lambda s:'NativeCallerModule=UNKNOWN'in s)
 v=VM();v.w(v.extra_lis[3]+0x48,f.q(0x21000));v.run('core_exact_page_rounding_allowed',lambda s:'CoreAllocationRoundingUsed=YES'in s and'ContextPEImageSize=0000000000020E60'in s and'ContextReadExtentBytes=0000000000020E60'in s and'PASS exact fixed Core StartImage frame'in s)
 for name,size in [('undersized_core_metadata',0x20e5f),('intermediate_core_metadata',0x20e61),('round_minus_one_core_metadata',0x20fff),('round_plus_one_core_metadata',0x21001),('extra_page_core_metadata',0x22000)]:
    v=VM();v.w(v.extra_lis[3]+0x48,f.q(size));v.run(name,lambda s:not v.stack_reads and'WARN exact or precisely Core-rounded LoadedImage size'in s)
 for name,offset,value in [('rounded_core_wrong_PE_size',80,struct.pack('<I',0x21000)),('rounded_core_wrong_entry',40,struct.pack('<I',0x1c05)),('rounded_core_wrong_machine',4,struct.pack('<H',0x14c))]:
    v=VM();v.w(v.extra_lis[3]+0x48,f.q(0x21000));peoff=int.from_bytes(v.r(CORE+0x3c,4),'little');v.w(CORE+peoff+offset,value);v.run(name,lambda s:not v.stack_reads and'WARN exact original PE size entry and architecture'in s)
 v=VM();v.w(v.extra_lis[4]+0x48,f.q(0x1d000));v.w(v.parent_rsp+0x60,f.q(BDS+0xf60b));v.run('rounding_not_extended_to_bds',lambda s:'NativeCallerModule=UNKNOWN'in s and'WARN exact or precisely Core-rounded LoadedImage size'in s)
 class RaceVM(VM):
    change_header=False
    def allocate(self):
        if self.arg(1)==87685:
            if self.change_header:
                peoff=int.from_bytes(self.r(CORE+0x3c,4),'little');self.w(CORE+peoff+80,struct.pack('<I',0x21000))
            else:self.w(self.extra_lis[3]+0x48,f.q(0x20e60))
        return super().allocate()
 for name,header in [('accepted_metadata_changes_during_callback',False),('PE_header_changes_during_callback',True)]:
    v=RaceVM();v.change_header=header;v.w(v.extra_lis[3]+0x48,f.q(0x21000));v.run(name,lambda s:not v.stack_reads and'WARN context module normalized complete text SHA256'in s)
 for ret in [0x2d7d,0x9025,0x960c,0x9754,0x97c9]:
    v=VM();v.w(v.parent_rsp+0x190,f.q(f.TSE+ret));v.run(f'known_outer_call_return_{ret:x}',lambda s:'PASS exact outer CALL target9F78 and return RVA'in s and'BROWSER_ABSENCE_PROOF=NO'in s)
 v=VM();v.w(v.parent_rsp+0x78,f.q(v.parent_rsp+0x132));v.run('launch_rbp_crosscheck_failure_blocks_new_slots',lambda s:'WARN launch RBP equals raw RSP plus131'in s and all(a<0x188 for a,n in v.stack_reads))
 class StaleLaunchVM(VM):
    change_callsite=False
    def allocate(self):
        n=self.arg(1);out=self.arg(2);r=super().allocate()
        if n==87685 and r==0:self.core_copy=self.q(out)
        return r
    def free(self):
        a=self.arg(0);r=super().free()
        if a==getattr(self,'core_copy',0):self.w(f.TSE+(0x9020 if self.change_callsite else 0x9f78),b'\x90')
        return r
 v=StaleLaunchVM();v.run('fresh_launch_hash_rejects_changed_function',lambda s:'WARN complete original AMITSE launch function SHA256'in s and all(a<0x188 for a,n in v.stack_reads))
 v=StaleLaunchVM();v.change_callsite=True;v.run('fresh_outer_call_bytes_reject_changed_target',lambda s:'PASS complete original AMITSE launch function SHA256'in s and'WARN exact outer CALL target9F78 and return RVA'in s)
 for name,typ,attrs in [('upper_frame_crosses_reserved_page',0,0),('upper_frame_crosses_readprotected_page',4,0x2000)]:
    v=VM();old=v.parent_rsp;v.parent_rsp=f.STACK+0x80f08;v.w(v.parent_rsp,v.r(old,0x198));v.w(f.sy['captured_entry'],f.q(v.parent_rsp));v.w(v.parent_rsp+0x78,f.q(v.parent_rsp+0x131));v.desc=[row for row in v.desc if row[1]!=f.STACK];v.desc.extend([(4,f.STACK,0x81000,0),(typ,f.STACK+0x81000,0x7f000,attrs)]);v.u.hook_add(UC_HOOK_MEM_READ,lambda u,access,a,n,value,data:v.stack_reads.append((a-v.parent_rsp,n)),begin=v.parent_rsp,end=v.parent_rsp+0x1ff)
    v.run(name,lambda s:'WARN launch outer slots within bounded data stack'in s and all(a<0x188 for a,n in v.stack_reads))
 v=VM();v.w(v.parent_rsp+0x190,f.q(0x77777777));v.run('unknown_upper_return_stops_at_observation',lambda s:'LaunchOuterCallerModule=UNKNOWN'in s and'NO_FURTHER_OUTER_STACK_WALK'in s)
 v=VM();v.w(v.parent_rsp+0x188,f.q(0xffffffffffffffff));v.run('saved_upper_rbp_never_dereferenced',lambda s:'LaunchOuterSavedRBP=FFFFFFFFFFFFFFFF'in s and'NO_FURTHER_OUTER_STACK_WALK'in s)
 report={'status':'PASS_ACTUAL_CONTEXT_PROBE_BYTES_SYNTHETIC_EFI','case_count':len(ROWS),'cases':ROWS,'efi_sha256':hashlib.sha256(f.EFI.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'baseline_fixture_sha256':hashlib.sha256((N12/'verify_probe.py').read_bytes()).hexdigest(),'scope':'Original Core-to-actual-entry-shim call plus actual collector identity/bounded-read cases. Native browser body, full boot ancestry, real page permissions and absence of active UI are not proven.'}
 (OUT/'verification.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'status':report['status'],'cases':len(ROWS)}))
if __name__=='__main__':main()
