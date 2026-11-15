"""Actual prerequisite EFI bytes with explicit EFI services/page tables.

Only read_cpu_env is substituted with a known CPU environment in this isolated
fixture. The real CPU query, allocator, page-permission service and execution
are additionally exercised by the exact ISO on OVMF.
"""
from pathlib import Path
import hashlib,json,re,struct,sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;N13=HERE.parents[1]
sys.path.insert(0,str(N13/'entry_probe03'))
import verify_context_probe as parent
f=parent.f
from unicorn import UC_HOOK_CODE,UC_HOOK_MEM_READ,UC_PROT_READ,UC_PROT_WRITE,UC_PROT_EXEC
from unicorn.x86_const import *
f.EFI=HERE/'build/SageNative13Prerequisite04.efi'
f.sy={m[0]:int(m[1],16)for m in re.findall(r'^\s+\d{4}:[0-9a-f]+\s+(\S+)\s+([0-9a-f]{16})',(HERE/'build/probe.map').read_text(),re.M)}
OUT=HERE/'tests';OUT.mkdir(exist_ok=True);ROWS=[]
CPU_GUID=f.guid('26baccb1-6f42-11d4-bce7-0080c73c8881');OWN=0x7000000

class VM(parent.VM):
 def __init__(self):
    super().__init__();self.no_attr=True;self.cpu_missing=False;self.allocate_page_error=False;self.allocate_wrong=None;self.allocate_wrong_type=False
    self.set_error_at=0;self.false_success_at=0;self.partial_error_at=0;self.neighbor_change_at=0;self.set_count=0;self.free_page_error=False;self.close_error=False;self.mutate_original_after_free=False
    self.ending_at=None;self.ending_seen=False;self.post_ending_calls=[];self.event_live=False;self.page_allocated=False;self.page_freed=0;self.attribute_requests=[];self.retained=False;self.grow_map_after_allocation=False
    self.cpu=f.HEAP+0x7a00;self.self_li=f.HEAP+0x7b00
    self.w(self.self_li+0x40,f.q(f.BASE)+f.q(f.pefile.PE(str(f.EFI)).OPTIONAL_HEADER.SizeOfImage))
    self.w(self.parent_rsp+0x190,f.q(f.TSE+0x2d7d));self.w(self.parent_rsp+0x188,f.q(self.parent_rsp+0x241))
    self.u.mem_map(OWN,0x10000);self.desc.append((7,OWN,0x10000,0))
    self.root=f.HEAP+0xc0000;self.next_table=self.root+4096;self.leaves={};self.level_entries={}
    self.w(self.root,bytes(0x30000))
    for base,n in [(f.HEAP,0x100000),(f.STACK,0x100000),(f.TSE,0xb0000),(f.SETUP,0x1b0000),(parent.CORE,0x21000),(parent.BDS,0x1d000),(f.BASE,0x20000),(OWN,0x10000)]:
        for address in range(base,base+n,4096):self.map_page(address,rw=not(f.TSE<=address<f.TSE+0xb0000 or f.SETUP<=address<f.SETUP+0x1b0000))
    self.env=[0x80010033,self.root,0x620,0xd00,0x0007040600070406,40,0]
    for off,name,fn in [(0x28,'AllocatePages',self.allocate_pages),(0x30,'FreePages',self.free_pages),(0x50,'CreateEvent',self.create_event),(0x70,'CloseEvent',self.close_event)]:self.w(self.bs+off,f.q(self.callback(name,fn)))
    self.w(self.cpu+0x38,f.q(self.callback('CpuSetMemoryAttributes',self.set_attributes)));self.before[0]=self.r(self.bs,0x178)
    self.u.hook_add(UC_HOOK_CODE,self.environment,begin=f.sy['read_cpu_env'],end=f.sy['read_cpu_env'])
 def map_page(self,address,rw=1,nx=0):
    table=self.root
    for level in (4,3,2):
        slot=table+8*((address>>(12+9*(level-1)))&511);self.level_entries[(address,level)]=slot
        value=self.q(slot)
        if not value:
            assert self.next_table<f.HEAP+0xef000
            value=self.next_table|3;self.next_table+=4096;self.w(value&~4095,bytes(4096));self.w(slot,f.q(value))
        table=value&~4095
    slot=table+8*((address>>12)&511);self.leaves[address]=slot;self.level_entries[(address,1)]=slot
    self.w(slot,f.q(address|1|(2 if rw else 0)|((1<<63)if nx else 0)))
 def permissions(self,address,rw,nx):
    slot=self.leaves[address];v=self.q(slot);v=(v&~(2|(1<<63)))|(2 if rw else 0)|((1<<63)if nx else 0);self.w(slot,f.q(v))
    self.u.mem_protect(address,4096,UC_PROT_READ|(UC_PROT_WRITE if rw else 0)|(0 if nx else UC_PROT_EXEC))
 def environment(self,u,a,n,data):
    self.w(self.arg(0),struct.pack('<5Q2I',*self.env));u.reg_write(UC_X86_REG_RAX,1)
    sp=u.reg_read(UC_X86_REG_RSP);u.reg_write(UC_X86_REG_RIP,self.q(sp));u.reg_write(UC_X86_REG_RSP,sp+8)
 def handle(self):
    if self.arg(0)==self.entry_image:self.w(self.arg(2),f.q(self.self_li));return 0
    return super().handle()
 def locate(self):
    if self.r(self.arg(0),16)==CPU_GUID:
        if self.cpu_missing:return f.ERR(14)
        self.w(self.arg(2),f.q(self.cpu));return 0
    return super().locate()
 def allocate_pages(self):
    assert(self.arg(0),self.arg(1),self.arg(2))in[(1,3,3),(1,4,3)]
    assert self.q(self.arg(3))==0x7fffffff
    if self.allocate_page_error:return f.ERR(9)
    if self.allocate_wrong is not None:self.w(self.arg(3),f.q(self.allocate_wrong));return 0
    assert not self.page_allocated;self.page_allocated=True;self.owned_type=self.arg(1)
    self.desc=[x for x in self.desc if not OWN<=x[1]<OWN+0x10000]
    self.desc.extend([(7 if self.allocate_wrong_type else self.owned_type,OWN,0x3000,0),(7,OWN+0x3000,0xd000,0)])
    self.w(self.arg(3),f.q(OWN));return 0
 def free_pages(self):
    assert self.arg(0)==OWN and self.arg(1)==3 and self.page_allocated
    if self.free_page_error:return f.ERR(7)
    assert all((self.q(self.leaves[OWN+i*4096])&((1<<63)|2))==2 for i in range(3))
    self.page_allocated=False;self.page_freed+=1
    if self.mutate_original_after_free and self.page_freed==1:self.w(f.TSE+0x400,bytes([self.r(f.TSE+0x400,1)[0]^1]))
    self.desc=[x for x in self.desc if not OWN<=x[1]<OWN+0x10000];self.desc.append((7,OWN,0x10000,0));return 0
 def create_event(self):
    assert self.arg(0)==0x201 and self.arg(1)==16 and self.arg(2)==f.sy['prerequisite_ending']
    self.event_live=True;self.w(self.arg(4),f.q(0xbeef));return 0
 def close_event(self):
    assert self.arg(0)==0xbeef and self.event_live
    if self.close_error:return f.ERR(7)
    self.event_live=False;return 0
 def set_attributes(self):
    self.set_count+=1
    assert self.arg(0)==self.cpu and self.arg(1)==OWN+4096 and self.arg(2)==4096 and self.page_allocated
    attrs=self.arg(3);assert not attrs&~0x24000;self.attribute_requests.append([hex(self.arg(1)),self.arg(2),hex(attrs)])
    if self.set_count==self.set_error_at:return f.ERR(3)
    if self.set_count==self.false_success_at:return 0
    self.permissions(OWN+4096,not(attrs&0x20000),bool(attrs&0x4000))
    if self.set_count==self.neighbor_change_at:self.permissions(OWN,0,0)
    return f.ERR(7)if self.set_count==self.partial_error_at else 0
 def memorymap(self):
    if self.page_allocated and self.grow_map_after_allocation:
        self.grow_map_after_allocation=False;self.w(self.arg(0),f.q(0x8000));self.w(self.arg(3),f.q(40));return f.ERR(5)
    return super().memorymap()
 def hook(self,u,a,n,data):
    if a not in self.callbacks:return super().hook(u,a,n,data)
    name,fn=self.callbacks[a]
    if self.ending_seen:self.post_ending_calls.append(name)
    self.calls.append(name);result=fn();u.reg_write(UC_X86_REG_RAX,result)
    target=self.ending_at
    trigger=target and target[0]==name and (target[1]is None or (self.set_count if name=='CpuSetMemoryAttributes'else self.calls.count(name))==target[1])
    if target and target[0]=='GetMemoryMapAfterAllocation' and name=='GetMemoryMap'and self.page_allocated:trigger=True
    if target and target[0]==name+'AfterAllocation' and self.page_allocated:trigger=True
    if trigger:
        self.ending_at=None;self.ending_seen=True
        # Execute actual notification bytes, then RET to the original service
        # caller with the already computed service result in RAX.
        u.reg_write(UC_X86_REG_RIP,f.sy['prerequisite_ending']);return
    sp=u.reg_read(UC_X86_REG_RSP);u.reg_write(UC_X86_REG_RIP,self.q(sp));u.reg_write(UC_X86_REG_RSP,sp+8)
 def invoke(self,fn,*args):
    sp=f.STACK+0xf0008;self.w(sp,f.q(f.STOP));self.u.reg_write(UC_X86_REG_RSP,sp)
    for reg,value in zip([UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9],args):self.u.reg_write(reg,value)
    self.u.emu_start(f.sy[fn],f.STOP+1,count=250000000)
    assert self.u.reg_read(UC_X86_REG_RIP)==f.STOP
    return self.u.reg_read(UC_X86_REG_RAX)
 def run(self,name,check):
    self.invoke('collect',self.st);raw=self.r(f.sy['probe_log'],self.q(f.sy['probe_log_bytes']));log=raw.decode()
    assert raw.endswith(b'SAGE_NATIVE13_PREREQUISITE04_END\r\n') and b'LOG_COMPLETE=YES' in raw
    assert not self.protected_writes and not self.outside_image_reads and not self.allocation_tail_reads
    assert self.r(self.bs,0x178)==self.before[0]and self.r(self.rt,0x88)==self.before[1]
    assert not self.post_ending_calls,self.post_ending_calls
    if not self.ending_seen:assert not self.live,self.live
    assert check(log),name+'\n'+log
    (OUT/(name+'.log')).write_bytes(raw)
    ROWS.append({'case':name,'passed':True,'log_sha256':hashlib.sha256(raw).hexdigest(),'attribute_requests':self.attribute_requests,'allocations_freed':self.page_freed,'ending_callback_executed':self.ending_seen,'no_boot_services_after_ending':not self.post_ending_calls,'zero_original_image_or_service_table_writes':True})

def main():
 v=VM();v.run('normal_code_and_data_owned_cycles',lambda s:s.count('PASS owned allocation cycle complete')==2 and'OwnedCodeReturn=000000004E313304'in s and'RetainedOwnedPages=0000000000000000'in s)
 v=VM();v.cpu_missing=True;v.run('cpu_protocol_missing_no_allocation',lambda s:not v.attribute_requests and not v.page_freed and'CPU_ARCH_ATTRIBUTE_SERVICE=UNAVAILABLE'in s)
 v=VM();v.allocate_page_error=True;v.run('allocate_pages_error_no_write',lambda s:not v.attribute_requests)
 for name,p in [('unaligned',OWN+1),('above_requested_max',0x80000000),('null',0),('foreign_module',f.TSE),('own_image',f.BASE),('DxeCore',parent.CORE),('BdsArch',parent.BDS)]:
    v=VM();v.allocate_wrong=p;v.run('allocation_'+name+'_quarantined',lambda s:not v.attribute_requests and not v.page_freed and'RetainedOwnedPages=0000000000000003'in s)
 v=VM();v.allocate_wrong_type=True;v.run('allocation_wrong_map_type_quarantined',lambda s:not v.attribute_requests and not v.page_freed)
 for step in (1,2,3,4):
    v=VM();v.set_error_at=step;v.run(f'attribute_error_step_{step}',lambda s:'OwnedSetAttributes.status=8000000000000003'in s)
 for step in (1,2,3):
    v=VM();v.false_success_at=step;v.run(f'attribute_false_success_step_{step}',lambda s:'WARN owned'in s and'PASS owned original semantic permissions restored'in s)
 v=VM();v.partial_error_at=1;v.run('attribute_partial_error_then_restore',lambda s:'PASS owned original semantic permissions restored'in s and v.page_freed==2)
 v=VM();v.neighbor_change_at=1;v.run('neighbor_permission_change_retains_pages',lambda s:'RetainedOwnedPages=0000000000000003'in s and v.page_freed==0)
 v=VM();v.free_page_error=True;v.run('free_pages_failure_retains_pages',lambda s:'RetainedOwnedPages=0000000000000003'in s)
 v=VM();v.close_error=True;v.run('close_event_failure_requires_resident_hold',lambda s:'ResidentHoldRequired=0000000000000001'in s and v.event_live)
 v=VM();v.mutate_original_after_free=True;v.run('post_service_original_text_mismatch_requires_hold',lambda s:'WARN AMITSE original text unchanged'in s and'ResidentHoldRequired=0000000000000001'in s)
 v=VM()
 for level in (1,2,3,4):
    slot=v.level_entries[(OWN+4096,level)];v.w(slot,f.q(v.q(slot)|4))
 v.run('owned_user_page_refused_before_write',lambda s:not v.attribute_requests and'RetainedOwnedPages=0000000000000003'in s)
 for name,n in [('CreateEvent',None),('AllocatePages',1),('CpuSetMemoryAttributes',1),('CpuSetMemoryAttributes',2),('CpuSetMemoryAttributes',3),('CpuSetMemoryAttributes',4),('FreePages',1),('CloseEvent',None),('GetMemoryMapAfterAllocation',None)]:
    v=VM();v.ending_at=(name,n);v.run(f'ending_during_{name}_{n}',lambda s:v.ending_seen and'ResidentHoldRequired=0000000000000001'in s)
 v=VM();v.ending_at=('GetMemoryMapAfterAllocation',None);v.grow_map_after_allocation=True;v.run('ending_during_map_growth_no_followup_services',lambda s:v.ending_seen and not v.post_ending_calls)
 for callback in ('AllocatePool','FreePool'):
    v=VM();v.ending_at=(callback+'AfterAllocation',None);v.grow_map_after_allocation=True;v.run('ending_during_map_growth_'+callback,lambda s:v.ending_seen and not v.post_ending_calls)
 # Execute the real read-only walk helper with map initialized by collect.
 v=VM();v.cpu_missing=True;v.run('walker_setup_inventory',lambda s:'CPU_ARCH_ATTRIBUTE_SERVICE=UNAVAILABLE'in s)
 table=f.HEAP+0x90000;data=b''.join(struct.pack('<IIQQQQ',typ,0,a,0,n//4096,attrs)for typ,a,n,attrs in v.desc)
 v.w(table,data);v.w(f.sy['map'],f.q(table));v.w(f.sy['map_bytes'],f.q(len(data)));v.w(f.sy['stride'],f.q(40))
 env=f.HEAP+0x7c00;out=f.HEAP+0x7d00;address=f.STACK+0x4000
 def walkcase(name,expected,alter=None,field=None,value=None):
    saved={a:v.q(a)for a in set(v.level_entries.values())};old_env=v.env[:];old_desc=v.desc[:]
    if alter:alter()
    mapped=b''.join(struct.pack('<IIQQQQ',typ,0,a,0,n//4096,attrs)for typ,a,n,attrs in v.desc);v.w(table,mapped);v.w(f.sy['map_bytes'],f.q(len(mapped)))
    v.w(env,struct.pack('<5Q2I',*v.env));ret=v.invoke('walk_with_env',address,env,out);assert ret==expected,(name,ret)
    if field is not None:assert int.from_bytes(v.r(out+field,4),'little')==value,(name,v.r(out,40).hex())
    ROWS.append({'case':name,'passed':True,'walker_return':ret})
    for a,value in saved.items():v.w(a,f.q(value))
    v.env=old_env;v.desc=old_desc
 for level in (1,2,3,4):
    slot=v.level_entries[(address,level)]
    walkcase(f'not_present_level_{level}',3,lambda a=slot:v.w(a,f.q(v.q(a)&~1)))
    def ro(a=slot):v.w(a,f.q(v.q(a)&~2))
    walkcase(f'ancestor_readonly_level_{level}',0,ro,24,0)
    def nx(a=slot):v.w(a,f.q(v.q(a)|(1<<63)))
    walkcase(f'ancestor_nx_level_{level}',0,nx,28,1)
 walkcase('nonidentity_translation_refused',5,lambda:v.w(v.leaves[address],f.q((address+4096)|3)))
 walkcase('NX_without_NXE_refused',4,lambda:(v.env.__setitem__(3,0x500),v.w(v.leaves[address],f.q(address|3|(1<<63)))))
 walkcase('reserved_top_level_largepage_bit',4,lambda:v.w(v.level_entries[(address,4)],f.q(v.q(v.level_entries[(address,4)])|128)))
 walkcase('unsupported_physical_width',1,lambda:v.env.__setitem__(5,53))
 for bit,name in [(20,'SMEP'),(21,'SMAP'),(22,'PKE'),(23,'CET'),(24,'PKS')]:walkcase('unmodeled_'+name+'_refused',1,lambda b=bit:v.env.__setitem__(2,v.env[2]|(1<<b)))
 walkcase('table_in_reserved_map_refused',2,lambda:v.desc.__setitem__(0,(0,f.HEAP,0x100000,0)))
 walkcase('table_in_readprotected_map_refused',2,lambda:v.desc.__setitem__(0,(4,f.HEAP,0x100000,0x2000)))
 walkcase('overlapping_table_map_refused',2,lambda:v.desc.append((4,v.root,4096,0)))
 for level in (2,3):
    size=1<<(12+9*(level-1));slot=v.level_entries[(address,level)]
    walkcase(f'identity_large_leaf_level_{level}',0,lambda s=slot,z=size:v.w(s,f.q((address&~(z-1))|0x83)),36,level)
    walkcase(f'large_leaf_reserved_alignment_level_{level}',4,lambda s=slot,z=size:v.w(s,f.q((address&~(z-1))|0x2083)))
 def user():
    for level in (1,2,3,4):
        slot=v.level_entries[(address,level)];v.w(slot,f.q(v.q(slot)|4))
 walkcase('effective_user_chain_observed',0,user,40,1)
 report={'status':'PASS_ACTUAL_PREREQUISITE_EFI_WITH_SYNTHETIC_SERVICES_AND_PAGE_TABLES','case_count':len(ROWS),'cases':ROWS,'efi_sha256':hashlib.sha256(f.EFI.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'scope':'Actual compiled EFI collector/walker/owned lifecycle/ending notification; CPU environment is explicit synthetic data. Real CPU queries and standard attribute service exercised separately in exact ISO OVMF. No native ASUS UI or hook installation.'}
 (OUT/'verification.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'status':report['status'],'cases':len(ROWS)}))
if __name__=='__main__':main()
