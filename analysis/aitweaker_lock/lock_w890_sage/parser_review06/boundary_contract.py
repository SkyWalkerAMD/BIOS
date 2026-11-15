"""Execute original loop bytes against its actual SPF table, with one lookup model.

The 0x41DCC formset lookup is explicitly modeled to return the synthetic-last
package index so that all eligible records skip output mutation. This isolates
the loop-bound contract and is not a parser or firmware boot test. Count 0/1/2
fixtures are semantic boundary probes; original shipped count remains 379.
"""
from pathlib import Path
import json,sys,struct,hashlib
H=Path(__file__).resolve().parent;B=H.parent;ROOT=B.parents[2]
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE, UC_HOOK_MEM_INVALID
from unicorn.x86_const import *
TSE=0x2000000; SPF=0x19000000;STACK=0x5000000;FAKE=0x6000000
source=next((ROOT/'analysis/workstation_20261008/W890_SAGE_0603').rglob('434 AMITSESetupData/0 EE4E5898-3914-4259-9D6E-DC7BD79403CF/0 FE612B72-203C-47B1-8560-A66D946EB371/body.bin'))
raw=source.read_bytes();assert len(raw)==0xf245c and raw[:4]==b'$SPF'
def q(x):return struct.pack('<Q',x)
def d(x):return struct.pack('<I',x)
def run(count,strict_end):
    u=Uc(UC_ARCH_X86,UC_MODE_64);pe=pefile.PE(str(B/'navigation/modules/AMITSE.efi'));pe.relocate_image(TSE)
    u.mem_map(TSE,0x200000);u.mem_write(TSE,pe.get_memory_mapped_image());u.mem_map(SPF,0xf3000);u.mem_write(SPF,raw)
    u.mem_map(STACK,0x10000);u.mem_map(FAKE,0x10000)
    u.mem_write(SPF+0x60,d(count));u.mem_write(TSE+0xbab10,q(SPF+0x60));u.mem_write(TSE+0xbab20,q(SPF));u.mem_write(TSE+0xbab18,q(SPF+0xf2394));u.mem_write(TSE+0xaff68,q(12))
    if strict_end:
        assert bytes(u.mem_read(TSE+0x4112c,6))==bytes.fromhex('0f86eefeffff')
        u.mem_write(TSE+0x4112c,bytes.fromhex('0f82eefeffff'))
    u.reg_write(UC_X86_REG_RSP,STACK+0x8000);u.reg_write(UC_X86_REG_R13,1);u.reg_write(UC_X86_REG_RDI,FAKE);u.reg_write(UC_X86_REG_RBX,FAKE+0x8000)
    state={'count_fixture':count,'shipped_count':379,'experimental_strict_end_in_emulator':strict_end,'indices':[],'lookup_calls':0,'stopped':None}
    def hook(u,address,size,_):
        rva=address-TSE
        if rva==0x41023:
            index=int(u.reg_read(UC_X86_REG_R14));state['indices'].append(index)
            if index>=count:state['stopped']={'kind':'DECLARED_ARRAY_BOUND','rva':hex(rva),'index':index};u.emu_stop()
        elif rva==0x41dcc:
            state['lookup_calls']+=1;sp=u.reg_read(UC_X86_REG_RSP);target=struct.unpack('<Q',u.mem_read(sp,8))[0]
            u.reg_write(UC_X86_REG_RAX,11);u.reg_write(UC_X86_REG_RSP,sp+8);u.reg_write(UC_X86_REG_RIP,target)
        elif rva in (0x41132,0x41139):state['stopped']={'kind':'LOOP_EXIT','rva':hex(rva)};u.emu_stop()
    def guard(u,access,address,size,value,_):
        if address+size>SPF+len(raw):state['stopped']={'kind':'SPF_EXTENT','address':hex(address),'size':size};u.emu_stop()
    u.hook_add(UC_HOOK_CODE,hook);u.hook_add(UC_HOOK_MEM_READ|UC_HOOK_MEM_WRITE,guard,begin=SPF,end=SPF+0xf2fff)
    try:u.emu_start(TSE+0x40fff,0,count=1000000)
    except Exception as e:state['exception']=str(e)
    return state
results=[run(n,strict)for n in [0,1,2,379]for strict in [False,True]]
for r in results:
    if r['count_fixture']>=2 and r['experimental_strict_end_in_emulator']:
        assert r['stopped']['kind']=='LOOP_EXIT' and r['indices']==list(range(1,r['count_fixture']))
    elif r['count_fixture']>=1:
        assert r['stopped']['kind']=='DECLARED_ARRAY_BOUND' and r['indices'][-1]==r['count_fixture']
    else:assert r['stopped']['kind']=='LOOP_EXIT' and not r['indices']
out={'scope':__doc__,'status':'PASS_EIGHT_CONTRACT_CHECKS','original_tse_sha256':hashlib.sha256((B/'navigation/modules/AMITSE.efi').read_bytes()).hexdigest(),'original_spf_sha256':hashlib.sha256(raw).hexdigest(),'source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'results':results,
    'finding':'Strict-end experiment visits every valid non-root shipped page (1..378) and excludes only 379. Its entry condition still attempts index1 when declared count=1, so it is not a general bound fix.'}
(H/'boundary_contract.json').write_text(json.dumps(out,indent=2)+'\n')
print(json.dumps({**out,'results':[{**r,'indices':{'count':len(r['indices']),'first':r['indices'][:2],'last':r['indices'][-2:]}}for r in results]},indent=2))
