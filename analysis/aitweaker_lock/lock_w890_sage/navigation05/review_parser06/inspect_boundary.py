"""Read-only witnesses of original parser instructions; no instruction patch."""
from pathlib import Path
import hashlib,json,sys,struct
H=Path(__file__).resolve().parent;B=H.parents[1]
sys.dont_write_bytecode=True;sys.path.insert(0,str(B/'parser_catalog05'))
import replay
from unicorn import UC_HOOK_CODE
from unicorn.x86_const import *
TSE=replay.TSE
v=replay.CatalogVM(changed=False);events=[];stages=[]
setup_only='--setup-only'in sys.argv
if setup_only:v.handles=[h for h in v.handles if v.package_models[h]['module']=='Setup']
globals_=[0xbaaf0,0xbaae8,0xbabc0,0xbab08,0xbab10,0xbab18,0xbab20]
def capture(stage):
 result={'stage':stage,'globals':{hex(r):hex(v.rq(TSE+r))for r in globals_}}
 for r in [0xbab10,0xbab18,0xbab20]:
  p=v.rq(TSE+r)
  if p:
   try:result[hex(r)]={'first32':bytes(v.u.mem_read(p,32)).hex(),'static_offset':hex(p-v.static)if v.static<=p<v.static+v.static_extent else None}
   except Exception as e:result[hex(r)]={'read_error':str(e)}
 stages.append(result)
def witness(u,a,n,_):
 if a not in [TSE+0x41020,TSE+0x41052]:return
 row={'rva':hex(a-TSE),'index_r14':u.reg_read(UC_X86_REG_R14),'table_r15':u.reg_read(UC_X86_REG_R15),'blob_r13':u.reg_read(UC_X86_REG_R13),'rdx':u.reg_read(UC_X86_REG_RDX),'rcx':u.reg_read(UC_X86_REG_RCX),'r9':u.reg_read(UC_X86_REG_R9)}
 try:
  table=row['table_r15'];index=row['index_r14'];row['count']=v.rd(table);row['offset']=v.rd(table+4+4*index)
  raw=row['blob_r13']+row['offset'];row['raw_page']=hex(raw);row['raw_first32']=bytes(u.mem_read(raw,32)).hex()
 except Exception as e:row['inspection_error']=str(e)
 if a==TSE+0x41052:
  read=row['rcx']+18;row['access_address']=hex(read);row['access_static_offset']=hex(read-v.static)
  row['static_range_ok']=v.static<=read and read+2<=v.static+v.static_extent
  if not row['static_range_ok']:
   row['stopped_before_original_invalid_read']=True;events.append(row);v.error='read-only witness stopped before original invalid read';u.emu_stop();return
 events.append(row)
v.u.hook_add(UC_HOOK_CODE,witness,begin=TSE+0x41020,end=TSE+0x41052)
capture('before native initialization')
for rva in [0x19cf8,0x1b7dc,0x1c17c]:v.call(rva);capture('after '+hex(rva))
out={'scope':__doc__,'hii_fixture':'Setup only'if setup_only else'11 catalog handles','original_tse_sha256':v.original_sha,'original_spf_sha256':v.static_sha,'replay_source_sha256':hashlib.sha256(Path(replay.__file__).read_bytes()).hexdigest(),'source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'static_base':hex(v.static),'static_extent':hex(v.static_extent),'stages':stages,'events':events}
try:out['return']=hex(v.call(0x40d94))
except Exception as e:out['observed_boundary']=str(e)
capture('after stopped original parser')
out['uefi_calls']=dict(v.calls)
table=v.rq(TSE+0xbab10);count=v.rd(table);first=v.rd(table+4)
out['table_arithmetic']={'count':count,'array_valid_indices':[0,count-1],'table_start_static_offset':hex(table-v.static),'first_record_static_offset':hex(first),'array_exclusive_end_static_offset':hex(table-v.static+4+count*4),'observed_one_past_read_equals_record0':table+4+count*4==v.static+first,'header_value_at_8':v.rw(v.static+8),'formset_base_static_offset':hex(v.rq(TSE+0xbab18)-v.static),'bad_read_formula':'formset_base + (header_u16_at_8 * 20) + 18','not_established':['why the original physical platform tolerates or avoids this access','a missing native initialization step','permission to patch the original loop or map arbitrary neighboring memory']}
target=H/('setup_only_boundary.json'if setup_only else'original_boundary.json');target.write_text(json.dumps(out,indent=2)+'\n')
print(json.dumps({'events':len(events),'last':events[-1:],'table':out['table_arithmetic'],'output_sha256':hashlib.sha256(target.read_bytes()).hexdigest()},indent=2))
