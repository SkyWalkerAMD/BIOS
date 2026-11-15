"""Independent ELF symbols/relocations/ARM bytes for the current-version Ghidra output."""
from pathlib import Path
import hashlib, importlib.util, json, re, struct, sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[4]
HELPER=ROOT/'analysis/aitweaker_lock/lock_sage_1904/review/flash_readiness/remote_only/component_backend_review/build_component_evidence.py'
spec=importlib.util.spec_from_file_location('elf_readonly',HELPER)
mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
Elf32=mod.Elf32
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM
FILES={'pdk':'usr/local/lib/libpdkapp.so.13.2.0','bios':'usr/local/lib/libcompamibios.so.6.12.0',
 'flash':'usr/local/lib/libflash.so.13.3.0','rest':'usr/local/bin/spx_restservice',
 'host':'usr/local/lib/libhosthelper.so.6.4.0','manager':'usr/local/lib/libcomponent_manager.so.13.8.0',
 'feature':'usr/local/lib/libfeaturedefine.so.13.6.0','helper':'usr/local/lib/libcomponent_manager_helper.so.13.3.0'}
def sha(b):return hashlib.sha256(b).hexdigest()
def main():
 report={'method':'Actual official 1.3.13 bytes: Ghidra headless decompilation cross-bound to independent ELF32 symbols, relocations and Capstone ARM instruction bytes.',
  'not_REA_ELF':'REA Windows Ghidra provider explicitly rejected ELF; rejection is response-020.json in rea_ace_secflash_elevated01.',
  'hardware_access':False,'firmware_execution':False,'libraries':{}}
 for label,file in FILES.items():
  path=HERE/'bmc1313_inputs'/file;e=Elf32(path);ddir=HERE/f'bmc1313_{label}_decompile'
  inv=json.loads((ddir/'function_inventory.json').read_text(encoding='utf8'))
  assert inv['executable_sha256']==sha(e.data)
  funcs={s['name']:s for s in e.symbols if s['section_index'] and (s['info']&15)==2}
  rows={};biases=set();out=HERE/'bmc1313_annotated'/label;out.mkdir(parents=True,exist_ok=True)
  for f in inv['functions']:
   if not f.get('pseudocode_file') or f['name'] not in funcs:continue
   s=funcs[f['name']];bias=int(f['address'],16)-s['va'];biases.add(bias)
   cp=ddir/f['pseudocode_file'];code=cp.read_text(encoding='utf8');off=e.offset(s['va'],s['size']);assert off is not None
   native=e.data[off:off+s['size']];calls=[];dis=[]
   for i in Cs(CS_ARCH_ARM,CS_MODE_ARM).disasm(native,s['va']):
    row={'elf_va':hex(i.address),'bytes':i.bytes.hex(),'instruction':i.mnemonic+' '+i.op_str}
    if i.mnemonic in ('bl','blx') and i.op_str.startswith('#'):
     row['target_elf_va']=hex(int(i.op_str[1:],0));row['target_name']=e.names.get(int(i.op_str[1:],0));calls.append(row)
    dis.append(row)
   literals={}
   for a in sorted(set(re.findall(r'(?:DAT_|PTR_)([0-9a-fA-F]{8})',code))):literals[a]=e.literal(int(a,16)-bias)
   ann='/* ELF literal/relocation annotations (Ghidra bias '+hex(bias)+').\n'+json.dumps(literals,indent=2).replace('*/','* /')+'\n*/\n'+code
   target=out/cp.name;target.write_text(ann,encoding='utf8')
   (out/(s['name']+'.instructions.json')).write_text(json.dumps(dis,indent=2)+'\n',encoding='utf8')
   rows[s['name']]={'elf_va':hex(s['va']),'ghidra_va':f['address'],'size':s['size'],'bytes_sha256':sha(native),
    'decompile_path':cp.relative_to(ROOT).as_posix(),'decompile_sha256':sha(cp.read_bytes()),
    'annotated_path':target.relative_to(ROOT).as_posix(),'annotated_sha256':sha(target.read_bytes()),'calls':calls,'literals':literals}
  assert len(biases)==1
  ent={'path':path.relative_to(ROOT).as_posix(),'sha256':sha(e.data),'ghidra_bias':hex(next(iter(biases))),
   'inventory_sha256':sha((ddir/'function_inventory.json').read_bytes()),'functions':rows,
   'imported_symbols':[s['name'] for s in e.symbols if not s['section_index'] and s['name']]}
  if label=='bios':
   table=next(s for s in e.symbols if s['name']=='amibios_cmd_tbl');ent['command_dispatch']=[]
   assert table['size']%8==0
   for d in range(0,table['size'],8):
    v=table['va']+d
    ent['command_dispatch'].append({'command':struct.unpack_from('<H',e.data,e.offset(v,2))[0],'elf_va':hex(v),'target':e.literal(v+4)})
  report['libraries'][label]=ent
 (HERE/'bmc1313_native_evidence.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf8')
 print(json.dumps({k:{'functions':len(v['functions']),'bias':v['ghidra_bias']} for k,v in report['libraries'].items()}))
if __name__=='__main__':main()
