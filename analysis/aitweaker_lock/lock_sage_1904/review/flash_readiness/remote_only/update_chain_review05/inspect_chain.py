"""Read-only local ELF/configuration inspection for BMC update chain review 05."""
from pathlib import Path
import hashlib, importlib.util, json, re, struct, sys
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
BASE = HERE.parent
ROOT = next(p for p in HERE.parents if (p/'tools/pydeps').is_dir())
sys.path.insert(0, str(ROOT/'tools/pydeps'))
spec=importlib.util.spec_from_file_location('elf_evidence', BASE/'component_backend_review/build_component_evidence.py')
mod=importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
Elf32=mod.Elf32
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM
LIB = BASE/'bmc_backend/5308416/usr/local/lib'
FILES = {'feature':LIB/'libfeaturedefine.so.13.6.6',
         'bios':LIB/'libcompamibios.so.13.0.1',
         'manager':LIB/'libcomponent_manager.so.13.8.3',
         'helper':LIB/'libcomponent_manager_helper.so.13.3.4',
         'rest':BASE/'bmc_backend/5308416/usr/local/bin/spx_restservice',
         'flash':LIB/'libflash.so.13.3.10'}
def sha(b): return hashlib.sha256(b).hexdigest()
def load(label): return Elf32(FILES[label])
def functions(elf, pattern):
    return [s for s in elf.symbols if s['section_index'] and (s['info']&15)==2 and re.search(pattern,s['name'])]
def disassemble(elf,sym):
    off=elf.offset(sym['va'],sym['size']); assert off is not None
    md=Cs(CS_ARCH_ARM,CS_MODE_ARM); md.detail=True
    lines=[]; rows=[]
    for i in md.disasm(elf.data[off:off+sym['size']],sym['va']):
        row={'va':hex(i.address),'bytes':i.bytes.hex(),'instruction':i.mnemonic+' '+i.op_str}
        tail=''
        if i.mnemonic in ('bl','blx','b') and i.op_str.startswith('#'):
            target=int(i.op_str[1:],0)
            if target in elf.names:
                row['target']=elf.names[target]; tail=' ; '+elf.names[target]
        m=re.match(r'[^,]+, \[pc, #(\-?0x[0-9a-f]+|\-?\d+)\]',i.op_str)
        if i.mnemonic.startswith('ldr') and m:
            literal=elf.literal(i.address+8+int(m.group(1),0));row['literal']=literal
            tail+=' ; '+json.dumps(literal,ensure_ascii=False)
        lines.append(f"{i.address:08x} {i.bytes.hex()} {i.mnemonic} {i.op_str}{tail}")
        rows.append(row)
    return {'symbol':sym,'bytes_sha256':sha(elf.data[off:off+sym['size']]),'instructions':rows},'\n'.join(lines)+'\n'
def main():
    patterns={'feature':'.*','bios':'Amibios|BiosConfiguration|bios_(start_update|enter_update_mode|prepare|exit|update|verify)|verify_bios_signature|SwitchGPIO|ActiveHost',
              'manager':'Init|main|CMD_.*(Verify|Prepare|Enter|Exit|Start)',
              'helper':'Init|main', 'rest':'^(main|getWebFeatureInt|setWebFeatureInt|link_feature_lib_spx_restservice_packs|maintenance_bios|VerifySignature_func|GetFeatureList_func|getBmcFeature_func)$',
              'flash':'^(VerifyImageSign|LoadPublicKey|GetHashLength)$'}
    out={}
    for label,pattern in patterns.items():
        if not FILES[label].is_file():
            print('MISSING',label,FILES[label]);continue
        elf=load(label); target=HERE/'disassembly'/label;target.mkdir(parents=True,exist_ok=True)
        out[label]={'path':str(FILES[label]),'sha256':sha(elf.data),'functions':{},'data_symbols':[s for s in elf.symbols if re.search('feature|macro',s['name'],re.I)]}
        for sym in functions(elf,pattern):
            r,t=disassemble(elf,sym);out[label]['functions'][sym['name']]=r
            (target/(sym['name']+'.txt')).write_text(t,encoding='utf-8')
        print(label,'functions',len(out[label]['functions']))
    (HERE/'native_inspection.json').write_text(json.dumps(out,indent=2),encoding='utf-8')
    report=json.loads((BASE/'vendor_bundle_evidence.json').read_text())
    def find(o):
        if isinstance(o,dict):
            if o.get('name') in ('features','BIOSUpdateView','BIOSOOBUpdateView'):
                print(json.dumps(o,ensure_ascii=False)[:14000])
            else:
                for v in o.values():find(v)
        elif isinstance(o,list):
            for v in o:find(v)
    find(report)
if __name__=='__main__':main()
