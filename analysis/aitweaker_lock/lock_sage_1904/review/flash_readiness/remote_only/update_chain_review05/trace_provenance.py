from pathlib import Path
import json,re,struct,sys
sys.dont_write_bytecode=True
from inspect_chain import HERE,BASE,FILES,Elf32,disassemble,sha
FILES.update({'ini':HERE/'official_inputs/5308416/usr/local/lib/libiniparser.so.13.2.0',
              'daemon':HERE/'official_inputs/5308416/usr/local/bin/compmanager'})
def refs(elf,va):
    return [{'offset':hex(m.start()),'va':hex(next((s['va']+m.start()-s['offset'] for s in elf.sections if s['type']!=8 and s['offset']<=m.start()<s['offset']+s['size']),0)),'literal':elf.literal(next((s['va']+m.start()-s['offset'] for s in elf.sections if s['type']!=8 and s['offset']<=m.start()<s['offset']+s['size']),0))} for m in re.finditer(re.escape(struct.pack('<I',va)),elf.data)]
def main():
    out={}
    for name in ['daemon','ini','feature','bios','rest']:
        elf=Elf32(FILES[name]);d=out[name]={'path':str(FILES[name]),'sha256':sha(elf.data),'symbols':[s for s in elf.symbols if re.search('corefeatures|Feature|Ini|iniparser|GetComp',s['name'])],'literal_refs':{}}
        symbols=[s for s in elf.symbols if s['section_index'] and (s['info']&15)==2 and re.search('IniLoadFile|iniparser_loaddef|iniparser_add_entry|iniparser_getstring',s['name'])]
        if name=='daemon':symbols+=[{'name':'main_ghidra','va':0x10f2c,'size':0x228}]
        if name=='rest':
            for token in [b'core_features',b'/api/feature',b'features',b'/api/maintenance/bios/verifySignature']:
                for m in re.finditer(re.escape(token),elf.data):
                    off=m.start();va=next((s['va']+off-s['offset'] for s in elf.sections if s['type']!=8 and s['offset']<=off<s['offset']+s['size']),0)
                    text=elf.string(va)
                    d['literal_refs'][hex(va)]={'text':text,'references':refs(elf,va)}
            for va in [0x14a3a4,0x14b62c,0x137f1c]:d['literal_refs'][hex(va)]={'function':elf.names.get(va),'references':refs(elf,va)}
        for sym in symbols:
            report,text=disassemble(elf,sym);target=HERE/'disassembly'/name;target.mkdir(parents=True,exist_ok=True)
            (target/(sym['name']+'.txt')).write_text(text,encoding='utf-8')
            d.setdefault('functions',{})[sym['name']]=report
    (HERE/'feature_provenance.json').write_text(json.dumps(out,indent=2),encoding='utf-8')
    print(json.dumps({k:{'symbols':v['symbols'],'refs':v['literal_refs']} for k,v in out.items() if k in ('daemon','rest')},indent=2))
if __name__=='__main__':main()
