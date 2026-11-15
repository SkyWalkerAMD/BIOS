"""Read original firmware images for a bounded cold-boot stack feasibility audit.

No loader, detour installation, original-file mutation or hardware interaction.
"""
from pathlib import Path
import hashlib,json,struct,sys,uuid
HERE=Path(__file__).resolve().parent;CASE=HERE.parents[2];ROOT=CASE.parents[2]
sys.path.insert(0,str(ROOT/'tools/pydeps'));import pefile
sha=lambda b:hashlib.sha256(b).hexdigest()
META=json.loads((CASE/'analysis/module_metadata.json').read_text());FV=Path(META['Setup']['source_path']).parents[2]
OUT=HERE/'boot_context';OUT.mkdir(parents=True,exist_ok=True)
sources={name:Path(META[name]['source_path'])for name in ['AMITSE','Setup']}
for name,guid in [('DxeCore','D6A2CB7F-6A18-4E2F-B43B-9920A733700A'),('BdsArch','8F4B8F82-9B91-4028-86E6-F4DB7D4C1DFF'),('WatchdogArch','F099D67F-71AE-4C36-B2A3-DCEB0EB2B7D8')]:
    files=[f for folder in FV.glob('*'+guid)for f in folder.rglob('*PE32 image section/body.bin')];assert len(files)==1;sources[name]=files[0]
rows=[]
for name,path in sources.items():
    data=path.read_bytes();dest=OUT/(name+'.original.efi');dest.write_bytes(data);pe=pefile.PE(data=data)
    sections=[{'name':s.Name.rstrip(b'\0').decode(errors='replace'),'rva':s.VirtualAddress,'virtual_size':s.Misc_VirtualSize,'raw_size':s.SizeOfRawData,'nonzero_bytes':sum(x!=0 for x in pe.get_data(s.VirtualAddress,s.Misc_VirtualSize)),'characteristics':hex(s.Characteristics)}for s in pe.sections]
    text=next(s for s in pe.sections if s.Name.rstrip(b'\0')==b'.text');xdata=next((s for s in pe.sections if s.Name.rstrip(b'\0')==b'.xdata'),None)
    candidates=[]
    if xdata:
        for section in pe.sections:
            if section.Name.rstrip(b'\0')not in [b'',b'.pdata']or section.Misc_VirtualSize%12:continue
            raw=pe.get_data(section.VirtualAddress,section.Misc_VirtualSize);functions=[];previous_end=0;bad=[]
            for i in range(0,len(raw),12):
                begin,end,unwind=struct.unpack_from('<III',raw,i)
                if not(text.VirtualAddress<=begin<end<=text.VirtualAddress+text.Misc_VirtualSize and xdata.VirtualAddress<=unwind<xdata.VirtualAddress+xdata.Misc_VirtualSize and begin>=previous_end):bad.append({'index':i//12,'begin':hex(begin),'end':hex(end),'unwind':hex(unwind)})
                previous_end=end;functions.append({'begin':begin,'end':end,'unwind':unwind})
            candidates.append({'rva':section.VirtualAddress,'bytes':section.Misc_VirtualSize,'count':len(functions),'range_validation_pass':not bad,'range_failures':bad[:12],'functions':functions})
    item={'name':name,'source':str(path),'copy':str(dest),'sha256':sha(data),'entry_rva':pe.OPTIONAL_HEADER.AddressOfEntryPoint,'image_size':pe.OPTIONAL_HEADER.SizeOfImage,'exception_directory':{'rva':pe.OPTIONAL_HEADER.DATA_DIRECTORY[3].VirtualAddress,'bytes':pe.OPTIONAL_HEADER.DATA_DIRECTORY[3].Size},'sections':sections,'candidate_runtime_function_tables':candidates}
    (OUT/(name+'.metadata.json')).write_text(json.dumps(item,indent=2)+'\n');rows.append({k:v for k,v in item.items()if k not in ['candidate_runtime_function_tables','sections']});rows[-1]['table_summaries']=[{k:v for k,v in c.items()if k!='functions'}for c in candidates]
report={'status':'ORIGINAL_UNWIND_TABLE_RANGE_AUDIT_NOT_STACK_PROOF','modules':rows,'source_sha256':sha(Path(__file__).read_bytes()),'protocol_references':[{'url':'https://raw.githubusercontent.com/tianocore/edk2/master/MdePkg/Include/Protocol/Bds.h','guid':'665e3ff6-46cc-11d4-9a38-0090273fc14d','role':'BDS Architectural Protocol'},{'url':'https://raw.githubusercontent.com/tianocore/edk2/master/MdePkg/Include/Protocol/WatchdogTimer.h','guid':'665e3ff5-46cc-11d4-9a38-0090273fc14d','role':'Watchdog Timer Architectural Protocol'}],'scope':'PE sections and candidate RUNTIME_FUNCTION ranges only. No unwind semantics, actual current stack, call-path proof or installer acceptance yet.'}
(HERE/'boot_context_audit.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'modules':[{'name':r['name'],'table_summaries':r['table_summaries']}for r in rows]}))
