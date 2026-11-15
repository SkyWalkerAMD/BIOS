"""Inventory static HII resources from authenticated original W890 0603 extracts.

No firmware or frozen component is modified. This preliminary inventory is not
a runtime HII identity or authorization proof.
"""
from pathlib import Path
import hashlib, json, re, struct, sys, uuid

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
BASE = ROOT / 'analysis/workstation_20261008'
sys.path.insert(0, str(ROOT / 'tools/pydeps'))
sys.path.insert(0, str(ROOT / 'analysis/aitweaker_lock'))
import pefile
from inspect_forms import NAMES

def sha(b): return hashlib.sha256(b).hexdigest()
def rel(p): return Path(p).resolve().relative_to(ROOT).as_posix()
def u16(b,p): return struct.unpack_from('<H',b,p)[0]
def u32(b,p): return struct.unpack_from('<I',b,p)[0]
def guid(b): return str(uuid.UUID(bytes_le=bytes(b)))
def save(p,x): p.write_text(json.dumps(x,ensure_ascii=False,indent=2)+'\n',encoding='utf8')

LOG = HERE.parent/'remote_172_20_2_245/hardware-inventory01-1794101290712-4fbdfdee/hardware-log.txt'
def observations():
    rows=[]
    for n,line in enumerate(LOG.read_text().splitlines(),1):
        m=re.match(r'HII ([0-9A-F-]{36}) handle=(0x[0-9A-F]+) forms=(\d+) password_controls=(\d+) main_form_2713=(\d+) main_form_2714=(\d+)',line)
        if m:
            rows.append(dict(package_list_guid=m[1].lower(), handle=m[2], forms=int(m[3]), password_controls=int(m[4]), main_form_2713=int(m[5]), main_form_2714=int(m[6]), line=n,callbacks=[]))
        m=re.match(r'  ConfigAccess\.(\w+) ([0-9A-F-]{36}|NON_FV_IMAGE) RVA=(0x[0-9A-F]+)',line)
        if m: rows[-1]['callbacks'].append(dict(method=m[1],owner_ffs_guid=m[2].lower(),rva=int(m[3],16),line=n))
        if 'HII.driver=0x0000000000000000' in line: rows[-1]['driver_is_null']=True
    return rows

def scan_forms(b):
    out=[]
    for hit in re.finditer(b'\x02\x0e',b):
        p=hit.start()-3
        if p<0 or p+6>len(b): continue
        z=u32(b,p); n=z&0xffffff
        if z>>24!=2 or n<27 or p+n>len(b): continue
        records=[]; stack=[]; q=p+4
        try:
            while q<p+n:
                op, raw=b[q:q+2]; size=raw&127; scope=bool(raw&128)
                if op not in NAMES or size<2 or q+size>p+n: raise ValueError('invalid opcode extent')
                r=dict(index=len(records),offset=q,package_offset=q-p,op=op,type=NAMES[op],size=size,scope=scope,parents=stack.copy(),hex=b[q:q+size].hex())
                records.append(r)
                if op==41:
                    if not stack: raise ValueError('END without scope')
                    records[stack.pop()]['end']=q+size
                elif scope: stack.append(len(records)-1)
                q+=size
            if q!=p+n or stack or records[0]['op']!=14: raise ValueError('unclosed stream')
            out.append(dict(offset=p,length=n,sha256=sha(b[p:p+n]),records=records,form_count=sum(r['op'] in (1,93) for r in records)))
        except (ValueError,IndexError): pass
    return out

def main():
    invpath=BASE/'W890_SAGE_0603/inventory.json'; inv=json.loads(invpath.read_text()); rows=observations()
    observed_guids=sorted({r['package_list_guid'] for r in rows})
    sources=[]; scanned=0
    for m in inv['modules']:
        for s in m['sections']:
            if s['type'] not in ('PE32 image','Raw'): continue
            path=BASE/s['path']; b=path.read_bytes()
            if sha(b)!=s['sha256']: raise ValueError('Original section hash mismatch: '+str(path))
            scanned+=1
            packs=scan_forms(b)
            hits={g:[x.start() for x in re.finditer(re.escape(uuid.UUID(g).bytes_le),b)] for g in observed_guids}
            hits={g:x for g,x in hits.items() if x}
            if not packs and not hits: continue
            item=dict(ffs_guid=m['guid'].lower(),module_name=m['name'],section_type=s['type'],path=rel(path),sha256=sha(b),size=len(b),observed_guid_byte_hits=hits,forms_packages=packs)
            if s['type']=='PE32 image':
                pe=pefile.PE(data=b,fast_load=True); item['entry_rva']=pe.OPTIONAL_HEADER.AddressOfEntryPoint; item['image_size']=pe.OPTIONAL_HEADER.SizeOfImage
                item['sections']=[dict(name=t.Name.rstrip(b'\0').decode(errors='replace'),rva=t.VirtualAddress,virtual_size=t.Misc_VirtualSize,file_offset=t.PointerToRawData,raw_size=t.SizeOfRawData,characteristics=t.Characteristics,sha256=sha(b[t.PointerToRawData:t.PointerToRawData+t.Misc_VirtualSize])) for t in pe.sections]
                for p in packs: p['rva']=pe.get_rva_from_offset(p['offset'])
            sources.append(item)
    save(HERE/'source_scan.json',dict(schema_version=1,inventory=dict(path=rel(invpath),sha256=sha(invpath.read_bytes())),hardware_log=dict(path=rel(LOG),sha256=sha(LOG.read_bytes())),hardware_instances=rows,sections_scanned=scanned,sources=sources))
    print(json.dumps(dict(sections_scanned=scanned,matched_sources=len(sources),forms=[dict(module=s['module_name'],guid=s['ffs_guid'],type=s['section_type'],counts=[p['form_count'] for p in s['forms_packages']],observed_guids=list(s['observed_guid_byte_hits'])) for s in sources if s['forms_packages']]),indent=2))

if __name__=='__main__': main()
