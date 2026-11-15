"""Record original SAGE FV allocation and all component byte hashes."""
from pathlib import Path
import hashlib,json,lzma,struct,sys
HERE=Path(__file__).resolve().parent
BASE=HERE.parents[1]
sys.path.insert(0,str(BASE/'lock_1904/lab'))
from inject_ovmf import valid_fv,find_free
CAP=BASE/'official_W790E_SAGE_SE_1904/W790E_SAGE_SE_1904/Pro-WS-W790E-SAGE-SE-ASUS-1904.CAP'
data=CAP.read_bytes();outer=0x3181000;container=outer+0x78;section=container+24
size=int.from_bytes(data[container+20:container+23],'little');aligned=(size+7)&~7
sn=int.from_bytes(data[section:section+3],'little');raw=lzma.decompress(data[section+24:section+sn],format=lzma.FORMAT_ALONE)
free,available,files=find_free(data,outer)
innerfree,inneravailable,innerfiles=find_free(raw,16)
following=next(x for x in files if int(x['offset'],16)>=container+aligned)
report={'source_sha256':hashlib.sha256(data).hexdigest(),'outer_fv_offset':hex(outer),'outer_fv_bytes':valid_fv(data,outer)[0],'outer_fv_header_bytes':valid_fv(data,outer)[1],'container_offset':hex(container),'container_ffs_bytes':size,'container_aligned_allocation':aligned,'container_alignment_bytes_hex':data[container+size:container+aligned].hex(),'next_outer_file_offset':following['offset'],'next_outer_file_guid':following['guid'],'outer_free_offset':hex(free),'outer_free_bytes':available,'outer_files':files,'inner_fv_offset':16,'inner_fv_bytes':valid_fv(raw,16)[0],'inner_fv_header_bytes':valid_fv(raw,16)[1],'inner_free_offset':hex(innerfree),'inner_free_bytes':inneravailable,'inner_files':innerfiles,'inner_ffs_count':len(innerfiles),'outer_ffs_count':len(files),'raw_decompressed_sha256':hashlib.sha256(raw).hexdigest(),'raw_decompressed_bytes':len(raw),'scope':'Read-only original layout. Recompression fit and modified integrity remain untested.'}
(HERE/'container_layout.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf8')
print(json.dumps({k:v for k,v in report.items() if k not in ('outer_files','inner_files')},indent=2))
