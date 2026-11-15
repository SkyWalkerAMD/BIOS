from pathlib import Path
import hashlib,json,struct,uuid
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[3];PRE=ROOT/'analysis/workstation_20261008'
inv=json.loads((PRE/'W890_SAGE_0603/inventory.json').read_text())
m=next(m for m in inv['modules'] if m['guid']=='FE612B72-203C-47B1-8560-A66D946EB371')
s=next(s for s in m['sections'] if s['type']=='Freeform subtype GUID');source=PRE/s['path'];b=source.read_bytes()
assert len(b)==s['size'] and hashlib.sha256(b).hexdigest()==s['sha256']
(HERE/'inputs/AMITSESetupData.bin').write_bytes(b)
def u32(at):return struct.unpack_from('<I',b,at)[0]
print(json.dumps(dict(header=b[:0x48].hex(),header_u32=[hex(u32(x)) for x in range(0,0x48,4)])))
base=u32(0x34);count=u32(base)
assert 0<count<2048 and base+4+count*4<=len(b)
items=[]
for index in range(count):
 off=base+u32(base+4+4*index)
 assert off+0x7c<=len(b)
 assert off==base+4+count*4+index*0x7c
 rawname=b[off+16:off+96];units=struct.unpack('<40H',rawname)
 assert 0 in units;name=rawname[:units.index(0)*2].decode('utf-16le')
 flags=u32(off+0x68)
 direct=bool(flags&0x1000 or index<=0x39 and (0x3ff800003fcfffe>>index)&1)
 items.append(dict(native_index=index,descriptor_offset=off,guid=str(uuid.UUID(bytes_le=b[off:off+16])),name=name,
                   attributes=u32(off+0x60),identifier=u32(off+0x64),flags=flags,
                   field_6c=u32(off+0x6c),field_70=u32(off+0x70),field_74=u32(off+0x74),declared_size=struct.unpack_from('<H',b,off+0x78)[0],
                   commit_route='skip' if flags&2 else 'SetVariable' if direct else 'RouteConfig',descriptor_hex=b[off:off+0x7c].hex()))
result=dict(source=str(source),source_sha256=s['sha256'],bytes=len(b),variable_table_offset=base,count=count,items=items,
            native_index_is_not_IFR_varstore=True)
(HERE/'native_variable_catalog.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(dict(count=count,table=hex(base),selected=[{k:e[k] for k in ['native_index','name','attributes','identifier','flags','declared_size','commit_route']} for e in items if e['native_index'] in [0,1,2,5,94,95,99]]),indent=2))
