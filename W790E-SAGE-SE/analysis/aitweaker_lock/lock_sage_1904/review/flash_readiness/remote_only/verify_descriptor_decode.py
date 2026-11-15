"""Exercise offline descriptor boundary and mask handling, no device access."""
from pathlib import Path
import hashlib,json,struct
from decode_flash_descriptor import decode,HERE,ROOT,sha
cap=ROOT/'analysis/aitweaker_lock/official_W790E_SAGE_SE_1904/W790E_SAGE_SE_1904/Pro-WS-W790E-SAGE-SE-ASUS-1904.CAP'
assert sha(cap)=='aba26bf927de341f1859dd6b5f35645564d5aea104fb26bcc7b5a98bcd96b0b3'
b=cap.read_bytes()[4096:8192]
r=decode(b)
assert r['total_configured_bytes']==64*1024*1024 and r['component_count']==1
assert r['regions'][9]['base']==0x693000 and r['regions'][9]['limit_inclusive']==0x2ffffff
assert not r['regions'][9]['descriptor_host_read_grant']
cases=[{'name':'official_descriptor_reference_not_live_backup','passed':True}]
for name,offset,value in [
    ('bad_signature',0x10,0),('table_in_header',0x14,(int(r['map0'],16)&~255)|1),
    ('region_table_past_end',0x14,(int(r['map0'],16)&~0xff0000)|0xff0000),
    ('unsupported_component_count',0x14,int(r['map0'],16)|0x300),
    ('unreviewed_density',r['component_offset'],(int(r['component_raw'],16)&~15)|8),
    ('region_beyond_configured_density',r['region_offset']+4,0x7fff3000),
    ('region_overlaps_descriptor',r['region_offset']+4,0x00010000),
]:
    x=bytearray(b);struct.pack_into('<I',x,offset,value)
    try:decode(bytes(x))
    except ValueError:pass
    else:raise AssertionError(name)
    cases.append({'name':name,'passed':True})
for mask in [0,1,1<<9,1<<12,1<<15,0xffff]:
    x=bytearray(b);word=((mask&0xfff)<<8)|((mask>>12)&15)
    struct.pack_into('<I',x,r['host_master_offset'],word)
    got=decode(bytes(x))
    assert int(got['descriptor_host_read_mask'],16)==mask
    assert all(q['descriptor_host_read_grant']==bool(mask&(1<<q['slot'])) for q in got['regions'])
    cases.append({'name':f'synthetic_modern_read_mask_{mask:04X}','passed':True})
out={'status':'PASS_OFFLINE_REFERENCE_AND_MUTATIONS','case_count':len(cases),'cases':cases,
     'decoder_sha256':sha(HERE/'decode_flash_descriptor.py'),'test_source_sha256':sha(Path(__file__)),
     'real_hardware_access':False,'reference_capsule_sha256':sha(cap)}
(HERE/'descriptor_decode_regression.json').write_text(json.dumps(out,indent=2)+'\n',encoding='utf-8')
print(json.dumps({'status':out['status'],'cases':len(cases)}))
