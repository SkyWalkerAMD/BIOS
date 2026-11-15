"""Validate every original SPF page descriptor against its declared regions."""
from pathlib import Path
import json,struct,hashlib,uuid,collections
H=Path(__file__).resolve().parent;B=H.parent
inv=json.loads((H/'original_inventory.json').read_text());raw=Path(inv['original_source']).read_bytes()
def d(at):return struct.unpack_from('<I',raw,at)[0]
def w(at):return struct.unpack_from('<H',raw,at)[0]
table=d(0x2c);count=d(table);data_end=d(0x30);gt=d(0x40);gc=d(gt);gb=gt+d(gt+4)
catalog=json.loads((B/'foreign_hii05/catalog.json').read_text()); forms={}
modules=[]
for package in catalog['packages']:
    if not package['producer_modules']:continue
    modules.append((package['producer_modules'][0]['module_name'],package['forms_packages']))
for module in catalog['unobserved_original_modules']:modules.append((module['module_name'],module['forms_packages']))
for module,packages in modules:
    for package in packages:
        for formset in package['formsets']:
            for form in formset['forms']:
                forms[(formset['guid'],form['form_id'])]={'module':module,'title':form['title']}
rows=[]
offsets=[d(table+4+4*i)for i in range(count)]
assert offsets[0]==table+4+4*count
for i,off in enumerate(offsets):
    assert off%4==0 and off+32<=data_end
    gi=w(off+8);form=w(off+10);controls=d(off+28);extent=32+4*controls;limit=offsets[i+1]if i+1<count else data_end
    assert off+extent<=limit and 0<=limit-(off+extent)<8
    assert raw[off+extent:limit]==bytes(limit-off-extent)
    assert gi<gc;guid=str(uuid.UUID(bytes_le=raw[gb+20*gi:gb+20*gi+16]))
    rows.append({'index':i,'offset':off,'exclusive_end':off+extent,'padding':limit-off-extent,'guid_index':gi,'guid':guid,'form_id':form,'parent_field':w(off+18),'controls':controls,'catalog_match':forms.get((guid,form))})
assert len(rows)==379 and max(r['guid_index']for r in rows)==9 and all(r['index']==i for i,r in enumerate(rows))
out={'status':'PASS_379_ORIGINAL_RECORD_EXTENTS','scope':__doc__,'source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'spf_sha256':hashlib.sha256(raw).hexdigest(),'catalog_sha256':hashlib.sha256((B/'foreign_hii05/catalog.json').read_bytes()).hexdigest(),
     'page_table':{'offset':table,'count':count,'exclusive_end':table+4+4*count,'first_record':offsets[0],'descriptor_region_exclusive_end':data_end},
     'guid_table':{'offset':gt,'count':gc,'first_record':gb,'exclusive_end':gb+20*gc},
     'matched_catalog_pages':sum(r['catalog_match']is not None for r in rows),'unmatched_catalog_pages':[r for r in rows if r['catalog_match']is None],
     'last_valid_record':rows[-1],'nonroot_records_skipped_by_strict_end':[],'one_past_slot_is_first_record_field':True,'rows':rows}
(H/'table_contract.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({k:v for k,v in out.items()if k!='rows'},indent=2))
