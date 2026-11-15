"""Independent source/record consistency checks; not a runtime safety test.

Reads the published catalog and original PE slices directly. No import from the
decoder, no firmware calls, no ownership fixtures and no mutable source writes.
"""
from pathlib import Path
import collections, hashlib, json, struct, sys, uuid
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[3]
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile
def sha(b):return hashlib.sha256(b).hexdigest()
def guid(b):return str(uuid.UUID(bytes_le=b))
def u16(b,p):return struct.unpack_from('<H',b,p)[0]
def u32(b,p):return struct.unpack_from('<I',b,p)[0]
def checked_source(d):
    b=(ROOT/d['path']).read_bytes();assert sha(b)==d['sha256'],d['path']
    if 'bytes' in d:assert len(b)==d['bytes']
    return b
def main():
    catpath=HERE/'catalog.json';cat=json.loads(catpath.read_text());rels=json.loads((HERE/'relationships.json').read_text())
    assert rels['catalog_sha256']==sha(catpath.read_bytes())
    for src in cat['sources'].values():checked_source(src)
    modules={}
    for p in cat['packages']:
        for m in p['producer_modules']:
            modules[m['ffs_guid']]=dict(m,forms_packages=[q for q in p['forms_packages'] if q['producer_ffs_guid']==m['ffs_guid']])
    for m in cat['unobserved_original_modules']:modules[m['ffs_guid']]=m
    stats=collections.Counter();results=[]
    for m in modules.values():
        original=(ROOT/m['path']).read_bytes();local=(ROOT/m['local_pe_path']).read_bytes()
        assert original==local and sha(original)==m['sha256']
        pe=pefile.PE(data=original,fast_load=True)
        for sec in m['sections']:
            assert sha(original[sec['file_offset']:sec['file_offset']+sec['virtual_size']])==sec['sha256']
        for cb in m['callback_bindings']:
            off=pe.get_offset_from_rva(cb['rva']);assert off==cb['file_offset']
            assert original[off:off+cb['original_window_bytes']].hex()==cb['original_window_hex']
            stats['callback_windows']+=1
        for pp in m['forms_packages']:
            blob=(ROOT/pp['blob_path']).read_bytes();db=(ROOT/pp['decoded_path']).read_bytes();d=json.loads(db)
            assert sha(blob)==pp['sha256'] and sha(db)==pp['decoded_sha256']
            assert original[pp['pe_offset']:pp['pe_offset']+pp['bytes']]==blob
            assert len(blob)==pp['bytes']==(u32(blob,0)&0xffffff) and blob[3]==2
            assert pe.get_rva_from_offset(pp['pe_offset'])==pp['pe_rva']
            assert d['formsets']==pp['formsets']
            rs=d['records'];pos=4;stack=[];forms=0;qs=0;store_map={}
            for idx,r in enumerate(rs):
                op=blob[pos];length=blob[pos+1]&127;scope=bool(blob[pos+1]&128);raw=blob[pos:pos+length]
                assert length>=2 and len(raw)==length and r['index']==idx
                assert r['op']==op and r['size']==length and r['scope']==scope
                assert r['package_offset']==pos and r['offset']==pos+pp['pe_offset']
                assert raw.hex()==r['hex'] and r['parents']==stack
                fs=next((k for k in reversed(stack) if rs[k]['op']==14),None)
                form=next((k for k in reversed(stack) if rs[k]['op'] in (1,93)),None)
                assert r['formset_record']==fs and r['form_record']==form
                assert r['formset_guid']==(rs[fs]['guid'] if fs is not None else None)
                if op==14:
                    assert r['guid']==guid(raw[2:18]);assert length==23+16*(raw[22]&3)
                    assert scope and fs is None
                elif op in (1,93):
                    assert r['form_id']==u16(raw,2);forms+=1
                else:assert r['form_id']==(rs[form]['form_id'] if form is not None else None)
                if op in (36,37,38):
                    if op==36:
                        vg=guid(raw[2:18]);vid=u16(raw,18);size=u16(raw,20);name=raw[22:-1].decode('ascii');attrs=None
                    elif op==38:
                        vg=guid(raw[4:20]);vid=u16(raw,2);size=u16(raw,24);name=raw[26:-1].decode('ascii');attrs=u32(raw,20)
                    else:vg=guid(raw[4:20]);vid=u16(raw,2);size=name=attrs=None
                    assert (r['guid'],r['varstore_id'],r['varstore_size'],r['name'],r['attributes'])==(vg,vid,size,name,attrs)
                    assert (fs,vid) not in store_map;store_map[(fs,vid)]=r
                    stats['varstore_records']+=1
                if op in (5,6,7,8,12,15,26,27,28,35):
                    assert (r['prompt_id'],r['help_id'],r['question_id'],r['varstore_id'],r['var_offset'],r['flags'])==(*struct.unpack_from('<5H',raw,2),raw[12]);qs+=1
                    ext=[rs[k]['guid'] for k in stack if rs[k]['op']==95]
                    assert r['ancestor_guid_extensions']==ext
                    if ext:assert r['offset_unit']=='EXTENSION_DEFINED' and r['byte_width'] is None
                    if op==15:
                        assert r['dynamic']==(length==13)
                        assert r['target_form']==(u16(raw,13) if length>=15 else None)
                        assert r['target_question']==(u16(raw,15) if length>=17 else None)
                        assert r['target_formset']==(guid(raw[17:33]) if length>=33 else None)
                        assert r['device_path_string_id']==(u16(raw,33) if length==35 else None)
                        stats['reference_records']+=1
                if op==41:
                    k=stack.pop();assert rs[k]['end']==r['offset']+length
                elif scope:stack.append(idx)
                pos+=length;stats['opcode_records']+=1
            assert pos==len(blob) and not stack
            assert forms==pp['form_count']==d['form_count'] and qs==pp['question_count']==d['question_count']
            for r in rs:
                if 'varstore_resolution' not in r:continue
                if r['varstore_id']==0:assert r['varstore_resolution']=='NO_STORAGE';continue
                v=store_map[(r['formset_record'],r['varstore_id'])]
                assert r['varstore_resolution']=='UNIQUE'
                for key in ('index','guid','name','varstore_id','varstore_size','attributes','storage_kind'):assert r['varstore'][key]==v[key]
            for fs in pp['formsets']:
                for field,key in [('forms','form_id'),('questions','question_id'),('varstores','varstore_id')]:
                    values=[r[key] for r in fs[field]];assert len(values)==len(set(values))
            stats['forms']+=forms;stats['questions']+=qs;stats['forms_packages']+=1
            results.append(dict(module_name=m['module_name'],ffs_guid=m['ffs_guid'],pe_sha256=m['sha256'],forms_sha256=pp['sha256'],form_count=forms,question_count=qs,opcode_records=len(rs),status='PASS_SOURCE_AND_SCOPE_CONSISTENCY'))
    log=(ROOT/cat['sources']['hardware_log']['path']).read_text();instances=[i for p in cat['packages'] for i in p['hardware_instances']]
    assert len(instances)==13 and sum(i['forms'] for i in instances)==391
    for p in cat['packages']:
        for i in p['hardware_instances']:
            line=log.splitlines()[i['line']-1];assert p['package_list_guid'].upper() in line and i['handle'] in line
        if p['producer_modules']:assert p['observed_forms_count_agrees']
        assert not p['runtime_forms_exported'] and not p['runtime_foreign_text_hash_measured']
    result=dict(status='PASS_STATIC_CATALOG_VERIFICATION_NOT_RUNTIME_AUTHORIZATION',catalog_sha256=sha(catpath.read_bytes()),relationships_sha256=sha((HERE/'relationships.json').read_bytes()),checks=dict(stats),packages=results,unresolved_runtime_package_guids=[p['package_list_guid'] for p in cat['packages'] if not p['producer_modules']],limitations=cat['limitations'])
    (HERE/'verification.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf8')
    print(json.dumps({k:v for k,v in result.items() if k not in ('packages','limitations')},indent=2))
if __name__=='__main__':main()
