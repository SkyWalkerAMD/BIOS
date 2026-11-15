"""Decode original HII forms, retaining native bytes and lexical FORM_SET scope.

Package-list identity is observed in the saved hardware log. Static original
forms are catalogued as candidates: that log did not export runtime forms or
hash the foreign LoadedImage .text. This script never grants runtime authority.
"""
from pathlib import Path
import collections, copy, hashlib, json, re, struct, sys, uuid
from scan_sources import HERE, ROOT, BASE, LOG, sha, rel, guid, u16, u32, save
from inspect_setup import string_packages
import pefile

QUESTION_OPS={5,6,7,8,12,15,26,27,28,35}
ZERO_GUID='00000000-0000-0000-0000-000000000000'
PROFILE_PATH=HERE.parent/'password/profile_0603.json'
NATIVE_PATH=HERE.parent/'write_sinks04/native_variable_catalog.json'

def source(path):
    b=path.read_bytes();return dict(path=rel(path),bytes=len(b),sha256=sha(b))

def enrich(pack,b,strings):
    rs=copy.deepcopy(pack['records'])
    formsets=[]; forms=[]; stores=[]; questions=[]; refs=[]; access=[]; unknown=[]
    for r in rs:
        p=r['offset']; op=r['op']; size=r['size']; raw=b[p:p+size]
        r['formset_record']=next((k for k in reversed(r['parents']) if rs[k]['op']==14),None)
        r['form_record']=next((k for k in reversed(r['parents']) if rs[k]['op'] in (1,93)),None)
        r['formset_guid']=rs[r['formset_record']]['guid'] if r['formset_record'] is not None else None
        r['form_id']=rs[r['form_record']]['form_id'] if r['form_record'] is not None else None
        if op==14:
            assert size>=23
            r.update(guid=guid(raw[2:18]),title_id=u16(raw,18),help_id=u16(raw,20),flags=raw[22])
            r['title']=strings.get(r['title_id']);r['class_guids']=[guid(raw[q:q+16]) for q in range(23,size-15,16)]
            assert len(r['class_guids'])==(r['flags']&3) and size==23+16*len(r['class_guids'])
            formsets.append(r)
        elif op in (1,93):
            assert size>=4
            r['form_id']=u16(raw,2)
            if op==1:
                assert size==6;r['title_id']=u16(raw,4);r['title']=strings.get(r['title_id'])
            else:
                assert (size-4)%18==0
                r['methods']=[dict(title_id=u16(raw,q),guid=guid(raw[q+2:q+18])) for q in range(4,size,18)]
            forms.append(r)
        elif op in (36,37,38):
            if op==36:
                assert size>=23 and raw[-1]==0
                r.update(guid=guid(raw[2:18]),varstore_id=u16(raw,18),varstore_size=u16(raw,20),name=raw[22:-1].decode('ascii'),attributes=None,storage_kind='BUFFER')
            elif op==37:
                assert size==20
                r.update(varstore_id=u16(raw,2),guid=guid(raw[4:20]),name=None,varstore_size=None,attributes=None,storage_kind='NAME_VALUE')
            else:
                assert size>=27 and raw[-1]==0
                r.update(varstore_id=u16(raw,2),guid=guid(raw[4:20]),attributes=u32(raw,20),varstore_size=u16(raw,24),name=raw[26:-1].decode('ascii'),storage_kind='EFI_VARIABLE')
            stores.append(r)
        elif op in QUESTION_OPS:
            assert size>=13
            r.update(prompt_id=u16(raw,2),help_id=u16(raw,4),question_id=u16(raw,6),varstore_id=u16(raw,8),var_offset=u16(raw,10),flags=raw[12])
            r.update(prompt=strings.get(r['prompt_id']),help=strings.get(r['help_id']),callback=bool(r['flags']&4),byte_width=None)
            if op in (5,7):
                assert size>=14;r['numeric_flags']=raw[13];r['byte_width']=1<<(raw[13]&3)
                if any(rs[k]['op']==95 for k in r['parents']):
                    r['byte_width']=None;r['extended_numeric_payload_hex']=raw[14:].hex()
                else:
                    assert size==14+3*r['byte_width']
                    w=r['byte_width'];r['min_value']=int.from_bytes(raw[14:14+w],'little');r['max_value']=int.from_bytes(raw[14+w:14+2*w],'little');r['step']=int.from_bytes(raw[14+2*w:],'little')
            elif op==6:
                assert size==14;r['byte_width']=1;r['checkbox_flags']=raw[13]
            elif op==8:
                assert size==17;r['min_size']=u16(raw,13);r['max_size']=u16(raw,15)
            elif op==28:
                assert size==16;r['min_size']=raw[13];r['max_size']=raw[14];r['string_flags']=raw[15]
            elif op in (26,27):
                assert size==14;r['date_time_flags']=raw[13];r['byte_width']=4 if op==26 else 3
            elif op==35:
                assert size==15;r['max_containers']=raw[13];r['ordered_flags']=raw[14]
            elif op==12:
                assert size in (13,15);r['question_config_string_id']=u16(raw,13) if size==15 else None
            elif op==15:
                assert size in (13,15,17,33,35)
                r.update(target_form=u16(raw,13) if size>=15 else None,target_question=u16(raw,15) if size>=17 else None,target_formset=guid(raw[17:33]) if size>=33 else None,device_path_string_id=u16(raw,33) if size==35 else None,dynamic=size==13)
                r['reference_variant']={13:'REF5',15:'REF',17:'REF2',33:'REF3',35:'REF4'}[size]
                r['target_formset_effective']=r['target_formset'] if r['target_formset'] not in (None,ZERO_GUID) else r['formset_guid']
                r['device_path_string']=strings.get(r['device_path_string_id'])
                refs.append(r)
            questions.append(r)
        elif op in (43,44):
            assert size==7
            r.update(varstore_id=u16(raw,2),var_offset=u16(raw,4),value_type=raw[6],byte_width={0:1,1:2,2:4,3:8,4:1,5:3,6:4}.get(raw[6]))
            access.append(r)
        elif op==81:
            assert size in (2,4,20)
            r.update(dynamic_question=True,device_path_string_id=u16(raw,2) if size>=4 else None,target_formset=guid(raw[4:20]) if size==20 else None)
            unknown.append(r)
        elif op==95:
            assert size>=18;r['guid']=guid(raw[2:18]);r['extension_payload_hex']=raw[18:].hex();unknown.append(r)
        elif op in (45,46,65): unknown.append(r)
    # Resolve local IDs only inside the declaring FORM_SET lexical scope.
    for r in questions+access:
        vs=[v for v in stores if v['formset_record']==r['formset_record'] and v['varstore_id']==r['varstore_id']]
        r['varstore_resolution']='NO_STORAGE' if r['varstore_id']==0 else 'UNIQUE' if len(vs)==1 else 'MISSING' if not vs else 'DUPLICATE'
        r['varstore']=({k:vs[0][k] for k in ('index','guid','name','varstore_id','varstore_size','attributes','storage_kind')} if len(vs)==1 and r['varstore_id']!=0 else None)
        r['offset_unit']='NAME_TOKEN' if r['varstore'] and r['varstore']['storage_kind']=='NAME_VALUE' else 'BYTE_CANDIDATE'
        # Any scoped GUID extension means this script cannot assert normal
        # byte semantics without identifying that extension.
        r['ancestor_guid_extensions']=[rs[k]['guid'] for k in r['parents'] if rs[k]['op']==95]
        if r['ancestor_guid_extensions']:r['offset_unit']='EXTENSION_DEFINED';r['byte_width']=None
    grouped=[]
    for fs in formsets:
        idx=fs['index']
        grouped.append(dict(record=fs,guid=fs['guid'],title=fs['title'],forms=[x for x in forms if x['formset_record']==idx],varstores=[x for x in stores if x['formset_record']==idx],questions=[x for x in questions if x['formset_record']==idx],refs=[x for x in refs if x['formset_record']==idx],variable_accesses=[x for x in access if x['formset_record']==idx],extension_record_indices=[x['index'] for x in unknown if x['formset_record']==idx]))
    return dict(records=rs,formsets=grouped,form_count=len(forms),question_count=len(questions),ref_count=len(refs),unknown_semantics_counts=dict(collections.Counter(x['type'] for x in unknown)))

def main():
    scan=json.loads((HERE/'source_scan.json').read_text());obs=scan['hardware_instances']
    protected_profile=json.loads(PROFILE_PATH.read_text()); native=json.loads(NATIVE_PATH.read_text())
    protected_stores=[x for x in native['items'] if x['native_index'] in (94,95,99)]
    for d in ('blobs','decoded','modules'): (HERE/d).mkdir(exist_ok=True)
    modules=[]
    for s in scan['sources']:
        if s['section_type']!='PE32 image' or not s['forms_packages']:continue
        b=(ROOT/s['path']).read_bytes();assert sha(b)==s['sha256'];pe=pefile.PE(data=b,fast_load=True)
        localpe=HERE/'modules'/(s['module_name']+'_'+s['ffs_guid']+'.efi');localpe.write_bytes(b)
        sm=string_packages(b);single=sm[0] if len(sm)==1 else None
        mod={k:v for k,v in s.items() if k!='forms_packages'};mod['local_pe_path']=rel(localpe)
        mod['string_packages']=[dict(offset=x['offset'],length=x['length'],sha256=sha(b[x['offset']:x['offset']+x['length']]),language='en-US',token_count=len(x['strings'])) for x in sm]
        mod['label_resolution']='UNIQUE_EN_US_IN_PRODUCER' if single else 'MULTIPLE_STRING_PACKAGES_UNRESOLVED'
        mod['forms_packages']=[]
        mod['callback_bindings']=[]
        for inst in obs:
            for cb in inst['callbacks']:
                if cb['owner_ffs_guid']==s['ffs_guid'] and not any(v['method']==cb['method'] and v['rva']==cb['rva'] for v in mod['callback_bindings']):
                    off=pe.get_offset_from_rva(cb['rva']);sec=pe.get_section_by_rva(cb['rva'])
                    assert sec and sec.Characteristics&0x20000000
                    mod['callback_bindings'].append(dict(cb,original_window_bytes=32,original_window_hex=b[off:off+32].hex(),file_offset=off,proof='HARDWARE_OWNER_FFS_GUID_AND_RVA_ONLY_FOREIGN_TEXT_HASH_NOT_CAPTURED'))
        for num,p in enumerate(s['forms_packages']):
            short=s['module_name']+'_'+str(num)
            raw=b[p['offset']:p['offset']+p['length']];bp=HERE/'blobs'/(short+'.forms.bin');bp.write_bytes(raw)
            dec=enrich(p,b,single['strings'] if single else {})
            dp=HERE/'decoded'/(short+'.json');save(dp,dict(module_source=source(localpe),forms_blob=source(bp),pe_offset=p['offset'],pe_rva=p['rva'],**dec))
            meta=dict(blob_path=rel(bp),sha256=sha(raw),bytes=len(raw),pe_offset=p['offset'],pe_rva=p['rva'],decoded_path=rel(dp),decoded_sha256=sha(dp.read_bytes()),form_count=dec['form_count'],question_count=dec['question_count'],ref_count=dec['ref_count'],formsets=dec['formsets'],unknown_semantics_counts=dec['unknown_semantics_counts'])
            mod['forms_packages'].append(meta)
        modules.append(mod)
    packages=[]
    for g in sorted({x['package_list_guid'] for x in obs}):
        instances=[x for x in obs if x['package_list_guid']==g]
        owners={c['owner_ffs_guid'] for x in instances for c in x['callbacks'] if c['owner_ffs_guid']!='non_fv_image'}
        candidates=[m for m in modules if m['ffs_guid'] in owners]
        evidence='OBSERVED_CALLBACK_OWNER_GUID_RVA_PLUS_UNIQUE_ORIGINAL_FORMS_COUNT'
        if not candidates and all(x.get('driver_is_null') for x in instances):
            candidates=[m for m in modules if g in m['observed_guid_byte_hits'] and sum(p['form_count'] for p in m['forms_packages'])==instances[0]['forms']]
            evidence='STATIC_GUID_BYTES_AND_FORM_COUNT_CANDIDATE_NULL_RUNTIME_DRIVER_REGISTRATION_REVIEW_REQUIRED'
        packs=[dict(x,producer_ffs_guid=m['ffs_guid'],producer_pe_sha256=m['sha256']) for m in candidates for x in m['forms_packages']]
        packages.append(dict(package_list_guid=g,hardware_instances=instances,producer_modules=[{k:v for k,v in m.items() if k!='forms_packages'} for m in candidates],forms_packages=packs,association=evidence if candidates else 'UNRESOLVED_NON_FV_ORIGINAL_NOT_CAPTURED',observed_forms_count_agrees=all(sum(x['form_count'] for x in packs)==i['forms'] for i in instances) if candidates else None,runtime_forms_exported=False,runtime_foreign_text_hash_measured=False))
    observed_modules={m['ffs_guid'] for p in packages for m in p['producer_modules']}
    unobserved=[m for m in modules if m['ffs_guid'] not in observed_modules]
    # Static cross-formset references are resolved against all original modules,
    # without equating a target GUID with a runtime HII handle.
    byfs=collections.defaultdict(list)
    for m in modules:
        for p in m['forms_packages']:
            for f in p['formsets']:byfs[f['guid']].append((m,p,f))
    protected_ids={x['id'] for x in protected_profile['protected_forms']}
    protected_exact={(v['guid'],v['name']) for v in protected_stores}
    relationships=[]
    for m in modules:
        qs=[q for p in m['forms_packages'] for f in p['formsets'] for q in f['questions']]
        variables=[v for p in m['forms_packages'] for f in p['formsets'] for v in f['varstores']]
        refs=[r for p in m['forms_packages'] for f in p['formsets'] for r in f['refs']]
        protected_questions=[]
        for q in qs:
            v=q['varstore'];reasons=[]
            if v and (v['guid'],v['name']) in protected_exact:
                reasons.append('EXACT_OC_VARIABLE_IDENTITY' if v['name']!='SocketMemoryConfig' else 'EXACT_SHARED_SOCKET_MEMORY_VARIABLE')
                if v['name']=='SocketMemoryConfig' and q['byte_width'] and q['offset_unit']=='BYTE_CANDIDATE':
                    if any(i in protected_profile['protected_memory_byte_offsets'] for i in range(q['var_offset'],q['var_offset']+q['byte_width'])):reasons.append('OVERLAPS_SETUP_AI_PROTECTED_MEMORY_BYTES')
            if reasons:protected_questions.append(dict(formset_guid=q['formset_guid'],form_id=q['form_id'],question_id=q['question_id'],record_index=q['index'],offset=q['offset'],varstore=v,var_offset=q['var_offset'],byte_width=q['byte_width'],prompt=q['prompt'],reasons=reasons))
        enriched_refs=[]
        for r in refs:
            targets=[]
            for tm,tp,tf in byfs.get(r['target_formset_effective'],[]):
                for ff in tf['forms']:
                    if ff['form_id']==r['target_form']:targets.append(dict(producer_ffs_guid=tm['ffs_guid'],formset_guid=tf['guid'],form_id=ff['form_id'],title=ff.get('title')))
            enriched_refs.append(dict(formset_guid=r['formset_guid'],form_id=r['form_id'],question_id=r['question_id'],record_index=r['index'],offset=r['offset'],hex=r['hex'],target_form=r['target_form'],target_formset=r['target_formset'],effective_target_formset=r['target_formset_effective'],target_question=r['target_question'],device_path_string_id=r['device_path_string_id'],dynamic=r['dynamic'],callback=r['callback'],candidate_targets=targets,setup_ai_target=(r['target_formset_effective']==protected_profile['setup_formset_guid'] and r['target_form'] in protected_ids)))
        relationships.append(dict(producer_ffs_guid=m['ffs_guid'],module_name=m['module_name'],observed=m['ffs_guid'] in observed_modules,declared_stores=[{k:v[k] for k in ('formset_guid','varstore_id','guid','name','varstore_size','attributes','storage_kind')} for v in variables],protected_variable_questions=protected_questions,references=enriched_refs,callback_question_count=sum(q['callback'] for q in qs),unresolved_varstore_questions=[dict(formset_guid=q['formset_guid'],form_id=q['form_id'],question_id=q['question_id'],record_index=q['index'],varstore_id=q['varstore_id'],resolution=q['varstore_resolution']) for q in qs if q['varstore_resolution'] in ('MISSING','DUPLICATE')]))
    catalog=dict(schema_version=1,status='STATIC_ORIGINAL_CATALOG_NOT_RUNTIME_AUTHORITY',board='ASUS Pro WS W890E-SAGE SE',bios='0603',sources=dict(cap=source(BASE/'W890_SAGE_0603/Pro-WS-W890E-SAGE-SE-ASUS-0603.CAP'),hardware_log=source(LOG),inventory=source(BASE/'W890_SAGE_0603/inventory.json'),source_scan=source(HERE/'source_scan.json'),ifr_definition=dict(**source(HERE/'UefiInternalFormRepresentation.edk2-stable202502.h'),url='https://raw.githubusercontent.com/tianocore/edk2/edk2-stable202502/MdePkg/Include/Uefi/UefiInternalFormRepresentation.h'),protected_profile=source(PROFILE_PATH),native_variable_catalog=source(NATIVE_PATH)),packages=packages,unobserved_original_modules=unobserved,limitations=['Hardware log exports counts, PackageList GUIDs and callback FFS GUID/RVAs, not runtime forms bytes or foreign module .text hashes.','Original forms are static templates; dynamic updates and option-ROM packages require runtime byte export/identity admission.','Form IDs and VarStore IDs are scoped to FORM_SET; equal IDs in different formsets are not equal objects.','Question callbacks, GUID extensions, dynamic REF5 and unresolved targets need independent behavior validation; absence of form2713 does not confer safety.','Labels come from the unique en-US package in a producer; multiple string packages are deliberately unresolved.'],protected_variable_identities=[{k:v[k] for k in ('guid','name','declared_size','attributes','native_index')} for v in protected_stores])
    save(HERE/'catalog.json',catalog);save(HERE/'relationships.json',dict(schema_version=1,catalog_sha256=sha((HERE/'catalog.json').read_bytes()),modules=relationships))
    summary=dict(hardware_handles=len(obs),hardware_forms=sum(x['forms'] for x in obs),unique_package_list_guids=len(packages),resolved_static_packages=sum(bool(p['producer_modules']) for p in packages),static_original_forms=sum(p['form_count'] for a in packages for p in a['forms_packages']),unresolved_packages=[p['package_list_guid'] for p in packages if not p['producer_modules']],all_static_forms=sum(p['form_count'] for m in modules for p in m['forms_packages']),module_results=[dict(module=r['module_name'],observed=r['observed'],protected_questions=len(r['protected_variable_questions']),memory_overlap=sum('OVERLAPS_SETUP_AI_PROTECTED_MEMORY_BYTES' in q['reasons'] for q in r['protected_variable_questions']),cross_setup_ai_refs=sum(v['setup_ai_target'] for v in r['references']),dynamic_refs=sum(v['dynamic'] for v in r['references']),unresolved_ref_targets=sum(not v['candidate_targets'] for v in r['references']),unresolved_store_questions=len(r['unresolved_varstore_questions']),callback_questions=r['callback_question_count']) for r in relationships])
    save(HERE/'summary.json',summary);print(json.dumps(summary,indent=2))

if __name__=='__main__': main()
