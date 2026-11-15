"""Pin the two static originals and the separately captured physical hashes."""
from pathlib import Path
import json,hashlib,sys
H=Path(__file__).resolve().parent;B=H.parent;ROOT=B.parents[2]
sha=lambda b:hashlib.sha256(b).hexdigest()
c=json.loads((B/'foreign_hii05/catalog.json').read_text());physical=json.loads((B/'hardware_hii06/reconciled01.json').read_text())
(H/'inputs').mkdir(exist_ok=True);out=[]
for package in c['packages']:
    for module in package['producer_modules']:
        if module['module_name'] not in ['NvmeDynamicSetup','SocketSetup']:continue
        p=ROOT/module['local_pe_path'];data=p.read_bytes();assert sha(data)==module['sha256'];(H/'inputs'/(module['module_name']+'.efi')).write_bytes(data)
        forms=[]
        for original in package['forms_packages']:
            f=ROOT/original['blob_path'];blob=f.read_bytes();assert sha(blob)==original['sha256'];(H/'inputs'/(module['module_name']+'.forms.bin')).write_bytes(blob)
            forms.append({k:original[k]for k in ['bytes','sha256','blob_path','pe_offset','pe_rva','decoded_path']})
        live=next(i for i in physical['hii_instances']if i['guid'].lower()==package['package_list_guid'])
        out.append({'module':module['module_name'],'original_pe_path':module['local_pe_path'],'original_pe_sha256':module['sha256'],'entry_rva':module['entry_rva'],'forms':forms,'physical':live})
result={'status':'INPUTS_PINNED_STATIC_AND_PHYSICAL_HASHES_DISTINCT','catalog_sha256':sha((B/'foreign_hii05/catalog.json').read_bytes()),'capture_sha256':sha((B/'hardware_hii06/capture01.json').read_bytes()),'reconciled_sha256':sha((B/'hardware_hii06/reconciled01.json').read_bytes()),'physical_log_sha256':physical['log']['sha256'],'modules':out,'physical_forms_bytes_available_here':False,'runtime_authorized':False}
(H/'inputs.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps([{ 'module':m['module'],'baseline':[(f['bytes'],f['sha256'])for f in m['forms']],'observed':[(f['bytes'],f['sha256'])for f in m['physical']['forms_packages']]}for m in out],indent=2))
