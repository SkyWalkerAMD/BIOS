"""Bind supplementary provenance without rewriting the stable catalog."""
from pathlib import Path
import hashlib,json,struct,sys,uuid
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[3]
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile
def sha(b):return hashlib.sha256(b).hexdigest()
def bind(p):
    p=Path(p);b=p.read_bytes();return dict(path=p.resolve().relative_to(ROOT).as_posix(),bytes=len(b),sha256=sha(b))
def save(p,x):p.write_text(json.dumps(x,ensure_ascii=False,indent=2)+'\n',encoding='utf8')
def main():
    c=json.loads((HERE/'catalog.json').read_text());cpu=next(p for p in c['packages'] if p['package_list_guid'].startswith('dbf338fe'))
    m=cpu['producer_modules'][0];b=(ROOT/m['local_pe_path']).read_bytes();pe=pefile.PE(data=b)
    def at(rva,size):return b[pe.get_offset_from_rva(rva):pe.get_offset_from_rva(rva)+size]
    assert at(0x3238,16)==uuid.UUID('ef9fc172-a1b2-4693-b327-6d32fc416042').bytes_le
    fp=cpu['forms_packages'][0];assert fp['pe_rva']==0x3284
    assert struct.unpack('<I',at(0x3280,4))[0]==fp['bytes']+4
    assert at(0x3284,fp['bytes'])==(ROOT/fp['blob_path']).read_bytes()
    ev=[]
    for n in (2,3,4,5,6,7,8):
        p=HERE/'rea05'/f'response-{n:03}.json';j=json.loads(p.read_text());assert not j.get('isError');x=j['structuredContent']
        assert x['subject']['digest']['sha256']==m['sha256']
        assert x['authority']=='shipped-artifact' and x['provider']['id']=='ghidra'
        ev.append(dict(**bind(p),evidence_id=x['evidence_id'],procedure=x['normalized_result']['procedure']['address']))
    save(HERE/'registration_provenance.json',dict(schema_version=1,status='STATIC_ORIGINAL_REGISTRATION_CONFIRMED_NOT_RUNTIME_HANDLE_ATTESTATION',catalog=bind(HERE/'catalog.json'),module=dict(ffs_guid=m['ffs_guid'],**bind(ROOT/m['local_pe_path'])),package_list_guid=cpu['package_list_guid'],driver_handle=0,registration_chain=[dict(rva=0x10f4,role='Native PE entry constructs literal DBF338FE GUID, sets DriverHandle argument to zero, passes strings-array RVA3050 and forms-array RVA3280 to22EC. All original instructions retained in REA evidence.'),dict(rva=0x1194,role='Captures Boot Services from ST+60; LocateProtocol at BS+140 with GUID bytes at3238 sets HiiDatabase pointer at34D8.'),dict(rva=0x22ec,role='Builds PackageList header and appends array bodies, strips 4-byte total-size prefixes, appends END package, calls HiiDatabase field0 (NewPackageList) with unchanged DriverHandle parameter.')],forms_array=dict(rva=0x3280,total_size=fp['bytes']+4,forms_rva=fp['pe_rva'],forms_bytes=fp['bytes'],forms_sha256=fp['sha256']),hii_database_guid=dict(rva=0x3238,hex=at(0x3238,16).hex(),guid='ef9fc172-a1b2-4693-b327-6d32fc416042'),dynamic_update_chain=[dict(rva=0x17b8,role='Original protocol notification collects CPU information and calls1380.'),dict(rva=0x1380,role='Builds insertion handles and label1234/1235 replacement; calls131C for CPU information records and2854 for update.'),dict(rva=0x131c,role='Creates STRING token then appends opcode3 (TEXT), size8, scope0 through24EC; information text is generated at runtime.'),dict(rva=0x2854,role='Uses HiiDatabase field20 (ExportPackageLists), rewrites forms with25A0, then field10 (UpdatePackageList) for the saved handle34D8/3538.')],abi_source='https://raw.githubusercontent.com/tianocore/edk2/edk2-stable202502/MdePkg/Include/Protocol/HiiDatabase.h',evidence=ev,limitations=['Static call/argument provenance proves the original producer and explains the NULL DriverHandle; it does not attest current runtime image bytes or current HII contents.','Dynamic CPU text changes mean the initial static forms-package hash is not assumed to equal the physical post-initialization package hash.','REA decompiler parameter recovery contains undefined/unaff values; original assembly and exact constants are the basis for the limited call-relationship claims. No firmware code was executed by this review.','The supplement upgrades the GetCpuInfo registration relation; stable catalog association retains its initial cautious candidate label for backwards-compatible hash binding.']))
    save(HERE/'count_reconciliation.json',dict(hardware_handles=13,hardware_forms=391,hardware_unique_package_list_guids=10,unique_static_cap_packages_with_hardware_match=9,unique_static_forms=379,unique_setup_forms=82,unique_foreign_cap_forms=297,additional_duplicate_ip4_ip6_forms=4,non_fv_unresolved_instances=2,non_fv_unresolved_forms=8,total_equation='82 + 297 + 4 + 8 = 391',native_parser_379_interpretation='The count matches the9 unique original FV producers, including297 foreign forms. Native HII=0 placeholders do not establish any runtime package-handle identity.'))
    ownership={'local_files':[],'external_files':[]}
    # policy05 is concurrently owned by root and is intentionally outside this
    # static catalog manifest. REA temp projects are ephemeral and not outputs.
    for folder in ('blobs','decoded','modules','rea05'):
        for p in sorted((HERE/folder).rglob('*')):
            if not p.is_file() or 'tmp' in p.relative_to(HERE/folder).parts:continue
            ownership['local_files'].append(bind(p))
    for name in ('scan_sources.py','build_catalog.py','verify_catalog.py','finalize_evidence.py','rea_session.mjs','UefiInternalFormRepresentation.edk2-stable202502.h','source_scan.json','direct_rip_refs.json','catalog.json','relationships.json','summary.json','verification.json','registration_provenance.json','count_reconciliation.json','variable_use_summary.json','README.txt'):
        ownership['local_files'].append(bind(HERE/name))
    paths={x['path'] for x in c['sources'].values()}
    paths.update(m['path'] for p in c['packages'] for m in p['producer_modules'])
    paths.update(m['path'] for m in c['unobserved_original_modules'])
    paths.update(('analysis/aitweaker_lock/inspect_setup.py','analysis/aitweaker_lock/inspect_forms.py'))
    for path in sorted(paths):
        p=ROOT/path
        if HERE in p.resolve().parents:continue
        ownership['external_files'].append(bind(p))
    manifest=dict(schema_version=1,status='STATIC_CATALOG_SOURCE_AND_SCOPE_VERIFIED',scope='Catalog and exact-source provenance only; no runtime authority, flash image or ordinary-page blanket permission.',excludes=['policy05/ belongs to root and is not frozen by this manifest','REA temporary projects and __pycache__'],**ownership)
    save(HERE/'component_manifest.json',manifest)
    print(json.dumps(dict(manifest=bind(HERE/'component_manifest.json'),local_bindings=len(ownership['local_files']),external_bindings=len(ownership['external_files'])),indent=2))
if __name__=='__main__':main()
