"""Bind independent source-byte, machine-code and actual REA review evidence."""
from pathlib import Path
import hashlib,json,sys
H=Path(__file__).resolve().parent;B=H.parent;ROOT=B.parents[2]
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
target=B/'navigation/modules/AMITSE.efi'; target_sha=sha(target); image=pefile.PE(str(target)).get_memory_mapped_image()
textdir=H/'rea_text';textdir.mkdir(exist_ok=True)
evidence=[]
for p in sorted((H/'rea02').glob('response-*.json')):
    outer=json.loads(p.read_text());assert not outer.get('isError'),p
    s=outer.get('structuredContent',{})
    if s.get('operation') not in ['analyze_function','read_bytes','xrefs']:continue
    assert s['subject']['digest']['sha256']==target_sha
    n=s['normalized_result'];row={'file':str(p.relative_to(H)),'sha256':sha(p),'operation':s['operation'],'parameters':s['parameters'],'evidence_id':s['evidence_id'],'original_tse_sha256':target_sha}
    if s['operation']=='analyze_function':
        rva=s['parameters']['procedure'];prefix=p.parent.name+'_'+p.stem+'_'+rva
        (textdir/(prefix+'.c.txt')).write_text(n['pseudocode'].replace('\r',''),encoding='utf-8')
        (textdir/(prefix+'.asm.json')).write_text(json.dumps(n['assembly'],indent=2)+'\n')
        row.update(procedure=n['procedure'],callers=n['callers'],callees=n['callees'],instruction_count=len(n['assembly']),facet_availability=n['facet_availability'])
    elif s['operation']=='read_bytes':
        address=int(n['address'],16);code=bytes.fromhex(n['bytes_hex']);assert n['complete'] and n['returned_bytes']==n['requested_bytes']==len(code)
        assert code==image[address:address+len(code)]
        row.update(exact_original_bytes_verified=True,returned_bytes=len(code),bytes_sha256=hashlib.sha256(code).hexdigest())
    else:row['references']=n
    evidence.append(row)
assert sum(x['operation']=='analyze_function'for x in evidence)==6
assert sum(x['operation']=='read_bytes'for x in evidence)==2
assert sum(x['operation']=='xrefs'for x in evidence)==3
(H/'rea_summary.json').write_text(json.dumps(evidence,indent=2)+'\n')
for run in ['rea','rea02']:
    closed=json.loads((H/run/'final-close.json').read_text());assert not closed.get('isError') and closed['structuredContent']['result'] is None
failure=json.loads(json.loads((H/'rea/response-002.json').read_text())['content'][0]['text'])['error']
assert failure['code']=='provider_timeout'
recovery={'initial_code':failure['code'],'startup_timeout_ms':failure['details']['timeout_ms'],'analysis_log_observation':'Ghidra import and autoanalysis succeeded in 32 seconds before bridge connection deadline.','initial_source_queries_succeeded':False,'retry_execution':'One approved local REA/Ghidra execution with local networking permitted; no provider configuration or timeout change.','retry_succeeded':True,'all_owned_sessions_closed':True,'no_repeated_provider_failure_loop':True}
(H/'rea_recovery.json').write_text(json.dumps(recovery,indent=2)+'\n')
table=json.loads((H/'table_contract.json').read_text());checks=json.loads((H/'boundary_contract.json').read_text());assert checks['status']=='PASS_EIGHT_CONTRACT_CHECKS' and table['status']=='PASS_379_ORIGINAL_RECORD_EXTENTS'
result={'status':'INDEPENDENT_REVIEW_COMPLETE_NOT_RELEASE_QUALIFICATION','board':'ASUS Pro WS W890E-SAGE SE','bios':'0603','original_tse_sha256':target_sha,'original_spf_sha256':table['spf_sha256'],
 'conclusion':'The original 379-entry page table and observed initializer sequence corroborate the one-past loop in the studied replay. The count is not a maximum index and slot379 is not a sentinel. A tail-only strict comparison excludes no valid non-root shipped page, but still fails a count1 contract probe. No missing count adjustment was identified in the reviewed loader/initializer windows. Actual full startup and physical allocation context remain unresolved.',
 'mechanical_checks':{'original_page_record_extents':379,'catalog_page_matches':table['matched_catalog_pages'],'unmatched_catalog_pages':table['unmatched_catalog_pages'],'last_valid_page':table['last_valid_record'],'nonroot_page_dropped_by_strict_tail':False},
 'actual_x64_checks':{'count':8,'loop_counts':[0,1,2,379],'service_model':'41DCC lookup returns synthetic-last-package index, intentionally skips output mutation.','not_full_parser':True,'tail_only_general_bounds_fix':False},
 'rea':{'function_dossiers':6,'original_byte_ranges_verified':2,'xref_queries':3,'evidence':[{'evidence_id':e['evidence_id'],'operation':e['operation'],'parameters':e['parameters'],'file':e['file']}for e in evidence],'recovery':recovery},
 'reviewed_parent_experiment_limit':'Existing differential results compare non-null IFR opcode bytes and native types plus placeholder metadata. They do not establish equality of every raw native descriptor byte or every intermediate heap access.',
 'remaining_requirements':['Explain the physical/original startup allocation and lifecycle behavior for the read beyond the SPF declaration, or replay an accurately captured native pre-parser state.','If a parser change is proposed, review both entry and tail bound contracts and its interaction with root synthetic-page counts; it is separate from this read-only review.','Full startup, native HII callbacks, actual GUI behavior and firmware release validation remain outside these tests.'],
 'recommendation':'Do not integrate the RAM-only tail change or make a flash-ready claim solely from this review. Keep the original failure and strict-tail experiment separate until full startup evidence resolves the boundary.',
 'hardware_actions':0,'firmware_file_mutations':0,'modified_capsules_written':0,'runtime_authorized':False}
(H/'review.json').write_text(json.dumps(result,indent=2)+'\n')
inputs=[target,Path(json.loads((H/'original_inventory.json').read_text())['original_source']),B/'foreign_hii05/catalog.json',B/'parser_catalog05/replay.py',B/'parser_catalog05/investigate_boundary.py',B/'parser_catalog05/boundary_experiment.json',B/'parser_catalog05/original.json',B/'integration05/parser_lab.py']
files=[p for p in H.rglob('*') if p.is_file() and p.name!='component_manifest.json' and 'tmp'not in p.relative_to(H).parts and '__pycache__'not in p.relative_to(H).parts]
manifest={'status':'FROZEN_REVIEW_COMPONENT','excluded':'Provider temporary runtime/cache/database; bytecode cache. Analysis evidence and closure records are included.','files':[{'path':str(p.relative_to(H)).replace('\\','/'),'sha256':sha(p),'bytes':p.stat().st_size}for p in sorted(files)],'external_bindings':[{'path':str(p.relative_to(ROOT)).replace('\\','/'),'sha256':sha(p),'bytes':p.stat().st_size}for p in inputs]}
(H/'component_manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
for row in manifest['files']:assert sha(H/row['path'])==row['sha256']
for row in manifest['external_bindings']:assert sha(ROOT/row['path'])==row['sha256']
print(json.dumps({'review_sha256':sha(H/'review.json'),'manifest_sha256':sha(H/'component_manifest.json'),'local_bindings':len(manifest['files']),'external_bindings':len(inputs),'actual_x64_tests':8,'mechanical_page_checks':379,'rea_function_dossiers':6,'closed':True},indent=2))
