"""Freeze the independent C05 container review. No firmware changes."""
from pathlib import Path
import hashlib,json
if not __debug__:raise RuntimeError('Run without -O')
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[1]
SOURCE=ROOT/'analysis/hero_ipmi_rc5_s23_20261108'
def rec(p):
    b=p.read_bytes();return {'path':p.relative_to(ROOT).as_posix(),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}
def verify(row):
    assert rec(ROOT/row['path'])==row
def main():
    names=('independent-byte-audit.json','verification-regressions.json','independent-inventory-exclusion.json')
    reports=[json.loads((HERE/n).read_text()) for n in names]
    assert all(r['passed'] for r in reports)
    pin='68cfc48a76d41f23edf093984818b64a6b13a686956666339733fe0a84e287f9'
    assert reports[0]['candidate_sha256']==pin and reports[0]['unchanged_ffs_count']==543
    assert reports[1]['cases']==20 and reports[1]['root_guards']==37
    assert reports[2]['input_sha256']['candidate']==pin and len(reports[2]['known_compiled_project_executables'])==15
    for filename,digest in reports[1]['source_sha256'].items():assert rec(SOURCE/filename)['sha256']==digest
    freeze=json.loads((SOURCE/'FROZEN-CANDIDATE05.json').read_text(encoding='utf-8'))
    verify(freeze['candidate'])
    for row in freeze['fixed_core_sources']+freeze['own_files']:verify(row)
    provenance=json.loads((SOURCE/'builder-source-provenance-final.json').read_text(encoding='utf-8'))
    verify(provenance['old_C04_CAP'])
    for pair in provenance['files']:verify(pair['source']);verify(pair['output'])
    for row in provenance['dependencies']:verify(row)
    out={'passed':True,'container_review_passed':True,'candidate':'C05 R5 + S23','candidate_sha256':pin,'candidate_bytes':33558528,
        'reports':[rec(HERE/n) for n in names],'source_provenance':rec(SOURCE/'builder-source-provenance-final.json'),'author_freeze':rec(SOURCE/'FROZEN-CANDIDATE05.json'),
        'frozen_manifest_entries_verified':len(freeze['fixed_core_sources'])+len(freeze['own_files'])+1,
        'results':{'only_two_existing_ipmi_guids_changed':True,'unchanged_ffs_vs_sectionfix':543,'original_order_and_fv_checksums':True,'capsule_header_and_outside_dxe_preserved':True,'wrapper_non_fv_and_metadata_preserved':True,'exact_frozen_r5_s23_pe_and_ffs':True,'actual_original_dxecore_section_stream_accepted':True,'former_trailing_zero_negative_rejected':True,'independent_cases':20,'author_guards':37,'stock_ffs_vs_official_preserved':541,'known_inventory_pes_excluded':15,'known_inventory_api_and_trigger_fingerprints_excluded':3},
        'runtime_evidence_separate':True,'final_zip_not_reviewed_here':True,'no_reviewer_hardware_actions':True,'old_c03_c04_sources_and_artifacts_unmodified':True,
        'limits':['This approves the exact offline C05 container structure, not its hardware FlashBack acceptance or recovery.',
            'RAM core results are separate from initial native DXE/SetupEnter timing after flashing the entire capsule.',
            'Actual host15 S23 menu binding and final package content require their own evidence; F10 LAN/watchdog/SEL writes are not established by this report.',
            'C05 retains complete P6 Setup/SPF resources. Support for old P5 resources in the runtime does not replace the native configuration resources in this capsule.']}
    p=HERE/'final-review.json';p.write_text(json.dumps(out,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(rec(p),indent=2))
if __name__=='__main__':main()
