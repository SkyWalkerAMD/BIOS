"""Verify the generated historical C07 publication; all source checks are local."""
from pathlib import Path
import hashlib,importlib.util,json
HERE=Path(__file__).resolve().parent;READY=HERE.parents[1]
def read(p):return json.loads(p.read_text(encoding='utf8'))
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()

def main():
    report=read(READY/'acceptance_status.json');c07=read(HERE/'validation07_result.json')
    assert report['latest_remote_validation']==c07
    assert report['latest_completed_validation_round']==7 and report['active_continuation']=='continuation08'
    assert not report['production_release_completed'] and not report['firmware_upload_performed'] and not report['firmware_flashing_performed']
    assert c07['raw_QR_pages_verified']==28 and c07['completed_diagnostic_captures']==4
    assert c07['interrupted_attempts_without_result']==1 and c07['frozen_file_bindings_verified']==985
    assert c07['binding_count_is_not_unique_file_count'] and len(report['three_major_gaps_zh'])==3
    for name,item in report['evidence'].items():assert sha(READY/name)==item['sha256'],name
    spec=importlib.util.spec_from_file_location('publication07_checks',READY/'publish_readiness.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    module.verify_bound_tree({k:v for k,v in c07.items() if k!='evidence_links'})
    old=read(READY/'remote_only/continuation06/validation06_result.json')
    assert old==report['prior_remote_validation06']
    assert sha(Path(c07['prior_continuation06_preserved']['path']))==c07['prior_continuation06_preserved']['sha256']
    assert c07['internal_image_unchanged']['sha256']==report['latest_internal_image_sha256']=='b1223ca05cf9630382e5fc014457d3c6343aaf7d970b58e5769950200f65ac02'
    for p in [READY.parents[1]/'requirements.json',READY.parents[2]/'requirements.json']:
        status=read(p)['production_release_work'];assert not status['release_ready'] and not status['flashing_performed']
        assert status['latest_completed_validation_round']==7 and status['active_continuation']=='continuation08'
    result={'status':'PASS_LOCAL_PUBLICATION_CONSISTENCY_AND_BINDINGS','evidence_links_verified':len(report['evidence']),
        'raw_QR_pages':28,'frozen_binding_count':985,'binding_count_is_not_unique_files':True,
        'historical_cleanup_only':True,'active_continuation':'continuation08','release_ready':False,
        'prior_C06_preserved':True,'N12_image_preserved':True,
        'files':{str(p.relative_to(READY)).replace('\\','/'):sha(p) for p in [HERE/'validation07_result.json',HERE/'publish_validation07.py',READY/'publish_readiness.py',READY/'acceptance_status.json',READY/'检查报告.html']}}
    (HERE/'publication07_check.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf8')
    print(json.dumps({'status':result['status'],'evidence_links_verified':len(report['evidence']),'release_ready':False}))
if __name__=='__main__':main()
