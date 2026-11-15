"""Freeze the completed publication; no device access or acceptance escalation."""
from pathlib import Path
import hashlib,json
HERE=Path(__file__).resolve().parent
READY=HERE.parents[1]
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
read=lambda p:json.loads(p.read_text(encoding='utf-8-sig'))

def main():
    check=read(HERE/'publication10_check.json')
    for rel,digest in check['files'].items():assert sha(READY/rel)==digest,rel
    render=read(HERE/'publication10_render.json')
    assert render['status']=='PASS_LOCAL_HTML_LAYOUT_AND_LINKS'
    assert sha(READY/'检查报告.html')==render['report_sha256']
    for item in render['screenshots']:assert sha(HERE/item['path'])==item['sha256']
    independent=HERE/'independent_publication10_review/independent_review.json'
    assert sha(independent)=='d288c3b6fa4f65bca5b6e992e56b28366f0be21d40414c154282adaf13e31df9'
    names=['publish_validation10.py','validation10_result.json','publication10_check.json','verify_report10.mjs','publication10_render.json',
           'publication10-top.png','publication10-middle.png','publication10-bottom.png','complete_snapshot_pages.py','freeze_publication10.py']
    files=[HERE/n for n in names]+sorted((HERE/'publication10_snapshot').glob('*'))+[independent]
    report={'status':'FROZEN_COMPLETED_C09_C10_PUBLICATION_NOT_RELEASE_READY',
            'visual_review':'Root inspected top and bottom PNG: readable text/table, no horizontal clipping; middle equals bottom for this short report.',
            'independent_render_limit':'Independent reviewer Edge launch failed; layout evidence is the separate successful root local render.',
            'release_ready':False,'task_complete':False,
            'files':{str(p.relative_to(HERE)).replace('\\','/'):{'bytes':p.stat().st_size,'sha256':sha(p)} for p in files}}
    out=HERE/'publication10_manifest.json'
    data=(json.dumps(report,ensure_ascii=False,indent=2)+'\n').encode()
    if out.exists():assert out.read_bytes()==data
    else:out.write_bytes(data)
    for rel,item in report['files'].items():assert sha(HERE/rel)==item['sha256'] and (HERE/rel).stat().st_size==item['bytes']
    print(json.dumps({'status':report['status'],'bindings':len(files),'sha256':sha(out)}))

if __name__=='__main__':main()
