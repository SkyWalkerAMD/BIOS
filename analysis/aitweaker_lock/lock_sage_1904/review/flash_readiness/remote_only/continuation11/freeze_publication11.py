"""Freeze the completed publication; no device access or acceptance escalation."""
from pathlib import Path
import hashlib,json
HERE=Path(__file__).resolve().parent
READY=HERE.parents[1]
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
read=lambda p:json.loads(p.read_text(encoding='utf-8-sig'))

def main():
    check=read(HERE/'publication11_check.json')
    for rel,digest in check['files'].items():assert sha(READY/rel)==digest,rel
    render=read(HERE/'publication11_render.json')
    assert render['status']=='PASS_LOCAL_HTML_LAYOUT_AND_LINKS'
    assert sha(READY/'检查报告.html')==render['report_sha256']
    for item in render['screenshots']:assert sha(HERE/item['path'])==item['sha256']
    independent=HERE/'independent_publication11_review/independent_review.json'
    assert sha(independent)=='a77a03d0aa69970cf1c7fd4835cde94119ad484d03c4af30f8c76abb2f187c7a'
    names=['publish_validation11.py','validation11_result.json','publication11_check.json','verify_report11.mjs','publication11_render.json',
           'publication11-top.png','publication11-middle.png','publication11-bottom.png','freeze_publication11.py']
    files=[HERE/n for n in names]+sorted((HERE/'publication11_snapshot').glob('*'))+[independent]
    report={'status':'FROZEN_COMPLETED_C11_PUBLICATION_NOT_RELEASE_READY',
            'visual_review':'Root inspected top and bottom PNG: readable text/table, no horizontal clipping; middle equals bottom for this short report.',
            'independent_render_limit':'Root sandbox Edge launch failed; escalated local-only render succeeded and was visually inspected. Independent review covers bound evidence and publication scope.',
            'release_ready':False,'task_complete':False,
            'files':{str(p.relative_to(HERE)).replace('\\','/'):{'bytes':p.stat().st_size,'sha256':sha(p)} for p in files}}
    out=HERE/'publication11_manifest.json'
    data=(json.dumps(report,ensure_ascii=False,indent=2)+'\n').encode()
    if out.exists():assert out.read_bytes()==data
    else:out.write_bytes(data)
    for rel,item in report['files'].items():assert sha(HERE/rel)==item['sha256'] and (HERE/rel).stat().st_size==item['bytes']
    print(json.dumps({'status':report['status'],'bindings':len(files),'sha256':sha(out)}))

if __name__=='__main__':main()
