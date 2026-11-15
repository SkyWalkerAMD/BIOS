from pathlib import Path
import hashlib,json,shutil,subprocess,sys
here=Path(__file__).resolve().parent;sage=here.parents[3];hw=sage/'remote_172_20_2_162'
ready=here.parents[1];candidate=ready/'native13_split_candidate/installer_design04/prerequisite_probe04'
independent=candidate.parent/'prereq04_independent_review'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def bound(p):return {'path':str(p),'bytes':p.stat().st_size,'sha256':sha(p)}
verified=[]
for folder,name,digest,count in [(candidate,'prerequisite04_manifest.json','1c70adb50d8e17c2672b091c4bc0ab8fa201a5035b3bfda1a67e017fb3033ba9',97),(independent,'review_manifest.json','771dc8792b501a9431e866b7da0e313ab34f3379dceeb42c474ba11522585f39',38)]:
    manifest=folder/name;assert sha(manifest)==digest
    rows=json.loads(manifest.read_text(encoding='utf-8'))['artifacts'];assert len(rows)==count
    for row in rows:
        p=(folder/row['path']).resolve();assert p.is_relative_to(folder.resolve())
        assert p.stat().st_size==row['bytes'] and sha(p)==row['sha256'],str(p)
    verified.append({'manifest':bound(manifest),'bindings':count})
source=hw/'operations/capture_native13_entry03.mjs'
assert sha(source)=='aec5ea48f2cd81730bf143123f293d755bc6d9c6d18f515a0c56923e3bdb6662'
text=source.read_text(encoding='utf-8').replace('native13_entry03','native13_prerequisite04').replace('native13-entry03','native13-prerequisite04').replace('entry_context_page','prerequisite_page').replace('entry-context QR capture','owned-RAM prerequisite QR capture')
dest=hw/'operations/capture_native13_prerequisite04.mjs';dest.write_text(text,encoding='utf-8',newline='\n')
decoder=hw/'read_native13_prerequisite04_qr.py'
smoke=here/'prerequisite04_decoder_smoke';smoke.mkdir(exist_ok=True)
screens=sorted((candidate/'ovmf/20261103_193613').glob('qr-[0-9][0-9].png'));assert len(screens)==6
for i,p in enumerate(screens,1):
    output=smoke/f'page-{i:02}.png';shutil.copyfile(p,output)
    subprocess.run([sys.executable,'-X','utf8',str(decoder),'frame',str(output)],check=True,capture_output=True)
completed=subprocess.run([sys.executable,'-X','utf8',str(decoder),'assemble',str(smoke)],check=True,capture_output=True)
decoded=json.loads(completed.stdout);assert decoded['bytes']==4071 and decoded['crc32']=='3A6F8B03'
assert decoded['sha256']=='268e1c1223907586984d5f795c82549d65ea89a823af678020a4a0a5b7dce842'
assert all(x==0 for x in decoded['owned_completion_fields'].values())
report={'status':'PASS_FROZEN_BINDINGS_AND_EXACT_ISO_CAPTURE_ADAPTER','scope':'Parent reviewed page walker, owned fixture, author and independent reports; transport smoke only, not additional firmware execution or hardware pass.',
        'verified':verified,'capture_source':bound(source),'capture_operation':bound(dest),'decoder':bound(decoder),
        'same_iso_smoke':decoded,'candidate_review':bound(candidate/'prerequisite04_review.json'),'independent_review':bound(independent/'independent_review.json')}
(here/'prerequisite04_parent_review.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
print(json.dumps({'status':report['status'],'verified_bindings':sum(x['bindings'] for x in verified),'operation':report['capture_operation'],'decoder':report['decoder'],'smoke_bytes':decoded['bytes'],'smoke_crc32':decoded['crc32']}))
