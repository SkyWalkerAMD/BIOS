from pathlib import Path
import hashlib,json,shutil

HERE=Path(__file__).resolve().parent;D04=HERE.parent
OLD=D04/'provider13_ovmf_lab';CAND=D04/'provider14_chrome07'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
assert sha(CAND/'local_candidate_manifest.json')=='150ae9aaba738a2c70f3075d741f4875f0c9f26ce8006ca83eafd71c5e9e7019'
assert sha(CAND/'build/AiTweakerSplitProvider14.UNSIGNED.local.efi')=='495fe43ffa8ebb685c1346501a08c2d2932bc94d62809ab01b3f019d33029630'
origins=[]
for name in ['persist_ui.c','fixture_extra.inc','run_persist_ui.py']:
    p=OLD/name;out=HERE/name;assert not out.exists()
    text=p.read_text(encoding='utf8').replace('P13','P14')
    if name=='fixture_extra.inc':
        # New reviewed template is over16KiB. Allocation and protection must
        # cover each actual payload; the old lab's four-page constant is not valid.
        old='uint8_t *module[2]={tse_base,setup_base},*guards[2]={pages(3,4),pages(3,4)};'
        new='UN guard_pages[2]={(AMITSE_GUARD_BYTES+4095u)/4096u,(SETUP_GUARD_BYTES+4095u)/4096u};\n uint8_t *module[2]={tse_base,setup_base},*guards[2]={pages(3,guard_pages[0]),pages(3,guard_pages[1])};'
        assert old in text;text=text.replace(old,new)
        old='set(cpu,(uintptr_t)guards[i],16384,0x20000)'
        assert old in text;text=text.replace(old,'set(cpu,(uintptr_t)guards[i],guard_pages[i]*4096,0x20000)')
    if name=='run_persist_ui.py':
        text=text.replace("CAND=D04/'provider13'","CAND=D04/'provider14_chrome07'")
        text=text.replace('2f7738e0cdfdb75a9557cf8c7bba233d512c17ac63063fea23d8e77975566e8a','150ae9aaba738a2c70f3075d741f4875f0c9f26ce8006ca83eafd71c5e9e7019')
        text=text.replace("len(manifest['artifacts'])==60","len(manifest['artifacts'])==49")
        text=text.replace('AiTweakerSplitProvider13.UNSIGNED.local.efi','AiTweakerSplitProvider14.UNSIGNED.local.efi')
        text=text.replace('caa80df1fa6414d635d28a3b65fec1c265968482ddb66268412483eff95deca9','495fe43ffa8ebb685c1346501a08c2d2932bc94d62809ab01b3f019d33029630')
        text=text.replace('frozen_candidate_60_bindings_unchanged','frozen_candidate_49_bindings_unchanged')
    out.write_text(text,encoding='utf8',newline='\n')
    origins.append({'source':str(p),'source_sha256':sha(p),'new':str(out),'new_sha256':sha(out)})
ref=HERE/'reference';ref.mkdir()
for p in (OLD/'reference').iterdir():
    if p.is_file():shutil.copyfile(p,ref/p.name);origins.append({'source':str(p),'source_sha256':sha(p),'new':str(ref/p.name),'new_sha256':sha(ref/p.name)})
(HERE/'reference_origins.json').write_text(json.dumps({'old_lab_preserved':True,'origins':origins,'scope':'Separate TCG-only P14 fixture. Native ASUS body and DXE entrypoints are not executed; no production candidate edits.'},indent=2)+'\n')
print('Prepared independent P14 lab; no VM launched by this preparation script')
