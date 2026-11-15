"""Prepare an unchanged full-app UI byte test; no recompilation or firmware execution."""
from pathlib import Path
import argparse,hashlib,json,re,shutil
HERE=Path(__file__).resolve().parent;D04=HERE.parent;TX=D04/'ram_transaction05'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
parser=argparse.ArgumentParser();parser.add_argument('--sha256',required=True);args=parser.parse_args()
src=TX/'app_build/SageNative13RamTest05.efi';assert sha(src)==args.sha256
out=HERE/('full_app_ui_'+args.sha256[:16]);out.mkdir(exist_ok=False);inputs=out/'inputs';(inputs/'source').mkdir(parents=True)
for name in ['SageNative13RamTest05.efi','app.map','app_build.json']:shutil.copyfile(TX/'app_build'/name,inputs/name)
for path in (TX/'source').iterdir():
    if path.is_file():shutil.copyfile(path,inputs/'source'/path.name)
parent=json.loads((inputs/'app_build.json').read_text());assert parent['efi_sha256']==args.sha256
for item in parent['sources']:
    path=inputs/item['path']
    if path.exists():assert sha(path)==item['sha256']
template=HERE/'ui_revision03/test_ui.py';code=template.read_text();shutil.copyfile(template,out/'suite_template.py')
old="HERE=Path(__file__).resolve().parent;TX=HERE.parents[1]/'ram_transaction05'"
assert code.count(old)==1;code=code.replace(old,"HERE=Path(__file__).resolve().parent;TX=HERE/'inputs'")
old="PE=HERE/'build/UI-EMULATION-FIXTURE-NOT-FOR-BOOT.EFI';p=pefile.PE(str(PE))"
assert code.count(old)==1;code=code.replace(old,"PE=HERE/'inputs/SageNative13RamTest05.efi';p=pefile.PE(str(PE))")
old="EXPORT={s.name.decode():BASE+s.address for s in p.DIRECTORY_ENTRY_EXPORT.symbols}"
replacement='''MAP=(HERE/'inputs/app.map').read_text()
EXPORT={}
for name in ['ui_capture_initial','ui_open_management','ui_open_original_setup','ui_restore_credential','ui_compare_original_stores','app_hold','app_log','app_number','app_result','app_ended','app_sessions','app_st','app_image','app_setup_hii','app_browser','app_hold_reason']:
    hits=re.findall(r'^\\s*\\d{4}:[a-fA-F0-9]+\\s+'+name+r'\\s+([a-fA-F0-9]+)\\s',MAP,re.M)
    assert len(hits)==1,(name,hits)
    EXPORT[name]=int(hits[0],16)
ARENA=0x70000000
for i,name in enumerate(['fixture_get','fixture_set','fixture_raise','fixture_restore','fixture_locate','fixture_list','fixture_export','fixture_send','fixture_query']):EXPORT[name]=ARENA+0x8000+i*0x20
EXPORT.update(fixture_hii=ARENA+0x300,fixture_state=ARENA+0x4000,fixture_provider_flags=ARENA+0x5000)
'''
assert code.count(old)==1;code=code.replace(old,replacement)
override='''
BaseModel=Model
class ActualFullAppModel(BaseModel):
    def call(self,name,*args):
        if name=='test_setup':
            self.u.mem_map(ARENA,0x10000)
            st,bs,rt,hii,browser,provider=ARENA,ARENA+0x100,ARENA+0x600,ARENA+0x300,ARENA+0x400,ARENA+0x700
            for key,value in [('app_st',st),('app_image',0x1111),('app_setup_hii',0x7777),('app_browser',browser)]:self.putq(EXPORT[key],value)
            self.putq(st+0x58,rt);self.putq(st+0x60,bs)
            for offset,key in [(0x18,'fixture_raise'),(0x20,'fixture_restore'),(0x140,'fixture_locate')]:self.putq(bs+offset,EXPORT[key])
            self.putd(rt+12,136);self.putd(rt+16,0x11223344);self.putq(rt+0x48,EXPORT['fixture_get']);self.putq(rt+0x58,EXPORT['fixture_set'])
            self.putq(hii+24,EXPORT['fixture_list']);self.putq(hii+32,EXPORT['fixture_export']);self.putq(browser,EXPORT['fixture_send'])
            self.putq(provider,0x3430393152504741);self.putd(provider+8,1);self.putd(provider+12,56);self.putq(provider+32,EXPORT['fixture_query']);self.putd(EXPORT['fixture_provider_flags'],1)
            # Layout is directly derived from frozen app.h/transaction.h: TX_CONTEXT720, SPLIT_CONTEXT96, RAM_SESSION856.
            session=EXPORT['app_sessions']+856;state=EXPORT['fixture_state']
            self.putq(session,0x3331585447415341);self.putd(session+8,2)
            self.putq(session+104,state);self.putq(session+112,4096)
            self.putq(session+720,0x333150534e4f4350);self.putd(session+728,1);self.putd(session+732,96)
            self.putq(session+800,state);self.putq(session+808,4096)
            self.putq(session+816,0x3333);self.putq(session+824,provider);self.putd(session+832,2);self.putd(session+844,1)
            self.putq(state+16,0x3331535441544547);self.putd(state+24,1)
            # app_require_services may inline its terminal loop. Detect its actual hold-reason store, not a replacement implementation.
            from unicorn import UC_HOOK_MEM_WRITE
            def hold_write(u,access,address,size,value,unused):
                assert size==4 and value
                self.hold=value;u.emu_stop()
            self.u.hook_add(UC_HOOK_MEM_WRITE,hold_write,begin=EXPORT['app_hold_reason'],end=EXPORT['app_hold_reason']+3)
            return ('RETURN',0)
        if name=='test_session':return ('RETURN',EXPORT['app_sessions']+856)
        if name=='test_condition':
            condition=args[0];s=self.session;state=EXPORT['fixture_state']
            if condition==1:self.putd(s+832,1)
            if condition==2:self.putd(s+8,1)
            if condition==3:self.putd(s+844,0)
            if condition==4:self.putd(s+8,3);self.putd(state+24,2)
            if condition==5:self.putq(state,1)
            if condition==6:self.putq(state+8,1)
            if condition==7:self.putq(state+16,0)
            if condition==8:self.putd(ARENA+0x600+16,0x11223345)
            if condition==9:self.putq(ARENA+0x400,0)
            if condition==10:self.putd(EXPORT['app_ended'],1)
            if condition==11:self.putd(s+20,1)
            if condition==12:self.putd(s+12,1)
            if condition==13:self.putq(s+800,state+8)
            if condition==14:self.putq(s+808,8192)
            return ('RETURN',0)
        return super().call(name,*args)
Model=ActualFullAppModel
'''
assert code.count('results=[]')==1;code=code.replace('results=[]',override+'\nresults=[]')
code=code.replace('PASS_ACTUAL_OPTIMIZED_UI_CODE_WITH_MOCKED_SERVICES_NOT_HARDWARE','PASS_ACTUAL_FULL_APP_UI_BYTES_WITH_MOCKED_BOUNDARIES_NOT_HARDWARE')
old="result={'status':'PASS_ACTUAL_FULL_APP_UI_BYTES_WITH_MOCKED_BOUNDARIES_NOT_HARDWARE',"
new=old+"\n        'actual_app_sha256':hashlib.sha256(PE.read_bytes()).hexdigest(),\n        'binding_scope':'Actual unchanged full-app UI functions and actual app_require_services execute; UEFI/provider service endpoints and pure log sink are mocked. app entry/installer do not run. No recompilation of app.',"
assert code.count(old)==1;code=code.replace(old,new)
(out/'test_full_app_ui.py').write_text(code)
build=out/'build';build.mkdir()
names=['session_ui.c','ui_bindings.h','app.h','efi.h','split_owner.h','transaction.h','provider.h','password_core.h','password_core.c','password_crypto.c']
rows=[{'path':str(inputs/'source'/name),'bytes':(inputs/'source'/name).stat().st_size,'sha256':sha(inputs/'source'/name)}for name in names]
(build/'build.json').write_text(json.dumps({'scope':'Existing full production app only; not rebuilt','pe':{'path':str(inputs/'SageNative13RamTest05.efi'),'sha256':args.sha256},'sources':rows},indent=2)+'\n')
(out/'derivation.json').write_text(json.dumps({'actual_app_sha256':args.sha256,'template_sha256':sha(template),'generated_test_sha256':sha(out/'test_full_app_ui.py'),'preparer_sha256':sha(Path(__file__)),'changes':['Full app/map supplies all actual UI and app lifecycle function bytes.','Mock service objects and the prevalidated RAM_SESSION are initialized in emulated RAM only.','The same 122 assertions run; no production source or binary is recompiled.','Terminal inline app_hold_reason write is observed to stop the emulator.']},indent=2)+'\n')
print(str(out/'test_full_app_ui.py'))
