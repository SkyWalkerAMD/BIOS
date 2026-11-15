"""Exact final source/assets/build delta review, with frozen predecessors read-only."""
from pathlib import Path
import hashlib,json,re,struct,sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;D04=HERE.parent;OLD=D04/'ram_transaction08'
ROOT=next(p for p in HERE.parents if (p/'tools/pydeps').is_dir());sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
exec(compile((HERE/'verify_frozen_inputs.py').read_text(),str(HERE/'verify_frozen_inputs.py'),'exec'),{'__file__':str(HERE/'verify_frozen_inputs.py')})
build=json.loads((HERE/'app_build/app_build.json').read_text())
app=HERE/'app_build/SageNative13RamTest09.efi';assert sha(app)==build['efi_sha256']
for row in build['sources']:assert sha(HERE/row['path'])==row['sha256']
for name,digest in build['objects'].items():assert sha(HERE/'app_build'/name)==digest
seed=json.loads((HERE/'source_derivation.json').read_text())
for row in seed['copied']:
 if row['destination'].startswith('source'):assert sha(HERE/row['destination'])==row['sha256']
allow={'app.c','platform.c','session_ui.c','transport/kvm.c','transaction_plan.h','provider_asset.h','split_profile.h'}
rows=[]
for p in sorted((OLD/'source').rglob('*')):
 if not p.is_file():continue
 name=p.relative_to(OLD/'source').as_posix();new=HERE/'source'/name;assert new.is_file()
 same=p.read_bytes()==new.read_bytes()
 assert same or name in allow,name
 rows.append({'path':name,'old_sha256':sha(p),'new_sha256':sha(new),'unchanged':same})
assert set(p.relative_to(HERE/'source').as_posix()for p in (HERE/'source').rglob('*')if p.is_file())==set(r['path']for r in rows)|{'diagnostic09.h'}
assert (HERE/'source/diagnostic09.h').read_bytes()==(D04/'diagnostic_guard09/source/diagnostic09.h').read_bytes()
assert (HERE/'source/split_profile.h').read_bytes()==(D04/'provider15_diagnostic09/source/split_profile.h').read_bytes()
for name in ['app.c','transport/kvm.c']:
 assert (HERE/'source'/name).read_bytes()==(OLD/'source'/name).read_bytes().replace(b'TEST08',b'TEST09')
assert (HERE/'source/session_ui.c').read_bytes()==(OLD/'source/session_ui.c').read_bytes().replace(b'unique exact independent P14 HII package',b'unique exact independent P15 HII package')

oldmeta=json.loads((D04/'static_chrome_candidate07/build/split_build.json').read_text());newmeta=json.loads((D04/'diagnostic_guard09/build/split_build.json').read_text())
fixed=['module','rva','kind','length','old']
assert [{k:r[k]for k in fixed}for r in oldmeta['patches']]==[{k:r[k]for k in fixed}for r in newmeta['patches']]
assert len(newmeta['patches'])==12
for name in ['AMITSE','Setup']:
 assert oldmeta['module_fixtures'][name]['original_image_size']==newmeta['module_fixtures'][name]['original_image_size']
assert oldmeta['original_bases']==newmeta['original_bases']

asset=(HERE/'source/provider_asset.h').read_text()
body=asset.split('static const uint8_t provider_file[]={',1)[1].split('};',1)[0]
embedded=bytes(int(x)for x in body.split(','));provider=D04/'provider15_diagnostic09/build/AiTweakerSplitProvider15.UNSIGNED.local.efi'
assert embedded==provider.read_bytes();p=pefile.PE(data=embedded)
mapped=bytearray(p.get_memory_mapped_image());mapped+=bytes(p.OPTIONAL_HEADER.SizeOfImage-len(mapped))
ranges=[(0,p.OPTIONAL_HEADER.SizeOfHeaders)]+[(s.VirtualAddress,s.Misc_VirtualSize or s.SizeOfRawData)for s in p.sections]
segments=re.findall(r'\{(\d+),(\d+),\{([\d,]+)\}\}',asset.split('provider_segments[]={',1)[1].split('};',1)[0])
assert len(segments)==len(ranges)
for (a,n),(aa,nn,hh)in zip(ranges,segments):
 assert (a,n)==(int(aa),int(nn))
 assert hashlib.sha256(mapped[a:a+n]).digest()==bytes(int(x)for x in hh.split(','))
relocs=[r.rva for b in p.DIRECTORY_ENTRY_BASERELOC for r in b.entries if r.type]
assert all(r.type in[0,10]for b in p.DIRECTORY_ENTRY_BASERELOC for r in b.entries)
assert relocs==[int(x)for x in asset.split('provider_relocs[]={',1)[1].split('};',1)[0].split(',')]
assert all(any(a<=r and r+8<=a+n for a,n in ranges)for r in relocs)
symbols={n:int(a,16)-p.OPTIONAL_HEADER.ImageBase for n,a in re.findall(r'^\s+[0-9A-Fa-f]{4}:[0-9A-Fa-f]+\s+(\S+)\s+([0-9A-Fa-f]{16})',(provider.parent/'provider.map').read_text(),re.M)}
assert int(re.search(r'#define PROVIDER_OBJECT_RVA (\d+)u',asset).group(1))==symbols['native_provider']
assert [int(x)for x in asset.split('provider_method_rvas[]={',1)[1].split('};',1)[0].split(',')]==[symbols[n]for n in['provider_begin','provider_end','provider_query','provider_request','provider_manage']]
assert (D04/'provider15_diagnostic09/build/management.pack').read_bytes()==(D04/'provider14_chrome07/build/management.pack').read_bytes()

report={'status':'PASS_EXACT_TX09_SOURCE_ASSETS_AND_FROZEN_PREDECESSOR_BINDINGS',
 'efi_sha256':sha(app),'build_sha256':sha(HERE/'app_build/app_build.json'),
 'compiled_sources_verified':len(build['sources']),'linked_objects_verified':len(build['objects']),
 'source_comparison':rows,'additional_source':'diagnostic09.h',
 'original_native_windows_unchanged':12,'public_context_provider_frame_binding_unchanged':True,
 'provider':{'sha256':sha(provider),'file_bytes':len(embedded),'loaded_bytes':len(mapped),
             'declared_ranges':[{'rva':a,'bytes':n}for a,n in ranges],
             'declared_bytes':sum(n for a,n in ranges),'DIR64_count':len(relocs),
             'object_rva':symbols['native_provider'],'method_rvas':{n:symbols[n]for n in['provider_begin','provider_end','provider_query','provider_request','provider_manage']},
             'HII_package_unchanged':True},
 'changes':['Only three diagnostic header fields initialize after existing state memset before hook publication.',
            'Generated guard/provider full identity assets and12 target offsets follow final frozen inputs.',
            'App/KVM TEST09 labels and P15 HII label; no session UI logic or Q schema change.',
            'verify_globals report status was corrected from inherited TX08 to TX09 after first local run; assertions and compiled source unchanged.'],
 'policy_scope':'No credential/state/rollback rule changed. Presence of old password-capable code is not authorization for enrollment in this diagnostics-only physical stage.',
 'recovery_gate':'Future real enrollment awaits the separately documented durable fixture and independent original-boot recovery implementation.',
 'no_device_actions':True,'source_sha256':sha(Path(__file__))}
(HERE/'integration_delta.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({'status':report['status'],'sources':len(rows)+1,'efi_sha256':sha(app)}))
