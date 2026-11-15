from bind_layout import *
import os,subprocess,sys
OUT=HERE/'loader_build';OUT.mkdir(exist_ok=True);Z=ROOT/'tools/zig-x86_64-windows-0.14.1/zig.exe'
env=os.environ.copy();env.update(ZIG_LOCAL_CACHE_DIR=str(OUT/'zig-local'),ZIG_GLOBAL_CACHE_DIR=str(OUT/'zig-global'))
aggregate='--aggregate'in sys.argv
sources=[]if aggregate else[HERE/'fixture.c',HERE/'uefi_fixture.c',HERE/'layout.c',HERE/'layout_slot.c',BASE/'password/core/password_crypto.c']
objects=[];commands=[]
def run(cmd):
 commands.append(cmd);r=subprocess.run(cmd,env=env,capture_output=True,text=True,creationflags=subprocess.CREATE_NO_WINDOW)
 if r.returncode:print(r.stdout+r.stderr);r.check_returncode()
def cc(src,obj):
 run([str(Z),'clang','-target','x86_64-unknown-windows-msvc','-nostdinc','-isystem',str(Z.parent/'lib/include'),'-I',str(OUT),
  '-O2','-std=c11','-ffreestanding','-fno-builtin','-fno-stack-protector','-fno-unwind-tables','-fno-asynchronous-unwind-tables',
  '-mno-red-zone','-mno-stack-arg-probe','-Wall','-Wextra','-Werror','-c',str(src),'-o',str(obj)])
for src in sources:
 obj=OUT/(src.stem+'.obj');cc(src,obj);objects.append(obj)
if aggregate:
 latest=json.loads((HERE/'latest_aggregate.json').read_text());module=Path(latest['pe']);manifest=Path(latest['report'])
 merged=module.read_bytes();profile=json.loads(manifest.read_text());need(sha(merged)==latest['sha256']==profile['merged_sha256'],'aggregate snapshot identity')
 sources+=[module,manifest]
else:
 extpath=OUT/'LOADER-FIXTURE.dll';run([str(Z),'lld-link','/dll','/noentry','/nodefaultlib','/machine:x64','/timestamp:0','/base:0x180000000',
  '/out:'+str(extpath),*[str(x)for x in objects],'/export:i05_layout_get','/export:i05_layout_live','/export:i05_layout_symbol'])
 ext=extpath.read_bytes();merged,profile=compose(ext,sha(ext),'i05_uefi_fixture_entry');merged,profile=bind_layout(merged,profile)
h='/* TCG-only packaging fixture, no password driver. */\n'
h+='static const uint8_t composed_fixture[]={'+','.join(str(b)for b in merged)+'};\n'
h+=f'#define FUNCTIONAL_AGGREGATE {int(aggregate)}\n#define EXPECTED_IMAGE_SIZE {profile["image_size"]}ULL\n#define LAYOUT_LIVE_RVA {profile["exports"]["i05_layout_live"]}ULL\n#define STARTED_RVA {profile["exports"].get("i05_fixture_started",0)}ULL\n'
(OUT/'loader_fixture.h').write_text(h,encoding='ascii')
obj=OUT/'loader_lab.obj';cc(HERE/'loader_lab.c',obj)
app=OUT/'W890-PE-Loader.PACKAGING-ONLY.efi';run([str(Z),'lld-link','/subsystem:efi_application','/entry:efi_main','/nodefaultlib','/machine:x64','/timestamp:0','/out:'+str(app),str(obj)])
report={'status':'TCG_ONLY_PACKAGING_LOADER_LAB','functional_aggregate_load_only':aggregate,'efi':str(app),'sha256':sha(app.read_bytes()),'composition':profile,'commands':commands,
 'inputs':[{'path':str(p),'sha256':sha(p.read_bytes())}for p in sources+[HERE/'layout.h',HERE/'loader_lab.c',HERE/'build_loader_lab.py',HERE/'bind_layout.py',HERE/'merge_pe.py',OUT/'loader_fixture.h']],
 'limitation':'Actual aggregate is LoadImage/identity/UnloadImage only; StartImage is compiled out. No original entry, HII publication or password write.'if aggregate else'Composed PE is embedded only in a TCG guarded lab application; no CAP or functional password candidate is emitted.'}
(OUT/'build_manifest.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
print(json.dumps({'status':report['status'],'efi':str(app),'sha256':report['sha256']}))
