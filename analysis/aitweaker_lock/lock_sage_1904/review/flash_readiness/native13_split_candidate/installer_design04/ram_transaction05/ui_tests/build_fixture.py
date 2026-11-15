from pathlib import Path
import hashlib,json,os,subprocess,sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;TX=HERE.parent;SRC=TX/'source'
ROOT=next(p for p in HERE.parents if (p/'tools/pydeps').is_dir())
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile
OUT=HERE/'build';OUT.mkdir(exist_ok=True)
zig=ROOT/'tools/zig-x86_64-windows-0.14.1/zig.exe'
env=os.environ.copy();env.update(ZIG_GLOBAL_CACHE_DIR=str(OUT/'zig-global'),ZIG_LOCAL_CACHE_DIR=str(OUT/'zig-local'))
sources=[SRC/'session_ui.c',SRC/'password_core.c',SRC/'password_crypto.c',HERE/'fixture.c'];objects=[];commands=[]
for source in sources:
    obj=OUT/(source.stem+'.obj');objects.append(obj)
    args=[str(zig),'clang','-target','x86_64-unknown-windows-msvc','-nostdinc','-isystem',str(zig.parent/'lib/include'),'-I',str(SRC),'-std=c11','-O2','-Wall','-Wextra','-Werror','-ffreestanding','-fno-builtin','-fno-stack-protector','-mno-red-zone','-mno-stack-arg-probe','-fshort-wchar','-c',str(source),'-o',str(obj)]
    commands.append(args);subprocess.run(args,env=env,check=True,cwd=ROOT)
exports=['test_setup','test_session','test_condition','ui_capture_initial','ui_open_management','ui_open_original_setup','ui_restore_credential','ui_compare_original_stores','app_hold','app_log','app_number','app_result','fixture_get','fixture_set','fixture_raise','fixture_restore','fixture_locate','fixture_list','fixture_export','fixture_send','fixture_query','fixture_hii','fixture_state','fixture_provider_flags','app_ended']
pe=OUT/'UI-EMULATION-FIXTURE-NOT-FOR-BOOT.EFI'
args=[str(zig),'lld-link','/subsystem:efi_application','/entry:test_setup','/nodefaultlib','/machine:x64','/dynamicbase','/fixed:no','/nxcompat','/timestamp:0','/out:'+str(pe),*[str(o)for o in objects],*['/export:'+name for name in exports]]
commands.append(args);subprocess.run(args,env=env,check=True,cwd=ROOT)
p=pefile.PE(str(pe));p.OPTIONAL_HEADER.CheckSum=p.generate_checksum();pe.write_bytes(p.write())
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
result={'scope':'Never boot. Actual optimized session_ui.c and exact password record validator under Unicorn; services are mocked.',
        'commands':commands,'pe':{'path':str(pe),'bytes':pe.stat().st_size,'sha256':sha(pe)},
        'sources':[{'path':str(s),'bytes':s.stat().st_size,'sha256':sha(s)}for s in sources+[SRC/'ui_bindings.h',SRC/'app.h',SRC/'efi.h',SRC/'split_owner.h',SRC/'transaction.h',SRC/'provider.h',SRC/'password_core.h']]}
(OUT/'build.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf8');print(json.dumps(result['pe']))
