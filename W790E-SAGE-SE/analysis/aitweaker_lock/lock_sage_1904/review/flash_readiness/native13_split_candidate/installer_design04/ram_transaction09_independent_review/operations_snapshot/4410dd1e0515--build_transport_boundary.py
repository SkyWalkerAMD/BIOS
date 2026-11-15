from pathlib import Path
import hashlib,json,os,subprocess,sys
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[7];SRC=HERE.parent/'ram_transaction09/source/transport';BUILD=HERE/'transport_boundary_build';BUILD.mkdir(exist_ok=True)
zig=ROOT/'tools/zig-x86_64-windows-0.14.1/zig.exe';env=os.environ.copy();env.update(ZIG_GLOBAL_CACHE_DIR=str(BUILD/'zig-global'),ZIG_LOCAL_CACHE_DIR=str(BUILD/'zig-local'))
objects=[];commands=[];sources=[SRC/'kvm.c',SRC/'probe_core.c',SRC/'vendor/qrcodegen.c',HERE/'transport_boundary_support.c']
for source in sources:
    obj=BUILD/(source.stem+'.obj');objects.append(obj)
    cmd=[str(zig),'clang','-target','x86_64-unknown-windows-msvc','-nostdinc','-isystem',str(zig.parent/'lib/include'),'-I',str(SRC),'-I',str(SRC/'compat'),'-DNDEBUG','-std=c11','-O2','-Wall','-Wextra','-ffreestanding','-fno-builtin','-fno-stack-protector','-mno-red-zone','-mno-stack-arg-probe','-fshort-wchar','-c',str(source),'-o',str(obj)]
    subprocess.run(cmd,check=True,env=env,cwd=ROOT);commands.append(cmd)
cmd=[str(zig),'lld-link','/subsystem:efi_boot_service_driver','/entry:kvm_present','/nodefaultlib','/machine:x64','/dynamicbase','/fixed:no','/nxcompat','/timestamp:0','/map:'+str(BUILD/'transport.map'),'/out:'+str(BUILD/'TransportBoundary.TESTONLY.efi'),*map(str,objects)]
subprocess.run(cmd,check=True,env=env,cwd=ROOT);commands.append(cmd)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
report={'status':'COMPILED_TEST_CARRIER_NOT_FOR_FIRMWARE_LAUNCH','efi_sha256':sha(BUILD/'TransportBoundary.TESTONLY.efi'),'sources':{str(p):sha(p) for p in sources},'commands':commands}
(BUILD/'build.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'status':report['status'],'efi_sha256':report['efi_sha256']}))
