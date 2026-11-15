from pathlib import Path
import datetime,hashlib,json,os,re,shutil,subprocess,sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;IN=HERE/'inputs'
ROOT=next(p for p in HERE.parents if (p/'tools/pydeps').is_dir())
sys.path[:0]=[str(ROOT/'tools/pydeps'),str(ROOT/'analysis/aitweaker_lock/uefi_vm_20261015')]
import pefile,disk_images
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
app_input=IN/'SageNative13RamTest05.efi';provider=IN/'AiTweakerSplitProvider13.UNSIGNED.local.efi'
assert sha(app_input)=='9115f1afbab01b624ed8e3da6cdba74c52e187785c77095e1544a6211a8dc6f3'
assert sha(provider)=='caa80df1fa6414d635d28a3b65fec1c265968482ddb66268412483eff95deca9'
parent_build=json.loads((IN/'app_build.json').read_text());assert parent_build['efi_sha256']==sha(app_input)
for row in parent_build['sources']:
    copied=IN/row['path']
    if copied.exists():assert sha(copied)==row['sha256'],str(copied)
app_pe=pefile.PE(str(app_input));p=pefile.PE(str(provider));text=(IN/'app.map').read_text()
names=['app_st','system_table','read_cpu_env','refresh_map','provider_before_start','environment']
symbols={}
for name in names:
    matches=re.findall(r'^\s*\d{4}:[a-fA-F0-9]+\s+'+name+r'\s+([a-fA-F0-9]+)\s',text,re.M)
    assert len(matches)==1,(name,matches)
    symbols[name]=int(matches[0],16)-app_pe.OPTIONAL_HEADER.ImageBase
relocs=[e.rva for block in p.DIRECTORY_ENTRY_BASERELOC for e in block.entries if e.type==10]
assert len(relocs)==17
regions=[(0,p.OPTIONAL_HEADER.SizeOfHeaders)]+[(s.VirtualAddress,s.Misc_VirtualSize)for s in p.sections]
active=[0,0x80,p.OPTIONAL_HEADER.SizeOfHeaders-1]
for s in p.sections:
    active.extend([s.VirtualAddress,s.VirtualAddress+s.Misc_VirtualSize-1])
    if s.Misc_VirtualSize>s.SizeOfRawData:active.append(s.VirtualAddress+s.SizeOfRawData)
padding=[]
for index,(start,size)in enumerate(regions):
    end=start+size;next_start=regions[index+1][0]if index+1<len(regions)else p.OPTIONAL_HEADER.SizeOfImage
    if end<next_start:padding.extend([end,next_start-1])
array=lambda name,data:'static const uint8_t '+name+'[]={'+','.join(str(n)for n in data)+'};\n'
header=array('app_file',app_input.read_bytes())+array('provider_file',provider.read_bytes())
header+=f'#define APP_IMAGE_BYTES {app_pe.OPTIONAL_HEADER.SizeOfImage}u\n#define PROVIDER_IMAGE_BYTES {p.OPTIONAL_HEADER.SizeOfImage}u\n#define PROVIDER_PREFERRED_BASE {p.OPTIONAL_HEADER.ImageBase}ULL\n#define PROVIDER_IMAGEBASE_FIELD {p.DOS_HEADER.e_lfanew+48}u\n'
for name,rva in symbols.items():header+=f'#define RVA_{name.upper()} {rva}u\n'
for name,values in [('relocs',relocs),('active_offsets',active),('padding_offsets',padding)]:header+='static const uint32_t '+name+'[]={'+','.join(str(x)for x in values)+'};\n'
(HERE/'payloads.h').write_text(header)
zig=ROOT/'tools/zig-x86_64-windows-0.14.1/zig.exe';build=HERE/'build';build.mkdir(exist_ok=True)
env=os.environ.copy();env.update(ZIG_GLOBAL_CACHE_DIR=str(build/'zig-global'),ZIG_LOCAL_CACHE_DIR=str(build/'zig-local'))
commands=[];objects=[]
for src in [HERE/'probe.c',IN/'source/password_crypto.c']:
    obj=build/(src.stem+'.obj');objects.append(obj)
    cmd=[str(zig),'clang','-target','x86_64-unknown-windows-msvc','-nostdinc','-isystem',str(zig.parent/'lib/include'),'-I',str(IN/'source'),'-I',str(HERE),'-O2','-std=c11','-Wall','-Wextra','-Werror','-ffreestanding','-fno-builtin','-fno-stack-protector','-mno-red-zone','-mno-stack-arg-probe','-fshort-wchar','-c',str(src),'-o',str(obj)]
    commands.append(cmd);subprocess.run(cmd,check=True,env=env,cwd=ROOT)
app=build/'ACTUAL-VALIDATOR-ONLY-TCG-NOT-FOR-HARDWARE.EFI'
cmd=[str(zig),'lld-link','/subsystem:efi_application','/entry:efi_main','/nodefaultlib','/machine:x64','/dynamicbase','/fixed:no','/timestamp:0','/out:'+str(app),*[str(o)for o in objects]]
commands.append(cmd);subprocess.run(cmd,check=True,env=env,cwd=ROOT)
run=HERE/'runs'/datetime.datetime.now().strftime('%Y%m%d_%H%M%S');run.mkdir(parents=True)
qemu=ROOT/'tools/qemu-11.1.0';share=qemu/'share';varsfile=run/'vars.fd';shutil.copyfile(share/'edk2-i386-vars.fd',varsfile)
disk_images.OUT=run;disk_images.VOLUME_SIZE=16*1024*1024;boot=run/'readonly-boot.img';disk_images.create(boot,'superfloppy',16,{'/EFI/BOOT/BOOTX64.EFI':app.read_bytes()});before=sha(boot)
cmd=[str(qemu/'qemu-system-x86_64.exe'),'-L',str(share),'-machine','q35','-accel','tcg,thread=single','-cpu','max','-m','512','-smp','1','-nic','none','-display','none','-monitor','none','-serial','file:'+str(run/'serial.log'),'-debugcon','file:'+str(run/'debug.log'),'-global','isa-debugcon.iobase=0x402','-device','isa-debug-exit,iobase=0xf4,iosize=0x4','-drive','if=pflash,format=raw,unit=0,readonly=on,file='+str(share/'edk2-x86_64-code.fd'),'-drive','if=pflash,format=raw,unit=1,file='+str(varsfile),'-drive','if=none,id=boot,format=raw,readonly=on,file='+str(boot),'-device','qemu-xhci,id=xhci','-device','usb-storage,bus=xhci.0,drive=boot,bootindex=1']
(run/'command.json').write_text(json.dumps(cmd,indent=2)+'\n')
with (run/'stderr.log').open('wb')as err:
    proc=subprocess.Popen(cmd,stdout=subprocess.DEVNULL,stderr=err,creationflags=subprocess.CREATE_NO_WINDOW)
    try:code=proc.wait(timeout=45)
    finally:
        if proc.poll()is None:proc.terminate();proc.wait(timeout=5)
raw=(run/'debug.log').read_text(encoding='ascii',errors='replace');part=raw[raw.index('ACTUAL_PLATFORM_VALIDATOR_BEGIN'):]
ok=code==33 and 'ACTUAL_PLATFORM_VALIDATOR_COMPLETE'in part and 'FAIL 'not in part and sha(boot)==before
inputs=[x for x in IN.rglob('*')if x.is_file()]
result={'status':'PASS_ACTUAL_LOADED_APP_VALIDATOR_IN_OVMF'if ok else'FAIL_RETAINED_EVIDENCE','exit_code':code,'actual_app_sha256':sha(app_input),
        'provider_sha256':sha(provider),'fixture_sha256':sha(app),'ovmf_sha256':sha(share/'edk2-x86_64-code.fd'),
        'checks':len(re.findall(r'^PASS ',part,re.M)),'symbols_rva':symbols,'relocations_tested':relocs,'active_mutations_tested':active,'padding_mutations_tested':padding,
        'imports_started':False,'raw_observation':part,'readonly_boot_unchanged':sha(boot)==before,'build_commands':commands,
        'source_bindings':[{'path':str(x),'bytes':x.stat().st_size,'sha256':sha(x)}for x in inputs+[HERE/'probe.c',HERE/'payloads.h',Path(__file__)]],
        'limits':['Actual pre-start validator from the unchanged loaded production app is executed; app entry, installer transaction, and P13 entry are not started.',
                  'Only app_st/system_table/environment/map BSS preconditions are initialized. Standard OVMF memory map and actual pagewalk are used.',
                  'Negative mutations affect only a new own copy of the loaded provider, correctly rebased for its new base. Original loaded provider complete hash remains unchanged.',
                  'This proves behavior in the recorded OVMF configuration, not ASUS loader compatibility or native UI acceptance.']}
(run/'result.json').write_text(json.dumps(result,indent=2)+'\n');(HERE/'latest_result.json').write_text(json.dumps({'run':str(run),'result':result},indent=2)+'\n');print(part);assert ok
