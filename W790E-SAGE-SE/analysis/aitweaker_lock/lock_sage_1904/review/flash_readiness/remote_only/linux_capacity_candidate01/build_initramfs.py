"""Build custom static PID1 and deterministic RAM initramfs. No stock init used."""
from pathlib import Path
import gzip,hashlib,json,os,struct,subprocess
HERE=Path(__file__).resolve().parent;ROOT=next(p for p in HERE.parents if (p/'tools/pydeps').is_dir())
OUT=HERE/'build';OUT.mkdir(exist_ok=True);SRC=HERE/'source';ZIG=ROOT/'tools/zig-x86_64-windows-0.14.1/zig.exe'
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
modules=json.loads((HERE/'modules.json').read_text())['modules'];assert len(modules)==8
env=os.environ.copy();env.update(ZIG_GLOBAL_CACHE_DIR=str(ROOT/'tools/zig-cache-global'),ZIG_LOCAL_CACHE_DIR=str(ROOT/'tools/zig-cache-local'))
commandline='rdinit=/init init=/init efi=noruntime noresume erst_disable pstore.backend=lc01_none initcall_blacklist=mei_me_driver_init,xlblk_init,netif_init ipv6.disable=1 panic=0 quiet loglevel=3 console=tty0'
(OUT/'commandline.txt').write_text(commandline,encoding='ascii')
sources=[SRC/'init.c',SRC/'core.c',SRC/'display.c',SRC/'vendor/qrcodegen.c'];rows=[]
def cpio(entries):
    buf=bytearray()
    for ino,(name,mode,data,maj,min_) in enumerate(entries+[('TRAILER!!!',0,b'',0,0)],1):
        nb=name.encode()+b'\0';fields=[ino,mode,0,0,1,0,len(data),0,0,maj,min_,len(nb),0]
        buf.extend(b'070701'+b''.join(f'{v:08x}'.encode() for v in fields));buf.extend(nb);buf.extend(b'\0'*(-len(buf)%4));buf.extend(data);buf.extend(b'\0'*(-len(buf)%4))
    buf.extend(b'\0'*(-len(buf)%512));return bytes(buf)
for variant in ['production','lab_selector_only']:
    target=OUT/variant;target.mkdir(exist_ok=True);exe=target/'init'
    flags=[] if variant=='production' else ['-DLC_USB_VID=0x46f4','-DLC_USB_PID=0x0001','-DLC_PCI_VID=0x1b36','-DLC_VARIANT="LAB_SELECTOR_ONLY"']
    cmd=[str(ZIG),'cc','-target','x86_64-linux-musl','-static','-std=c11','-O2','-Wall','-Wextra','-Werror','-fno-stack-protector','-fno-pie','-no-pie','-I',str(SRC),*flags,*map(str,sources),'-o',str(exe)]
    subprocess.run(cmd,check=True,env=env)
    elf=exe.read_bytes();assert elf[:6]==b'\x7fELF\2\1';phoff=struct.unpack_from('<Q',elf,32)[0];ents,num=struct.unpack_from('<HH',elf,54)
    assert all(struct.unpack_from('<I',elf,phoff+i*ents)[0] not in [2,3] for i in range(num)),'Dynamic executable forbidden'
    entries=[(n,0o040755,b'',0,0) for n in ['dev','proc','sys','modules']]
    entries+=[('dev/console',0o020600,b'',5,1),('dev/null',0o020666,b'',1,3),('init',0o100755,elf,0,0)]
    for m in modules:
        path=HERE/'modules'/m['filename'];assert sha(path)==m['sha256'] and path.stat().st_size==m['bytes'];entries.append(('modules/'+m['filename'],0o100444,path.read_bytes(),0,0))
    raw=cpio(entries);image=target/'CAPACITY01.IMG';image.write_bytes(gzip.compress(raw,compresslevel=9,mtime=0))
    rows.append({'variant':variant,'not_for_hardware':variant!='production','binary_sha256':sha(exe),'binary_bytes':len(elf),'initramfs_sha256':sha(image),'initramfs_bytes':image.stat().st_size,'cpio_bytes':len(raw),
      'entries':[{'name':n,'mode':oct(m),'bytes':len(d),'sha256':hashlib.sha256(d).hexdigest() if d else None,'device':[ma,mi]} for n,m,d,ma,mi in entries],'command':cmd})
cmd=[str(ZIG),'cc','-target','x86_64-windows-gnu','-shared','-std=c11','-O2','-Wall','-Wextra','-Werror','-I',str(SRC),str(SRC/'core.c'),str(SRC/'vendor/qrcodegen.c'),'-Wl,--export-all-symbols','-o',str(OUT/'core_test.dll')]
subprocess.run(cmd,check=True,env=env)
report={'status':'BUILT_AWAITING_LOCAL_VALIDATION','hardware_approved':False,'hardware_executed':False,'kernel_source':'official/vmlinuz-lts','kernel_sha256':sha(HERE/'official/vmlinuz-lts'),
 'commandline':commandline,'commandline_sha256':sha(OUT/'commandline.txt'),'source_files':{p.relative_to(HERE).as_posix():sha(p) for p in SRC.rglob('*') if p.is_file()},
 'variants':rows,'core_test_dll_sha256':sha(OUT/'core_test.dll'),'core_test_command':cmd,
 'scope':'Only custom static PID1 and8 bound modules. No stock init, shell, executables/helpers or extra modules. Test variant changes only compile-time PCI/USB identifier constants and visible label; it is never for target hardware.'}
(OUT/'build.json').write_text(json.dumps(report,indent=2),encoding='utf8');print(json.dumps({'status':report['status'],'kernel_sha256':report['kernel_sha256'],'variants':[{k:r[k] for k in ['variant','binary_sha256','initramfs_sha256','initramfs_bytes']} for r in rows]},indent=2))
