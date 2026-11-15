"""Actual OVMF HII services, original inert module fixtures, lab-only authority."""
from pathlib import Path
from datetime import datetime,timezone
import hashlib,json,os,shutil,struct,subprocess,sys,time,uuid
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;M=HERE.parent;BASE=M.parent;ROOT=M.parents[3];P=BASE/'password'
sys.path[:0]=[str(ROOT/'tools/pydeps'),str(ROOT/'tools/kvm-pydeps'),str(ROOT/'analysis/aitweaker_lock'),str(ROOT/'analysis/aitweaker_lock/uefi_vm_20261015')]
import pefile,pycdlib,disk_images
from inspect_setup import string_packages
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def save(p,v):p.write_text(json.dumps(v,indent=2,ensure_ascii=False)+'\n',encoding='utf8')
def blob(n,b):return 'static const uint8_t '+n+'[]={\n'+''.join(','.join(hex(v)for v in b[i:i+32])+',\n'for i in range(0,len(b),32))+'};\n'
def main():
    folder=HERE/'runs'/datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S');folder.mkdir(parents=True)
    profile=json.loads((P/'profile_0603.json').read_text());fixtures='';inputs=[]
    for name in ['Setup','AMITSE']:
        path=ROOT/profile['sources'][name]['path'];assert sha(path)==profile['sources'][name]['sha256'];inputs.append(path)
        pe=pefile.PE(str(path));mapped=pe.get_memory_mapped_image();text=next(s for s in pe.sections if s.Name.rstrip(b'\0')==b'.text')
        fixtures+=blob(name.lower()+'_headers',mapped[:4096])+blob(name.lower()+'_text',mapped[4096:4096+text.Misc_VirtualSize])
    raw=inputs[0].read_bytes();ss=string_packages(raw);assert len(ss)==1
    english=raw[ss[0]['offset']:ss[0]['offset']+ss[0]['length']];french=bytearray(english);assert french[46:52]==b'en-US\0';french[46:52]=b'fr-FR\0'
    forms=(P/'official_forms_0603.pack').read_bytes();assert hashlib.sha256(forms).hexdigest()=='0111abd4e9914a32b865fc95af15990687a9d05f984df533c30e028e38cbba2f'
    pack=uuid.UUID('899407d7-99fe-43d8-9a21-79ec328cac21').bytes_le+struct.pack('<I',24+len(forms)+len(english)+len(french))+forms+english+french+bytes.fromhex('040000df')
    fixtures+=blob('original_package',pack)+blob('original_forms',forms)
    (HERE/'fixtures.h').write_text(fixtures,encoding='ascii')
    subprocess.run([sys.executable,'-X','utf8',str(M/'build.py')],check=True,creationflags=subprocess.CREATE_NO_WINDOW)
    build=json.loads((M/'build/build.json').read_text());shutil.copy2(M/'build/build.json',folder/'build.json')
    app=M/'build/W890Management04.QEMU_ONLY.LAB.efi';shutil.copy2(app,folder/app.name)
    Q=ROOT/'tools/qemu-11.1.0';share=Q/'share';varsfile=folder/'vars.fd';shutil.copyfile(share/'edk2-i386-vars.fd',varsfile)
    disk_images.OUT=folder;disk_images.VOLUME_SIZE=16*1024*1024;boot=folder/'boot.img';disk_images.create(boot,'superfloppy',16,{'/EFI/BOOT/BOOTX64.EFI':app.read_bytes()})
    iso=folder/'W890Management04.TCG_ONLY.iso';cd=pycdlib.PyCdlib();cd.new(interchange_level=3,vol_ident='W890_MP04_LAB',joliet=3);cd.add_file(str(boot),iso_path='/EFIBOOT.IMG;1',joliet_path='/EFIBOOT.IMG');cd.add_eltorito('/EFIBOOT.IMG;1',bootcatfile='/BOOT.CAT;1',boot_load_size=boot.stat().st_size//512,platform_id=0xef,efi=True,media_name='noemul');cd.write(str(iso));cd.close()
    debug=folder/'debug.log';cmd=[str(Q/'qemu-system-x86_64.exe'),'-L',str(share),'-machine','q35,accel=tcg','-cpu','max','-m','512','-smp','1','-nic','none','-display','none','-monitor','none','-serial','file:'+str(folder/'serial.log'),'-debugcon','file:'+str(debug),'-global','isa-debugcon.iobase=0x402','-device','isa-debug-exit,iobase=0xf4,iosize=0x4','-drive','if=pflash,format=raw,unit=0,readonly=on,file='+str(share/'edk2-x86_64-code.fd'),'-drive','if=pflash,format=raw,unit=1,file='+str(varsfile),'-drive','if=none,id=boot,format=raw,media=cdrom,readonly=on,file='+str(iso),'-device','ide-cd,drive=boot,bus=ide.0,bootindex=1']
    save(folder/'qemu_command.json',cmd);print('START',folder,flush=True)
    inputs += [ROOT/p for p in build['sources']]+[M/'build.py',BASE/'password_runtime02/lab/profile_fixture.h']
    report={'status':'RUNNING','scope':'Actual OVMF HII Database/String/notifications and compiled MP04+Runtime02; inert original module images and lab cold-window authority. No ASUS native browser execution or hardware password writes.','efi_sha256':sha(app),'component_sha256':build['component']['sha256'],'build_sha256':sha(folder/'build.json'),'iso_sha256_before':sha(iso),'ovmf_sha256':sha(share/'edk2-x86_64-code.fd'),'inputs':{str(p):sha(p)for p in inputs+[HERE/'lab.c',HERE/'run.py',HERE/'fixtures.h']}}
    try:
        start=time.monotonic()
        with (folder/'stdout.log').open('wb')as out,(folder/'stderr.log').open('wb')as err:
            proc=subprocess.Popen(cmd,stdin=subprocess.DEVNULL,stdout=out,stderr=err,creationflags=subprocess.CREATE_NO_WINDOW)
            try:code=proc.wait(timeout=180)
            except subprocess.TimeoutExpired:proc.terminate();proc.wait(timeout=10);raise RuntimeError('lab timed out')
        log=debug.read_text(encoding='ascii',errors='replace');report.update(exit_code=code,seconds=round(time.monotonic()-start,3),checks=log.count('PASS '),debug_sha256=sha(debug),iso_sha256_after=sha(iso))
        assert code==33 and 'MP04_LAB_PASS' in log and 'FAIL ' not in log,log[-3500:]
        assert report['iso_sha256_before']==report['iso_sha256_after'];report['status']='PASS_ACTUAL_OVMF_HII_AND_COMPILED_PUBLISHER'
    except Exception as e:report.update(status='FAILED_EVIDENCE_RETAINED',error=str(e));raise
    finally:save(folder/'result.json',report);print(json.dumps({k:report[k]for k in ['status','checks','efi_sha256']if k in report}),flush=True);print('REPORT',folder/'result.json',flush=True)
if __name__=='__main__':main()
