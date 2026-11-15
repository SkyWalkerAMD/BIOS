"""Local control: bypass bootstrap and boot the identical Linux bytes via fw_cfg.
This cannot establish bootstrap correctness and is never a deliverable path.
"""
from pathlib import Path
import argparse,datetime,json,shutil,subprocess,sys,time,traceback
OUT=Path(__file__).resolve().parent.parent;sys.path.insert(0,str(OUT))
from build_loader import sha
from run_tests import Q,SHARE,QMP,save

def main():
    p=argparse.ArgumentParser();p.add_argument('manifest',type=Path);p.add_argument('--with-cd',action='store_true');a=p.parse_args()
    m=json.loads(a.manifest.read_text());c=m['contract'];folder=OUT/'tests/fwcfg-controls'/(datetime.datetime.now().strftime('%Y%m%d_%H%M%S')+('_cd' if a.with_cd else '_no_cd'));folder.mkdir(parents=True)
    for label in ['kernel','initrd']:assert sha(c[label]['path'])==c[label]['sha256']
    assert 'console=ttyS0,115200' in c['cmdline'];assert sha(m['iso'])==m['iso_sha256']
    varsfile=folder/'vars.fd';shutil.copyfile(SHARE/'edk2-i386-vars.fd',varsfile)
    args=[str(Q/'qemu-system-x86_64.exe'),'-L',str(SHARE),'-machine','q35,accel=tcg','-cpu','max','-m','768','-smp','1','-nic','none','-display','none','-monitor','none','-qmp','stdio','-serial','file:'+str(folder/'serial.log'),'-no-reboot','-drive','if=pflash,format=raw,unit=0,readonly=on,file='+str(SHARE/'edk2-x86_64-code.fd'),'-drive','if=pflash,format=raw,unit=1,file='+str(varsfile),'-kernel',c['kernel']['path'],'-initrd',c['initrd']['path'],'-append',c['cmdline'],'-device','qemu-xhci,id=xhci,addr=0x14']
    if a.with_cd:args+=['-drive','if=none,id=boot,format=raw,media=cdrom,readonly=on,file='+m['iso'],'-device','ide-cd,drive=boot,bus=ide.0']
    save(folder/'command.json',args);result={'scope':'Local fw_cfg control ONLY; bootstrap bypassed, never a bootstrap acceptance result','with_cd':a.with_cd,'manifest_sha256':sha(a.manifest),'passed':False};proc=None;start=time.monotonic()
    try:
        with (folder/'stderr.log').open('wb') as err:
            proc=subprocess.Popen(args,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=err,text=True,encoding='utf8',creationflags=subprocess.CREATE_NO_WINDOW);(folder/'qemu.pid').write_text(str(proc.pid));qmp=QMP(proc,folder);qmp.command('qmp_capabilities',timeout=15)
            deadline=time.monotonic()+90
            while time.monotonic()<deadline:
                assert proc.poll() is None,'QEMU exited';s=(folder/'serial.log').read_text(errors='replace') if (folder/'serial.log').exists() else ''
                if 'Kernel panic' in s:raise RuntimeError(s.split('Kernel panic',1)[1].splitlines()[0])
                if 'PROBE_COMPLETE' in s:
                    assert 'LINUX-CAPACITY-01 PRODUCTION' in s and 'RESULT=REFUSED_OR_FAILED' in s and 'SG_IO_CALLS=0 ' in s and 'MODULES=0' in s
                    result['passed']=True;break
                time.sleep(.2)
            if not result['passed']:raise TimeoutError('No final PID1 report')
            qmp.command('quit');assert proc.wait(timeout=10)==0
            result['iso_unchanged']=sha(m['iso'])==m['iso_sha256'];assert result['iso_unchanged']
    except Exception as e:result['error']=str(e);result['traceback']=traceback.format_exc()
    finally:
        if proc and proc.poll() is None:proc.terminate();proc.wait(timeout=5)
        result['seconds']=round(time.monotonic()-start,2);save(folder/'result.json',result)
    print(json.dumps(result,indent=2));raise SystemExit(0 if result['passed'] else 1)
if __name__=='__main__':main()
