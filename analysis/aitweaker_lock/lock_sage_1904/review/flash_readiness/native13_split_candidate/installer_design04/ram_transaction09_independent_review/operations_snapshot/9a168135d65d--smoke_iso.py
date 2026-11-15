"""Boot exact RAM_TEST09 optical image in OVMF; verify unsupported-board refusal."""
from pathlib import Path
import argparse,datetime,hashlib,importlib.util,json,queue,re,shutil,struct,subprocess,sys,threading,time,zlib
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[7];SAGE=HERE.parents[4]
decoder_path=SAGE/'remote_172_20_2_162/read_native13_ram_test09_qr.py'
spec=importlib.util.spec_from_file_location('ram09_actual_decoder',decoder_path);dec=importlib.util.module_from_spec(spec);sys.modules[spec.name]=dec;spec.loader.exec_module(dec)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
class QMP:
 def __init__(self,p):
    self.p=p;self.n=0;self.q=queue.Queue()
    def reader():
        for line in iter(p.stdout.readline,b''):self.q.put(line)
        self.q.put(b'')
    threading.Thread(target=reader,daemon=True).start();assert 'QMP' in json.loads(self.q.get(timeout=5));self.command('qmp_capabilities')
 def command(self,name,args=None):
    self.n+=1;obj={'execute':name,'id':self.n}
    if args is not None:obj['arguments']=args
    self.p.stdin.write(json.dumps(obj).encode()+b'\n');self.p.stdin.flush()
    while True:
        value=json.loads(self.q.get(timeout=10))
        if value.get('id')==self.n:
            if 'error'in value:raise RuntimeError(value['error'])
            return value.get('return')
 def key(self,key):self.command('send-key',{'keys':[{'type':'qcode','data':key}],'hold-time':50});time.sleep(.5)
 def screen(self,dest):
    ppm=dest.with_suffix('.ppm');self.command('screendump',{'filename':str(ppm)});raw=ppm.read_bytes();match=re.match(rb'P6\s+(\d+)\s+(\d+)\s+255\s',raw);assert match
    width,height=map(int,match.groups());rgb=raw[match.end():];assert len(rgb)==width*height*3
    def chunk(kind,data):return struct.pack('>I',len(data))+kind+data+struct.pack('>I',zlib.crc32(kind+data)&0xffffffff)
    scan=b''.join(b'\0'+rgb[y*width*3:(y+1)*width*3] for y in range(height))
    dest.write_bytes(b'\x89PNG\r\n\x1a\n'+chunk(b'IHDR',struct.pack('>IIBBBBB',width,height,8,2,0,0,0))+chunk(b'IDAT',zlib.compress(scan))+chunk(b'IEND',b''))

def main():
 parser=argparse.ArgumentParser();parser.add_argument('--package',required=True);parser.add_argument('--sha256',required=True);args=parser.parse_args()
 package=Path(args.package).resolve()
 assert package.is_relative_to(HERE/'packages') and sha(package)==args.sha256
 info=json.loads(package.read_text());iso=Path(info['iso']);efi=Path(info['efi']);assert sha(iso)==info['iso_sha256'] and sha(efi)==info['efi_sha256']
 run=HERE/'ovmf'/datetime.datetime.now().strftime('%Y%m%d_%H%M%S');run.mkdir(parents=True)
 (run/'runner-snapshot.py').write_bytes(Path(__file__).read_bytes())
 (run/'decoder-snapshot.py').write_bytes(decoder_path.read_bytes())
 (run/'p3-transport-snapshot.py').write_bytes(dec.P3.read_bytes())
 qemu=ROOT/'tools/qemu-11.1.0';share=qemu/'share';varsfile=run/'vars.fd';shutil.copyfile(share/'edk2-i386-vars.fd',varsfile)
 argv=[str(qemu/'qemu-system-x86_64.exe'),'-L',str(share),'-machine','q35,accel=tcg','-cpu','max','-m','512','-smp','1','-nic','none','-display','none','-monitor','none','-qmp','stdio','-serial','file:'+str(run/'serial.log'),'-debugcon','file:'+str(run/'debug.log'),'-global','isa-debugcon.iobase=0x402','-drive','if=pflash,format=raw,unit=0,readonly=on,file='+str(share/'edk2-x86_64-code.fd'),'-drive','if=pflash,format=raw,unit=1,file='+str(varsfile),'-drive','media=cdrom,readonly=on,file='+str(iso),'-boot','order=d']
 (run/'command.json').write_text(json.dumps(argv,indent=2)+'\n');process=None;error=None;checks=[];records=[]
 try:
    with (run/'stderr.log').open('wb') as stderr:
        process=subprocess.Popen(argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=stderr,creationflags=subprocess.CREATE_NO_WINDOW);qmp=QMP(process)
        first=None
        for attempt in range(20):
            time.sleep(2);qmp.screen(run/f'boot-{attempt:02}.png');qmp.key('q');time.sleep(.5);image=run/f'probe-qr-{attempt:02}.png';qmp.screen(image)
            try:
                frame=dec.decoder.read_image(image);meta=dec.decoder.parse_frame(frame)
                if meta['page']!=1:raise ValueError('Expected page one')
                dec.header(meta['data']);first=frame;break
            except ValueError:pass
        assert first is not None,'RAM_TEST09 did not expose a decodable refusal log'
        def collect(label,firstframe):
            meta=dec.decoder.parse_frame(firstframe);frames=[firstframe];dest=run/label;dest.mkdir()
            qmp.screen(dest/'page-01.png');(dest/'page-01.frame').write_bytes(firstframe)
            for page in range(2,meta['pages']+1):
                qmp.key('n');image=dest/f'page-{page:02}.png';qmp.screen(image);frame=dec.decoder.read_image(image);parsed=dec.decoder.parse_frame(frame);assert parsed['page']==page
                frames.append(frame);image.with_suffix('.frame').write_bytes(frame)
            payload,result=dec.decoder.assemble(frames,require_inventory=False);result['snapshot_id']=dec.validate(payload);(dest/'hardware-log.txt').write_bytes(payload);records.append({'label':label,**result});return payload
        initial=collect('snapshot1',first)
        assert b'FAIL complete initial original identity and boot context\r\n' in initial
        assert b'MODE=0000000000000000\r\n' in initial and b'OPERATION_ID=0000000000000000\r\n' in initial and b'ACTION=' not in initial
        checks+=['Exact packaged ISO booted in OVMF','Unsupported platform refused before any menu transaction','All first-snapshot QR pages independently decoded with exact CRC and completeness']
        qmp.key('t');qmp.screen(run/'text-view.png');qmp.key('q');qmp.screen(run/'qr-return.png');assert dec.decoder.parse_frame(dec.decoder.read_image(run/'qr-return.png'))['page']==1
        qmp.key('esc');qmp.screen(run/'refused-menu.png');qmp.key('1');qmp.key('2');qmp.key('q');qmp.screen(run/'refusal-after-keys.png')
        second=collect('snapshot2',dec.decoder.read_image(run/'refusal-after-keys.png'))
        assert dec.header(second)!=dec.header(initial)
        assert re.sub(rb'SNAPSHOT_ID=[0-9A-F]{16}',b'SNAPSHOT_ID=ID',initial)==re.sub(rb'SNAPSHOT_ID=[0-9A-F]{16}',b'SNAPSHOT_ID=ID',second),'Refused transaction keys changed the journal'
        checks+=['Text/QR/ESC viewer transitions returned to the resident menu','Keys 1 and 2 ignored on unsupported platform; operation ID and journal unchanged','Distinct second snapshot preserved same refusal evidence']
        qmp.command('quit');process.wait(timeout=5)
 except Exception as exc:error=repr(exc)
 finally:
    if process and process.poll() is None:process.terminate();process.wait(timeout=10)
 unchanged=sha(iso)==info['iso_sha256'] and sha(efi)==info['efi_sha256'];assert unchanged
 report={'status':'PASS_EXACT_ISO_OVMF_REFUSAL_AND_QR_TRANSPORT' if error is None else 'FAILED_OR_INCOMPLETE','error':error,'run':str(run),'checks':checks,'snapshots':records,'iso_sha256':info['iso_sha256'],'efi_sha256':info['efi_sha256'],'package_sha256':sha(package),'runner_sha256':sha(Path(__file__)),'decoder_sha256':sha(decoder_path),'input_images_unchanged':unchanged,'qemu_exit_code':process.returncode if process else None,'scope':'Actual hash-bound candidate application, optical boot, unsupported-platform refusal and QR/text transport. No ASUS modules, native installation, password UI, physical disks, NIC or BMC attached.'}
 (run/'result.json').write_text(json.dumps(report,indent=2)+'\n');(HERE/'latest_smoke_result.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'status':report['status'],'error':error,'run':str(run)}));return 0 if error is None else 1

if __name__=='__main__':sys.exit(main())
