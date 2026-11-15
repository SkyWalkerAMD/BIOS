"""Run unchanged P2 in local QEMU/OVMF using regular image files only.

No host disks, USB passthrough, host directory sharing, or network adapters.
The optional VMRUNNER application is test instrumentation, not a release EFI.
"""
from pathlib import Path
import argparse,datetime,hashlib,json,queue,re,shutil,struct,subprocess,threading,time,traceback,zlib
from disk_images import OUT,ROOT,create,inspect,sha

QEMU_DIR=ROOT/'tools/qemu-11.1.0'
QEMU=QEMU_DIR/'qemu-system-x86_64.exe'
SHARE=QEMU_DIR/'share'
CODE=SHARE/'edk2-x86_64-code.fd'
VARS=SHARE/'edk2-i386-vars.fd'
P2=OUT.parent/'probe_p2/USB/EFI/BOOT/BOOTX64.EFI'
P2_SHA='a16b2e7e0af6aa48cd375a3a3fbd77e58f60a50edd929751fcfe6951d6df64b5'
MARKER=b'AITWEAKER-PROBE-P2\r\n'
CANARY=b'Existing user file: must survive byte for byte.\x00\xff\r\n'*47
ERR7='8000000000000007'

CASES=[
 {'id':'01_gpt_sata','label':'GPT / FAT32 / SATA: boot, create, flush, read back'},
 {'id':'02_cold_reboot','label':'Cold boot again with previous disk and variable-store bytes','input_from':'01_gpt_sata'},
 {'id':'03_repeat_three','label':'Load and run the same P2 three times in one UEFI boot','repeat':3,'new_logs':3},
 {'id':'04_mbr_usb','label':'MBR / FAT32 / USB xHCI removable boot','layout':'mbr','transport':'usb'},
 {'id':'05_superfloppy_usb','label':'Unpartitioned FAT32 USB removable boot','layout':'superfloppy','transport':'usb'},
 {'id':'06_fat16_mbr','label':'MBR / FAT16 / SATA compatibility','layout':'mbr','fat_type':16},
 {'id':'07_missing_marker','label':'Missing marker: reject log creation','marker':None,'status':ERR7,'new_logs':0},
 {'id':'08_wrong_marker','label':'Old P1 marker: reject log creation','marker':b'AITWEAKER-PROBE-P1\r\n','status':ERR7,'new_logs':0},
 {'id':'09_readonly','label':'Read-only USB boot disk: return error, preserve all disk bytes','transport':'usb','readonly':True,'status':ERR7,'new_logs':0},
 {'id':'10_full_volume','label':'No free clusters: fail write without claiming success','full':True,'status':ERR7,'new_logs':0,'allow_empty_log':True},
 {'id':'11_existing_log','label':'Existing AITWK-000.TXT: preserve it and use 001','existing':1},
 {'id':'12_names_exhausted','label':'All 1000 log names occupied: error without overwrite','existing':1000,'status':ERR7,'new_logs':0},
 {'id':'13_other_marker_only','label':'Marker on secondary disk only: do not redirect writes','marker':None,'secondary':True,'status':ERR7,'new_logs':0},
 {'id':'14_two_marked_disks','label':'Both disks marked: write only to the boot disk','secondary':True},
 {'id':'15_direct_sata','label':'Unchanged P2 as BOOTX64.EFI: direct GPT/SATA firmware boot','direct':True},
 {'id':'16_direct_usb','label':'Unchanged P2 as BOOTX64.EFI: direct FAT32 USB firmware boot','direct':True,'layout':'superfloppy','transport':'usb'},
]

def json_write(path,data):
    path.write_text(json.dumps(data,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')

class QMP:
    def __init__(self,proc,folder):
        self.proc=proc;self.items=queue.Queue();self.serial=0;self.folder=folder
        self.thread=threading.Thread(target=self.read,daemon=True);self.thread.start()
    def read(self):
        with (self.folder/'qmp.jsonl').open('w',encoding='utf-8') as output:
            for line in self.proc.stdout:
                output.write(line);output.flush()
                try:self.items.put(json.loads(line))
                except json.JSONDecodeError:pass
    def command(self,name,args=None,timeout=5):
        self.serial+=1;seq=self.serial
        request={'execute':name,'id':seq}
        if args is not None:request['arguments']=args
        self.proc.stdin.write(json.dumps(request)+'\n');self.proc.stdin.flush()
        deadline=time.monotonic()+timeout
        while time.monotonic()<deadline:
            try:obj=self.items.get(timeout=.1)
            except queue.Empty:
                if self.proc.poll() is not None:raise RuntimeError('QEMU exited during QMP '+name)
                continue
            if obj.get('id')==seq:
                if 'error' in obj:raise RuntimeError(obj['error'])
                return obj.get('return')
        raise TimeoutError('QMP command '+name)

def ppm_to_png(src,dst):
    """Lossless screenshot format conversion, no external imaging dependency."""
    with src.open('rb') as f:
        assert f.readline().strip()==b'P6'
        line=f.readline()
        while line.startswith(b'#'):line=f.readline()
        w,h=map(int,line.split());assert f.readline().strip()==b'255';pixels=f.read()
    assert len(pixels)==w*h*3
    def chunk(tag,data):return struct.pack('>I',len(data))+tag+data+struct.pack('>I',zlib.crc32(tag+data))
    raw=b''.join(b'\x00'+pixels[i*w*3:(i+1)*w*3] for i in range(h))
    dst.write_bytes(b'\x89PNG\r\n\x1a\n'+chunk(b'IHDR',struct.pack('>IIBBBBB',w,h,8,2,0,0,0))+
                    chunk(b'IDAT',zlib.compress(raw,6))+chunk(b'IEND',b''))

def screenshot(qmp,folder):
    ppm=folder/'screen.ppm'
    qmp.command('screendump',{'filename':str(ppm)})
    ppm_to_png(ppm,folder/'screen.png')

def base_files(case):
    files={'/EFI/BOOT/BOOTX64.EFI':P2.read_bytes() if case.get('direct') else (OUT/'VMRUNNER.EFI').read_bytes(),
           '/P2PROBE.EFI':P2.read_bytes(),'/SENTINEL.BIN':CANARY,
           '/VMCASE.TXT':str(case.get('repeat',1)).encode('ascii')}
    if case.get('marker',MARKER) is not None:files['/AITWEAKER-PROBE.TAG']=case.get('marker',MARKER)
    for i in range(case.get('existing',0)):files[f'/AITWK-{i:03}.TXT']=f'PREEXISTING LOG {i}: DO NOT OVERWRITE\r\n'.encode('ascii')
    return files

def qemu_command(case,folder,meta,extra):
    args=[str(QEMU),'-L',str(SHARE),'-machine','q35,accel=tcg','-cpu','max','-m','512','-smp','1',
          '-nic','none','-display','none','-monitor','none','-qmp','stdio',
          '-serial','file:'+str(folder/'serial.log'),'-debugcon','file:'+str(folder/'debug.log'),
          '-global','isa-debugcon.iobase=0x402','-device','isa-debug-exit,iobase=0xf4,iosize=0x4',
          '-drive','if=pflash,format=raw,unit=0,readonly=on,file='+str(CODE),
          '-drive','if=pflash,format=raw,unit=1,file='+str(folder/'vars.fd'),
          '-drive','if=none,id=bootdisk,format=raw,file='+meta['path']+(',readonly=on' if case.get('readonly') else '')]
    if case.get('transport')=='usb':args+=['-device','qemu-xhci,id=xhci','-device','usb-storage,drive=bootdisk,bus=xhci.0,bootindex=1']
    else:args+=['-device','ide-hd,drive=bootdisk,bus=ide.0,bootindex=1']
    if extra:args+=['-drive','if=none,id=otherdisk,format=raw,file='+extra['path'],'-device','ide-hd,drive=otherdisk,bus=ide.1']
    return args

def run_vm(case,folder,meta,extra):
    args=qemu_command(case,folder,meta,extra)
    json_write(folder/'command.json',args)
    start=time.monotonic();captured=False;done=False;last_capture=0
    with (folder/'stderr.log').open('wb') as err:
        proc=subprocess.Popen(args,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=err,
                              text=True,encoding='utf-8',creationflags=subprocess.CREATE_NO_WINDOW)
        qmp=QMP(proc,folder)
        try:
            qmp.command('qmp_capabilities',timeout=15)
            while proc.poll() is None:
                elapsed=time.monotonic()-start
                serial=(folder/'serial.log').read_bytes() if (folder/'serial.log').exists() else b''
                if case.get('direct') and b'Done. Returning to firmware' in serial:
                    screenshot(qmp,folder);captured=True;done=True
                    # Let P2 finish its own 3-second Stall and return before stopping the VM.
                    time.sleep(4);qmp.command('quit');break
                if not captured and b'Saved ' in serial:
                    screenshot(qmp,folder);captured=True
                if elapsed>150:
                    screenshot(qmp,folder);captured=True
                    qmp.command('quit');raise TimeoutError('No completed EFI run within 150 seconds')
                if elapsed-last_capture>30 and not captured:
                    screenshot(qmp,folder);last_capture=elapsed
                time.sleep(.1)
            rc=proc.wait(timeout=10)
            qmp.thread.join(timeout=2)
        finally:
            if proc.poll() is None:
                proc.terminate()
                try:proc.wait(timeout=5)
                except subprocess.TimeoutExpired:proc.kill();proc.wait(timeout=5)
    return {'exit_code':rc,'elapsed_seconds':round(time.monotonic()-start,3),
            'direct_completion_seen':done,'screenshot_captured':captured}

def run_case(case,all_results,retry=False):
    folder=OUT/'cases'/case['id']
    if folder.exists():
        if not retry:raise FileExistsError(str(folder)+' already exists; pass --retry for a separate new attempt')
        n=2
        while folder.with_name(case['id']+f'_attempt{n}').exists():n+=1
        folder=folder.with_name(case['id']+f'_attempt{n}')
    folder.mkdir(parents=True)
    record={'id':case['id'],'label':case['label'],'folder':str(folder.relative_to(OUT)),
            'started_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'p2_sha256':sha(P2),'platform':'QEMU q35 / TCG / generic OVMF, not ASUS firmware',
            'direct_firmware_boot':bool(case.get('direct')),'passed':False}
    try:
        assert record['p2_sha256']==P2_SHA,'Released P2 changed'
        if 'input_from' in case:
            source=all_results[case['input_from']];assert source['passed']
            old_folder=OUT/source['folder'];old_meta=source['image']
            shutil.copyfile(old_meta['path'],folder/'disk.img')
            shutil.copyfile(old_folder/'vars.fd',folder/'vars.fd')
            meta={**old_meta,'path':str(folder/'disk.img'),'sha256':sha(folder/'disk.img')}
            record['cold_boot_source_image_sha256']=source['disk_sha256_after']
            assert meta['sha256']==source['disk_sha256_after']
        else:
            meta=create(folder/'disk.img',layout=case.get('layout','gpt'),fat_type=case.get('fat_type',32),
                        files=base_files(case),full=case.get('full',False))
            shutil.copyfile(VARS,folder/'vars.fd')
        record['image']=meta
        before=inspect(meta['path'],meta['offset']);json_write(folder/'files_before.json',before['files'])
        record['disk_sha256_before']=before['sha256'];record['vars_sha256_before']=sha(folder/'vars.fd')
        extra=None;extra_before=None
        if case.get('secondary'):
            extra=create(folder/'secondary.img',files={'/AITWEAKER-PROBE.TAG':MARKER,'/SECONDARY-CANARY.BIN':CANARY})
            extra_before=inspect(extra['path'],extra['offset']);record['secondary_image']=extra
        record['run']=run_vm(case,folder,meta,extra)
        after=inspect(meta['path'],meta['offset']);json_write(folder/'files_after.json',after['files'])
        record['disk_sha256_after']=after['sha256'];record['vars_sha256_after']=sha(folder/'vars.fd')
        record['fat_copies_identical']=after['fat_copies_identical']
        record['existing_files_preserved']=all(after['files'].get(k)==v for k,v in before['files'].items())
        assert record['existing_files_preserved'],'Existing file changed or disappeared'
        if case.get('readonly'):assert before['sha256']==after['sha256'],'Read-only disk image changed'
        if extra:
            extra_after=inspect(extra['path'],extra['offset'])
            record['secondary_unchanged']=extra_before['sha256']==extra_after['sha256']
            record['secondary_no_logs']=not extra_after['logs']
            assert record['secondary_unchanged'] and record['secondary_no_logs'],'Unexpected secondary disk change'
        debug=(folder/'debug.log').read_text(encoding='ascii',errors='replace')
        serial=(folder/'serial.log').read_text(encoding='utf-8',errors='replace')
        new={k:v for k,v in after['logs'].items() if k not in before['logs']}
        complete={k:v for k,v in new.items() if v.endswith(b'PROBE_COMPLETE\r\n')}
        record['new_logs']=[{'name':k,'bytes':len(v),'sha256':hashlib.sha256(v).hexdigest(),
                             'crc32':f'{zlib.crc32(v):08X}','complete':k in complete} for k,v in sorted(new.items())]
        for name,data in new.items():(folder/name).write_bytes(data)
        assert len(complete)==case.get('new_logs',1),(len(complete),'complete logs',record['new_logs'])
        if case.get('allow_empty_log'):assert all(len(v)==0 or k in complete for k,v in new.items())
        else:assert len(new)==case.get('new_logs',1),'Unexpected incomplete file'
        for name,data in complete.items():
            assert b'COLLECTION_STATUS=PARTIAL\r\n' in data,'Unexpected generic OVMF target inventory status'
            assert b'COLLECTION_STATUS=COMPLETE' not in data
        record['generic_inventory_status']='PARTIAL' if complete else 'NO_SAVED_INVENTORY'
        if case.get('direct'):
            assert record['run']['exit_code']==0 and record['run']['direct_completion_seen']
            assert 'Saved ' in serial and 'Done. Returning to firmware' in serial
            record['efi_return_status']='not instrumented; direct console completion and persisted log observed'
        else:
            loads=re.findall(r'VM_LOAD_STATUS=([0-9A-F]{16})',debug)
            statuses=re.findall(r'VM_PROBE_RETURN=([0-9A-F]{16})',debug)
            record['load_statuses']=loads;record['efi_return_statuses']=statuses
            assert record['run']['exit_code']==33 and 'VM_RUNNER_DONE' in debug,record['run']
            assert loads==['0000000000000000']*case.get('repeat',1),loads
            assert statuses==[case.get('status','0000000000000000')]*case.get('repeat',1),statuses
            matches=re.findall(r'VM_READBACK_INDEX=([0-9A-F]{16}) STATUS=([0-9A-F]{16}) SIZE=([0-9A-F]{16}) CRC32=([0-9A-F]{16})',debug)
            readbacks=[]
            for idx,status,size,crc in matches:
                name=f'AITWK-{int(idx,16):03}.TXT';data=after['logs'][name]
                assert int(status,16)==0 and int(size,16)==len(data) and int(crc,16)==zlib.crc32(data),(name,'UEFI read-back mismatch')
                readbacks.append(name)
            for name in complete:assert name in readbacks,'New log not read back via real UEFI filesystem'
            record['uefi_readbacks_verified']=readbacks
        if case.get('status')==ERR7:assert 'Saved ' not in serial,'Error case claimed save success'
        assert sha(P2)==P2_SHA
        record['passed']=True
    except Exception as exc:
        record['error']=str(exc);record['traceback']=traceback.format_exc()
    record['finished_utc']=datetime.datetime.now(datetime.timezone.utc).isoformat()
    json_write(folder/'result.json',record)
    return record

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--case',action='append');parser.add_argument('--retry',action='store_true');args=parser.parse_args()
    assert all(p.is_file() for p in (QEMU,CODE,VARS,P2,OUT/'VMRUNNER.EFI')),'Missing QEMU/OVMF or EFI artifacts'
    result_file=OUT/'results.json'
    results=json.loads(result_file.read_text(encoding='utf-8')) if result_file.exists() else {}
    chosen=[c for c in CASES if not args.case or c['id'] in args.case]
    assert chosen,'No selected test'
    for case in chosen:
        if case['id'] in results and results[case['id']]['passed'] and not args.retry:
            print('ALREADY PASS',case['id'],flush=True);continue
        print('RUN',case['id'],case['label'],flush=True)
        result=run_case(case,results,args.retry);results[case['id']]=result;json_write(result_file,results)
        print('PASS' if result['passed'] else 'FAIL',case['id'],result.get('error',''),flush=True)
        if not result['passed']:raise SystemExit(1)
    print('VM test results:',sum(x['passed'] for x in results.values()),'/',len(results),'PASS',flush=True)

if __name__=='__main__':main()
