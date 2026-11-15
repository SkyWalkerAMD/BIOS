"""Independent, read-only ISO/FAT/PE/QR audit; never execute a candidate or connect a device."""
from pathlib import Path
import hashlib,json,re,struct,sys,zlib
HERE=Path(__file__).resolve().parent;D04=HERE.parent;DEL=D04/'ram_test05_delivery'
ROOT=next(p for p in HERE.parents if (p/'tools/kvm-pydeps').is_dir())
sys.dont_write_bytecode=True
sys.path[:0]=[str(ROOT/'tools/kvm-pydeps'),str(ROOT/'tools/pydeps')]
from PIL import Image
import pefile,zxingcpp
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
u16=lambda b,o:struct.unpack_from('<H',b,o)[0]
u32=lambda b,o:struct.unpack_from('<I',b,o)[0]
FINAL='9115f1afbab01b624ed8e3da6cdba74c52e187785c77095e1544a6211a8dc6f3'
CASES=[('cabc716104efe637','20261103_210243','historical intermediate'),('cce126b2d995ab87','20261103_211918','historical intermediate'),('9115f1afbab01b62','20261103_212825','current reviewed candidate')]
bindings={}
def bind(p):
    p=Path(p).resolve();assert p.is_relative_to(ROOT)
    bindings[str(p.relative_to(ROOT)).replace('\\','/') ]={'path':str(p.relative_to(ROOT)).replace('\\','/'),'bytes':p.stat().st_size,'sha256':sha(p)}
    return p

def fat_audit(raw,expected):
    assert len(raw)==16*1024*1024 and raw[510:512]==b'\x55\xaa'
    bps,spc,res,nfat,roots=u16(raw,11),raw[13],u16(raw,14),raw[16],u16(raw,17)
    total=u16(raw,19)or u32(raw,32);spf=u16(raw,22)
    assert bps==512 and spc and spc&(spc-1)==0 and nfat==2 and roots and spf
    assert total*bps==len(raw) and raw[54:62]==b'FAT16   '
    rootsecs=(roots*32+bps-1)//bps;data_sector=res+nfat*spf+rootsecs
    clusters=(total-data_sector)//spc;assert 4085<=clusters<65525
    ft=raw[res*bps:(res+spf)*bps];assert ft==raw[(res+spf)*bps:(res+2*spf)*bps]
    assert u16(ft,0)&0xff==raw[21] and u16(ft,1*2)>=0xfff8
    owned=set();files={};directories=[]
    def chain(first):
        out=[];seen=set();c=first
        while True:
            assert 2<=c<clusters+2 and c not in seen and c not in owned,(first,c)
            seen.add(c);owned.add(c);out.append(c);c=u16(ft,c*2)
            if c>=0xfff8:break
            assert c!=0xfff7 and c<0xfff0
        return b''.join(raw[(data_sector+(c-2)*spc)*bps:(data_sector+(c-1)*spc)*bps]for c in out)
    def directory(buf,parent):
        for off in range(0,len(buf),32):
            e=buf[off:off+32]
            if not e[0]:break
            assert e[0]!=0xe5 and e[11]!=0x0f,'Unexpected deleted/LFN entry'
            if e[11]&8:assert parent=='';continue
            name=e[:8].decode('ascii').rstrip();ext=e[8:11].decode('ascii').rstrip()
            if name in ['.','..']:continue
            if ext:name+='.'+ext
            assert u16(e,20)==0
            p=parent+'/'+name;size=u32(e,28);content=chain(u16(e,26))
            if e[11]&0x10:
                assert size==0;directories.append(p);directory(content,p)
            else:
                assert size<=len(content) and size>len(content)-spc*bps
                assert p not in files;files[p]=content[:size]
    start=(res+nfat*spf)*bps;directory(raw[start:start+roots*32],'')
    assert directories==['/EFI','/EFI/BOOT'] and list(files)==['/EFI/BOOT/BOOTX64.EFI']
    assert files['/EFI/BOOT/BOOTX64.EFI']==expected
    allocated={i for i in range(2,clusters+2)if u16(ft,i*2)!=0};assert allocated==owned,'Unexpected orphan allocation'
    return {'filesystem':'FAT16 superfloppy','bytes':len(raw),'bytes_per_sector':bps,'sectors_per_cluster':spc,'clusters':clusters,'allocated_clusters':len(owned),'fat_copies_equal':True,'directories':directories,'only_file':'/EFI/BOOT/BOOTX64.EFI','file_bytes':len(expected),'file_sha256':hashlib.sha256(expected).hexdigest(),'orphan_allocations':0}

def iso_audit(raw,fat):
    assert len(raw)%2048==0
    descriptors=[];boot=None;pvd=None
    for lba in range(16,32):
        d=raw[lba*2048:(lba+1)*2048];assert d[1:6]==b'CD001' and d[6]==1
        descriptors.append({'lba':lba,'type':d[0]})
        if d[0]==0:assert boot is None and d[7:39].rstrip(b'\0 ')==b'EL TORITO SPECIFICATION';boot=d
        if d[0]==1:assert pvd is None;pvd=d
        if d[0]==255:break
    assert descriptors==[{'lba':16,'type':1},{'lba':17,'type':0},{'lba':18,'type':2},{'lba':19,'type':255}]
    assert u32(pvd,80)==struct.unpack_from('>I',pvd,84)[0]==len(raw)//2048
    catalog_lba=u32(boot,71);cat=raw[catalog_lba*2048:(catalog_lba+1)*2048]
    assert len(cat)==2048 and cat[0]==1 and cat[1]==0xef and cat[30:32]==b'\x55\xaa'
    assert sum(struct.unpack('<16H',cat[:32]))&0xffff==0
    assert cat[32]==0x88 and cat[33]==0 and u16(cat,34)==0 and cat[36]==0 and cat[37]==0
    assert not any(cat[64:]),'Additional boot entries prohibited'
    nsectors=u16(cat,38);image_lba=u32(cat,40)
    assert nsectors*512==len(fat) and raw[image_lba*2048:image_lba*2048+len(fat)]==fat
    assert image_lba*2048+len(fat)==len(raw)
    # Parse the ISO primary root directory independently of pycdlib.
    root=pvd[156:190];rlba=u32(root,2);rsize=u32(root,10);listing={};data=raw[rlba*2048:rlba*2048+rsize];off=0
    while off<len(data):
        if not data[off]:off=((off//2048)+1)*2048;continue
        e=data[off:off+data[off]];off+=len(e);assert len(e)>=34
        name=e[33:33+e[32]]
        if name in [b'\0',b'\1']:continue
        assert not(e[25]&2);listing[name.decode('ascii')]=(u32(e,2),u32(e,10))
    assert listing=={'BOOT.CAT;1':(catalog_lba,2048),'EFIBOOT.IMG;1':(image_lba,len(fat))},listing
    return {'volume_descriptors':descriptors,'catalog_lba':catalog_lba,'validation_checksum_valid':True,'only_boot_platform':'EFI 0xEF','boot_media':'no emulation','boot_image_lba':image_lba,'load_sectors_512':nsectors,'only_boot_entry':True,'legacy_bios_boot_entry':False,'embedded_fat_exact':True,'primary_root_files':listing}

def qr_audit(png,frame_path=None):
    codes=zxingcpp.read_barcodes(Image.open(png));assert len(codes)==1
    b=bytes(codes[0].bytes);head,content=b.split(b'\n\n',1)
    m=re.fullmatch(rb'AITWK-P3-KVM\nT=(\d+);C=([0-9A-F]{8});P=(\d+)/(\d+);O=(\d+);N=(\d+);D=([0-9A-F]{8})',head);assert m
    total,crc,page,pages,offset,length,pcrc=m.groups();total,page,pages,offset,length=map(int,[total,page,pages,offset,length])
    assert page==pages==1 and offset==0 and total==length==len(content)
    actual=f'{zlib.crc32(content)&0xffffffff:08X}'.encode();assert actual==crc==pcrc
    if frame_path:assert b==frame_path.read_bytes()
    assert content.startswith(b'AITWK-P3-KVM\r\nSAGE_NATIVE13_RAM_TEST05\r\n')
    assert content.count(b'SAGE_NATIVE13_RAM_TEST05_END\r\n')==1 and content.endswith(b'SAGE_NATIVE13_RAM_TEST05_END\r\n')
    for t in [b'MODE=0000000000000000\r\n',b'OPERATION_ID=0000000000000000\r\n',b'FAIL exact SAGE SE 1904 SMBIOS\r\n',b'FAIL complete initial original identity and boot context\r\n',b'LOG_OVERFLOW=NO\r\n',b'LOG_COMPLETE=YES\r\n']:
        assert content.count(t)==1
    assert b'ACTION='not in content
    ids=re.findall(rb'SNAPSHOT_ID=([0-9A-F]{16})\r\n',content);assert len(ids)==1
    return content,{'png':str(png.relative_to(ROOT)),'pages':pages,'bytes':total,'crc32':actual.decode(),'sha256':hashlib.sha256(content).hexdigest(),'snapshot_id':ids[0].decode()}

def audit(case):
    short,runid,role=case;package=DEL/'packages'/short/'package.json';info=json.loads(package.read_text());run=DEL/'ovmf'/runid;result=json.loads((run/'result.json').read_text())
    for p in list(package.parent.rglob('*'))+list(run.rglob('*')):
        if p.is_file():bind(p)
    efi=Path(info['efi']);iso=Path(info['iso']);fat=Path(info['boot_image'])
    assert sha(efi)==info['efi_sha256']==result['efi_sha256'] and sha(iso)==info['iso_sha256']==result['iso_sha256']
    assert sha(fat)==info['boot_image_sha256'] and sha(package)==result['package_sha256']
    assert info['hardware_execution']is False and info['firmware_release_ready']is False
    assert result['status']=='PASS_EXACT_ISO_OVMF_REFUSAL_AND_QR_TRANSPORT' and result['error']is None and result['qemu_exit_code']==0 and result['input_images_unchanged']is True
    raw=efi.read_bytes();pe=pefile.PE(data=raw)
    assert pe.FILE_HEADER.Machine==0x8664 and pe.OPTIONAL_HEADER.Subsystem==10
    for i in [1,4,13]:assert pe.OPTIONAL_HEADER.DATA_DIRECTORY[i].Size==pe.OPTIONAL_HEADER.DATA_DIRECTORY[i].VirtualAddress==0
    assert pe.OPTIONAL_HEADER.DATA_DIRECTORY[5].Size>0
    assert all((s.Characteristics&0xA0000000)!=0xA0000000 for s in pe.sections)
    entry=pe.OPTIONAL_HEADER.AddressOfEntryPoint;assert any(s.VirtualAddress<=entry<s.VirtualAddress+s.Misc_VirtualSize and s.Characteristics&0x20000000 for s in pe.sections)
    argv=json.loads((run/'command.json').read_text());assert argv.count('-nic')==1 and argv[argv.index('-nic')+1]=='none'
    assert not any(x in argv for x in ['-net','-netdev','-hda','-hdb','-hdd','-device','-kernel','-initrd'])
    drives=[argv[i+1]for i,x in enumerate(argv)if x=='-drive'];assert len(drives)==3
    share=ROOT/'tools/qemu-11.1.0/share'
    assert drives==['if=pflash,format=raw,unit=0,readonly=on,file='+str(share/'edk2-x86_64-code.fd'),'if=pflash,format=raw,unit=1,file='+str(run/'vars.fd'),'media=cdrom,readonly=on,file='+str(iso)]
    assert argv[argv.index('-qmp')+1]=='stdio' and argv[argv.index('-monitor')+1]=='none'
    pairs=[]
    for png in run.rglob('*.png'):
        ppm=png.with_suffix('.ppm');assert ppm.is_file()
        a,b=Image.open(png),Image.open(ppm);assert a.size==b.size and a.convert('RGB').tobytes()==b.convert('RGB').tobytes();pairs.append(str(png.relative_to(run)))
    snapshots=[];payloads=[]
    for label in ['snapshot1','snapshot2']:
        sub=run/label;payload,entry=qr_audit(sub/'page-01.png',sub/'page-01.frame');assert payload==(sub/'hardware-log.txt').read_bytes()
        saved=next(x for x in result['snapshots']if x['label']==label)
        for field in ['pages','bytes','crc32','sha256','snapshot_id']:assert entry[field]==saved[field]
        snapshots.append(entry);payloads.append(payload)
    assert snapshots[0]['snapshot_id']!=snapshots[1]['snapshot_id']
    assert re.sub(rb'SNAPSHOT_ID=[0-9A-F]{16}',b'SNAPSHOT_ID=ID',payloads[0])==re.sub(rb'SNAPSHOT_ID=[0-9A-F]{16}',b'SNAPSHOT_ID=ID',payloads[1])
    assert qr_audit(run/'qr-return.png')[0]==payloads[0]
    assert qr_audit(run/'refusal-after-keys.png')[0]==payloads[1]
    for png in run.glob('probe-qr-*.png'):assert qr_audit(png)[0]==payloads[0]
    provenance={}
    for p,key in [(package.parent/'packager-snapshot.py','packager_sha256'),(run/'runner-snapshot.py','runner_sha256'),(run/'decoder-snapshot.py','decoder_sha256')]:
        reference=info if key=='packager_sha256' else result
        provenance[key]={'recorded_sha256':reference[key],'snapshot_present':p.exists()}
        if p.exists():assert sha(p)==reference[key]
    if role=='current reviewed candidate':
        assert info['efi_sha256']==FINAL and info['iso_sha256']=='aca8533281df2d2432881a28441143baf104bc3655bc3309620c76055251ae78'
        for name,key in [('package_app.py','packager_sha256'),('smoke_iso.py','runner_sha256')]:
            bind(DEL/name);assert sha(DEL/name)==provenance[key]['recorded_sha256']
    return {'role':role,'package_sha256':sha(package),'efi_sha256':sha(efi),'efi_bytes':len(raw),'iso_sha256':sha(iso),'iso_bytes':iso.stat().st_size,'fat':fat_audit(fat.read_bytes(),raw),'eltorito':iso_audit(iso.read_bytes(),fat.read_bytes()),'pe_machine':'AMD64','pe_subsystem':'EFI_APPLICATION','import_delayimport_security_directories_empty':True,'pe_has_rwx_section':False,'command_has_network':False,'command_has_host_disks':False,'only_writable_vm_storage':'per-run OVMF variable copy','png_ppm_pairs':len(pairs),'snapshots':snapshots,'provenance':provenance,'scope':'Optical boot and unsupported-platform refusal/menu log transport only; no native installer or password success inferred.'}

def main():
    reports=[audit(c)for c in CASES]
    for p in [ROOT/'tools/qemu-11.1.0/qemu-system-x86_64.exe',ROOT/'tools/qemu-11.1.0/share/edk2-x86_64-code.fd',ROOT/'tools/qemu-11.1.0/share/edk2-i386-vars.fd']:bind(p)
    result={'status':'PASS_INDEPENDENT_READONLY_DELIVERY_REVIEW','final_efi_sha256':FINAL,'reviews':reports,'bindings':list(bindings.values()),'limitations':['The cabc and cce packages/runs are historical intermediates, including old wording calling cabc final. Only 9115/aca85332 identifies this reviewed candidate.','The first historical cabc package/run lacks source snapshots; its recorded script hashes are preserved and not reconstructed from the newer scripts.','The recorded runner sends keys 1 and 2 and the second complete log differs only by snapshot ID. This proves the observed refusal path, not installation success.','Screenshots and results are local OVMF evidence. This review performs no physical device operation and grants no firmware flash/release approval.']}
    (HERE/'delivery_structure_result.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'status':result['status'],'packages':len(reports),'png_ppm_pairs':sum(x['png_ppm_pairs']for x in reports),'raw_snapshots':sum(len(x['snapshots'])for x in reports),'bindings':len(bindings)}))
if __name__=='__main__':main()
