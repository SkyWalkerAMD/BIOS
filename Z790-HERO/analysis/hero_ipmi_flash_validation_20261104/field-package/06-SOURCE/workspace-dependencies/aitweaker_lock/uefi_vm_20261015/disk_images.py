"""Create/check regular FAT disk-image FILES; never open host disk devices."""
from pathlib import Path
import sys,struct,uuid,zlib,hashlib,warnings
OUT=Path(__file__).resolve().parent
ROOT=OUT.parents[2]
sys.path.insert(0,str(ROOT/'tools/vm-pydeps'))
warnings.filterwarnings('ignore',message='pkg_resources is deprecated.*')
from pyfatfs.PyFat import PyFat
from pyfatfs.PyFatFS import PyFatFS

SECTOR=512
VOLUME_SIZE=64*1024*1024

def image_path(path):
    path=Path(path).resolve()
    assert path.is_relative_to(OUT.resolve()) and path.suffix=='.img',path
    return path

def sha(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as f:
        for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
    return h.hexdigest()

def partition_tables(path,layout,offset,fat_type):
    if layout=='superfloppy':return
    first=offset//SECTOR;length=VOLUME_SIZE//SECTOR
    mbr=bytearray(SECTOR)
    if layout=='mbr':
        struct.pack_into('<B3sB3sII',mbr,446,0x80,b'\xfe\xff\xff',0x0c if fat_type==32 else 0x0e,
                         b'\xfe\xff\xff',first,length)
        mbr[510:]=b'\x55\xaa'
        with path.open('r+b') as f:f.seek(0);f.write(mbr)
        return
    assert layout=='gpt'
    # Windows QEMU raw files require whole 4 KiB request-alignment units.
    # Leave up to seven spare sectors before the backup GPT array.
    total=((first+length+33+7)//8)*8
    struct.pack_into('<B3sB3sII',mbr,446,0,b'\x00\x02\x00',0xee,b'\xff'*3,1,total-1)
    mbr[510:]=b'\x55\xaa'
    entries=bytearray(128*128)
    entries[:16]=uuid.UUID('c12a7328-f81f-11d2-ba4b-00a0c93ec93b').bytes_le
    entries[16:32]=uuid.UUID('a12a7328-f81f-41d2-ba4b-00a0c93ec93b').bytes_le
    struct.pack_into('<QQQ',entries,32,first,first+length-1,0)
    entries[56:56+len('P2 VM ESP'.encode('utf-16-le'))]='P2 VM ESP'.encode('utf-16-le')
    def header(here,other,entry_lba):
        h=bytearray(SECTOR)
        struct.pack_into('<8sIIIIQQQQ16sQIII',h,0,b'EFI PART',0x10000,92,0,0,here,other,
          34,total-34,uuid.UUID('d0063aa1-d70b-46b3-9a2a-123400000015').bytes_le,
          entry_lba,128,128,zlib.crc32(entries))
        struct.pack_into('<I',h,16,zlib.crc32(h[:92]));return h
    with path.open('r+b') as f:
        f.truncate(total*SECTOR);f.seek(0);f.write(mbr);f.write(header(1,total-1,2));f.write(entries)
        f.seek((total-33)*SECTOR);f.write(entries);f.write(header(total-1,1,total-33))

def create(path,layout='gpt',fat_type=32,files=None,full=False):
    path=image_path(path);path.parent.mkdir(parents=True,exist_ok=True)
    offset=0 if layout=='superfloppy' else 2048*SECTOR
    path.write_bytes(b'')
    fat=PyFat(offset=offset)
    fat.mkfs(str(path),fat_type=fat_type,size=VOLUME_SIZE,label='P2VMTEST',volume_id=0x20261015)
    fat.close()
    # Write the conventional partition-relative hidden-sector count in both boot copies.
    with path.open('r+b') as f:
        f.seek(offset+28);f.write(struct.pack('<I',offset//SECTOR))
        if fat_type==32:f.seek(offset+6*SECTOR+28);f.write(struct.pack('<I',offset//SECTOR))
    with PyFatFS(str(path),offset=offset,utc=True) as fs:
        for name,data in (files or {}).items():
            parent=str(Path(name).parent).replace('\\','/')
            if parent not in ('.','/'):fs.makedirs(parent,recreate=True)
            fs.writebytes(name,data)
        if full:
            fs.writebytes('/FILL.BIN',b'')
            p=fs.fs;head=p.bpb_header
            clusters=(p._get_total_sectors()-p.first_data_sector)//head['BPB_SecPerClus']
            free=sum(1 for i in range(2,clusters+2) if p.fat[i]==0)
            # Exact remaining data space; leave directory slots so Create can succeed
            # while the subsequent Write returns EFI_VOLUME_FULL.
            with fs.openbin('/FILL.BIN','w') as f:
                remaining=free*p.bytes_per_cluster
                while remaining:
                    n=min(1024*1024,remaining);f.write(b'F'*n);remaining-=n
            assert sum(1 for i in range(2,clusters+2) if p.fat[i]==0)==0
    partition_tables(path,layout,offset,fat_type)
    return {'path':str(path),'offset':offset,'layout':layout,'fat_type':fat_type,'sha256':sha(path)}

def inspect(path,offset):
    path=image_path(path);files={};logs={}
    with PyFatFS(str(path),offset=offset,read_only=True,utc=True) as fs:
        for name in fs.walk.files():
            data=fs.readbytes(name)
            files[name]={'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()}
            if Path(name).name.upper().startswith('AITWK-') and name.upper().endswith('.TXT'):
                logs[Path(name).name]=data
    with path.open('rb') as f:
        f.seek(offset);bpb=f.read(SECTOR)
        bps=struct.unpack_from('<H',bpb,11)[0];reserved=struct.unpack_from('<H',bpb,14)[0]
        count=bpb[16];fatsz=struct.unpack_from('<H',bpb,22)[0] or struct.unpack_from('<I',bpb,36)[0]
        f.seek(offset+reserved*bps);fats=[f.read(fatsz*bps) for _ in range(count)]
    assert bpb[510:512]==b'\x55\xaa' and count==2 and fats[0]==fats[1],'FAT copies disagree'
    return {'files':files,'logs':logs,'fat_copies_identical':True,'sha256':sha(path)}

if __name__=='__main__':
    p=OUT/'smoke'/'fat32.img'
    meta=create(p,files={'/AITWEAKER-PROBE.TAG':b'AITWEAKER-PROBE-P2\r\n','/EFI/BOOT/BOOTX64.EFI':b'test'})
    result=inspect(p,meta['offset']);assert len(result['files'])==2
    print('Host FAT image smoke check PASS',meta)
