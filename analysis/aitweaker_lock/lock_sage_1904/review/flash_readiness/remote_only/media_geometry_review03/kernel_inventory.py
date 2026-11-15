"""List only kernel containers/module names in the already present public image."""
from pathlib import Path
import hashlib,json,struct,zlib

HERE=Path(__file__).resolve().parent
REMOTE=HERE.parent
SOURCE=REMOTE/'official_bmc/W7901157.ima'
EXPECTED='0eea0a707e9bcaa6da157db0c8c637b889c456889e0e550a7fb1756a528e565a'

def main():
    raw=SOURCE.read_bytes();assert hashlib.sha256(raw).hexdigest()==EXPECTED
    candidates=[];cursor=0
    while True:
        at=raw.find(b'\x27\x05\x19\x56',cursor)
        if at<0:break
        cursor=at+4
        if at+64>len(raw):continue
        header=raw[at:at+64]
        magic,hcrc,time,size,load,entry,dcrc=struct.unpack('>7I',header[:28])
        check=bytearray(header);check[4:8]=b'\0'*4
        valid=(zlib.crc32(check)&0xffffffff)==hcrc and at+64+size<=len(raw)
        if not valid:continue
        data=raw[at+64:at+64+size]
        row={'offset':at,'payload_bytes':size,'load':hex(load),'entry':hex(entry),
             'os':header[28],'arch':header[29],'type':header[30],'compression':header[31],
             'name':header[32:].split(b'\0')[0].decode('ascii',errors='replace'),
             'data_crc_valid':(zlib.crc32(data)&0xffffffff)==dcrc,'sha256':hashlib.sha256(data).hexdigest(),
             'leading_hex':data[:64].hex()}
        candidates.append(row)
        if row['type']==2 and row['data_crc_valid']:
            output=HERE/'kernel_payload.bin';output.write_bytes(data);row['output']=output.name
    inv=json.loads((REMOTE/'bmc_backend_inventory.json').read_text())
    paths=[x for x in inv['files'] if x['path'].startswith('/lib/modules/') or any(s in x['path'].lower() for s in ['vmlinux','/boot/','kernel','nbd'])]
    signatures={}
    for name,magic in [('gzip',b'\x1f\x8b\x08'),('xz',b'\xfd7zXZ\0'),('arm_zimage',b'\x18\x28\x6f\x01'),
                       ('fit_dtb',b'\xd0\x0d\xfe\xed'),('fmh',b'$MODULE$')]:
        hits=[];cursor=0
        while len(hits)<32:
            at=raw.find(magic,cursor,5308416)
            if at<0:break
            hits.append(at);cursor=at+len(magic)
        signatures[name]=hits
    fmh=[]
    for at in range(0,len(raw)-128,65536):
        if raw[at:at+8]==b'$MODULE$':
            head=raw[at:at+128]
            fmh.append({'offset':at,'header_hex':head.hex(),'ascii':''.join(chr(x) if 32<=x<127 else '.' for x in head)})
    kernels=[]
    for at in signatures['gzip']:
        try:
            obj=zlib.decompressobj(31)
            data=obj.decompress(raw[at:5308416],32*1024*1024)
            if not obj.eof:continue
            row={'gzip_offset':at,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()}
            banner_at=data.find(b'Linux version ')
            if banner_at>=0:
                row['linux_banner']=data[banner_at:banner_at+256].split(b'\0')[0].decode('ascii',errors='replace')
                target=HERE/'kernel_uncompressed.bin';target.write_bytes(data);row['output']=target.name
            kernels.append(row)
        except zlib.error:pass
    out={'source':str(SOURCE),'source_sha256':EXPECTED,'uimage_candidates':candidates,'bounded_filesystem_paths':paths,
         'scan_limit':5308416,'signatures':signatures,'gzip_payloads':kernels,'aligned_fmh_headers':fmh}
    (HERE/'kernel_inventory.json').write_text(json.dumps(out,indent=2),encoding='utf8');print(json.dumps(out,indent=2))
if __name__=='__main__':main()
