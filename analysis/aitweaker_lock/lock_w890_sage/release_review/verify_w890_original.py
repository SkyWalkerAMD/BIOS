"""Read-only, pinned W890E-SAGE SE 0603 release prerequisites.

No board, updater, key material other than public keys, or firmware write is
accessed. Negative controls change bytes only in process memory. The signing
stream is a rule demonstrated for this exact image, not a universal AMI spec.
"""
from __future__ import annotations
from pathlib import Path
import base64, hashlib, json, struct, subprocess, uuid, zipfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
EXTRACT = ROOT / 'analysis/workstation_20261008'
BOARD = EXTRACT / 'W890_SAGE_0603'
ZIP = ROOT / 'Pro-WS-W890E-SAGE-SE-ASUS-0603.zip'
CAP = BOARD / 'Pro-WS-W890E-SAGE-SE-ASUS-0603.CAP'
ZIP_SHA = '5bad35967954afb2f10123828e3698c1f36b413b21ce127f15778ed424997df8'
CAP_SHA = 'c7b12934cd0904a9cd4cfca53f656931bd5164e3bc30b99b043c2c2cb39a92d1'
OPENSSL = Path('D:/OpenSSL-Win64/bin/openssl.exe')

def sha(data): return hashlib.sha256(data).hexdigest()
def guid(data): return str(uuid.UUID(bytes_le=bytes(data)))
def check(ok, label):
    if not ok: raise ValueError(label)
def bind(path): return dict(path=str(path.resolve()), size=path.stat().st_size, sha256=sha(path.read_bytes()))
def save(path, obj): path.write_text(json.dumps(obj, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')

def pss(block, digest):
    check(len(block)==528 and guid(block[:16])=='51aa59de-fdf2-4ea3-bc63-875fb7842ee9', 'RSA block format')
    n=int.from_bytes(block[16:272], 'big'); s=int.from_bytes(block[272:], 'big')
    check(n.bit_length()==2048 and n&1, 'RSA modulus')
    if s>=n: return dict(valid=False, reason='signature representative out of range')
    em=pow(s,65537,n).to_bytes(256,'big'); h=em[223:255]
    mask=b''.join(hashlib.sha256(h+i.to_bytes(4,'big')).digest() for i in range(7))[:223]
    db=bytearray(a^b for a,b in zip(em[:223], mask)); db[0]&=0x7f
    checks=dict(trailer=em[-1]==0xbc, top_bit=not(em[0]&0x80), padding=db[:214]==bytes(214),
                delimiter=db[214]==1, digest=h==hashlib.sha256(bytes(8)+digest+bytes(db[-8:])).digest())
    return dict(valid=all(checks.values()), checks=checks, rsa_bits=2048, exponent=65537,
                padding='PSS', hash='SHA256', mgf='MGF1-SHA256', salt_bytes=8,
                modulus_sha256=sha(block[16:272]), signature_sha256=sha(block[272:]), digest=digest.hex())

def capsule(data):
    check(len(data)==67112960 and guid(data[:16])=='4a3ca68b-7723-48fb-803d-578cc1fec44d','W890 capsule identity/layout')
    header,flags,size,body,layout=struct.unpack_from('<IIIHH',data,16)
    check((header,flags,size,body,layout)==(4096,0x10005,len(data),4096,0x458),'W890 header fields')
    check(struct.unpack_from('<IHH',data,0x20)==(0x438,0x200,0xef1),'cert header')
    check(guid(data[0x28:0x38])=='a7717414-c616-4977-9420-844712a735bf','cert type')
    areas=[]; off=layout
    while True:
        check(off+24<=header,'layout bounds'); entry=data[off:off+24]; off+=24
        if entry==bytes(24): break
        physical,raw,length,kind,attrs=struct.unpack('<QIIII',entry)
        check(length>0 and raw+length<=len(data)-body,'area bounds')
        areas.append(dict(index=len(areas), table_offset=off-24, physical_address=physical,
                          body_offset=raw, cap_offset=raw+body, size=length, kind=kind,
                          attributes=attrs, signed=bool(attrs&0x200)))
    check(len(areas)==32 and off==0x770,'W890 region inventory')
    cursor=0
    for item in sorted(areas,key=lambda r:r['body_offset']):
        check(item['body_offset']==cursor,'disjoint whole body partition');cursor+=item['size']
    check(cursor==67108864,'whole body size')
    return dict(header_size=header,flags=flags,body_size=cursor,body_offset=body,
                layout_offset=layout,layout_end=off,areas=areas,
                physical_mapping_note='ROM layout contains more than one physical address window; do not apply a single W790 memory-base formula.')

def firmware_digest(data, header):
    h=hashlib.sha256()
    for area in header['areas']:
        if area['signed']: h.update(data[area['cap_offset']:area['cap_offset']+area['size']])
    h.update(data[header['layout_offset']:header['layout_end']]); return h.digest()

def der_length(n): return bytes([n]) if n<128 else bytes([0x80+((n.bit_length()+7)//8)])+n.to_bytes((n.bit_length()+7)//8,'big')
def der(tag,b): return bytes([tag])+der_length(len(b))+b
def rsa_public_pem(modulus):
    n=modulus if not(modulus[0]&0x80) else b'\0'+modulus
    encoded=der(0x30,der(2,n)+der(2,b'\x01\x00\x01'))
    body=base64.b64encode(encoded).decode();return '-----BEGIN RSA PUBLIC KEY-----\n'+'\n'.join(body[i:i+64] for i in range(0,len(body),64))+'\n-----END RSA PUBLIC KEY-----\n'

def openssl_verify(name, block, digest, expected):
    out=HERE/'public_signature_material';out.mkdir(exist_ok=True)
    key=out/(name+'.public.pem');sig=out/(name+'.signature.bin');dg=out/(name+'.digest.bin')
    key.write_text(rsa_public_pem(block[16:272]),encoding='ascii');sig.write_bytes(block[272:]);dg.write_bytes(digest)
    argv=[str(OPENSSL),'pkeyutl','-verify','-pubin','-inkey',str(key),'-sigfile',str(sig),'-in',str(dg),
          '-pkeyopt','digest:sha256','-pkeyopt','rsa_padding_mode:pss','-pkeyopt','rsa_pss_saltlen:8','-pkeyopt','rsa_mgf1_md:sha256']
    result=subprocess.run(argv,capture_output=True,text=True,timeout=20)
    check((result.returncode==0)==expected,'OpenSSL result '+name)
    return dict(name=name, expected_valid=expected, valid=result.returncode==0, returncode=result.returncode,
                argv=argv, stdout=result.stdout.strip(), stderr=result.stderr.strip(), artifacts=[bind(x) for x in (key,sig,dg)])

def scan_fv(path):
    header=(path/'header.bin').read_bytes();body=(path/'body.bin').read_bytes();data=header+body
    check(data[40:44]==b'_FVH','FV magic');length=struct.unpack_from('<Q',data,32)[0];hs=struct.unpack_from('<H',data,48)[0]
    check(length==len(data),'FV length');check(sum(struct.unpack('<'+'H'*(hs//2),data[:hs]))&0xffff==0,'FV header checksum')
    position=(len(header)+7)&~7;files=[]
    while position<len(data):
        if data[position:position+24]==b'\xff'*24:
            check(data[position:]==b'\xff'*(len(data)-position),'FV trailing erased free bytes');break
        check(position+24<=len(data),'FFS header bounds');h=data[position:position+24]
        size=int.from_bytes(h[20:23],'little');hsize=24
        if h[19]&1:
            check(size==0xffffff and position+32<=len(data),'large FFS header');size=struct.unpack_from('<Q',data,position+24)[0];hsize=32
        check(hsize<=size<=len(data)-position,'FFS size')
        fullh=data[position:position+hsize];b=data[position+hsize:position+size]
        check((sum(fullh)-fullh[17]-fullh[23])&255==0,'FFS header checksum')
        check(((sum(b)+h[17])&255==0) if h[19]&0x40 else h[17]==0xaa,'FFS data checksum')
        files.append(dict(guid=guid(h[:16]),offset=position,size=size,type=h[18],attributes=h[19],state=h[23],sha256=sha(data[position:position+size])))
        position=(position+size+7)&~7
    return dict(directory=str(path.resolve()),full_size=len(data),full_sha256=sha(data),header_size=len(header),
                checked_ffs_count=len(files),files=files,free_offset=position,erased_free_bytes=len(data)-position,
                checksum_validation='PASS',inputs=[bind(path/'header.bin'),bind(path/'body.bin')])

def fit_info(data):
    physical=struct.unpack_from('<Q',data,len(data)-0x40)[0]
    off=physical-0xfc000000+0x1000
    check(0<=off<len(data)-16 and data[off:off+8]==b'_FIT_   ','FIT top-window pointer')
    count=int.from_bytes(data[off+8:off+11],'little');check(1<=count<=4096 and off+count*16<=len(data),'FIT count')
    entries=[]
    for n in range(count):
        b=data[off+16*n:off+16*(n+1)]
        entries.append(dict(index=n,address=int.from_bytes(b[:8],'little'),size=int.from_bytes(b[8:11],'little'),
                            version=int.from_bytes(b[12:14],'little'),type=b[14]&127,checksum_valid_flag=bool(b[14]&128)))
    return dict(physical_address=physical,cap_offset=off,table_sha256=sha(data[off:off+16*count]),entries=entries,
                bootguard_hardware_enforcement=None,changed_region_ibb_coverage=None,
                limit='Table entries do not establish fused or runtime Boot Guard policy.')

def descriptor_info(data, historical):
    body=data[0x1000:]
    check(struct.unpack_from('<I',body,0x10)[0]==0x0ff0a55a,'Intel descriptor signature')
    flmap0=struct.unpack_from('<I',body,0x14)[0];frba=((flmap0>>16)&255)*16
    check(flmap0==0x40003 and frba==0x40,'W890 flash region table')
    regions=[]
    for item in historical['regions']:
        raw=struct.unpack_from('<I',body,frba+4*item['index'])[0]
        start=(raw&0x7fff)*0x1000;end=(((raw>>16)&0x7fff)+1)*0x1000
        check(start<end<=len(body),'flash descriptor region bounds')
        check(raw==int(item['raw_flreg'],16) and start==int(item['spi_start'],16) and end==int(item['spi_end_exclusive'],16),'descriptor inventory cross-check')
        digest=sha(body[start:end]);check(digest==item['sha256'],'descriptor region identity')
        regions.append(dict(index=item['index'],name=item['name'],register=raw,body_offset=start,size=end-start,cap_offset=start+0x1000,sha256=digest))
    return dict(signature=True,flmap0=flmap0,frba=frba,regions=regions,
                first_two_4k_descriptor_blocks_identical=body[:0x1000]==body[0x1000:0x2000],
                current_hardware_access_permissions=None,
                limit='This is the original file descriptor, not a live SPI permission read or JEDEC chip identity.')

def main():
    data=CAP.read_bytes();check(sha(data)==CAP_SHA,'pinned CAP');check(sha(ZIP.read_bytes())==ZIP_SHA,'pinned ZIP')
    with zipfile.ZipFile(ZIP) as z:
        check(z.testzip() is None,'ZIP CRC');check(z.read(CAP.name)==data,'ZIP member matches CAP')
        package=[dict(name=i.filename,size=i.file_size,sha256=sha(z.read(i))) for i in z.infolist() if not i.is_dir()]
        config=z.read('Pro-WS-W890E-SAGE-SE-ASUS-0603.CFG').decode('ascii')
    header=capsule(data);digest=firmware_digest(data,header)
    cert_digest=hashlib.sha256(data[0x48:0x148]).digest()
    auth=dict(firmware=pss(data[0x38:0x248],digest),certificate=pss(data[0x248:0x458],cert_digest))
    check(auth['firmware']['valid'] and auth['certificate']['valid'],'original signatures')
    wrong_cert=pss(data[0x248:0x458],hashlib.sha256(data[0x20:0x248]).digest());check(not wrong_cert['valid'],'W790 certificate rule rejected')
    modified=bytearray(data);modified[0x1841000]^=1
    changed_digest=firmware_digest(modified,header);changed=pss(data[0x38:0x248],changed_digest)
    check(not changed['valid'],'changed DXE invalidates signature')
    layout_changed=bytearray(data);layout_changed[0x458]^=1
    check(not pss(data[0x38:0x248],firmware_digest(layout_changed,header))['valid'],'changed layout invalidates signature')
    openssl=[openssl_verify('original_firmware',data[0x38:0x248],digest,True),
             openssl_verify('original_certificate',data[0x248:0x458],cert_digest,True),
             openssl_verify('changed_dxe_negative',data[0x38:0x248],changed_digest,False),
             openssl_verify('wrong_w790_cert_rule_negative',data[0x248:0x458],hashlib.sha256(data[0x20:0x248]).digest(),False)]
    inventory=json.loads((BOARD/'inventory.json').read_text(encoding='utf-8'))
    modules=[]
    for m in inventory['modules']:
        p=EXTRACT/m['path'];content=(p/'header.bin').read_bytes()
        if (p/'body.bin').exists(): content+=(p/'body.bin').read_bytes()
        else: check(len(content)==m['size'],'missing nonempty FFS body')
        check(len(content)==m['size'] and sha(content)==m['sha256'],'extracted module '+m['guid'])
        modules.append(dict(guid=m['guid'],name=m['name'],sha256=sha(content),size=len(content),path=m['path']))
    volumes=[]
    for n in inventory['nodes']:
        if n.get('info',{}).get('Type')=='Volume' and n['path'].split('\\')[-1].endswith(('4F1C52D3-D824-4D2A-A2F0-EC40C23C5916','5C60F367-A505-419A-859E-2A4FF6CA6FE5')):
            volumes.append(scan_fv(EXTRACT/n['path']))
    check(len(volumes)==2,'two main DXE volume carriers')
    outer=next(x for x in volumes if x['full_size']==0x630000)
    check(sha(data[0x1841000:0x1841000+0x630000])==outer['full_sha256'],'outer FV against original CAP')
    fwkey=next(m for m in inventory['modules'] if m['guid']=='3FEEC852-F14C-4E7F-97FD-4C3A8C5BBECC')
    keysection=next(s for s in fwkey['sections'] if s['type']=='Raw');rootkey=(EXTRACT/keysection['path']).read_bytes()
    check(rootkey==data[0x258:0x358],'embedded public root key matches certificate modulus')
    save(HERE/'checked_modules.json',dict(count=len(modules),modules=modules))
    save(HERE/'checked_dxe_volumes.json',dict(volumes=volumes,capacity_note='Inner free bytes alone cannot hold a 60 KiB provider. Outer free space does not prove dispatch or safe resize.'))
    result=dict(status='PASS_ORIGINAL_STATIC_PREREQUISITES_NOT_RELEASE_ACCEPTANCE',target='ASUS Pro WS W890E-SAGE SE 0603',
        script=bind(Path(__file__)),original=bind(CAP),source_zip=bind(ZIP),zip_members=package,package_cfg=config,
        capsule=header,signature=auth,firmware_signed_digest=digest.hex(),
        certificate_signed_range=dict(start=0x48,end_exclusive=0x148,reason='observed flags bit 2 / public-key-only certificate'),
        embedded_public_root=bind(EXTRACT/keysection['path']),openssl=bind(OPENSSL),openssl_results=openssl,
        negative_controls=dict(changed_dxe_cap_offset=0x1841000,changed_dxe_rejected=not changed['valid'],changed_layout_rejected=True,wrong_w790_certificate_rule_rejected=not wrong_cert['valid'],tampered_images_written=False),
        modules=bind(HERE/'checked_modules.json'),volumes=bind(HERE/'checked_dxe_volumes.json'),
        descriptor=descriptor_info(data,inventory['descriptor']),fit=fit_info(data),original_inputs_unchanged=sha(CAP.read_bytes())==CAP_SHA and sha(ZIP.read_bytes())==ZIP_SHA,
        limits=['No patched candidate was supplied for this verification.','No device access, update upload, Prepare, or flash operation.',
                'Signature self-consistency and matching embedded public key do not prove the current hardware updater trust policy.',
                'BMC 2.01.11 acceptance and recovery must be assessed on W890 evidence, independently of W790.',
                'Main DXE free capacity is measured; relocation/expansion, dispatch and complete boot are not validated.'],
        release_ready=False)
    save(HERE/'original_static_review.json',result)
    print(json.dumps(dict(status=result['status'],signatures={k:v['valid'] for k,v in auth.items()},checked_modules=len(modules),
        dxe=[dict(size=x['full_size'],files=x['checked_ffs_count'],free=x['erased_free_bytes']) for x in volumes],
        report_sha256=sha((HERE/'original_static_review.json').read_bytes()),release_ready=False)))

if __name__=='__main__': main()
