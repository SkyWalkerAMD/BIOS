"""Bounded extraction of SquashFS carriers from the public BMC package.

Filesystem contents are data only. This does not execute firmware or flasher.
"""
from pathlib import Path
import hashlib, json, struct, subprocess, zipfile

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[3]
SEVEN=ROOT/'tools/7zip-26.04/7z.exe'
ZIP=HERE/'W890-ASUS-2.1.11.zip'
IMAGE=HERE/'W8902111.ima_enc'

def bind(path):
    b=path.read_bytes()
    return {'path':str(path.resolve()),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}

def main():
    if bind(ZIP)['sha256']!='168813872f08432d905eccdac89fd1b420f4ac523cde60af0612b40b72ef44de':
        raise ValueError('Pinned official ZIP differs')
    with zipfile.ZipFile(ZIP) as z: data=z.read('W890-ASUS-2.1.11/Image/W8902111.ima_enc')
    if hashlib.sha256(data).hexdigest()!='ceacc396a0bb894dfb14b41613d7fd33a1842668199d7d5127675c11e72a5375':
        raise ValueError('Pinned image differs')
    if IMAGE.exists():
        if IMAGE.read_bytes()!=data: raise ValueError('Existing image differs')
    else: IMAGE.write_bytes(data)
    offset=0; candidates=[]
    while True:
        offset=data.find(b'hsqs',offset)
        if offset<0: break
        if offset+96>len(data): break
        inode_count,mtime,block,fragments=struct.unpack_from('<IIII',data,offset+4)
        comp,blocklog,flags,ids,major,minor=struct.unpack_from('<HHHHHH',data,offset+20)
        used=struct.unpack_from('<Q',data,offset+40)[0]
        valid=(major==4 and minor==0 and comp in range(1,7) and block==(1<<blocklog)
               and 96<=used<=len(data)-offset and 4096<=block<=1048576 and inode_count>0)
        row={'offset':offset,'major':major,'minor':minor,'bytes_used':used,'plausible':valid}
        if valid:
            target=HERE/f'squashfs_{offset:08x}.bin'
            content=data[offset:offset+used]
            if target.exists():
                if target.read_bytes()!=content: raise ValueError('Existing carrier differs')
            else: target.write_bytes(content)
            args=[str(SEVEN),'l','-slt',str(target)]
            result=subprocess.run(args,capture_output=True,timeout=60)
            if result.returncode!=0: raise ValueError(result.stderr.decode('utf-8','replace'))
            listing=target.with_suffix('.listing.txt')
            listing.write_bytes(result.stdout)
            row.update({'compression':comp,'inode_count':inode_count,'block_size':block,
                        'carrier':bind(target),'listing':bind(listing)})
        candidates.append(row);offset+=4
    report={'image':bind(IMAGE),'extractor':bind(SEVEN),'candidates':candidates,
            'target_execution':False,'hardware_access':False,'note':'ima_enc is a filename, not proof its entire body is encrypted'}
    (HERE/'bmc_filesystems.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'image':report['image'],'candidates':candidates}))

if __name__=='__main__': main()
