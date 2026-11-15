"""Fetch the authorized QEMU public release in bounded HTTPS byte ranges."""
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor,as_completed
import subprocess,hashlib,json
OUT=Path(__file__).resolve().parent
ROOT=OUT.parents[2]
DEST=ROOT/'tools/uefi-vm-downloads'
PARTS=DEST/'qemu-parts'
URL='https://qemu.weilnetz.de/w64/qemu-w64-setup-20260811.exe'
SIZE=206615928
EXPECTED='5bcf9eed634e8575a37b74f445af41a2fe4106da512d0c30c368301d4c105037fdfab40a5287367a28a957624cddebbc8c07e16c88ab6634f554cdf3d16bf543'
CHUNK=1024*1024

def fetch(index):
    start=index*CHUNK;end=min(SIZE,start+CHUNK)-1;path=PARTS/f'{index:04}.part'
    if path.exists() and path.stat().st_size==end-start+1:return index
    args=['curl.exe','--fail','--location','--silent','--show-error','--connect-timeout','15',
          '--max-time','120','--retry','2','--range',f'{start}-{end}',
          '--output',str(path),URL]
    subprocess.run(args,check=True,creationflags=subprocess.CREATE_NO_WINDOW)
    assert path.stat().st_size==end-start+1,(index,path.stat().st_size)
    return index

def main():
    PARTS.mkdir(parents=True,exist_ok=True)
    first=DEST/'qemu-first-megabyte.part'
    if first.exists() and first.stat().st_size==CHUNK:(PARTS/'0000.part').write_bytes(first.read_bytes())
    count=(SIZE+CHUNK-1)//CHUNK
    with ThreadPoolExecutor(max_workers=8) as pool:
        for i,f in enumerate(as_completed(pool.submit(fetch,k) for k in range(count)),1):
            f.result()
            if i%20==0 or i==count:print('QEMU download chunks',i,'/',count,flush=True)
    target=DEST/'qemu-w64-setup-20260811.exe';h=hashlib.sha512()
    with target.open('wb') as output:
        for i in range(count):
            b=(PARTS/f'{i:04}.part').read_bytes();h.update(b);output.write(b)
    assert h.hexdigest()==EXPECTED,'Downloaded release SHA-512 does not match publisher'
    result={'source':URL,'size':SIZE,'sha512':h.hexdigest(),'publisher_sha512_matches':True}
    (OUT/'download_provenance.json').write_text(json.dumps(result,indent=2),encoding='utf8')
    print('QEMU publisher SHA-512 verified',flush=True)

if __name__=='__main__':main()
