"""Restore BROWSER_BASELINE06 snapshots as data; never execute QR content or infer test success."""
from pathlib import Path
import hashlib, importlib.util, json, re, sys
HERE=Path(__file__).resolve().parent
P3=HERE.parents[1]/'probe_p3_kvm/decode_captures.py'
if hashlib.sha256(P3.read_bytes()).hexdigest()!='f1ad8dc74f62136ce06a1b1cdb18df24de3bcaae0acdd1d388a769d31c128283':
    raise ValueError('P3 decoder identity changed')
spec=importlib.util.spec_from_file_location('browser_baseline06_transport',P3)
decoder=importlib.util.module_from_spec(spec);sys.modules[spec.name]=decoder;spec.loader.exec_module(decoder)
PREFIX=b'AITWK-P3-KVM\r\nSAGE_NATIVE13_BROWSER_BASELINE06\r\n'
END=b'SAGE_NATIVE13_BROWSER_BASELINE06_END\r\n'
SNAP=re.compile(rb'(?m)^SNAPSHOT_ID=([0-9A-Fa-f]{16})\r?$')

def header(data):
    if not data.startswith(PREFIX):raise ValueError('BROWSER_BASELINE06 snapshot identity mismatch')
    ids=SNAP.findall(data)
    if len(ids)!=1:raise ValueError('Exactly one snapshot ID required in first QR chunk')
    return ids[0].decode().upper()

def validate(raw):
    if len(raw)>=24576 or not raw.endswith(END) or raw.count(END)!=1:
        raise ValueError('Snapshot completeness/size mismatch')
    snapshot=header(raw)
    if header(raw[:768])!=snapshot:raise ValueError('Snapshot ID outside first chunk')
    for key,value in [(b'LOG_COMPLETE',b'YES'),(b'LOG_OVERFLOW',b'NO')]:
        values=re.findall(rb'(?m)^'+key+rb'=([^\r\n]*)\r?$',raw)
        if values!=[value]:raise ValueError('Snapshot completeness marker mismatch')
    return snapshot

def put_exact(file,data):
    if file.exists():
        if file.read_bytes()!=data:raise FileExistsError('Refusing to replace evidence')
    else:
        with file.open('xb') as out:out.write(data)

def main():
    if len(sys.argv)!=3:raise ValueError('Expected frame or assemble and one local path')
    mode=sys.argv[1];target=Path(sys.argv[2])
    if mode=='frame':
        raw=decoder.read_image(target);info=decoder.parse_frame(raw)
        if info['pages']>32 or info['total']>=24576:raise ValueError('Snapshot bounds exceeded')
        meta={k:v for k,v in info.items() if k!='data'}
        if info['page']==1:meta['snapshot_id']=header(info['data'])
        put_exact(target.with_suffix('.frame'),raw);print(json.dumps(meta))
    elif mode=='assemble':
        frames=sorted(target.glob('page-[0-9][0-9].frame'))
        raw,meta=decoder.assemble([p.read_bytes() for p in frames],require_inventory=False)
        meta['snapshot_id']=validate(raw)
        put_exact(target/'hardware-log.txt',raw)
        meta.update(scope='Snapshot transport, identity and completeness only. Does not establish native browser success or absence of OEM internal variable writes. No password or flash acceptance inferred.',semantic_parse_pending=True)
        meta['files']={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(target.iterdir()) if p.is_file() and p.name!='manifest.json'}
        put_exact(target/'manifest.json',(json.dumps(meta,indent=2)+'\n').encode('utf-8'))
        print(json.dumps(meta))
    else:raise ValueError('Unsupported action')

if __name__=='__main__':main()
