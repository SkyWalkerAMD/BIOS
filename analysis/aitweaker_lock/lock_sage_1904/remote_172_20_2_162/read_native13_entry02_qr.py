"""Transport-only capture of the read-only N13 entry-context probe."""
from pathlib import Path
import hashlib, importlib.util, json, sys
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('native13_entry02_p3_decoder', HERE.parents[1]/'probe_p3_kvm/decode_captures.py')
decoder=importlib.util.module_from_spec(spec)
sys.modules[spec.name]=decoder
spec.loader.exec_module(decoder)

def main():
    if sys.argv[1]=='frame':
        screenshot=Path(sys.argv[2]);raw=decoder.read_image(screenshot)
        info=decoder.parse_frame(raw)
        if info['pages']>64 or info['total']>=24576:raise ValueError('Capture limit exceeded')
        screenshot.with_suffix('.frame').write_bytes(raw)
        print(json.dumps({k:v for k,v in info.items() if k!='data'}))
    elif sys.argv[1]=='assemble':
        folder=Path(sys.argv[2])
        raw,meta=decoder.assemble([p.read_bytes() for p in sorted(folder.glob('*.frame'))],require_inventory=False)
        head=b'AITWK-P3-KVM\r\nSAGE_NATIVE13_ENTRY_CONTEXT02_READONLY\r\n'
        required=[b'INSTALLATION_AUTHORIZED_BY_PROBE=NO',b'RuntimeTableChanged=NO',
                  b'ProviderStarted=NO',b'LOG_COMPLETE=YES',b'LOG_OVERFLOW=NO',
                  b'BROWSER_ABSENCE_PROOF=NO',b'INSTALLATION_AUTHORIZED_BY_CONTEXT=NO']
        if len(raw)>=24576 or not raw.startswith(head) or not raw.endswith(b'SAGE_NATIVE13_ENTRY_CONTEXT02_END\r\n'):
            raise ValueError('Probe identity, length or completion marker mismatch')
        if any(raw.count(x)!=1 for x in required):raise ValueError('Read-only or completeness marker mismatch')
        if raw.count(b'NO_FLASH_NO_HOOKS_NO_VARIABLE_WRITES_NO_DISK_WRITES')!=2:
            raise ValueError('Read-only scope markers mismatch')
        target=folder/'hardware-log.txt'
        if target.exists() and target.read_bytes()!=raw:raise FileExistsError(target)
        target.write_bytes(raw)
        meta['scope']='Transport and read-only markers only. No install or browser-absence proof.'
        meta['semantic_parse_pending']=True
        meta['files']={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(folder.glob('*'))
                       if p.is_file() and p.name!='manifest.json'}
        (folder/'manifest.json').write_text(json.dumps(meta,indent=2)+'\n',encoding='utf8')
        print(json.dumps(meta))
    else:raise ValueError('Unsupported action')

if __name__=='__main__':main()
